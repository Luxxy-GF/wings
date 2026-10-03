use super::super::{ProcessHandle, ProcessStatus, StatusReceiver};
use super::{IncusExecutor, InstanceState, client::segment, storage::Storage};
use anyhow::{Context, ensure};
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::AsyncWriteExt,
    sync::{broadcast, mpsc},
};
use tokio_tungstenite::tungstenite::Message;

// The real image entrypoint remains argv, never interpolated into a host shell.
// Control files live in a separate Incus volume, outside panel-visible server data.
pub const SUPERVISOR: &str = concat!(
    "rm -f /opt/wings-control/exit; exec 3<&0; ",
    r#""$@" <&3 3<&- & child=$!; exec 3<&-; "#,
    r#"printf '%s\n' "$child" > /opt/wings-control/pid; "#,
    r#"trap 'kill -TERM "$child" 2>/dev/null' TERM; "#,
    r#"trap 'kill -INT "$child" 2>/dev/null' INT; "#,
    r#"trap 'kill -QUIT "$child" 2>/dev/null' QUIT; "#,
    r#"while :; do wait "$child"; code=$?; kill -0 "$child" 2>/dev/null || break; done; "#,
    r#"printf '%s\n' "$code" > /opt/wings-control/exit.tmp; "#,
    r#"mv /opt/wings-control/exit.tmp /opt/wings-control/exit; exit "$code""#,
);

pub fn encode_argv(args: &[String]) -> anyhow::Result<String> {
    ensure!(
        !args.is_empty() && args.iter().all(|arg| !arg.contains('\0')),
        "invalid OCI argv"
    );
    Ok(args
        .iter()
        .map(|arg| format!("'{}'", arg.replace('\'', "'\\''")))
        .collect::<Vec<_>>()
        .join(" "))
}

pub fn launch_script(args: &[String]) -> anyhow::Result<String> {
    // StartExecute inherits Incus's fork log descriptors, rather than the console.
    // Connect the game to the instance console explicitly before the supervisor starts.
    let script = format!(
        "#!/bin/sh\nexec </dev/console >/dev/console 2>&1\nexec {}\n",
        encode_argv(args)?
    );
    ensure!(script.len() <= 262144, "OCI launch script exceeds 256 KiB");
    Ok(script)
}

fn console_input(data: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(data.len());
    let mut previous = None;
    for &byte in data {
        if byte == b'\n' {
            if previous != Some(b'\r') {
                input.push(b'\r');
            }
        } else {
            input.push(byte);
        }
        previous = Some(byte);
    }
    input
}

pub struct Handle {
    name: String,
    executor: IncusExecutor,
    server: Weak<crate::server::InnerServer>,
    started: Arc<AtomicBool>,
    stdin: mpsc::Sender<Vec<u8>>,
    lines: broadcast::Sender<Arc<compact_str::CompactString>>,
    limited: broadcast::Sender<Arc<compact_str::CompactString>>,
    log_path: PathBuf,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}
impl Drop for Handle {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
impl Handle {
    pub async fn connect(
        executor: IncusExecutor,
        server: &crate::server::Server,
        name: String,
        attached: bool,
        runtime: bool,
    ) -> anyhow::Result<(Arc<dyn ProcessHandle>, StatusReceiver)> {
        let (stdin, stdin_rx) = mpsc::channel(150);
        let capacity = executor.config.load().system.websocket_log_count.max(1);
        let (lines, _) = broadcast::channel(capacity * 2);
        let (limited, _) = broadcast::channel(capacity);
        let (status, status_rx) = mpsc::channel(8);
        let started = Arc::new(AtomicBool::new(attached));
        let log_path = executor
            .state_root()
            .join("logs")
            .join(format!("{name}.log"));
        tokio::fs::create_dir_all(log_path.parent().context("log directory missing")?).await?;
        if !attached {
            tokio::fs::write(&log_path, []).await?;
        }
        let weak = Arc::downgrade(server);
        let console = tokio::spawn(console_task(
            executor.clone(),
            name.clone(),
            stdin_rx,
            lines.clone(),
            limited.clone(),
            log_path.clone(),
        ));
        let monitor = tokio::spawn(monitor_task(
            executor.clone(),
            name.clone(),
            Arc::clone(&started),
            status,
            weak.clone(),
            runtime,
        ));
        Ok((
            Arc::new(Self {
                name,
                executor,
                server: weak,
                started,
                stdin,
                lines,
                limited,
                log_path,
                tasks: vec![console, monitor],
            }),
            status_rx,
        ))
    }
}

async fn console_task(
    executor: IncusExecutor,
    name: String,
    mut stdin: mpsc::Receiver<Vec<u8>>,
    lines: broadcast::Sender<Arc<compact_str::CompactString>>,
    limited: broadcast::Sender<Arc<compact_str::CompactString>>,
    path: PathBuf,
) {
    let mut pending = Vec::new();
    let mut line_count = 0;
    let mut interval = std::time::Instant::now();
    let mut initial_replay = true;
    let mut emit = |chunk: &[u8]| {
        pending.extend_from_slice(chunk);
        while let Some(position) = pending.iter().position(|byte| *byte == b'\n') {
            let bytes: Vec<_> = pending.drain(..=position).collect();
            let line = Arc::new(compact_str::CompactString::from(
                String::from_utf8_lossy(&bytes).trim_end_matches(['\r', '\n']),
            ));
            let _ = lines.send(Arc::clone(&line));
            let cfg = executor.config.load();
            if interval.elapsed() >= Duration::from_millis(cfg.throttles.line_reset_interval) {
                interval = std::time::Instant::now();
                line_count = 0;
            }
            line_count += 1;
            if !cfg.throttles.enabled || line_count <= cfg.throttles.lines {
                let _ = limited.send(line);
            }
        }
        // A guest can output an endless line. Bound its pending line buffer too.
        if pending.len() > 65536 {
            pending.clear();
        }
    };
    loop {
        let connection = async {
            let (operation, fds) = executor.client.console(&name).await?;
            let data_secret = fds
                .get("0")
                .and_then(Value::as_str)
                .context("console data descriptor missing")?;
            let control_secret = fds
                .get("control")
                .and_then(Value::as_str)
                .context("console control descriptor missing")?;
            // Match the official client: establish control before activating data.
            let mut control = executor
                .client
                .websocket(&operation, control_secret)
                .await?;
            let data = executor.client.websocket(&operation, data_secret).await?;
            control
                .send(Message::Text(
                    json!({
                        "command": "window-resize", "args": {"width": "120", "height": "40"}
                    })
                    .to_string()
                    .into(),
                ))
                .await?;
            Ok::<_, anyhow::Error>((data, control))
        }
        .await;
        match connection {
            Ok((mut data, mut control)) => {
                tracing::debug!(instance = %name, "Incus console websockets connected");
                // Incus acknowledges the WebSocket before its forkconsole child
                // initializes the terminal (which can flush early input). Keep
                // queued commands until that initial attachment has settled.
                let input_ready = tokio::time::sleep(Duration::from_secs(5));
                tokio::pin!(input_ready);
                let mut accept_input = false;
                let log = tokio::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                    .await;
                let Ok(mut log) = log else {
                    tracing::error!(instance = %name, "could not open Incus console log");
                    return;
                };
                if initial_replay {
                    if let Ok(Ok(buffer)) = tokio::time::timeout(
                        Duration::from_secs(2),
                        executor.client.console_buffer(&name),
                    )
                    .await
                    {
                        let _ = log.write_all(&buffer).await;
                        emit(&buffer);
                    }
                    initial_replay = false;
                }
                tracing::debug!(instance = %name, "Incus console input/output loop ready");
                loop {
                    tokio::select! {
                        () = &mut input_ready, if !accept_input => {
                            accept_input = true;
                        }
                        command = stdin.recv(), if accept_input => {
                            let Some(command) = command else { return; };
                            if data.send(Message::Binary(command.into())).await.is_err() { break; }
                            tracing::debug!(instance = %name, "Incus console input frame sent");
                        }
                        message = data.next() => {
                            let chunk = match message { Some(Ok(Message::Binary(data))) => data, Some(Ok(Message::Text(data))) => data.as_bytes().to_vec().into(), Some(Ok(Message::Ping(ping))) => { let _ = data.send(Message::Pong(ping)).await; continue; }, Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break, _ => continue };
                            // Keep a bounded local replay log. A rolling file reader is never a status signal.
                            if log.metadata().await.is_ok_and(|meta| meta.len() > 10 * 1024 * 1024) { let _ = log.set_len(0).await; }
                            let _ = log.write_all(&chunk).await;
                            emit(&chunk);
                        }
                        message = control.next() => {
                            match message { Some(Ok(Message::Ping(data))) => { let _ = control.send(Message::Pong(data)).await; }, Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break, _ => {} }
                        }
                    }
                }
            }
            Err(err) => {
                tracing::debug!(instance = %name, error = %err, "Incus console not yet available; retrying");
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn monitor_task(
    executor: IncusExecutor,
    name: String,
    started: Arc<AtomicBool>,
    status: mpsc::Sender<ProcessStatus>,
    server: Weak<crate::server::InnerServer>,
    runtime: bool,
) {
    let mut previous = String::new();
    let mut running_announced = false;
    let mut cpu = None::<(u64, std::time::Instant)>;
    loop {
        let state = executor
            .client
            .get::<InstanceState>(&format!("/1.0/instances/{}/state", segment(&name)))
            .await;
        match state {
            Ok(state) => {
                if runtime && let Some(server) = server.upgrade() {
                    let now = std::time::Instant::now();
                    let cpu_usage = state.cpu.get("usage").copied().unwrap_or(0);
                    let percent = cpu.map_or(0.0, |(before, time)| {
                        cpu_usage.saturating_sub(before) as f64
                            / now.duration_since(time).as_nanos().max(1) as f64
                            * 100.0
                    });
                    cpu = Some((cpu_usage, now));
                    let build = server.configuration.read().await;
                    server.resource_usage.send_modify(|usage| {
                        usage.memory_bytes = state.memory.get("usage").copied().unwrap_or(0);
                        usage.memory_limit_bytes = state.memory.get("total").copied().unwrap_or(0);
                        usage.cpu_absolute = percent;
                        usage.cpu_limit_absolute = if build.build.cpu_limit > 0 {
                            build.build.cpu_limit as u32
                        } else {
                            std::thread::available_parallelism()
                                .map_or(100, |threads| threads.get() as u32 * 100)
                        };
                        usage.uptime = state
                            .started_at
                            .as_ref()
                            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                            .map_or(0, |time| {
                                if state.status == "Running" || state.status == "Frozen" {
                                    chrono::Utc::now()
                                        .signed_duration_since(time)
                                        .num_milliseconds()
                                        .max(0) as u64
                                } else {
                                    0
                                }
                            });
                        if let Some(counters) =
                            state.network.get("eth0").and_then(|v| v.get("counters"))
                        {
                            usage.network.rx_bytes = counters
                                .get("bytes_received")
                                .and_then(Value::as_u64)
                                .unwrap_or(0);
                            usage.network.tx_bytes = counters
                                .get("bytes_sent")
                                .and_then(Value::as_u64)
                                .unwrap_or(0);
                            usage.network.rx_packets = counters
                                .get("packets_received")
                                .and_then(Value::as_u64)
                                .unwrap_or(0);
                            usage.network.tx_packets = counters
                                .get("packets_sent")
                                .and_then(Value::as_u64)
                                .unwrap_or(0);
                        }
                    });
                }
                if state.status != previous {
                    match state.status.as_str() {
                        "Running" => {
                            running_announced = true;
                            started.store(true, Ordering::SeqCst);
                            if status.send(ProcessStatus::Running).await.is_err() {
                                return;
                            }
                        }
                        "Frozen" if status.send(ProcessStatus::Paused).await.is_err() => return,
                        _ => {}
                    }
                    previous = state.status.clone();
                }
                if state.status == "Stopped" && started.load(Ordering::SeqCst) {
                    // A successful start can finish between polls. Installer consumers require
                    // an acknowledged start before a final stop; do not lose fast jobs.
                    if !running_announced && status.send(ProcessStatus::Running).await.is_err() {
                        return;
                    }

                    let exit = executor
                        .client
                        .read_file(
                            &executor
                                .storage
                                .file_path(&Storage::control_name(&name), "exit"),
                        )
                        .await;
                    let code = exit
                        .ok()
                        .and_then(|data| String::from_utf8(data).ok())
                        .and_then(|s| s.trim().parse::<i32>().ok())
                        .unwrap_or(-1);
                    // Finish automatic script cleanup before notifying consumers;
                    // they may immediately drop this handle and abort its tasks.
                    if name.starts_with("wgx-")
                        && let Err(error) = executor.remove_instance(&name).await
                    {
                        tracing::warn!(instance = %name, %error, "could not clean up Incus script instance");
                    }
                    let _ = status
                        .send(ProcessStatus::Stopped {
                            exit_code: code,
                            oom_killed: false,
                        })
                        .await;
                    // Incus has no durable Docker-equivalent per-exit OOM flag; do not infer it from code 137.
                    return;
                }
            }
            Err(err) => {
                tracing::warn!(instance = %name, error = %err, "could not read Incus process state")
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

#[async_trait::async_trait]
impl ProcessHandle for Handle {
    async fn logs(
        &self,
        lines: Option<usize>,
    ) -> anyhow::Result<Box<dyn tokio::io::AsyncRead + Send + Unpin>> {
        if let Some(lines) = lines {
            let data = tokio::fs::read(&self.log_path).await?;
            let text = String::from_utf8_lossy(&data);
            let selected = text
                .lines()
                .rev()
                .take(lines)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join("\n");
            Ok(Box::new(std::io::Cursor::new(selected.into_bytes())))
        } else {
            Ok(Box::new(tokio::fs::File::open(&self.log_path).await?))
        }
    }
    async fn send_stdin(&self, data: Vec<u8>) -> anyhow::Result<()> {
        ensure!(data.len() <= 65536, "console input exceeds 64 KiB");
        // The Incus console is a terminal; Enter is CR, as in its official CLI.
        self.stdin
            .send(console_input(&data))
            .await
            .context("Incus console closed")
    }
    async fn subscribe_stdout_lines(
        &self,
    ) -> anyhow::Result<broadcast::Receiver<Arc<compact_str::CompactString>>> {
        Ok(self.lines.subscribe())
    }
    async fn subscribe_stdout_lines_ratelimited(
        &self,
    ) -> anyhow::Result<broadcast::Receiver<Arc<compact_str::CompactString>>> {
        Ok(self.limited.subscribe())
    }
    async fn sync_configuration(&self) -> anyhow::Result<()> {
        if self.name.starts_with("wgs-")
            && let Some(server) = self.server.upgrade()
        {
            self.executor.sync_server(&server, &self.name).await?;
        }
        Ok(())
    }
    async fn start(&self) -> anyhow::Result<()> {
        self.executor
            .client
            .state(&self.name, "start", false)
            .await?;
        self.started.store(true, Ordering::SeqCst);
        if self.name.starts_with("wgs-")
            && let Err(err) = self.executor.publish(&self.name).await
        {
            if let Some(server) = self.server.upgrade() {
                let _ = self
                    .executor
                    .network
                    .sync(server.uuid, "", &std::collections::BTreeMap::new())
                    .await;
            }
            let _ = self.executor.client.state(&self.name, "stop", true).await;
            return Err(err);
        }
        Ok(())
    }
    async fn stop(&self) -> anyhow::Result<()> {
        if self.name.starts_with("wgs-")
            && let Some(server) = self.server.upgrade()
        {
            let config = server.process_configuration.read().await;
            match config.stop.r#type.as_str() {
                "command" => {
                    let mut command = config
                        .stop
                        .value
                        .as_ref()
                        .map(|value| value.as_bytes().to_vec())
                        .unwrap_or_default();
                    command.push(b'\n');
                    return self.send_stdin(command).await;
                }
                "signal" => {
                    let signal = match config.stop.value.as_deref() {
                        Some("SIGINT" | "C") => "INT",
                        Some("SIGQUIT") => "QUIT",
                        Some("SIGTERM") => "TERM",
                        _ => return self.kill().await,
                    };
                    let pid = self
                        .executor
                        .client
                        .read_file(
                            &self
                                .executor
                                .storage
                                .file_path(&Storage::control_name(&self.name), "pid"),
                        )
                        .await?;
                    let pid: u32 = std::str::from_utf8(&pid)?.trim().parse()?;
                    ensure!(pid > 1, "invalid game process PID");
                    let result = self.executor.client.mutate(reqwest::Method::POST, &format!("/1.0/instances/{}/exec", segment(&self.name)), json!({"command": ["/bin/sh", "-c", format!("kill -s {signal} {pid}")], "wait-for-websocket": false, "interactive": false})).await?;
                    ensure!(
                        result.pointer("/metadata/return").and_then(Value::as_i64) == Some(0),
                        "Incus stop signal was not delivered"
                    );
                    return Ok(());
                }
                _ => {}
            }
        }
        self.executor.client.state(&self.name, "stop", false).await
    }
    async fn kill(&self) -> anyhow::Result<()> {
        self.executor.client.state(&self.name, "stop", true).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn console_enter_normalizes_lf_and_crlf_without_changing_control_bytes() {
        assert_eq!(console_input(b"stop\n"), b"stop\r");
        assert_eq!(console_input(b"one\r\ntwo\nthree\r"), b"one\rtwo\rthree\r");
        assert_eq!(console_input(b"\x03\x1b[A"), b"\x03\x1b[A");
    }
    #[tokio::test]
    async fn supervisor_preserves_stdin_and_records_fast_exit() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let script = SUPERVISOR.replace(
            "/opt/wings-control",
            &directory.path().display().to_string(),
        );
        let mut child = tokio::process::Command::new("/bin/sh")
            .args([
                "-c",
                &script,
                "wings-supervisor",
                "/bin/sh",
                "-c",
                "read -r input; printf '%s' \"$input\"; exit 7",
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let mut input = child.stdin.take().context("missing stdin")?;
        input.write_all(b"hello from console\n").await?;
        drop(input);
        let output =
            tokio::time::timeout(Duration::from_secs(5), child.wait_with_output()).await??;
        assert_eq!(output.status.code(), Some(7));
        assert_eq!(output.stdout, b"hello from console");
        assert_eq!(
            tokio::fs::read(directory.path().join("exit")).await?,
            b"7\n"
        );
        Ok(())
    }

    #[test]
    fn argv_quotes_shell_metacharacters_and_empty_arguments() -> anyhow::Result<()> {
        assert_eq!(
            encode_argv(&[
                "hello world".into(),
                "a'b".into(),
                "".into(),
                "$(touch /tmp/unsafe)".into()
            ])?,
            "'hello world' 'a'\\''b' '' '$(touch /tmp/unsafe)'"
        );
        assert!(encode_argv(&["bad\0arg".into()]).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn multiline_argv_preserves_trailing_newlines_and_literal_metacharacters()
    -> anyhow::Result<()> {
        let args = vec![
            "/bin/sh".into(),
            "-c".into(),
            "printf '%s\\000' \"$@\"".into(),
            "probe".into(),
            "line one\nline two\n\n".into(),
            "carriage\rreturn".into(),
            "".into(),
            "a'b $(false) ; literal".into(),
        ];
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("launch");
        let console = directory.path().join("console");
        tokio::fs::write(&console, []).await?;
        tokio::fs::write(
            &path,
            launch_script(&args)?.replace("/dev/console", &console.display().to_string()),
        )
        .await?;
        let output = tokio::process::Command::new("/bin/sh")
            .arg(&path)
            .output()
            .await?;
        assert!(output.status.success());
        let expected = args
            .iter()
            .skip(4)
            .flat_map(|arg| arg.bytes().chain([0]))
            .collect::<Vec<_>>();
        assert_eq!(tokio::fs::read(&console).await?, expected);
        Ok(())
    }
}
