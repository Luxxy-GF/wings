use futures::SinkExt;
use futures::StreamExt;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use rand::distr::SampleString;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicI32, Ordering},
        Arc, Weak,
    },
};
use tokio::{net::UnixStream, sync::RwLock};
use tokio_tungstenite::tungstenite::Message;

const INCUS_SLEEP_ENTRYPOINT: &str = "/bin/sh -lc \"exec sleep 86400\"";
const INCUS_CAP_DROP: &str =
    "lxc.cap.drop = setpcap mknod audit_write net_raw dac_override fowner fsetid net_bind_service sys_chroot setfcap sys_ptrace";

struct IncusExecSession {
    ws: tokio_tungstenite::WebSocketStream<UnixStream>,
    control_ws: Option<tokio_tungstenite::WebSocketStream<UnixStream>>,
    operation: String,
}

// ─── HTTP client over Incus Unix socket ───────────────────────────────────────

struct IncusClient {
    socket_path: String,
}

impl IncusClient {
    fn new(socket_path: &str) -> Self {
        Self { socket_path: socket_path.to_string() }
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, anyhow::Error> {
        let stream = UnixStream::connect(&self.socket_path).await?;
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
        tokio::spawn(conn);

        let body_bytes = match &body {
            Some(v) => Bytes::from(serde_json::to_vec(v)?),
            None => Bytes::new(),
        };

        let req = Request::builder()
            .method(method)
            .uri(format!("http://localhost{}", path))
            .header("Host", "localhost")
            .header("Content-Type", "application/json")
            .header("Content-Length", body_bytes.len().to_string())
            .body(Full::new(body_bytes))?;
        let resp = sender.send_request(req).await?;
        let status = resp.status();
        let body = resp.collect().await?.to_bytes();

        // Some endpoints (e.g. console?action=show) may return an empty body.
        let json: Value = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body)?
        };

        if !status.is_success() && status.as_u16() != 202 {
            let msg = json
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("unknown error")
                .to_string();
            return Err(anyhow::anyhow!("incus API error {}: {}", status, msg));
        }

        Ok(json)
    }

    async fn get(&self, path: &str) -> Result<Value, anyhow::Error> {
        self.request(Method::GET, path, None).await
    }

    async fn post(&self, path: &str, body: Value) -> Result<Value, anyhow::Error> {
        self.request(Method::POST, path, Some(body)).await
    }

    async fn put(&self, path: &str, body: Value) -> Result<Value, anyhow::Error> {
        self.request(Method::PUT, path, Some(body)).await
    }

    async fn patch(&self, path: &str, body: Value) -> Result<Value, anyhow::Error> {
        self.request(Method::PATCH, path, Some(body)).await
    }

    async fn delete(&self, path: &str) -> Result<Value, anyhow::Error> {
        self.request(Method::DELETE, path, None).await
    }

    /// For async Incus operations, wait until the operation finishes.
    async fn wait_for_operation(&self, op_url: &str) -> Result<Value, anyhow::Error> {
        // Strip the /1.0 prefix if present in the operation URL, then append /wait
        let wait_path = format!("{}/wait", op_url);
        let resp = self.get(&wait_path).await?;
        let status = resp
            .pointer("/metadata/status")
            .and_then(Value::as_str)
            .unwrap_or("Unknown");
        if status == "Failure" {
            let err = resp
                .pointer("/metadata/err")
                .and_then(Value::as_str)
                .unwrap_or("operation failed");
            return Err(anyhow::anyhow!("incus operation failed: {}", err));
        }
        Ok(resp)
    }

    /// If the API response is async, wait for the operation to finish.
    async fn ensure_done(&self, resp: Value) -> Result<(), anyhow::Error> {
        let resp_type = resp.get("type").and_then(Value::as_str).unwrap_or("sync");
        if resp_type == "async" {
            if let Some(op) = resp.get("operation").and_then(Value::as_str) {
                self.wait_for_operation(op).await?;
            }
        }
        Ok(())
    }

    /// Open a WebSocket console for an instance.
    /// Returns (websocket_stream, control_ws).
    async fn console_websocket(
        &self,
        instance_name: &str,
    ) -> Result<
        tokio_tungstenite::WebSocketStream<UnixStream>,
        anyhow::Error,
    > {
        // Request a new console session
        let resp = self
            .post(
                &format!("/1.0/instances/{}/console", instance_name),
                json!({
                    "width": 220,
                    "height": 50,
                    "type": "console"
                }),
            )
            .await?;

        let op_id = resp
            .pointer("/operation")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("no operation in console response"))?;

        let secret = resp
            .pointer("/metadata/metadata/fds/0")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("no console secret in operation metadata"))?
            .to_string();

        // Connect via WebSocket over the Unix socket
        let ws_path = format!("{}/websocket?secret={}", op_id, secret);
        let stream = UnixStream::connect(&self.socket_path).await?;
        let url = format!("ws://localhost{}", ws_path);

        let (ws, _) = tokio_tungstenite::client_async(url, stream).await?;
        Ok(ws)
    }

    /// Exec a command interactively in an instance; returns the PTY WebSocket (FD 0).
    /// Output from the command flows through this WebSocket, making it suitable
    /// for streaming install-script output to the panel.
    async fn exec_pty_websocket(
        &self,
        instance_name: &str,
        command: &[&str],
        env: std::collections::HashMap<String, String>,
        cwd: Option<&str>,
    ) -> Result<IncusExecSession, anyhow::Error> {
        let env_json: serde_json::Map<String, Value> = env
            .into_iter()
            .map(|(k, v)| (k, Value::String(v)))
            .collect();

        let mut body = json!({
            "command": command,
            "wait-for-websocket": true,
            "interactive": true,
            "environment": env_json
        });
        if let Some(dir) = cwd {
            body["cwd"] = Value::String(dir.to_string());
        }

        let resp = self
            .post(&format!("/1.0/instances/{}/exec", instance_name), body)
            .await?;

        let op_id = resp
            .pointer("/operation")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("no operation in exec response"))?;
        let operation = op_id.to_string();

        let secret = resp
            .pointer("/metadata/metadata/fds/0")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("no fd0 secret in exec response"))?
            .to_string();

        let ws = self.connect_operation_websocket(op_id, &secret).await?;

        let control_ws = match resp
            .pointer("/metadata/metadata/fds/control")
            .and_then(Value::as_str)
        {
            Some(secret) => Some(self.connect_operation_websocket(op_id, secret).await?),
            None => None,
        };

        Ok(IncusExecSession {
            ws,
            control_ws,
            operation,
        })
    }

    async fn connect_operation_websocket(
        &self,
        op_id: &str,
        secret: &str,
    ) -> Result<tokio_tungstenite::WebSocketStream<UnixStream>, anyhow::Error> {
        let ws_path = format!("{}/websocket?secret={}", op_id, secret);
        let stream = UnixStream::connect(&self.socket_path).await?;
        let url = format!("ws://localhost{}", ws_path);

        let (ws, _) = tokio_tungstenite::client_async(url, stream).await?;
        Ok(ws)
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Incus container names must start with a letter, be ≤63 chars, alphanumeric + hyphens.
fn instance_name(
    uuid: &uuid::Uuid,
    cfg: &crate::config::InnerConfig,
    server_name: &str,
) -> String {
    if cfg.incus.server_name_in_container_name {
        let filtered: String = server_name
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
            .take(55)
            .collect();
        let name = format!("w-{}-{}", filtered, uuid);
        name[..name.len().min(63)].to_string()
    } else {
        format!("w-{}", uuid)
    }
}

/// Extract the registry hostname from a Docker-style image reference.
fn registry_for_image(image: &str) -> &str {
    let image = image.trim_end_matches('~');
    let parts: Vec<&str> = image.splitn(2, '/').collect();
    if parts.len() == 2 && (parts[0].contains('.') || parts[0].contains(':')) {
        parts[0]
    } else {
        "docker.io"
    }
}

/// Parse a Docker-style image reference into an Incus OCI source object.
/// Pass `credentials` as `Some((username, password))` to authenticate with the registry.
fn parse_image_source(image: &str, credentials: Option<(&str, &str)>) -> Value {
    let image = image.trim_end_matches('~');
    let parts: Vec<&str> = image.splitn(2, '/').collect();
    let (server, alias) = if parts.len() == 2
        && (parts[0].contains('.') || parts[0].contains(':'))
    {
        (format!("https://{}", parts[0]), parts[1].to_string())
    } else {
        ("https://docker.io".to_string(), image.to_string())
    };

    let mut source = json!({
        "type": "image",
        "protocol": "oci",
        "server": server,
        "alias": alias
    });

    if let Some((username, password)) = credentials {
        if !username.is_empty() {
            source["username"] = Value::String(username.to_string());
            source["password"] = Value::String(password.to_string());
        }
    }

    source
}

/// Build Incus config keys for resource limits.
fn build_resource_config(
    build: &crate::server::configuration::ServerConfigurationBuild,
    overhead: &crate::config::DockerOverhead,
    pid_limit: u64,
) -> HashMap<String, String> {
    let mut cfg = HashMap::new();

    let real_memory = build.memory_limit + build.overhead_memory;
    if real_memory > 0 {
        let limit_bytes = overhead.get_memory(real_memory.into()).as_bytes();
        cfg.insert("limits.memory".to_string(), format!("{}B", limit_bytes));
    }

    if build.cpu_limit > 0 {
        cfg.insert(
            "limits.cpu.allowance".to_string(),
            format!("{}%", build.cpu_limit),
        );
    }
    if let Some(threads) = &build.threads {
        cfg.insert("limits.cpu".to_string(), threads.to_string());
    }

    if pid_limit > 0 {
        cfg.insert("limits.processes".to_string(), pid_limit.to_string());
    }

    cfg
}

/// Build proxy devices for port allocations.
fn build_proxy_devices(
    allocations: &crate::server::configuration::ServerConfigurationAllocations,
) -> HashMap<String, Value> {
    let mut devices = HashMap::new();
    for (ip, ports) in &allocations.mappings {
        for port in ports {
            let tcp_key = format!("proxy-{}-tcp", port);
            devices.insert(
                tcp_key,
                json!({
                    "type": "proxy",
                    "listen": format!("tcp:{}:{}", ip, port),
                    "connect": format!("tcp:127.0.0.1:{}", port)
                }),
            );
            let udp_key = format!("proxy-{}-udp", port);
            devices.insert(
                udp_key,
                json!({
                    "type": "proxy",
                    "listen": format!("udp:{}:{}", ip, port),
                    "connect": format!("udp:127.0.0.1:{}", port)
                }),
            );
        }
    }
    devices
}

/// Build a NIC device connecting the instance to a bridge.
fn build_nic_device(bridge: &str) -> Value {
    json!({
        "type": "nic",
        "name": "eth0",
        "network": bridge
    })
}

fn incus_mount_target(target: &str) -> &str {
    match target {
        // In LXC, /sys/class/dmi/id/product_uuid is a symlink. Mounting over the
        // resolved sysfs node preserves reads through the symlink and avoids
        // LXC's symlink mount refusal during forkstart.
        "/sys/class/dmi/id/product_uuid" => "/sys/devices/virtual/dmi/id/product_uuid",
        _ => target,
    }
}

fn shell_command(command: &str) -> Vec<String> {
    vec!["/bin/sh".to_string(), "-lc".to_string(), command.to_string()]
}

fn parse_config_u32(config: &Value, key: &str) -> Option<u32> {
    config.get(key)?.as_str()?.parse().ok()
}

fn map_id_from_idmap(config: &Value, nsid: u32, is_uid: bool) -> u32 {
    let Some(idmap) = config
        .get("volatile.idmap.current")
        .and_then(Value::as_str)
        .and_then(|value| serde_json::from_str::<Value>(value).ok())
    else {
        return nsid;
    };

    let Some(entries) = idmap.as_array() else {
        return nsid;
    };

    for entry in entries {
        if entry.get(if is_uid { "Isuid" } else { "Isgid" }) != Some(&Value::Bool(true)) {
            continue;
        }

        let hostid = entry.get("Hostid").and_then(Value::as_u64).unwrap_or(0) as u32;
        let start = entry.get("Nsid").and_then(Value::as_u64).unwrap_or(0) as u32;
        let range = entry
            .get("Maprange")
            .and_then(Value::as_u64)
            .unwrap_or(0) as u32;
        if nsid >= start && nsid < start.saturating_add(range) {
            return hostid.saturating_add(nsid - start);
        }
    }

    nsid
}

async fn make_server_data_writable(base_path: PathBuf) -> Result<(), anyhow::Error> {
    tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
        let mut stack = vec![base_path];

        while let Some(path) = stack.pop() {
            let metadata = match std::fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(err) => return Err(err.into()),
            };

            if metadata.file_type().is_symlink() {
                continue;
            }

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = if metadata.is_dir() { 0o777 } else { 0o666 };
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode));
            }

            if !metadata.is_dir() {
                continue;
            }

            for entry in std::fs::read_dir(&path)? {
                stack.push(entry?.path());
            }
        }

        Ok(())
    })
    .await??;

    Ok(())
}

fn is_in_use_error(err: &anyhow::Error) -> bool {
    let msg = err.to_string().to_lowercase();
    msg.contains("in use") || msg.contains("busy")
}

fn is_missing_instance_error(err: &anyhow::Error) -> bool {
    let msg = err.to_string().to_lowercase();
    msg.contains("not found") || msg.contains("instance not found")
}

fn sanitize_console_line(bytes: &[u8]) -> compact_str::CompactString {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            // Strip ANSI/VT escape sequences. Progress tools often emit cursor
            // movement or erase-line controls which corrupt the panel console.
            0x1b => {
                i += 1;
                if i < bytes.len() && bytes[i] == b'[' {
                    i += 1;
                    while i < bytes.len() {
                        let byte = bytes[i];
                        i += 1;
                        if (0x40..=0x7e).contains(&byte) {
                            break;
                        }
                    }
                }
            }
            b'\x08' => {
                out.pop();
                i += 1;
            }
            byte if byte < 0x20 && byte != b'\t' => {
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }

    compact_str::CompactString::from_utf8_lossy(&out).trim().into()
}

fn incus_lifecycle_lock(server_uuid: &str) -> Arc<tokio::sync::Mutex<()>> {
    static LOCKS: std::sync::OnceLock<
        std::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    > = std::sync::OnceLock::new();

    let locks = LOCKS.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
    let mut locks = locks.lock().expect("incus lifecycle lock poisoned");
    Arc::clone(
        locks
            .entry(server_uuid.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
    )
}

// ─── Process handle ───────────────────────────────────────────────────────────

struct IncusProcessHandle {
    instance_name: String,
    client: Arc<IncusClient>,
    server: Weak<super::super::InnerServer>,
    app_config: Arc<crate::config::Config>,

    resource_usage: Arc<RwLock<super::super::resources::ResourceUsage>>,
    stdin_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    stdout_ratelimited_rx:
        tokio::sync::broadcast::Receiver<Arc<compact_str::CompactString>>,
    stdout_rx: tokio::sync::broadcast::Receiver<Arc<compact_str::CompactString>>,

    state_task: tokio::task::JoinHandle<()>,
    stats_task: tokio::task::JoinHandle<()>,
    stdin_task: tokio::task::JoinHandle<()>,
    stdout_task: tokio::task::JoinHandle<()>,
    control_task: Option<tokio::task::JoinHandle<()>>,
}

impl IncusProcessHandle {
    /// `ws` is either a console WebSocket (for server processes) or an exec PTY WebSocket
    /// (for installer/script processes).  When `stop_container_on_ws_close` is true the
    /// container is force-stopped as soon as the WebSocket closes — this is used for
    /// installer/script containers whose PID 1 is a long-running sleep so the state task can
    /// learn the installation finished.
    async fn new(
        instance_name: String,
        client: Arc<IncusClient>,
        server: &super::super::Server,
        app_config: Arc<crate::config::Config>,
        status_tx: tokio::sync::mpsc::Sender<(
            super::ProcessStatus,
            super::super::resources::ResourceUsage,
        )>,
        ws: tokio_tungstenite::WebSocketStream<tokio::net::UnixStream>,
        exec_operation: Option<String>,
        control_ws: Option<tokio_tungstenite::WebSocketStream<tokio::net::UnixStream>>,
        stop_container_on_ws_close: bool,
    ) -> Result<Self, anyhow::Error> {
        let (stdin_tx, mut stdin_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(150);
        let (stdout_ratelimited_tx, stdout_ratelimited_rx) =
            tokio::sync::broadcast::channel::<Arc<compact_str::CompactString>>(
                app_config.load().system.websocket_log_count,
            );
        let (stdout_tx, stdout_rx) = tokio::sync::broadcast::channel::<
            Arc<compact_str::CompactString>,
        >(app_config.load().system.websocket_log_count * 2);

        let resource_usage = Arc::new(RwLock::new(super::super::resources::ResourceUsage {
            disk_bytes: server.filesystem.limiter_usage().await,
            state: server.state.get_state(),
            ..Default::default()
        }));

        let (mut ws_write, mut ws_read) = ws.split();

        let control_task = control_ws.map(|mut control_ws| {
            tokio::spawn(async move {
                while let Some(msg) = control_ws.next().await {
                    if msg.is_err() {
                        break;
                    }
                }
            })
        });

        // Signals the stdout task to exit its read loop when the container stops,
        // in case Incus doesn't send a WS close frame promptly after container exit.
        let stopped_notify = Arc::new(tokio::sync::Notify::new());
        let stdout_stopped_notify = Arc::clone(&stopped_notify);
        let exec_exit_code = Arc::new(AtomicI32::new(i32::MIN));

        // stdin task: forward data from the channel to the WebSocket
        let stdin_task = tokio::spawn(async move {
            while let Some(data) = stdin_rx.recv().await {
                if let Err(err) = ws_write.send(Message::Binary(data.into())).await {
                    tracing::error!(error = %err, "failed to write to incus console stdin");
                    break;
                }
            }
        });

        // stdout task: read from WebSocket, parse lines, broadcast
        let stdout_task = tokio::spawn({
            let server = server.clone();
            let app_config = Arc::clone(&app_config);
            let stopped_notify = stdout_stopped_notify;
            let client_for_stop = Arc::clone(&client);
            let name_for_stop = instance_name.clone();
            let exec_exit_code = Arc::clone(&exec_exit_code);

            async move {
                let notified = stopped_notify.notified();
                tokio::pin!(notified);

                let mut buffer = Vec::with_capacity(1024);
                let mut line_start = 0;
                let mut pending_carriage_return = false;
                let mut was_notified = false;

                let mut ratelimit_counter = 0u64;
                let mut ratelimit_start = std::time::Instant::now();

                let mut allow_ratelimit = || {
                    ratelimit_counter += 1;
                    let config = app_config.load();
                    if config.throttles.enabled
                        && config.throttles.line_reset_interval > 0
                        && ratelimit_counter >= config.throttles.lines
                    {
                        if ratelimit_start.elapsed()
                            < std::time::Duration::from_millis(
                                config.throttles.line_reset_interval,
                            )
                        {
                            if ratelimit_counter == config.throttles.lines {
                                tracing::debug!(
                                    server = %server.uuid,
                                    "ratelimit reached for server output"
                                );
                                server.log_daemon_with_prelude(
                                    "Server is outputting console data too quickly -- throttling...",
                                );
                            }
                            return false;
                        } else {
                            ratelimit_counter = 0;
                            ratelimit_start = std::time::Instant::now();
                        }
                    }
                    true
                };

                'ws_loop: loop {
                    let data = tokio::select! {
                        biased;
                        msg = ws_read.next() => match msg {
                            Some(Ok(Message::Binary(b))) => b.to_vec(),
                            Some(Ok(Message::Text(t))) => t.into_bytes(),
                            Some(Ok(Message::Close(_))) | None => break 'ws_loop,
                            Some(Ok(_)) => continue 'ws_loop,
                            Some(Err(err)) => {
                                tracing::debug!(
                                    server = %server.uuid,
                                    error = %err,
                                    "incus console ws closed"
                                );
                                break 'ws_loop;
                            }
                        },
                        _ = &mut notified => { was_notified = true; break 'ws_loop; }
                    };

                    for byte in data {
                        if pending_carriage_return {
                            if byte != b'\n' {
                                buffer.push(b'\n');
                            }
                            pending_carriage_return = false;
                        }

                        if byte == b'\r' {
                            pending_carriage_return = true;
                        } else {
                            buffer.push(byte);
                        }
                    }

                    let mut search_start = line_start;

                    loop {
                        if let Some(pos) =
                            buffer[search_start..].iter().position(|&b| b == b'\n')
                        {
                            let newline_pos = search_start + pos;

                            if newline_pos - line_start <= 512 {
                                let line = sanitize_console_line(&buffer[line_start..newline_pos]);
                                let line = Arc::new(line);
                                if allow_ratelimit() {
                                    stdout_ratelimited_tx.send(Arc::clone(&line)).ok();
                                }
                                stdout_tx.send(line).ok();
                                line_start = newline_pos + 1;
                                search_start = line_start;
                            } else {
                                let line =
                                    sanitize_console_line(&buffer[line_start..(line_start + 512)]);
                                let line = Arc::new(line);
                                if allow_ratelimit() {
                                    stdout_ratelimited_tx.send(Arc::clone(&line)).ok();
                                }
                                stdout_tx.send(line).ok();
                                line_start += 512;
                                search_start = line_start;
                            }
                        } else {
                            let current_line_length = buffer.len() - line_start;
                            if current_line_length > 512 {
                                let line =
                                    sanitize_console_line(&buffer[line_start..(line_start + 512)]);
                                let line = Arc::new(line);
                                if allow_ratelimit() {
                                    stdout_ratelimited_tx.send(Arc::clone(&line)).ok();
                                }
                                stdout_tx.send(line).ok();
                                line_start += 512;
                                search_start = line_start;
                            } else {
                                break;
                            }
                        }
                    }

                    if line_start > 1024 && line_start > buffer.len() / 2 {
                        buffer.drain(0..line_start);
                        line_start = 0;
                    }
                }

                if pending_carriage_return {
                    buffer.push(b'\n');
                }

                if line_start < buffer.len() {
                    let line = sanitize_console_line(&buffer[line_start..]);
                    let line = Arc::new(line);
                    if allow_ratelimit() {
                        stdout_ratelimited_tx.send(Arc::clone(&line)).ok();
                    }
                    stdout_tx.send(line).ok();
                }

                // For installer/script containers: exec WS close means the script
                // finished. PID 1 is still sleeping, so force-stop the container here
                // and report the exec operation's real exit code.
                if stop_container_on_ws_close && !was_notified {
                    let exit_code = match exec_operation.as_deref() {
                        Some(operation) => {
                            match client_for_stop.wait_for_operation(operation).await {
                                Ok(resp) => resp
                                    .pointer("/metadata/metadata/return")
                                    .or_else(|| resp.pointer("/metadata/return"))
                                    .and_then(Value::as_i64)
                                    .unwrap_or(0) as i32,
                                Err(err) => {
                                    tracing::warn!(
                                        operation = %operation,
                                        "failed to wait for incus exec operation: {}",
                                        err
                                    );
                                    -1
                                }
                            }
                        }
                        None => -1,
                    };

                    tracing::debug!(
                        instance = %name_for_stop,
                        exit_code,
                        "exec finished, stopping container"
                    );
                    exec_exit_code.store(exit_code, Ordering::Relaxed);
                    if let Ok(resp) = client_for_stop
                        .put(
                            &format!("/1.0/instances/{}/state", name_for_stop),
                            json!({ "action": "stop", "force": true }),
                        )
                        .await
                    {
                        let _ = client_for_stop.ensure_done(resp).await;
                    }
                }

                tracing::debug!(server = %server.uuid, "incus stdout task ended");
            }
        });

        // stats task: poll instance state every second for resource metrics
        let stats_client = Arc::clone(&client);
        let stats_name = instance_name.clone();
        let stats_usage = Arc::clone(&resource_usage);
        let stats_server = server.clone();

        let stats_task = tokio::spawn(async move {
            let mut prev_cpu_total: u64 = 0;
            let mut prev_instant: Option<std::time::Instant> = None;

            loop {
                let state_path = format!("/1.0/instances/{}/state", stats_name);
                let (state_result, disk_bytes) = tokio::join!(
                    stats_client.get(&state_path),
                    stats_server.filesystem.limiter_usage(),
                );
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;

                let state = match state_result {
                    Ok(v) => v,
                    Err(err) => {
                        if is_missing_instance_error(&err) || err.to_string().contains("Invalid PID") {
                            tracing::debug!(
                                server = %stats_server.uuid,
                                "incus instance state disappeared; ending stats task"
                            );
                            break;
                        }

                        tracing::warn!(
                            server = %stats_server.uuid,
                            "failed to get incus instance state: {:?}",
                            err
                        );
                        continue;
                    }
                };

                let mut usage = stats_usage.write().await;
                usage.disk_bytes = disk_bytes;
                usage.state = stats_server.state.get_state();

                // Memory
                if let Some(mem_usage) = state.pointer("/metadata/memory/usage").and_then(Value::as_u64) {
                    usage.memory_bytes = mem_usage;
                }
                if let Some(mem_total) = state.pointer("/metadata/memory/total").and_then(Value::as_u64) {
                    usage.memory_limit_bytes = mem_total;
                }

                // Network (sum first interface)
                if let Some(net_obj) = state.pointer("/metadata/network").and_then(Value::as_object) {
                    for (iface, net) in net_obj {
                        if iface == "lo" {
                            continue;
                        }
                        if let Some(rx) = net.pointer("/counters/bytes_received").and_then(Value::as_u64) {
                            usage.network.rx_bytes = rx;
                        }
                        if let Some(tx) = net.pointer("/counters/bytes_sent").and_then(Value::as_u64) {
                            usage.network.tx_bytes = tx;
                        }
                        break;
                    }
                }

                // CPU: usage is nanoseconds total
                if let Some(cpu_ns) = state.pointer("/metadata/cpu/usage").and_then(Value::as_u64) {
                    let now = std::time::Instant::now();
                    usage.cpu_absolute = if let Some(prev) = prev_instant {
                        let cpu_delta_ns = cpu_ns.saturating_sub(prev_cpu_total) as f64;
                        let wall_delta_ns = now.duration_since(prev).as_nanos() as f64;
                        if wall_delta_ns > 0.0 && cpu_delta_ns > 0.0 {
                            ((cpu_delta_ns / wall_delta_ns) * 100.0 * 1000.0).round() / 1000.0
                        } else {
                            0.0
                        }
                    } else {
                        0.0
                    };
                    prev_cpu_total = cpu_ns;
                    prev_instant = Some(now);
                }
            }
        });

        // state task: poll for container status transitions
        let state_client = Arc::clone(&client);
        let state_name = instance_name.clone();
        let state_usage = Arc::clone(&resource_usage);
        let state_stopped_notify = Arc::clone(&stopped_notify);
        let state_exec_exit_code = Arc::clone(&exec_exit_code);

        let state_task = tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;

                let resp = match state_client
                    .get(&format!("/1.0/instances/{}/state", state_name))
                    .await
                {
                    Ok(v) => v,
                    Err(err) => {
                        // "Invalid PID -1" means the container's init process exited
                        // and Incus hasn't updated the state record yet.  Treat it as
                        // stopped so the installation/server flow completes cleanly.
                        if err.to_string().contains("Invalid PID") || is_missing_instance_error(&err) {
                            tracing::debug!(
                                instance = %state_name,
                                "incus instance is gone; treating as stopped"
                            );
                            let usage = *state_usage.read().await;
                            let exit_code = match state_exec_exit_code.load(Ordering::Relaxed) {
                                i32::MIN => -1,
                                code => code,
                            };
                            let _ = status_tx
                                .send((
                                    super::ProcessStatus::Stopped {
                                        exit_code,
                                        oom_killed: false,
                                    },
                                    usage,
                                ))
                                .await;
                            state_stopped_notify.notify_one();
                            break;
                        }
                        tracing::warn!(
                            instance = %state_name,
                            "failed to inspect incus instance state: {:?}",
                            err
                        );
                        continue;
                    }
                };

                let status = resp
                    .pointer("/metadata/status")
                    .and_then(Value::as_str)
                    .unwrap_or("Unknown");

                let is_stopped = !matches!(status, "Running" | "Frozen");

                let process_status = match status {
                    "Running" => super::ProcessStatus::Running,
                    "Frozen" => super::ProcessStatus::Paused,
                    _ => {
                        state_usage.write().await.uptime = 0;
                        let exit_code = match state_exec_exit_code.load(Ordering::Relaxed) {
                            i32::MIN => -1,
                            code => code,
                        };
                        super::ProcessStatus::Stopped {
                            exit_code,
                            oom_killed: false,
                        }
                    }
                };

                let usage = *state_usage.read().await;
                if status_tx.send((process_status, usage)).await.is_err() {
                    break;
                }

                if is_stopped {
                    // Wake the stdout task so it exits its read loop and the
                    // installation/server flow can complete cleanly.
                    state_stopped_notify.notify_one();
                    break;
                }
            }
        });

        Ok(Self {
            instance_name,
            client,
            server: Arc::downgrade(&**server),
            app_config,
            resource_usage,
            stdin_tx,
            stdout_ratelimited_rx,
            stdout_rx,
            state_task,
            stats_task,
            stdin_task,
            stdout_task,
            control_task,
        })
    }
}

impl Drop for IncusProcessHandle {
    fn drop(&mut self) {
        self.state_task.abort();
        self.stats_task.abort();
        self.stdin_task.abort();
        self.stdout_task.abort();
        if let Some(control_task) = &self.control_task {
            control_task.abort();
        }
    }
}

#[async_trait::async_trait]
impl super::ProcessHandle for IncusProcessHandle {
    async fn resource_usage(
        &self,
    ) -> Result<super::super::resources::ResourceUsage, anyhow::Error> {
        Ok(*self.resource_usage.read().await)
    }

    async fn logs(
        &self,
        lines: Option<usize>,
    ) -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin>, anyhow::Error> {
        let resp = self
            .client
            .get(&format!(
                "/1.0/instances/{}/console?action=show",
                self.instance_name
            ))
            .await?;

        // The console log is returned as a base64-encoded string in metadata
        let content = resp
            .pointer("/metadata")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();

        let bytes = if content.is_empty() {
            Vec::new()
        } else {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(&content)
                .unwrap_or_else(|_| content.into_bytes())
        };

        // Apply line limit if requested
        let bytes = if let Some(n) = lines {
            let mut start = 0;
            let mut count = 0;
            for (i, &b) in bytes.iter().enumerate().rev() {
                if b == b'\n' {
                    count += 1;
                    if count >= n {
                        start = i + 1;
                        break;
                    }
                }
            }
            bytes[start..].to_vec()
        } else {
            bytes
        };

        Ok(Box::new(std::io::Cursor::new(bytes)))
    }

    async fn send_stdin(&self, data: Vec<u8>) -> Result<(), anyhow::Error> {
        self.stdin_tx.send(data).await.map_err(Into::into)
    }

    async fn subscribe_stdout_lines_ratelimited(
        &self,
    ) -> Result<
        tokio::sync::broadcast::Receiver<Arc<compact_str::CompactString>>,
        anyhow::Error,
    > {
        Ok(self.stdout_ratelimited_rx.resubscribe())
    }

    async fn subscribe_stdout_lines(
        &self,
    ) -> Result<
        tokio::sync::broadcast::Receiver<Arc<compact_str::CompactString>>,
        anyhow::Error,
    > {
        Ok(self.stdout_rx.resubscribe())
    }

    async fn sync_configuration(&self) -> Result<(), anyhow::Error> {
        let server = self
            .server
            .upgrade()
            .ok_or_else(|| anyhow::anyhow!("server has been dropped"))?;

        let app_cfg = self.app_config.load();
        let server_cfg = server.configuration.read().await;
        let resource_cfg = build_resource_config(
            &server_cfg.build,
            &app_cfg.docker.overhead,
            app_cfg.incus.container_pid_limit,
        );

        let config_patch: HashMap<String, Value> = resource_cfg
            .into_iter()
            .map(|(k, v)| (k, Value::String(v)))
            .collect();

        self.client
            .patch(
                &format!("/1.0/instances/{}", self.instance_name),
                json!({ "config": config_patch }),
            )
            .await?;

        Ok(())
    }

    async fn start(&self) -> Result<(), anyhow::Error> {
        if let Some(server) = self.server.upgrade() {
            make_server_data_writable(PathBuf::from(server.filesystem.base().as_str())).await?;
        }

        let result = async {
            let resp = self
                .client
                .put(
                    &format!("/1.0/instances/{}/state", self.instance_name),
                    json!({ "action": "start" }),
                )
                .await?;
            self.client.ensure_done(resp).await
        }
        .await;

        match result {
            Ok(()) => Ok(()),
            Err(e) => {
                let msg = e.to_string().to_lowercase();
                if msg.contains("already running") || msg.contains("already started") {
                    return Ok(());
                }
                // Incus error messages vary by version; fall back to checking real state.
                match self
                    .client
                    .get(&format!("/1.0/instances/{}/state", self.instance_name))
                    .await
                {
                    Ok(state)
                        if state
                            .pointer("/metadata/status")
                            .and_then(Value::as_str)
                            == Some("Running") =>
                    {
                        tracing::debug!(
                            instance = %self.instance_name,
                            "start() failed but instance is running, treating as no-op: {:#}",
                            e
                        );
                        Ok(())
                    }
                    _ => {
                        tracing::warn!(
                            instance = %self.instance_name,
                            "start() failed: {:#}",
                            e
                        );
                        Err(e)
                    }
                }
            }
        }
    }

    async fn stop(&self) -> Result<(), anyhow::Error> {
        let server = self
            .server
            .upgrade()
            .ok_or_else(|| anyhow::anyhow!("server has been dropped"))?;

        let process_config = server.process_configuration.read().await;
        let stop_type = process_config.stop.r#type.clone();
        let stop_value = process_config.stop.value.clone();
        drop(process_config);

        match stop_type.as_str() {
            "command" => {
                let mut command = stop_value
                    .map(|s| s.as_bytes().to_vec())
                    .unwrap_or_default();
                command.push(b'\n');
                match self.stdin_tx.send(command).await {
                    Ok(()) => Ok(()),
                    Err(_) => {
                        let resp = self
                            .client
                            .put(
                                &format!("/1.0/instances/{}/state", self.instance_name),
                                json!({ "action": "stop", "force": true }),
                            )
                            .await?;
                        match self.client.ensure_done(resp).await {
                            Ok(()) => Ok(()),
                            Err(err) => {
                                let msg = err.to_string().to_lowercase();
                                if msg.contains("already stopped")
                                    || msg.contains("not running")
                                    || msg.contains("not found")
                                {
                                    Ok(())
                                } else {
                                    Err(err)
                                }
                            }
                        }
                    }
                }
            }
            "signal" => {
                // PID 1 is the sleep shim used to keep the OCI container alive.
                // Killing PID 1 leaves the actual exec process ambiguous, so use
                // Incus' container stop path for signal-style stops.
                let timeout = match stop_value.as_deref().map(str::to_uppercase).as_deref() {
                    Some("SIGKILL") | Some("KILL") => 0,
                    _ => 30,
                };
                let resp = self
                    .client
                    .put(
                        &format!("/1.0/instances/{}/state", self.instance_name),
                        json!({ "action": "stop", "timeout": timeout, "force": timeout == 0 }),
                    )
                    .await?;
                match self.client.ensure_done(resp).await {
                    Ok(()) => Ok(()),
                    Err(err) => {
                        let msg = err.to_string().to_lowercase();
                        if msg.contains("already stopped")
                            || msg.contains("not running")
                            || msg.contains("not found")
                        {
                            Ok(())
                        } else {
                            Err(err)
                        }
                    }
                }
            }
            _ => {
                let resp = self
                    .client
                    .put(
                        &format!("/1.0/instances/{}/state", self.instance_name),
                        json!({ "action": "stop", "timeout": 30 }),
                    )
                    .await?;
                match self.client.ensure_done(resp).await {
                    Ok(()) => Ok(()),
                    Err(err) => {
                        let msg = err.to_string().to_lowercase();
                        if msg.contains("already stopped")
                            || msg.contains("not running")
                            || msg.contains("not found")
                        {
                            Ok(())
                        } else {
                            Err(err)
                        }
                    }
                }
            }
        }
    }

    async fn kill(&self) -> Result<(), anyhow::Error> {
        let result = async {
            let resp = self
                .client
                .put(
                    &format!("/1.0/instances/{}/state", self.instance_name),
                    json!({ "action": "stop", "force": true }),
                )
                .await?;
            self.client.ensure_done(resp).await
        }
        .await;

        match result {
            Ok(()) => Ok(()),
            Err(err) => {
                let msg = err.to_string().to_lowercase();
                if msg.contains("already stopped")
                    || msg.contains("not running")
                    || msg.contains("not found")
                {
                    Ok(())
                } else {
                    Err(err)
                }
            }
        }
    }
}

// ─── Executor ────────────────────────────────────────────────────────────────

pub struct IncusExecutor {
    client: Arc<IncusClient>,
    app_config: Arc<crate::config::Config>,
}

impl IncusExecutor {
    pub fn new(app_config: Arc<crate::config::Config>) -> Self {
        let socket = app_config.load().incus.socket.clone();
        Self {
            client: Arc::new(IncusClient::new(&socket)),
            app_config,
        }
    }

    async fn stop_instance_if_present(&self, name: &str) {
        match self
            .client
            .put(
                &format!("/1.0/instances/{}/state", name),
                json!({ "action": "stop", "force": true }),
            )
            .await
        {
            Ok(resp) => {
                if let Err(err) = self.client.ensure_done(resp).await {
                    tracing::debug!(
                        instance = %name,
                        "failed to wait for incus instance stop, continuing cleanup: {}",
                        err
                    );
                }
            }
            Err(err) => {
                let msg = err.to_string().to_lowercase();
                if !msg.contains("not found")
                    && !msg.contains("already stopped")
                    && !msg.contains("not running")
                {
                    tracing::debug!(
                        instance = %name,
                        "failed to stop incus instance before cleanup, continuing: {}",
                        err
                    );
                }
            }
        }
    }

    async fn delete_instance_if_present(&self, name: &str) {
        for attempt in 0..10 {
            let result = async {
                let resp = self.client.delete(&format!("/1.0/instances/{}", name)).await?;
                self.client.ensure_done(resp).await
            }
            .await;

            match result {
                Ok(()) => return,
                Err(err) => {
                    let msg = err.to_string().to_lowercase();
                    if msg.contains("not found") {
                        return;
                    }

                    if msg.contains("in use") || msg.contains("busy") {
                        tracing::debug!(
                            instance = %name,
                            attempt = attempt + 1,
                            "incus instance still in use during delete; waiting before retry"
                        );
                        self.stop_instance_if_present(name).await;
                        tokio::time::sleep(std::time::Duration::from_millis(
                            250 * (attempt + 1),
                        ))
                        .await;
                        continue;
                    }

                    tracing::error!(
                        instance = %name,
                        "failed to delete incus instance: {}",
                        err
                    );
                    return;
                }
            }
        }

        tracing::error!(
            instance = %name,
            "failed to delete incus instance: still in use after retries"
        );
    }

    async fn cleanup_instance_name(&self, name: &str) {
        self.stop_instance_if_present(name).await;
        self.delete_instance_if_present(name).await;
        self.wait_for_instance_cleanup(name).await;
    }

    async fn wait_for_instance_cleanup(&self, name: &str) {
        let pool = self.app_config.load().incus.storage_pool.clone();
        let instance_path = format!("/1.0/instances/{}", name);
        let volume_path = format!("/1.0/storage-pools/{}/volumes/container/{}", pool, name);

        for attempt in 0..20 {
            let instance_gone = match self.client.get(&instance_path).await {
                Ok(_) => false,
                Err(err) => is_missing_instance_error(&err),
            };
            let volume_gone = match self.client.get(&volume_path).await {
                Ok(_) => false,
                Err(err) => is_missing_instance_error(&err),
            };

            if instance_gone && volume_gone {
                return;
            }

            tracing::debug!(
                instance = %name,
                attempt = attempt + 1,
                instance_gone,
                volume_gone,
                "waiting for incus instance cleanup"
            );
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }

        tracing::debug!(
            instance = %name,
            "continuing after waiting for incus cleanup"
        );
    }

    async fn set_sleep_entrypoint(&self, name: &str) -> Result<Option<Vec<String>>, anyhow::Error> {
        let instance = self.client.get(&format!("/1.0/instances/{}", name)).await?;
        let image_entrypoint = instance
            .pointer("/metadata/config/oci.entrypoint")
            .and_then(Value::as_str)
            .filter(|entrypoint| !entrypoint.trim().is_empty())
            .map(shell_command);

        let resp = self
            .client
            .patch(
                &format!("/1.0/instances/{}", name),
                json!({
                    "config": {
                        "oci.entrypoint": INCUS_SLEEP_ENTRYPOINT
                    }
                }),
            )
            .await?;
        self.client.ensure_done(resp).await?;

        Ok(image_entrypoint)
    }

    async fn create_instance(&self, name: &str, body: &Value) -> Result<(), anyhow::Error> {
        self.wait_for_instance_cleanup(name).await;

        let result = async {
            let resp = self.client.post("/1.0/instances", body.clone()).await?;
            self.client.ensure_done(resp).await
        }
        .await;

        if let Err(err) = result {
            if is_in_use_error(&err) {
                self.cleanup_instance_name(name).await;
            }
            return Err(err);
        }

        Ok(())
    }

    async fn start_instance(&self, name: &str) -> Result<(), anyhow::Error> {
        let state_path = format!("/1.0/instances/{}/state", name);

        for attempt in 0..10 {
            let result = async {
                let resp = self
                    .client
                    .put(&state_path, json!({ "action": "start" }))
                    .await?;
                self.client.ensure_done(resp).await
            }
            .await;

            match result {
                Ok(()) => return Ok(()),
                Err(err) => {
                    let msg = err.to_string().to_lowercase();
                    if !msg.contains("address already in use")
                        && !msg.contains("in use")
                        && !msg.contains("busy")
                    {
                        return Err(err);
                    }

                    tracing::warn!(
                        instance = %name,
                        attempt = attempt + 1,
                        "incus instance was still busy during start; waiting before retry"
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(
                        500 * (attempt + 1),
                    ))
                    .await;
                }
            }
        }

        unreachable!("start retry loop always returns");
    }

    async fn build_script_environment(
        &self,
        server: &super::super::Server,
        script: &super::super::installation::InstallationScript,
    ) -> HashMap<String, String> {
        let server_cfg = server.configuration.read().await;
        let mut env: HashMap<String, String> = server_cfg
            .environment(&self.app_config)
            .into_iter()
            .filter_map(|var| {
                let mut parts = var.splitn(2, '=');
                Some((parts.next()?.to_string(), parts.next()?.to_string()))
            })
            .collect();
        drop(server_cfg);

        for (k, v) in &script.environment {
            let s = match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            env.insert(k.to_string(), s);
        }

        env
    }

    async fn chown_server_data_for_instance(
        &self,
        name: &str,
        server: &super::super::Server,
    ) -> Result<(), anyhow::Error> {
        let instance = self.client.get(&format!("/1.0/instances/{}", name)).await?;
        let config = instance
            .pointer("/metadata/config")
            .ok_or_else(|| anyhow::anyhow!("missing incus instance config"))?;

        let uid = parse_config_u32(config, "oci.uid").unwrap_or(0);
        let gid = parse_config_u32(config, "oci.gid").unwrap_or(0);
        let host_uid = map_id_from_idmap(config, uid, true);
        let host_gid = map_id_from_idmap(config, gid, false);
        let base_path = PathBuf::from(server.filesystem.base().as_str());

        tokio::task::spawn_blocking(move || -> Result<(), anyhow::Error> {
            let mut stack = vec![base_path.clone()];

            while let Some(path) = stack.pop() {
                #[cfg(unix)]
                std::os::unix::fs::chown(&path, Some(host_uid), Some(host_gid))?;

                let metadata = match std::fs::symlink_metadata(&path) {
                    Ok(metadata) => metadata,
                    Err(_) => continue,
                };

                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = if metadata.is_dir() { 0o777 } else { 0o666 };
                    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode));
                }

                if !metadata.is_dir() {
                    continue;
                }

                for entry in std::fs::read_dir(&path)? {
                    let entry = entry?;
                    stack.push(entry.path());
                }
            }

            Ok(())
        })
        .await??;

        Ok(())
    }

    /// Find a running instance whose name contains `name_filter` but not `exclude`.
    async fn find_running_instance(
        &self,
        name_filter: &str,
        exclude: Option<&str>,
    ) -> Option<String> {
        let resp = self
            .client
            .get("/1.0/instances?recursion=1")
            .await
            .ok()?;

        let instances = resp.pointer("/metadata")?.as_array()?;

        for inst in instances {
            let name = inst.get("name")?.as_str()?;
            if !name.contains(name_filter) {
                continue;
            }
            if let Some(excl) = exclude {
                if name.contains(excl) {
                    continue;
                }
            }
            let status = inst
                .pointer("/state/status")
                .or_else(|| inst.get("status"))
                .and_then(Value::as_str)
                .unwrap_or("");
            if status == "Running" {
                return Some(name.to_string());
            }
        }
        None
    }

    /// Force-stop and delete all instances whose name contains `name_filter`.
    async fn delete_instances_matching(&self, name_filter: &str) -> Result<(), anyhow::Error> {
        let resp = self.client.get("/1.0/instances?recursion=1").await?;
        let empty = vec![];
        let instances = resp
            .pointer("/metadata")
            .and_then(Value::as_array)
            .unwrap_or(&empty);

        for inst in instances {
            let name = match inst.get("name").and_then(Value::as_str) {
                Some(n) if n.contains(name_filter) => n.to_string(),
                _ => continue,
            };

            self.cleanup_instance_name(&name).await;
        }
        Ok(())
    }

    /// Build the full instance-create JSON body for a server container.
    /// Returns (body, entrypoint, env) where entrypoint and env are passed to
    /// exec_pty_websocket after the container starts.
    async fn build_server_instance(
        &self,
        name: &str,
        server: &super::super::Server,
    ) -> Result<(Value, Option<Vec<String>>, HashMap<String, String>), anyhow::Error> {
        let app_cfg = self.app_config.load();
        let server_cfg = server.configuration.read().await;

        let mut config: HashMap<String, Value> = build_resource_config(
            &server_cfg.build,
            &app_cfg.docker.overhead,
            app_cfg.incus.container_pid_limit,
        )
        .into_iter()
        .map(|(k, v)| (k, Value::String(v)))
        .collect();

        // Environment variables
        for var in server_cfg.environment(&self.app_config) {
            if let Some((k, v)) = var.splitn(2, '=').collect::<Vec<_>>().as_slice().split_at(1).0.iter().next().map(|k| {
                let rest = var[k.len() + 1..].to_string();
                (*k, rest)
            }) {
                config.insert(format!("environment.{}", k), Value::String(v));
            }
        }

        config.insert("security.nesting".to_string(), Value::String("false".to_string()));
        config.insert("security.privileged".to_string(), Value::String("false".to_string()));
        config.insert("raw.lxc".to_string(), Value::String(INCUS_CAP_DROP.to_string()));
        let (run_uid, run_gid) = if app_cfg.system.user.rootless.enabled {
            (
                app_cfg.system.user.rootless.container_uid,
                app_cfg.system.user.rootless.container_gid,
            )
        } else {
            (app_cfg.system.user.uid, app_cfg.system.user.gid)
        };
        config.insert("oci.uid".to_string(), Value::String(run_uid.to_string()));
        config.insert("oci.gid".to_string(), Value::String(run_gid.to_string()));

        // Devices
        let mut devices: HashMap<String, Value> = HashMap::new();
        devices.insert(
            "root".to_string(),
            json!({ "type": "disk", "path": "/", "pool": app_cfg.incus.storage_pool }),
        );
        devices.insert("eth0".to_string(), build_nic_device(&app_cfg.incus.network.bridge));

        // Server data mount
        let server_base = server.filesystem.base().to_string();
        devices.insert(
            "server-data".to_string(),
            json!({
                "type": "disk",
                "path": "/home/container",
                "source": server_base,
                "shift": "true"
            }),
        );

        // Proxy devices for port allocations
        for (k, v) in build_proxy_devices(&server_cfg.allocations) {
            devices.insert(k, v);
        }

        // Additional mounts from server configuration.
        // mounts() may include the server data directory itself; skip any path
        // already occupied by an existing device to avoid duplicate-path errors.
        let occupied: std::collections::HashSet<String> = devices
            .values()
            .filter_map(|v| v.get("path").and_then(Value::as_str).map(str::to_string))
            .collect();

        for mount in server_cfg.mounts(&self.app_config, &server.filesystem).await {
            let target = incus_mount_target(mount.target.as_str());
            if occupied.contains(target) {
                continue;
            }
            let key = format!(
                "mount-{}",
                target.replace('/', "-").trim_start_matches('-')
            );
            devices.insert(
                key,
                json!({
                    "type": "disk",
                    "path": target,
                    "source": mount.source,
                    "readonly": mount.read_only
                }),
            );
        }

        let image = server_cfg.container.image.clone();
        let entrypoint = server_cfg.entrypoint.clone();

        // Collect environment for the caller to pass to exec_pty_websocket.
        let env: HashMap<String, String> = server_cfg
            .environment(&self.app_config)
            .into_iter()
            .filter_map(|var| {
                let mut parts = var.splitn(2, '=');
                let k = parts.next()?.to_string();
                let v = parts.next()?.to_string();
                Some((k, v))
            })
            .collect();

        drop(server_cfg);

        let registry = registry_for_image(&image);
        let creds = app_cfg.incus.registries.get(registry);
        let credentials = creds.as_ref().map(|c| (c.username.as_str(), c.password.as_str()));

        let body = json!({
            "name": name,
            "type": "container",
            "source": parse_image_source(&image, credentials),
            "config": config,
            "devices": devices
        });

        Ok((body, entrypoint, env))
    }

    /// Build the instance-create JSON body for an installer/script container.
    /// PID 1 is a long-running sleep so the container stays alive while the actual
    /// install script is executed via exec_pty_websocket.
    fn build_installer_instance(
        &self,
        name: &str,
        server: &super::super::Server,
        script: &super::super::installation::InstallationScript,
        env: &HashMap<String, String>,
        server_mount_target: &str,
        script_mount_source: &str,
        script_mount_target: &str,
    ) -> Value {
        let app_cfg = self.app_config.load();

        let mem_bytes = app_cfg
            .docker
            .overhead
            .get_memory(app_cfg.incus.installer_limits.memory)
            .as_bytes();

        let mut config: HashMap<String, Value> = HashMap::from([
            (
                "limits.memory".to_string(),
                Value::String(format!("{}B", mem_bytes)),
            ),
            (
                "limits.cpu.allowance".to_string(),
                Value::String(format!("{}%", app_cfg.incus.installer_limits.cpu)),
            ),
            (
                "security.privileged".to_string(),
                Value::String("true".to_string()),
            ),
        ]);

        // Environment
        for (k, v) in env {
            config.insert(format!("environment.{}", k), Value::String(v.clone()));
        }

        let mut devices: HashMap<String, Value> = HashMap::new();
        devices.insert(
            "root".to_string(),
            json!({ "type": "disk", "path": "/", "pool": app_cfg.incus.storage_pool }),
        );
        devices.insert("eth0".to_string(), build_nic_device(&app_cfg.incus.network.bridge));
        devices.insert(
            "server-data".to_string(),
            json!({
                "type": "disk",
                "path": server_mount_target,
                "source": server.filesystem.base().to_string()
            }),
        );
        devices.insert(
            "install-scripts".to_string(),
            json!({
                "type": "disk",
                "path": script_mount_target,
                "source": script_mount_source
            }),
        );

        let registry = registry_for_image(&script.container_image);
        let creds = app_cfg.incus.registries.get(registry);
        let credentials = creds.as_ref().map(|c| (c.username.as_str(), c.password.as_str()));

        json!({
            "name": name,
            "type": "container",
            "source": parse_image_source(&script.container_image, credentials),
            "config": config,
            "devices": devices
        })
    }
}

type StatusReceiver =
    tokio::sync::mpsc::Receiver<(super::ProcessStatus, super::super::resources::ResourceUsage)>;

#[async_trait::async_trait]
impl super::ServerExecutor for IncusExecutor {
    async fn boot(&self) -> Result<(), anyhow::Error> {
        let bridge = self.app_config.load().incus.network.bridge.clone();
        match self.client.get(&format!("/1.0/networks/{}", bridge)).await {
            Ok(_) => {
                tracing::info!("incus bridge network '{}' already exists", bridge);
            }
            Err(_) => {
                tracing::info!("creating incus bridge network '{}'", bridge);
                let resp = self
                    .client
                    .post(
                        "/1.0/networks",
                        json!({
                            "name": bridge,
                            "type": "bridge",
                            "config": {
                                "ipv4.address": "auto",
                                "ipv4.nat": "true",
                                "ipv6.address": "none"
                            }
                        }),
                    )
                    .await?;
                self.client.ensure_done(resp).await?;
                tracing::info!("created incus bridge network '{}'", bridge);
            }
        }
        Ok(())
    }

    async fn setup_server_process(
        &self,
        server: &super::super::Server,
    ) -> Result<(Arc<dyn super::ProcessHandle>, StatusReceiver), anyhow::Error> {
        let lifecycle_lock = incus_lifecycle_lock(&server.uuid.to_string());
        let _lifecycle_guard = lifecycle_lock.lock().await;

        let name = {
            let app_cfg = self.app_config.load();
            let server_cfg = server.configuration.read().await;
            instance_name(&server_cfg.uuid, &app_cfg, &server_cfg.meta.name)
        };

        // Clean up any leftover instance before creating a fresh one. Incus
        // deletes asynchronously, so wait for deletion before reusing the name.
        self.cleanup_instance_name(&name).await;

        let (body, entrypoint, env) = self.build_server_instance(&name, server).await?;

        self.create_instance(&name, &body).await?;

        let image_entrypoint = self.set_sleep_entrypoint(&name).await?;
        self.chown_server_data_for_instance(&name, server).await?;

        // Start the instance (PID 1 = sleep; game server runs via exec below).
        self.start_instance(&name).await?;

        // Launch the game server via exec so its I/O flows through the PTY WebSocket.
        let exec_entrypoint = entrypoint.or(image_entrypoint);
        let (ws, exec_operation, control_ws, stop_on_close) = if let Some(ep) = exec_entrypoint {
            let cmd: Vec<&str> = ep.iter().map(String::as_str).collect();
            let session = self
                .client
                .exec_pty_websocket(&name, &cmd, env, Some("/home/container"))
                .await?;
            (session.ws, Some(session.operation), session.control_ws, true)
        } else {
            // No known entrypoint; fall back to the console WebSocket.
            let ws = self.client.console_websocket(&name).await?;
            (ws, None, None, false)
        };

        let (status_tx, status_rx) = tokio::sync::mpsc::channel(1);
        let handle = Arc::new(
            IncusProcessHandle::new(
                name,
                Arc::clone(&self.client),
                server,
                Arc::clone(&self.app_config),
                status_tx,
                ws,
                exec_operation,
                control_ws,
                stop_on_close,
            )
            .await?,
        );

        Ok((handle, status_rx))
    }

    async fn attach_server_process(
        &self,
        server: &super::super::Server,
    ) -> Result<(Arc<dyn super::ProcessHandle>, StatusReceiver), anyhow::Error> {
        let uuid = server.uuid.to_string();
        let name = self
            .find_running_instance(&uuid, Some("installer"))
            .await
            .ok_or_else(|| anyhow::anyhow!("no running incus instance found for server {}", uuid))?;

        let ws = self.client.console_websocket(&name).await?;

        let (status_tx, status_rx) = tokio::sync::mpsc::channel(1);
        let handle = Arc::new(
            IncusProcessHandle::new(
                name,
                Arc::clone(&self.client),
                server,
                Arc::clone(&self.app_config),
                status_tx,
                ws,
                None,
                None,
                false,
            )
            .await?,
        );

        Ok((handle, status_rx))
    }

    async fn cleanup_server_process(&self, server: &super::super::Server) -> Result<(), anyhow::Error> {
        let uuid = server.uuid.to_string();
        let lifecycle_lock = incus_lifecycle_lock(&uuid);
        let _lifecycle_guard = lifecycle_lock.lock().await;

        // Delete all instances containing the server UUID.
        self.delete_instances_matching(&uuid).await
    }

    async fn setup_installation_process(
        &self,
        server: &super::super::Server,
        script: &super::super::installation::InstallationScript,
    ) -> Result<(Arc<dyn super::ProcessHandle>, StatusReceiver), anyhow::Error> {
        let lifecycle_lock = incus_lifecycle_lock(&server.uuid.to_string());
        let _lifecycle_guard = lifecycle_lock.lock().await;

        let name = format!("w-{}-installer", server.uuid);

        // Clean up any leftover instance from a previous failed install.
        self.cleanup_instance_name(&name).await;

        let tmp_dir = std::path::Path::new(&self.app_config.load().system.tmp_directory)
            .join(server.uuid.to_string());
        tokio::fs::create_dir_all(&tmp_dir).await?;
        tokio::fs::write(
            tmp_dir.join("install.sh"),
            script.script.replace("\r\n", "\n"),
        )
        .await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&tmp_dir, std::fs::Permissions::from_mode(0o755)).await?;
        }

        let env = self.build_script_environment(server, script).await;
        let body = self.build_installer_instance(
            &name,
            server,
            script,
            &env,
            "/mnt/server",
            &tmp_dir.to_string_lossy(),
            "/mnt/install",
        );

        self.create_instance(&name, &body).await?;

        self.set_sleep_entrypoint(&name).await?;

        // Start the container; PID 1 is a long-running sleep.
        self.start_instance(&name).await?;

        // Execute the install script via a PTY so output reliably flows to the WebSocket.
        let session = self
            .client
            .exec_pty_websocket(
                &name,
                &[script.entrypoint.as_str(), "/mnt/install/install.sh"],
                env,
                Some("/mnt/server"),
            )
            .await?;

        let (status_tx, status_rx) = tokio::sync::mpsc::channel(1);
        let handle = Arc::new(
            IncusProcessHandle::new(
                name,
                Arc::clone(&self.client),
                server,
                Arc::clone(&self.app_config),
                status_tx,
                session.ws,
                Some(session.operation),
                session.control_ws,
                true, // stop container when exec WS closes
            )
            .await?,
        );

        Ok((handle, status_rx))
    }

    async fn attach_installation_process(
        &self,
        server: &super::super::Server,
    ) -> Result<(Arc<dyn super::ProcessHandle>, StatusReceiver), anyhow::Error> {
        let name = format!("w-{}-installer", server.uuid);

        let ws = self.client.console_websocket(&name).await?;

        let (status_tx, status_rx) = tokio::sync::mpsc::channel(1);
        let handle = Arc::new(
            IncusProcessHandle::new(
                name,
                Arc::clone(&self.client),
                server,
                Arc::clone(&self.app_config),
                status_tx,
                ws,
                None,
                None,
                false,
            )
            .await?,
        );

        Ok((handle, status_rx))
    }

    async fn cleanup_installation_process(
        &self,
        server: &super::super::Server,
    ) -> Result<(), anyhow::Error> {
        let lifecycle_lock = incus_lifecycle_lock(&server.uuid.to_string());
        let _lifecycle_guard = lifecycle_lock.lock().await;

        let name = format!("w-{}-installer", server.uuid);

        self.cleanup_instance_name(&name).await;

        Ok(())
    }

    async fn setup_script_process(
        &self,
        server: &super::super::Server,
        script: &super::super::installation::InstallationScript,
    ) -> Result<(Arc<dyn super::ProcessHandle>, StatusReceiver), anyhow::Error> {
        let lifecycle_lock = incus_lifecycle_lock(&server.uuid.to_string());
        let _lifecycle_guard = lifecycle_lock.lock().await;

        let name = format!(
            "w-{}-script-{}",
            server.uuid,
            rand::distr::Alphanumeric.sample_string(&mut rand::rng(), 8)
        );

        let tmp_dir = std::path::Path::new(&self.app_config.load().system.tmp_directory)
            .join(server.uuid.to_string());
        tokio::fs::create_dir_all(&tmp_dir).await?;
        tokio::fs::write(
            tmp_dir.join("script.sh"),
            script.script.replace("\r\n", "\n"),
        )
        .await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&tmp_dir, std::fs::Permissions::from_mode(0o755)).await?;
        }

        let env = self.build_script_environment(server, script).await;
        let body = self.build_installer_instance(
            &name,
            server,
            script,
            &env,
            "/mnt/server",
            &tmp_dir.to_string_lossy(),
            "/mnt/script",
        );

        self.create_instance(&name, &body).await?;

        self.set_sleep_entrypoint(&name).await?;

        // Start the container; PID 1 is a long-running sleep.
        self.start_instance(&name).await?;

        let session = self
            .client
            .exec_pty_websocket(
                &name,
                &[script.entrypoint.as_str(), "/mnt/script/script.sh"],
                env,
                Some("/mnt/server"),
            )
            .await?;

        let (status_tx, status_rx) = tokio::sync::mpsc::channel(1);
        let handle = Arc::new(
            IncusProcessHandle::new(
                name,
                Arc::clone(&self.client),
                server,
                Arc::clone(&self.app_config),
                status_tx,
                session.ws,
                Some(session.operation),
                session.control_ws,
                true, // stop container when exec WS closes
            )
            .await?,
        );

        Ok((handle, status_rx))
    }
}
