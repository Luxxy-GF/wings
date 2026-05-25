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
    sync::{Arc, Weak},
};
use tokio::{net::UnixStream, sync::RwLock};
use tokio_tungstenite::tungstenite::Message;

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
        let json: Value = serde_json::from_slice(&body)?;

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

/// Parse a Docker-style image reference into an Incus OCI source object.
fn parse_image_source(image: &str) -> Value {
    let image = image.trim_end_matches('~');
    // Split off the registry if the first component contains a dot or colon
    let parts: Vec<&str> = image.splitn(2, '/').collect();
    let (server, alias) = if parts.len() == 2
        && (parts[0].contains('.') || parts[0].contains(':'))
    {
        (format!("https://{}", parts[0]), parts[1].to_string())
    } else {
        ("https://docker.io".to_string(), image.to_string())
    };

    json!({
        "type": "image",
        "protocol": "oci",
        "server": server,
        "alias": alias
    })
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
}

impl IncusProcessHandle {
    async fn new(
        instance_name: String,
        client: Arc<IncusClient>,
        server: &super::super::Server,
        app_config: Arc<crate::config::Config>,
        status_tx: tokio::sync::mpsc::Sender<(
            super::ProcessStatus,
            super::super::resources::ResourceUsage,
        )>,
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

        // Open the console WebSocket for stdin/stdout
        let ws = client.console_websocket(&instance_name).await?;
        let (mut ws_write, mut ws_read) = ws.split();

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

            async move {
                let mut buffer = Vec::with_capacity(1024);
                let mut line_start = 0;

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

                while let Some(msg) = ws_read.next().await {
                    let data = match msg {
                        Ok(Message::Binary(b)) => b.to_vec(),
                        Ok(Message::Text(t)) => t.into_bytes(),
                        Ok(Message::Close(_)) => break,
                        Ok(_) => continue,
                        Err(err) => {
                            tracing::debug!(
                                server = %server.uuid,
                                error = %err,
                                "incus console ws closed"
                            );
                            break;
                        }
                    };

                    buffer.extend_from_slice(&data);

                    let mut search_start = line_start;

                    loop {
                        if let Some(pos) =
                            buffer[search_start..].iter().position(|&b| b == b'\n')
                        {
                            let newline_pos = search_start + pos;

                            if newline_pos - line_start <= 512 {
                                let line = compact_str::CompactString::from_utf8_lossy(
                                    &buffer[line_start..newline_pos],
                                )
                                .trim()
                                .into();
                                let line = Arc::new(line);
                                if allow_ratelimit() {
                                    stdout_ratelimited_tx.send(Arc::clone(&line)).ok();
                                }
                                stdout_tx.send(line).ok();
                                line_start = newline_pos + 1;
                                search_start = line_start;
                            } else {
                                let line = compact_str::CompactString::from_utf8_lossy(
                                    &buffer[line_start..(line_start + 512)],
                                )
                                .trim()
                                .into();
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
                                let line = compact_str::CompactString::from_utf8_lossy(
                                    &buffer[line_start..(line_start + 512)],
                                )
                                .trim()
                                .into();
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

                if line_start < buffer.len() {
                    let line =
                        compact_str::CompactString::from_utf8_lossy(&buffer[line_start..])
                            .trim()
                            .into();
                    let line = Arc::new(line);
                    if allow_ratelimit() {
                        stdout_ratelimited_tx.send(Arc::clone(&line)).ok();
                    }
                    stdout_tx.send(line).ok();
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

        let state_task = tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;

                let resp = match state_client
                    .get(&format!("/1.0/instances/{}/state", state_name))
                    .await
                {
                    Ok(v) => v,
                    Err(err) => {
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

                let process_status = match status {
                    "Running" => {
                        // Update uptime from instance started_at if available
                        super::ProcessStatus::Running
                    }
                    "Frozen" => super::ProcessStatus::Paused,
                    _ => {
                        state_usage.write().await.uptime = 0;
                        super::ProcessStatus::Stopped {
                            exit_code: -1,
                            oom_killed: false,
                        }
                    }
                };

                let usage = *state_usage.read().await;
                if status_tx.send((process_status, usage)).await.is_err() {
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
        })
    }
}

impl Drop for IncusProcessHandle {
    fn drop(&mut self) {
        self.state_task.abort();
        self.stats_task.abort();
        self.stdin_task.abort();
        self.stdout_task.abort();
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
        let resp = self
            .client
            .put(
                &format!("/1.0/instances/{}/state", self.instance_name),
                json!({ "action": "start" }),
            )
            .await?;
        self.client.ensure_done(resp).await
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
                self.stdin_tx
                    .send(command)
                    .await
                    .map_err(|e| anyhow::anyhow!(e))
            }
            "signal" => {
                // Incus does not have a direct signal API; send via exec
                let signal = match stop_value.as_deref().map(str::to_uppercase).as_deref() {
                    Some("SIGINT") | Some("C") => "SIGINT",
                    Some("SIGTERM") => "SIGTERM",
                    Some("SIGQUIT") => "SIGQUIT",
                    Some("SIGABRT") => "SIGABRT",
                    _ => "SIGKILL",
                };
                let resp = self
                    .client
                    .post(
                        &format!("/1.0/instances/{}/exec", self.instance_name),
                        json!({
                            "command": ["kill", format!("-{}", signal), "1"],
                            "wait-for-websocket": false,
                            "interactive": false,
                        }),
                    )
                    .await?;
                self.client.ensure_done(resp).await
            }
            _ => {
                let resp = self
                    .client
                    .put(
                        &format!("/1.0/instances/{}/state", self.instance_name),
                        json!({ "action": "stop", "timeout": 30 }),
                    )
                    .await?;
                self.client.ensure_done(resp).await
            }
        }
    }

    async fn kill(&self) -> Result<(), anyhow::Error> {
        let resp = self
            .client
            .put(
                &format!("/1.0/instances/{}/state", self.instance_name),
                json!({ "action": "stop", "force": true }),
            )
            .await?;
        self.client.ensure_done(resp).await
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

            // Stop first (ignore errors — might already be stopped)
            let _ = self
                .client
                .put(
                    &format!("/1.0/instances/{}/state", name),
                    json!({ "action": "stop", "force": true }),
                )
                .await;

            if let Err(err) = self
                .client
                .delete(&format!("/1.0/instances/{}", name))
                .await
            {
                tracing::error!(instance = %name, "failed to delete incus instance: {}", err);
            }
        }
        Ok(())
    }

    /// Build the full instance-create JSON body for a server container.
    async fn build_server_instance(
        &self,
        name: &str,
        server: &super::super::Server,
    ) -> Result<Value, anyhow::Error> {
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
        config.insert(
            "raw.lxc".to_string(),
            Value::String(
                "lxc.cap.drop = setpcap mknod audit_write net_raw dac_override fowner fsetid net_bind_service sys_chroot setfcap sys_ptrace".to_string(),
            ),
        );

        // Devices
        let mut devices: HashMap<String, Value> = HashMap::new();
        devices.insert("eth0".to_string(), build_nic_device(&app_cfg.incus.network.bridge));

        // Server data mount
        let server_base = server.filesystem.base().to_string();
        devices.insert(
            "server-data".to_string(),
            json!({
                "type": "disk",
                "path": "/home/container",
                "source": server_base
            }),
        );

        // Proxy devices for port allocations
        for (k, v) in build_proxy_devices(&server_cfg.allocations) {
            devices.insert(k, v);
        }

        // Additional mounts from server configuration
        for mount in server_cfg.mounts(&self.app_config, &server.filesystem).await {
            let key = format!(
                "mount-{}",
                mount.target.replace('/', "-").trim_start_matches('-')
            );
            devices.insert(
                key,
                json!({
                    "type": "disk",
                    "path": mount.target,
                    "source": mount.source,
                    "readonly": mount.read_only
                }),
            );
        }

        let image = server_cfg.container.image.clone();
        let entrypoint = server_cfg.entrypoint.clone();

        drop(server_cfg);

        let mut body = json!({
            "name": name,
            "type": "container",
            "source": parse_image_source(&image),
            "config": config,
            "devices": devices
        });

        // Set entrypoint via raw exec config if present
        if let Some(ep) = entrypoint {
            if let Some(obj) = body.get_mut("config").and_then(Value::as_object_mut) {
                obj.insert(
                    "raw.lxc".to_string(),
                    Value::String(format!(
                        "lxc.init.cmd = {}\nlxc.cap.drop = setpcap mknod audit_write net_raw dac_override fowner fsetid net_bind_service sys_chroot setfcap sys_ptrace",
                        ep.join(" ")
                    )),
                );
            }
        }

        Ok(body)
    }

    /// Build the instance-create JSON body for an installer/script container.
    fn build_installer_instance(
        &self,
        name: &str,
        server: &super::super::Server,
        script: &super::super::installation::InstallationScript,
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
        ]);

        // Environment
        for (k, v) in &script.environment {
            let val = match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            config.insert(format!("environment.{}", k), Value::String(val));
        }

        let mut devices: HashMap<String, Value> = HashMap::new();
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

        json!({
            "name": name,
            "type": "container",
            "source": parse_image_source(&script.container_image),
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
        let name = {
            let app_cfg = self.app_config.load();
            let server_cfg = server.configuration.read().await;
            instance_name(&server_cfg.uuid, &app_cfg, &server_cfg.meta.name)
        };

        let body = self.build_server_instance(&name, server).await?;

        let resp = self.client.post("/1.0/instances", body).await?;
        self.client.ensure_done(resp).await?;

        // Start the instance
        let resp = self
            .client
            .put(
                &format!("/1.0/instances/{}/state", name),
                json!({ "action": "start" }),
            )
            .await?;
        self.client.ensure_done(resp).await?;

        let (status_tx, status_rx) = tokio::sync::mpsc::channel(1);
        let handle = Arc::new(
            IncusProcessHandle::new(
                name,
                Arc::clone(&self.client),
                server,
                Arc::clone(&self.app_config),
                status_tx,
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

        let (status_tx, status_rx) = tokio::sync::mpsc::channel(1);
        let handle = Arc::new(
            IncusProcessHandle::new(
                name,
                Arc::clone(&self.client),
                server,
                Arc::clone(&self.app_config),
                status_tx,
            )
            .await?,
        );

        Ok((handle, status_rx))
    }

    async fn cleanup_server_process(&self, server: &super::super::Server) -> Result<(), anyhow::Error> {
        let uuid = server.uuid.to_string();
        // Delete all instances containing the server UUID but not installer/script
        self.delete_instances_matching(&uuid).await
    }

    async fn setup_installation_process(
        &self,
        server: &super::super::Server,
        script: &super::super::installation::InstallationScript,
    ) -> Result<(Arc<dyn super::ProcessHandle>, StatusReceiver), anyhow::Error> {
        let name = format!("w-{}-installer", server.uuid);

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

        let body = self.build_installer_instance(
            &name,
            server,
            script,
            "/mnt/server",
            &tmp_dir.to_string_lossy(),
            "/mnt/install",
        );

        let resp = self.client.post("/1.0/instances", body).await?;
        self.client.ensure_done(resp).await?;

        let resp = self
            .client
            .put(
                &format!("/1.0/instances/{}/state", name),
                json!({ "action": "start" }),
            )
            .await?;
        self.client.ensure_done(resp).await?;

        // Kick off the install script via exec
        let exec_resp = self
            .client
            .post(
                &format!("/1.0/instances/{}/exec", name),
                json!({
                    "command": [script.entrypoint.as_str(), "/mnt/install/install.sh"],
                    "wait-for-websocket": false,
                    "interactive": true,
                    "record-output": true
                }),
            )
            .await?;
        self.client.ensure_done(exec_resp).await?;

        let (status_tx, status_rx) = tokio::sync::mpsc::channel(1);
        let handle = Arc::new(
            IncusProcessHandle::new(
                name,
                Arc::clone(&self.client),
                server,
                Arc::clone(&self.app_config),
                status_tx,
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

        let (status_tx, status_rx) = tokio::sync::mpsc::channel(1);
        let handle = Arc::new(
            IncusProcessHandle::new(
                name,
                Arc::clone(&self.client),
                server,
                Arc::clone(&self.app_config),
                status_tx,
            )
            .await?,
        );

        Ok((handle, status_rx))
    }

    async fn cleanup_installation_process(
        &self,
        server: &super::super::Server,
    ) -> Result<(), anyhow::Error> {
        let name = format!("w-{}-installer", server.uuid);

        let _ = self
            .client
            .put(
                &format!("/1.0/instances/{}/state", name),
                json!({ "action": "stop", "force": true }),
            )
            .await;

        if let Err(err) = self
            .client
            .delete(&format!("/1.0/instances/{}", name))
            .await
        {
            tracing::error!(instance = %name, "failed to delete installer instance: {}", err);
        }

        Ok(())
    }

    async fn setup_script_process(
        &self,
        server: &super::super::Server,
        script: &super::super::installation::InstallationScript,
    ) -> Result<(Arc<dyn super::ProcessHandle>, StatusReceiver), anyhow::Error> {
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

        let body = self.build_installer_instance(
            &name,
            server,
            script,
            "/mnt/server",
            &tmp_dir.to_string_lossy(),
            "/mnt/script",
        );

        let resp = self.client.post("/1.0/instances", body).await?;
        self.client.ensure_done(resp).await?;

        let resp = self
            .client
            .put(
                &format!("/1.0/instances/{}/state", name),
                json!({ "action": "start" }),
            )
            .await?;
        self.client.ensure_done(resp).await?;

        let exec_resp = self
            .client
            .post(
                &format!("/1.0/instances/{}/exec", name),
                json!({
                    "command": [script.entrypoint.as_str(), "/mnt/script/script.sh"],
                    "wait-for-websocket": false,
                    "interactive": true,
                    "record-output": true
                }),
            )
            .await?;
        self.client.ensure_done(exec_resp).await?;

        let (status_tx, status_rx) = tokio::sync::mpsc::channel(1);
        let handle = Arc::new(
            IncusProcessHandle::new(
                name,
                Arc::clone(&self.client),
                server,
                Arc::clone(&self.app_config),
                status_tx,
            )
            .await?,
        );

        Ok((handle, status_rx))
    }
}
