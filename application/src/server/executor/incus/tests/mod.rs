use super::*;

#[test]
fn stopped_state_accepts_null_statistics_without_hiding_invalid_data() -> anyhow::Result<()> {
    let state: InstanceState = serde_json::from_value(json!({
        "status": "Stopped", "pid": 0, "cpu": null, "memory": null, "network": null
    }))?;
    assert!(state.cpu.is_empty() && state.memory.is_empty() && state.network.is_empty());
    assert!(
        serde_json::from_value::<InstanceState>(json!({
            "status": "Running", "cpu": {"usage": "invalid"}
        }))
        .is_err()
    );
    Ok(())
}

#[test]
fn requires_lts_and_capabilities() -> anyhow::Result<()> {
    let extensions = [
        "instance_oci",
        "instance_oci_entrypoint",
        "oci_network_config",
        "network_forward",
        "proxy_nat",
        "file_storage_volume",
    ]
    .map(str::to_owned);
    verify_version("7.0.1", &extensions)?;
    verify_version("7.0.2-distro1", &extensions)?;
    assert!(verify_version("7.0", &extensions).is_err());
    assert!(verify_version("7.0.0", &extensions).is_err());
    assert!(verify_version("7.1", &extensions).is_err());
    assert!(verify_version("6.0.5", &extensions).is_err());
    assert!(verify_version("7.0.1", &[]).is_err());
    Ok(())
}

#[tokio::test]
async fn unix_transport_waits_for_async_operation_and_scopes_project() -> anyhow::Result<()> {
    let fixture = MockIncus::new(vec![
        (
            "POST /1.0/instances?project=wings",
            reqwest::StatusCode::OK,
            json!({"type": "async", "operation": "/1.0/operations/job", "metadata": {}}),
        ),
        (
            "GET /1.0/operations/job/wait?project=wings&timeout=120",
            reqwest::StatusCode::OK,
            json!({"type": "sync", "metadata": {"status_code": 200, "metadata": {"result": "done"}}}),
        ),
    ])?;
    let result = fixture
        .client
        .mutate(Method::POST, "/1.0/instances", json!({"name": "test"}))
        .await?;
    assert_eq!(
        result.pointer("/metadata/result").and_then(Value::as_str),
        Some("done")
    );
    fixture.finish().await
}

#[test]
fn docker_remains_default() -> anyhow::Result<()> {
    let config: crate::config::InnerConfig = serde_norway::from_str("{}")?;
    assert_eq!(
        config.runtime.backend,
        crate::config::RuntimeBackend::Docker
    );
    let config: crate::config::InnerConfig =
        serde_norway::from_str("runtime:\n  backend: incus\n  incus:\n    project: test-node\n")?;
    assert_eq!(config.runtime.incus.project, "test-node");
    Ok(())
}

#[tokio::test]
async fn cpu_and_io_limits_use_hard_incus_limits() -> anyhow::Result<()> {
    let config = Arc::new(crate::config::Config::mock());
    let executor = IncusExecutor::new(config)?;
    let mut server = ServerConfiguration::mock(uuid::Uuid::new_v4());
    server.build.cpu_limit = 250;
    server.build.memory_limit = 512;
    server.build.overhead_memory = 64;
    server.build.swap = 0;
    let resources = executor.resources(&server, false)?;
    assert_eq!(
        resources.get("limits.cpu.allowance").map(String::as_str),
        Some("250ms/100ms")
    );
    assert_eq!(
        resources.get("limits.memory").map(String::as_str),
        Some("576MiB")
    );
    assert_eq!(
        resources.get("limits.memory.swap").map(String::as_str),
        Some("false")
    );
    assert_eq!(
        resources.get("limits.disk.priority").map(String::as_str),
        Some("5")
    );
    server.build.memory_limit = 0;
    server.build.overhead_memory = 64;
    server.build.cpu_limit = 0;
    let resources = executor.resources(&server, false)?;
    assert!(!resources.contains_key("limits.memory"));
    assert!(!resources.contains_key("limits.cpu.allowance"));
    Ok(())
}

#[tokio::test]
async fn entrypoint_override_retains_image_command_arguments() -> anyhow::Result<()> {
    let executor = IncusExecutor::new(Arc::new(crate::config::Config::mock()))?;
    let mut server = ServerConfiguration::mock(uuid::Uuid::new_v4());
    server.entrypoint = Some(vec!["/replacement".into(), "arg with space".into()]);
    let image = image::Image {
        uid: 1000,
        gid: 1000,
        fingerprint: "test".into(),
        digest: "test".into(),
        args: vec!["/original".into(), "--flag".into()],
        cmd: vec!["--flag".into()],
        environment: BTreeMap::from([
            ("PATH".into(), "/image/bin".into()),
            ("JAVA_HOME".into(), "/image/java".into()),
        ]),
    };
    let process = executor.process_config(&server, &image, false, None)?;
    assert!(process.get("user.wings.launch").is_some_and(|value| {
        value
            .trim_end()
            .ends_with("'/replacement' 'arg with space' '--flag'")
    }));
    assert_eq!(
        process.get("environment.JAVA_HOME").map(String::as_str),
        Some("/image/java")
    );
    assert_eq!(process.get("oci.uid").map(String::as_str), Some("1000"));
    assert_eq!(process.get("oci.gid").map(String::as_str), Some("1000"));
    let installer = executor.process_config(
        &server,
        &image,
        true,
        Some(vec!["/bin/sh".into(), "/mnt/install.sh".into()]),
    )?;
    assert!(
        installer
            .get("user.wings.launch")
            .is_some_and(|value| value.trim_end().ends_with("'/bin/sh' '/mnt/install.sh'"))
    );
    assert_eq!(installer.get("oci.uid").map(String::as_str), Some("0"));
    assert_eq!(installer.get("oci.gid").map(String::as_str), Some("0"));
    Ok(())
}

#[test]
fn wildcard_allocations_are_preserved_for_nat_proxies() -> anyhow::Result<()> {
    let mut server = ServerConfiguration::mock(uuid::Uuid::new_v4());
    server
        .allocations
        .mappings
        .insert("0.0.0.0".into(), vec![25565]);
    assert_eq!(
        network::allocations(&server)?.get(&"0.0.0.0".parse()?),
        Some(&BTreeSet::from([25565]))
    );
    let spec = firewall_spec(&server, "10.76.0.2".parse()?)?;
    assert!(spec.bindings.iter().all(|binding| binding.ip.is_none()));
    server
        .allocations
        .mappings
        .insert("192.0.2.20".into(), vec![25566]);
    assert!(network::allocations(&server)?.contains_key(&"192.0.2.20".parse()?));
    server
        .allocations
        .mappings
        .insert("192.0.2.20".into(), vec![25565]);
    assert!(network::allocations(&server).is_err());
    server.allocations.mappings.remove("192.0.2.20");
    server.allocations.mappings.insert("::".into(), vec![25565]);
    assert!(network::allocations(&server).is_err());
    Ok(())
}

#[tokio::test]
async fn api_errors_keep_status_for_conditional_retries() -> anyhow::Result<()> {
    let fixture = MockIncus::new(vec![(
        "PUT /1.0/networks/test/forwards/192.0.2.10?project=wings",
        reqwest::StatusCode::PRECONDITION_FAILED,
        json!({"type": "error", "error_code": 412, "error": "ETag mismatch"}),
    )])?;
    let result = fixture
        .client
        .request(
            Method::PUT,
            "/1.0/networks/test/forwards/192.0.2.10",
            Some(&json!({})),
            Some("old"),
            true,
        )
        .await;
    assert!(result.is_err());
    if let Err(err) = result {
        assert!(client::is_status(
            &err,
            reqwest::StatusCode::PRECONDITION_FAILED
        ));
    }
    fixture.finish().await
}

#[tokio::test]
async fn failed_async_operation_and_error_envelopes_are_not_successes() -> anyhow::Result<()> {
    let fixture = MockIncus::new(vec![
        (
            "POST /1.0/instances?project=wings",
            reqwest::StatusCode::OK,
            json!({"type": "async", "operation": "/1.0/operations/job"}),
        ),
        (
            "GET /1.0/operations/job/wait?project=wings&timeout=120",
            reqwest::StatusCode::OK,
            json!({"type": "sync", "metadata": {"status_code": 400, "err": "start failed"}}),
        ),
        (
            "GET /1.0/instances/missing?project=wings",
            reqwest::StatusCode::OK,
            json!({"type": "error", "error_code": 404, "error": "missing"}),
        ),
        (
            "GET /1.0/instances/missing?project=wings",
            reqwest::StatusCode::NOT_FOUND,
            json!(null),
        ),
    ])?;
    let error = fixture
        .client
        .mutate(Method::POST, "/1.0/instances", json!({}))
        .await
        .err()
        .context("failed operation was accepted")?;
    assert!(error.to_string().contains("start failed"));
    assert!(
        fixture
            .client
            .optional::<Instance>("/1.0/instances/missing")
            .await?
            .is_none()
    );
    assert!(
        fixture
            .client
            .optional::<Instance>("/1.0/instances/missing")
            .await?
            .is_none()
    );
    fixture.finish().await
}

#[test]
fn api_paths_and_operation_ids_stay_within_the_incus_api() -> anyhow::Result<()> {
    let client = Client::new(&crate::config::IncusRuntime::default())?;
    for path in [
        "https://example.org/1.0",
        "//example.org/1.0",
        "/1.00",
        "/1.0/../../outside",
        "/1.0#fragment",
    ] {
        assert!(client.url(path, true).is_err(), "accepted {path}");
    }
    assert_eq!(client.url("/1.0", true)?.query(), Some("project=wings"));
    assert!(client.url("/1.0", false)?.query().is_none());
    Ok(())
}

#[tokio::test]
async fn async_operation_urls_cannot_redirect_or_append_queries() -> anyhow::Result<()> {
    for operation in [
        "/1.0/operations/",
        "/1.0/operations/../instances",
        "/1.0/operations/job?project=default",
        "https://example.org/1.0/operations/job",
    ] {
        let fixture = MockIncus::new(vec![(
            "POST /1.0/instances?project=wings",
            reqwest::StatusCode::OK,
            json!({"type": "async", "operation": operation}),
        )])?;
        assert!(
            fixture
                .client
                .mutate(Method::POST, "/1.0/instances", json!({}))
                .await
                .is_err()
        );
        fixture.finish().await?;
    }
    Ok(())
}

#[tokio::test]
async fn console_handshake_has_a_deadline() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let socket = directory.path().join("incus.sock");
    let listener = tokio::net::UnixListener::bind(&socket)?;
    let client = Client::new(&crate::config::IncusRuntime {
        socket: socket.display().to_string(),
        operation_timeout_seconds: 1,
        ..Default::default()
    })?;
    let (result, accepted) = tokio::join!(
        tokio::time::timeout(
            Duration::from_secs(3),
            client.websocket("/1.0/operations/job", "secret")
        ),
        listener.accept()
    );
    let _connection = accepted?;
    let error = result?
        .err()
        .context("console handshake did not time out")?;
    assert!(error.to_string().contains("timed out"));
    Ok(())
}

#[test]
fn instance_updates_preserve_editable_settings_and_omit_runtime_fields() -> anyhow::Result<()> {
    let instance: Instance = serde_json::from_value(json!({
        "name": "wgs-test", "project": "wings", "status": "Running",
        "architecture": "x86_64", "description": "operator description",
        "ephemeral": true, "stateful": true, "profiles": ["custom"],
        "config": {"environment.PATH": "/bin"},
        "devices": {"root": {"type": "disk", "path": "/"}},
        "expanded_devices": {"inherited": {"type": "disk", "path": "/extra"}}
    }))?;
    let body = instance.update_body();
    assert_eq!(
        body.get("description"),
        Some(&json!("operator description"))
    );
    assert_eq!(body.get("architecture"), Some(&json!("x86_64")));
    assert_eq!(body.get("ephemeral"), Some(&json!(true)));
    assert_eq!(body.get("stateful"), Some(&json!(true)));
    assert_eq!(body.get("profiles"), Some(&json!(["custom"])));
    assert_eq!(body.pointer("/devices/root/path"), Some(&json!("/")));
    for field in ["name", "project", "status", "expanded_devices"] {
        assert!(body.get(field).is_none());
    }
    assert!(
        serde_json::from_value::<InstanceState>(json!({
            "status": "Running", "network": {"eth0": {"counters": {"bytes_received": "invalid"}}}
        }))
        .is_err()
    );
    Ok(())
}

#[test]
fn helper_cleanup_excludes_games_and_unrelated_instances() -> anyhow::Result<()> {
    let server = uuid::Uuid::new_v4();
    for (name, helper) in [
        (format!("wgi-{server}"), true),
        (format!("wgx-{server}-0123456789abcdef"), true),
        (format!("wgs-{server}"), false),
        (format!("wgi-{}", uuid::Uuid::new_v4()), false),
        (format!("wgx-{server}-unrelated"), false),
    ] {
        let instance: Instance = serde_json::from_value(json!({"name": name}))?;
        assert_eq!(instance.is_helper_for(server), helper);
    }
    Ok(())
}

#[tokio::test]
async fn recovery_checks_ownership_before_preparing_the_filesystem() -> anyhow::Result<()> {
    let state = crate::routes::AppState::mock();
    let executor = IncusExecutor::new(Arc::clone(&state.config))?;
    let server = Server::mock(uuid::Uuid::new_v4(), state);
    server.filesystem.disk_checker.abort();
    let instance: Instance =
        serde_json::from_value(json!({"name": IncusExecutor::name(server.uuid)}))?;
    let error = executor
        .verify_data_mount(&server, &instance)
        .await
        .err()
        .context("unmanaged instance was accepted")?;
    assert!(
        error
            .to_string()
            .contains("refusing unmanaged Incus instance")
    );
    Ok(())
}

struct MockIncus {
    client: Client,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
    _directory: tempfile::TempDir,
}

impl MockIncus {
    fn new(responses: Vec<(&'static str, reqwest::StatusCode, Value)>) -> anyhow::Result<Self> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let directory = tempfile::tempdir()?;
        let socket = directory.path().join("incus.sock");
        let listener = tokio::net::UnixListener::bind(&socket)?;
        let client = Client::new(&crate::config::IncusRuntime {
            socket: socket.display().to_string(),
            ..Default::default()
        })?;
        let task = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(5), async move {
                for (expected, status, response) in responses {
                    let (mut stream, _) = listener.accept().await?;
                    let mut request = Vec::new();
                    let mut buffer = [0; 1024];
                    while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                        let size = stream.read(&mut buffer).await?;
                        ensure!(size > 0, "Incus request ended before its headers");
                        request.extend_from_slice(buffer.get(..size).context("request buffer")?);
                    }
                    ensure!(
                        String::from_utf8_lossy(&request).starts_with(expected),
                        "unexpected Incus request: {}",
                        String::from_utf8_lossy(&request)
                    );
                    let body = serde_json::to_vec(&response)?;
                    let headers = format!(
                        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        status.as_u16(), status.canonical_reason().unwrap_or(""), body.len()
                    );
                    stream.write_all(headers.as_bytes()).await?;
                    stream.write_all(&body).await?;
                }
                Ok::<_, anyhow::Error>(())
            }).await.context("mock Incus request timed out")?
        });
        Ok(Self {
            client,
            task,
            _directory: directory,
        })
    }

    async fn finish(self) -> anyhow::Result<()> {
        self.task.await?
    }
}

mod live;
