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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let dir = tempfile::tempdir()?;
    let socket = dir.path().join("incus.sock");
    let listener = tokio::net::UnixListener::bind(&socket)?;
    let server = tokio::spawn(async move {
        for (expected, response) in [
            (
                "POST /1.0/instances?project=wings",
                json!({"type": "async", "operation": "/1.0/operations/job", "metadata": {}}),
            ),
            (
                "GET /1.0/operations/job/wait?project=wings&timeout=120",
                json!({"type": "sync", "metadata": {"status_code": 200, "metadata": {"result": "done"}}}),
            ),
        ] {
            let (mut stream, _) = listener.accept().await?;
            let mut request = Vec::new();
            let mut buffer = [0; 1024];
            loop {
                let size = stream.read(&mut buffer).await?;
                if size == 0 {
                    break;
                }
                request.extend_from_slice(buffer.get(..size).unwrap_or_default());
                if request.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            ensure!(
                String::from_utf8_lossy(&request).starts_with(expected),
                "unexpected Incus request"
            );
            let body = serde_json::to_vec(&response)?;
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes()).await?;
            stream.write_all(&body).await?;
        }
        Ok::<_, anyhow::Error>(())
    });
    let config = crate::config::IncusRuntime {
        socket: socket.display().to_string(),
        ..Default::default()
    };
    let client = Client::new(&config)?;
    let result = client
        .mutate(Method::POST, "/1.0/instances", json!({"name": "test"}))
        .await?;
    assert_eq!(
        result.pointer("/metadata/result").and_then(Value::as_str),
        Some("done")
    );
    server.await??;
    Ok(())
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
    // A configured overhead must not turn an unlimited memory setting into a hard limit.
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
fn wildcard_allocations_require_a_concrete_address() -> anyhow::Result<()> {
    let mut server = ServerConfiguration::mock(uuid::Uuid::new_v4());
    server
        .allocations
        .mappings
        .insert("0.0.0.0".into(), vec![25565]);
    assert!(network::allocations(&server, &[]).is_err());
    let ip: IpAddr = "192.0.2.10".parse()?;
    assert_eq!(
        network::allocations(&server, &[ip])?.get(&ip),
        Some(&BTreeSet::from([25565]))
    );
    server.allocations.mappings.insert("::".into(), vec![25565]);
    assert!(network::allocations(&server, &[ip]).is_err());
    Ok(())
}

#[tokio::test]
async fn api_errors_keep_status_for_conditional_retries() -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let dir = tempfile::tempdir()?;
    let socket = dir.path().join("incus.sock");
    let listener = tokio::net::UnixListener::bind(&socket)?;
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut buffer = [0; 1024];
        let _ = stream.read(&mut buffer).await?;
        let body = r#"{"type":"error","error_code":412,"error":"ETag mismatch"}"#;
        stream.write_all(format!("HTTP/1.1 412 Precondition Failed\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await?;
        Ok::<_, anyhow::Error>(())
    });
    let config = crate::config::IncusRuntime {
        socket: socket.display().to_string(),
        ..Default::default()
    };
    let client = Client::new(&config)?;
    let result = client
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
    server.await??;
    Ok(())
}

/// Exercises this executor against a real, disposable Incus 7.0.x node. Explicit opt-in.
/// Requires INCUS_TEST_POOL (existing btrfs/ZFS pool), INCUS_TEST_LISTEN_IP, root socket
/// access, skopeo, Incus 7.0 client, and nftables.
#[tokio::test]
#[ignore = "requires an explicitly configured disposable Incus 7.0.x node"]
async fn live_incus_lifecycle_volume_console_and_forwards() -> anyhow::Result<()> {
    use tokio::io::AsyncReadExt;
    use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};
    let _ = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_filter(
                    tracing_subscriber::filter::Targets::new()
                        .with_target("wings_rs::server::executor::incus", tracing::Level::DEBUG),
                ),
        )
        .try_init();
    let pool = std::env::var("INCUS_TEST_POOL").context("set INCUS_TEST_POOL")?;
    let listen: IpAddr = std::env::var("INCUS_TEST_LISTEN_IP")
        .context("set INCUS_TEST_LISTEN_IP")?
        .parse()?;
    let socket =
        std::env::var("INCUS_TEST_SOCKET").unwrap_or_else(|_| "/var/lib/incus/unix.socket".into());
    let temp = tempfile::tempdir()?;
    let node = uuid::Uuid::new_v4();
    let project = format!("wings-test-{}", node.simple());
    let network = format!(
        "wgt{}",
        node.simple().to_string().get(..8).context("test node ID")?
    );
    let mut state = crate::routes::AppState::mock();
    {
        let config = state.config.mutate_in_place_for_testing();
        config.uuid = node;
        config.runtime.backend = crate::config::RuntimeBackend::Incus;
        config.runtime.incus.project = project.clone();
        config.runtime.incus.network = network.clone();
        config.runtime.incus.socket = socket;
        config.runtime.incus.storage_pool = pool;
        config.runtime.incus.listen_addresses = vec![listen];
        config.runtime.incus.ipv4_address =
            std::env::var("INCUS_TEST_CIDR").unwrap_or_else(|_| "10.237.19.1/24".into());
        config.system.root_directory =
            crate::config::SystemPath::new(temp.path().display().to_string());
        config.system.data_directory =
            crate::config::SystemPath::new(temp.path().join("data").display().to_string());
        config.system.tmp_directory =
            crate::config::SystemPath::new(temp.path().join("tmp").display().to_string());
        config.system.vmount_directory =
            crate::config::SystemPath::new(temp.path().join("vmounts").display().to_string());
        config.system.disk_check_use_inotify = false;
        config.system.user.uid = 1000;
        config.system.user.gid = 1000;
    }
    let executor = IncusExecutor::new(Arc::clone(&state.config))?;
    Arc::get_mut(&mut state)
        .context("test state already shared")?
        .executor = Arc::new(executor.clone());
    executor.boot().await?;
    let server = Server::mock(uuid::Uuid::new_v4(), state);
    server.filesystem.disk_checker.abort();
    let port: u16 = std::env::var("INCUS_TEST_PORT")
        .unwrap_or_else(|_| "34567".into())
        .parse()?;
    {
        let mut config = server.configuration.write().await;
        config.container.image = std::env::var("INCUS_TEST_IMAGE")
            .unwrap_or_else(|_| "python:3.13-alpine".into())
            .into();
        config.build.disk_space = 256;
        config.build.memory_limit = 128;
        config.build.overhead_memory = 0;
        config.build.cpu_limit = 100;
        config.build.io_weight = None;
        config.entrypoint = Some(vec![
            "python3".into(),
            "-u".into(),
            "-c".into(),
            format!(
                r#"import socket, threading, sys
open('/home/container/persist', 'w').write('volume-data')
def tcp():
    s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1); s.bind(('0.0.0.0',{port})); s.listen()
    while True:
        c,a=s.accept(); c.sendall(b'tcp-ok'); c.close()
def udp():
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('0.0.0.0',{port}))
    while True:
        d,a=s.recvfrom(100); s.sendto(b'udp-ok',a)
threading.Thread(target=tcp,daemon=True).start()
threading.Thread(target=udp,daemon=True).start()
print('READY',flush=True)
for line in sys.stdin:
    if line.strip()=='stop': sys.exit(7)
"#
            ),
        ]);
        config
            .allocations
            .mappings
            .insert(listen.to_string().into(), vec![port]);
        server.process_configuration.write().await.stop.r#type = "command".into();
        server.process_configuration.write().await.stop.value = Some("stop".into());
    }
    let outcome = async {
        server.filesystem.setup().await;
        server.filesystem.chown_path("")?;
        ensure!(
            !server.filesystem.is_uninitialized(),
            "host server directory did not initialize"
        );
        let (handle, _status) = executor.setup_server_process(&server).await?;
        eprintln!("Live resources: project={project} instance={}", IncusExecutor::name(server.uuid));
        eprintln!("PASS OCI import and host-directory instance creation");
        handle.start().await?;
        let mut tcp = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                match tokio::net::TcpStream::connect(SocketAddr::new(listen, port)).await {
                    Ok(stream) => break stream,
                    Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
                }
            }
        })
        .await?;
        let mut reply = [0; 6];
        tcp.read_exact(&mut reply).await?;
        ensure!(&reply == b"tcp-ok", "TCP forward failed");
        let udp = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        udp.send_to(b"test", SocketAddr::new(listen, port)).await?;
        let mut reply = [0; 6];
        tokio::time::timeout(Duration::from_secs(10), udp.recv_from(&mut reply)).await??;
        ensure!(&reply == b"udp-ok", "UDP forward failed");
        eprintln!("PASS real TCP/UDP forward traffic");
        drop(handle); // Simulate Wings console disconnect without stopping the game.
        let (reattached, mut status) = executor.attach_server_process(&server).await?;
        reattached.stop().await?;
        let exit = tokio::time::timeout(Duration::from_secs(60), async {
            while let Some(status) = status.recv().await {
                if let super::super::ProcessStatus::Stopped { exit_code, .. } = status {
                    return Ok::<_, anyhow::Error>(exit_code);
                }
            }
            anyhow::bail!("process status ended without exit")
        })
        .await??;
        ensure!(exit == 7, "game exit code was not preserved");
        eprintln!("PASS console reconnect, stdin stop, and exit code 7");
        drop(reattached);
        ensure!(
            tokio::fs::read_to_string(server.filesystem.base_path.join("persist")).await?
                == "volume-data",
            "stopped-server file access failed"
        );
        executor.cleanup_server_process(&server).await?;
        ensure!(
            tokio::fs::read_to_string(server.filesystem.base_path.join("persist")).await?
                == "volume-data",
            "instance cleanup removed persistent data"
        );
        use std::os::unix::fs::MetadataExt;
        ensure!(
            tokio::fs::metadata(server.filesystem.base_path.join("persist"))
                .await?
                .uid()
                == 1000,
            "container writes were not mapped to the host data account"
        );
        eprintln!("PASS host data ownership and persistence after instance cleanup");
        let image = server.configuration.read().await.container.image.clone();
        let installer = crate::server::installation::InstallationScript {
            container_image: image.clone(),
            entrypoint: "/bin/sh".into(),
            script: "set -eu\nprintf installed > /mnt/server/installed\nprintf 0 > \"$INSTALL_STATUS_FILE\"\nprintf 100 > \"$INSTALL_PROGRESS_FILE\"\n".into(),
            environment: Default::default(),
        };
        let (installer_handle, mut installer_status) = executor
            .setup_installation_process(&server, &installer)
            .await?;
        installer_handle.start().await?;
        ensure!(
            wait_live_exit(&mut installer_status).await? == 0,
            "installer failed"
        );
        drop(installer_handle);
        executor.cleanup_installation_process(&server).await?;
        let staging = executor.config.tmp_data_path(server.uuid);
        ensure!(
            tokio::fs::read_to_string(staging.join("progress")).await? == "100"
                && tokio::fs::read_to_string(staging.join("status")).await? == "0",
            "installer progress/status host files were not updated"
        );
        ensure!(
            tokio::fs::read_to_string(server.filesystem.base_path.join("installed")).await?
                == "installed",
            "installer data did not persist"
        );
        let script = crate::server::installation::InstallationScript {
            container_image: image,
            entrypoint: "/bin/sh".into(),
            script: "set -eu\nprintf scripted > /mnt/server/scripted\nexit 9\n".into(),
            environment: Default::default(),
        };
        let (script_handle, mut script_status) =
            executor.setup_script_process(&server, &script).await?;
        script_handle.start().await?;
        ensure!(
            wait_live_exit(&mut script_status).await? == 9,
            "fast script exit status was not preserved"
        );
        drop(script_handle);
        executor.cleanup_owned_helpers(server.uuid).await?;
        ensure!(
            tokio::fs::read_to_string(server.filesystem.base_path.join("scripted")).await?
                == "scripted",
            "script data did not persist"
        );
        eprintln!("PASS installer status/progress mounts and script-helper fast exit");
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if let Err(error) = &outcome {
        eprintln!("Incus lifecycle failure before cleanup: {error:#}");
        if std::env::var("INCUS_TEST_KEEP_FAILURE").as_deref() == Ok("1") {
            server.filesystem.close();
            eprintln!(
                "Retained owned test project {project}, network {network}, data {}",
                temp.keep().display()
            );
            return outcome;
        }
    }
    server.filesystem.close();
    let _ = executor.cleanup_server_process(&server).await;
    let _ = executor.cleanup_owned_helpers(server.uuid).await;
    // The test owns this randomly named project exclusively. Retain the operator's pool.
    let images: Vec<Value> = executor.client.get("/1.0/images?recursion=1").await?;
    for image in images {
        if let Some(fingerprint) = image.get("fingerprint").and_then(Value::as_str) {
            executor
                .client
                .mutate(
                    Method::DELETE,
                    &format!("/1.0/images/{}", segment(fingerprint)),
                    json!({}),
                )
                .await?;
        }
    }
    let mut global = executor.client.clone();
    global.project = "default".into();
    global
        .mutate(
            Method::DELETE,
            &format!("/1.0/networks/{}", segment(&network)),
            json!({}),
        )
        .await?;
    executor
        .client
        .request(
            Method::DELETE,
            &format!("/1.0/projects/{}", segment(&project)),
            None,
            None,
            false,
        )
        .await?;
    outcome
}

async fn wait_live_exit(status: &mut super::super::StatusReceiver) -> anyhow::Result<i32> {
    tokio::time::timeout(Duration::from_secs(30), async {
        while let Some(status) = status.recv().await {
            if let super::super::ProcessStatus::Stopped { exit_code, .. } = status {
                return Ok(exit_code);
            }
        }
        anyhow::bail!("process status ended without exit")
    })
    .await?
}
