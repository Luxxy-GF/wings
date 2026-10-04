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
        network::allocations(&server, &[])?.get(&"0.0.0.0".parse()?),
        Some(&BTreeSet::from([25565]))
    );
    let ip: IpAddr = "192.0.2.10".parse()?;
    assert_eq!(
        network::allocations(&server, &[ip])?.get(&"0.0.0.0".parse()?),
        Some(&BTreeSet::from([25565]))
    );
    let spec = firewall_spec(&server, "10.76.0.2".parse()?, &[ip])?;
    assert!(spec.bindings.iter().all(|binding| binding.ip.is_none()));
    server
        .allocations
        .mappings
        .insert("192.0.2.20".into(), vec![25566]);
    assert!(network::allocations(&server, &[ip])?.contains_key(&"192.0.2.20".parse()?));
    server
        .allocations
        .mappings
        .insert("192.0.2.20".into(), vec![25565]);
    assert!(network::allocations(&server, &[ip]).is_err());
    server.allocations.mappings.remove("192.0.2.20");
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

#[tokio::test]
#[ignore = "requires an explicitly configured disposable Incus 7.0.x node"]
async fn live_incus_lifecycle_volume_console_and_forwards() -> anyhow::Result<()> {
    live_incus_lifecycle(true, false).await
}

#[tokio::test]
#[ignore = "requires an explicitly configured disposable Incus 7.0.x node"]
async fn live_incus_allocation_proxies_and_cleanup() -> anyhow::Result<()> {
    live_incus_lifecycle(false, false).await
}

#[tokio::test]
#[ignore = "requires an explicitly configured disposable Incus 7.0.x node"]
async fn live_incus_backup_transfer_and_limits() -> anyhow::Result<()> {
    live_incus_lifecycle(false, true).await
}

async fn live_incus_lifecycle(test_console: bool, transfer_only: bool) -> anyhow::Result<()> {
    use tokio::io::AsyncReadExt;
    use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};
    let _ = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_filter(
                    tracing_subscriber::filter::Targets::new()
                        .with_target("wings_rs::server::executor::incus", tracing::Level::DEBUG)
                        .with_target("wings_rs::routes::api::transfers", tracing::Level::DEBUG)
                        .with_target("wings_rs::server::filesystem", tracing::Level::INFO),
                ),
        )
        .try_init();
    let pool = std::env::var("INCUS_TEST_POOL").context("set INCUS_TEST_POOL")?;
    let listen: IpAddr = std::env::var("INCUS_TEST_LISTEN_IP")
        .context("set INCUS_TEST_LISTEN_IP")?
        .parse()?;
    let socket =
        std::env::var("INCUS_TEST_SOCKET").unwrap_or_else(|_| "/var/lib/incus/unix.socket".into());
    let temp = match std::env::var("INCUS_TEST_DATA_ROOT") {
        Ok(root) => tempfile::tempdir_in(root)?,
        Err(_) => tempfile::tempdir()?,
    };
    let quota = std::env::var("INCUS_TEST_QUOTA").unwrap_or_default();
    let read_only = temp.path().join("read-only");
    let read_write = temp.path().join("read-write");
    std::fs::create_dir(&read_only)?;
    std::fs::create_dir(&read_write)?;
    std::fs::write(read_only.join("fixture"), "readonly-data")?;
    std::os::unix::fs::chown(&read_write, Some(1000), Some(1000))?;
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
        config.tundra.enabled = true;
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
        config.system.backup_directory =
            crate::config::SystemPath::new(temp.path().join("backups").display().to_string());
        config.system.vmount_directory =
            crate::config::SystemPath::new(temp.path().join("vmounts").display().to_string());
        config.allowed_mounts = vec![
            read_only.display().to_string().into(),
            read_write.display().to_string().into(),
        ];
        config.system.disk_limiter_mode = match quota.as_str() {
            "btrfs" => crate::server::filesystem::limiter::DiskLimiterMode::BtrfsSubvolume,
            "fuse" => crate::server::filesystem::limiter::DiskLimiterMode::FuseQuota,
            "" => crate::server::filesystem::limiter::DiskLimiterMode::None,
            _ => anyhow::bail!("unknown INCUS_TEST_QUOTA"),
        };
        config.system.disk_check_use_inotify = false;
        config.system.user.uid = 1000;
        config.system.user.gid = 1000;
        if let Ok(registry) = std::env::var("INCUS_TEST_REGISTRY") {
            config.docker.registries.insert(
                registry,
                crate::config::DockerRegistryConfiguration {
                    username: "fixture-user".into(),
                    password: "fixture pass:'@/%".into(),
                },
            );
        }
    }
    if quota == "fuse" {
        ensure!(
            state
                .config
                .vmount_path(uuid::Uuid::nil())
                .join("fs.fqsock")
                .as_os_str()
                .len()
                < 108,
            "FUSE test control socket path is too long; set INCUS_TEST_DATA_ROOT to a shorter directory"
        );
    }
    let executor = IncusExecutor::new(Arc::clone(&state.config))?;
    Arc::get_mut(&mut state)
        .context("test state already shared")?
        .executor = Arc::new(executor.clone());
    executor.boot().await?;
    let mut server = Server::mock(uuid::Uuid::new_v4(), state);
    server.filesystem.disk_checker.abort();
    let mut console = server.websocket.subscribe();
    let console_task = tokio::spawn(async move {
        while let Ok(message) = console.recv().await {
            for arg in message.args.iter() {
                eprintln!("Live console: {arg}");
            }
        }
    });
    let port: u16 = std::env::var("INCUS_TEST_PORT")
        .unwrap_or_else(|_| "34567".into())
        .parse()?;
    {
        let mut config = server.configuration.write().await;
        config.container.image = std::env::var("INCUS_TEST_IMAGE")
            .unwrap_or_else(|_| "python:3.13-alpine".into())
            .into();
        config.build.disk_space = if quota.is_empty() { 256 } else { 8 };
        config.mounts = vec![
            crate::server::configuration::Mount {
                default: false,
                source: read_only.display().to_string().into(),
                target: "/extra-ro".into(),
                read_only: true,
            },
            crate::server::configuration::Mount {
                default: false,
                source: read_write.display().to_string().into(),
                target: "/extra-rw".into(),
                read_only: false,
            },
        ];
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
assert '127.0.0.2' in open('/etc/hosts').read(), 'Incus hid Wings private hosts file'
assert open('/extra-ro/fixture').read() == 'readonly-data'
try:
    open('/extra-ro/forbidden','w').write('bad')
    raise AssertionError('read-only mount was writable')
except OSError as e:
    assert e.errno == 30, e
open('/extra-rw/result','w').write('mount-ok')
if {quota_enabled}:
    import os
    try:
        with open('/home/container/quota-probe','wb', buffering=0) as f:
            for _ in range(32):
                f.write(os.urandom(1024*1024))
                os.fsync(f.fileno())
        raise AssertionError('game data exceeded quota')
    except OSError as e:
        assert e.errno in (28,122), e
    os.remove('/home/container/quota-probe')
    open('/home/container/quota-result','w').write('quota-ok')
def tcp():
    s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1); s.bind(('0.0.0.0',{port})); s.listen()
    while True:
        c,a=s.accept(); open('/home/container/tcp-peer','w').write(a[0]); c.sendall(b'tcp-ok'); c.close()
def udp():
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('0.0.0.0',{port}))
    while True:
        d,a=s.recvfrom(100); open('/home/container/udp-peer','w').write(a[0]); s.sendto(b'udp-ok',a)
threading.Thread(target=tcp,daemon=True).start()
threading.Thread(target=udp,daemon=True).start()
print('READY',flush=True)
for line in sys.stdin:
    if line.strip()=='stop': sys.exit(7)
"#,
                quota_enabled = if quota.is_empty() { "False" } else { "True" }
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
        tokio::fs::create_dir_all(executor.config.resolve_as_path(|cfg| &cfg.system.tmp_directory)).await?;
        tokio::fs::create_dir_all(server.filesystem.base_path.parent().context("test data parent missing")?).await?;
        server.filesystem.setup().await;
        server.filesystem.chown_path("")?;
        ensure!(
            !server.filesystem.is_uninitialized(),
            "host server directory did not initialize"
        );
        if !quota.is_empty() {
            server.filesystem.update_disk_limit(8 * 1024 * 1024).await;
        }
        if transfer_only {
            executor.prepare_data_mount(&server).await?;
            return live_backup_and_transfer(&server, &executor, &temp, !quota.is_empty()).await;
        }
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
        eprintln!("PASS concrete-address TCP/UDP NAT proxy traffic");
        ensure!(std::fs::read_to_string(read_write.join("result"))? == "mount-ok", "writable extra mount failed");
        ensure!(!read_only.join("forbidden").exists(), "read-only extra mount changed");
        eprintln!("PASS allowlisted read-only/read-write mounts with mapped ownership");
        if !quota.is_empty() {
            ensure!(std::fs::read_to_string(server.filesystem.base_path.join("quota-result"))? == "quota-ok", "data quota did not reject an over-limit guest write");
            eprintln!("PASS {quota} game-data quota enforcement inside Incus");
        }
        if let Ok(checkpoint) = std::env::var("INCUS_TEST_REBOOT_CHECKPOINT") {
            let root = executor.config.resolve_as_path(|cfg| &cfg.system.root_directory);
            tokio::fs::write(root.join("states.json"), serde_json::to_vec(&BTreeMap::from([(server.uuid, crate::server::state::ServerState::Running)]))?).await?;
            let mut settings = serde_json::to_value(&*server.configuration.read().await)?;
            settings["auto_start_behavior"] = json!("unless_stopped");
            let record = json!({"config": &**executor.config.load(), "settings": settings,
                "boot_id": std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?,
                "listen": listen, "port": port});
            tokio::fs::write(&checkpoint, serde_json::to_vec(&record)?).await?;
            tokio::fs::set_permissions(&checkpoint, std::os::unix::fs::PermissionsExt::from_mode(0o600)).await?;
            eprintln!("PASS reboot checkpoint prepared at {checkpoint}");
            return Ok(());
        }
        let adapter = tundra_node::IncusAdapter::with_runtime(
            executor.client.socket.clone(), project.clone(), format!("wings:{node}"))?;
        let info = adapter.inspect(&IncusExecutor::name(server.uuid)).await?;
        ensure!(info.running && info.pid > 0 && info.ip.is_some(), "Tundra failed to adopt Incus server");
        ensure!(adapter.inspect("wgi-not-a-server").await.is_err(), "Tundra adopted an installer");
        let wrong = tundra_node::IncusAdapter::with_runtime(executor.client.socket.clone(), project.clone(), "wings:other-node".into())?;
        ensure!(wrong.inspect(&IncusExecutor::name(server.uuid)).await.is_err(), "Tundra adopted another owner's container");
        use tundra_node::FrontendBinder;
        let target = tundra_node::ContainerTarget { pid: info.pid };
        let tcp_addr: std::net::SocketAddrV4 = "127.0.9.9:24242".parse()?;
        let udp_addr: std::net::SocketAddrV4 = "127.0.9.9:24243".parse()?;
        let tcp_frontend = tokio::net::TcpListener::from_std(tundra_node::NetnsBinder.bind_tcp(&target, tcp_addr)?)?;
        let udp_frontend = tokio::net::UdpSocket::from_std(tundra_node::NetnsBinder.bind_udp(&target, udp_addr)?)?;
        let host_tcp = std::net::TcpListener::bind(tcp_addr)?;
        let host_udp = std::net::UdpSocket::bind(udp_addr)?;
        let hosts_path = server.app_state.config.vmount_path(server.uuid).join("hosts");
        let mut hosts = std::fs::read_to_string(&hosts_path)?;
        hosts.push_str("127.0.9.9 test-peer.tunnel\n");
        std::fs::write(&hosts_path, hosts)?;
        let inside = tokio::process::Command::new("incus").args([
            "exec", &IncusExecutor::name(server.uuid), "--project", &project, "--", "python3", "-c",
            "import socket; assert socket.gethostbyname('test-peer.tunnel') == '127.0.9.9'; t=socket.create_connection(('test-peer.tunnel',24242)); t.sendall(b'private-tcp'); u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); u.sendto(b'private-udp',('127.0.9.9',24243))"
        ]).kill_on_drop(true).spawn()?;
        let (mut stream, _) = tokio::time::timeout(Duration::from_secs(10), tcp_frontend.accept()).await??;
        let mut data = [0;11]; stream.read_exact(&mut data).await?;
        ensure!(&data == b"private-tcp", "private TCP frontend unreachable inside Incus");
        let mut data = [0;11]; tokio::time::timeout(Duration::from_secs(10), udp_frontend.recv_from(&mut data)).await??;
        ensure!(&data == b"private-udp", "private UDP frontend unreachable inside Incus");
        ensure!(inside.wait_with_output().await?.status.success(), "private frontend client failed");
        drop((tcp_frontend, udp_frontend, host_tcp, host_udp));
        eprintln!("PASS Tundra Incus adoption, ownership isolation, and real TCP/UDP namespace frontends");

        let desired = BTreeMap::from([(listen, BTreeSet::from([port]))]);
        let name = IncusExecutor::name(server.uuid);
        let instance = executor.instance(&name).await?;
        let target = instance.config.get("user.wings.ip").context("test instance IP missing")?.clone();
        let device_names: BTreeSet<_> = instance.devices.keys().filter(|name| name.starts_with("wings-port-")).cloned().collect();
        ensure!(device_names.len() == 2, "expected two protocol proxy devices");
        executor.network.sync(server.uuid, "", &BTreeMap::new()).await?;
        let path = IncusExecutor::instance_path(&name);
        let mut value: Value = executor.client.get(&path).await?;
        value["config"]["user.wings.allocations"] = json!(serde_json::to_string(&desired)?);
        executor.client.mutate(Method::PUT, &path, value).await?;
        let mut global = executor.client.clone();
        global.project = "default".into();
        let forwards_path = format!("/1.0/networks/{network}/forwards");
        let forward_path = format!("{forwards_path}/{listen}");
        let owner = format!("wings:{node}");
        let ports: Vec<_> = ["tcp", "udp"].iter().map(|protocol| json!({
            "protocol": protocol, "listen_port": port.to_string(), "target_address": target,
            "description": format!("{owner}:{}", server.uuid)
        })).collect();
        let mut mixed = ports.clone();
        mixed.push(json!({"protocol": "tcp", "listen_port": (port + 1).to_string(), "target_address": target, "description": "operator-rule"}));
        global.mutate(Method::POST, &forwards_path, json!({"listen_address": listen.to_string(), "description": owner, "ports": mixed})).await?;
        ensure!(executor.network.boot().await.is_err(), "migration overwrote an unrelated forward entry");
        let unchanged: Value = global.get(&forward_path).await?;
        ensure!(unchanged["ports"].as_array().is_some_and(|p| p.len() == 3), "failed migration changed shared forward");
        global.mutate(Method::PUT, &forward_path, json!({"description": owner, "config": {}, "ports": ports})).await?;
        executor.network.boot().await?;
        ensure!(global.optional::<Value>(&forward_path).await?.is_none(), "legacy forward was not removed");
        let mut stream = tokio::net::TcpStream::connect(SocketAddr::new(listen, port)).await?;
        stream.read_exact(&mut reply).await?;
        ensure!(&reply == b"tcp-ok", "migration lost running-server TCP publication");
        eprintln!("PASS migration of running instance and preservation of unrelated forwarding rules");
        {
            let mut config = server.configuration.write().await;
            config.allocations.mappings.clear();
            config.allocations.mappings.insert("0.0.0.0".into(), vec![port]);
        }
        executor.sync_server(&server, &name).await?;
        let instance = executor.instance(&name).await?;
        ensure!(device_names.iter().all(|name| !instance.devices.contains_key(name)), "stale concrete proxy survived wildcard update");
        let socket = tokio::net::TcpSocket::new_v4()?;
        socket.bind(SocketAddr::new(listen, 0))?;
        let mut stream = socket.connect(SocketAddr::new(listen, port)).await?;
        stream.read_exact(&mut reply).await?;
        ensure!(&reply == b"tcp-ok", "wildcard TCP proxy failed");
        let udp = tokio::net::UdpSocket::bind(SocketAddr::new(listen, 0)).await?;
        udp.send_to(b"test", SocketAddr::new(listen, port)).await?;
        tokio::time::timeout(Duration::from_secs(10), udp.recv_from(&mut reply)).await??;
        ensure!(&reply == b"udp-ok", "wildcard UDP proxy failed");
        for peer in ["tcp-peer", "udp-peer"] {
            ensure!(tokio::fs::read_to_string(server.filesystem.base_path.join(peer)).await? == listen.to_string(), "NAT proxy changed client source IP");
        }
        let used = executor.network.used_ports(&[listen]).await?;
        ensure!(used[&listen].iter().any(|p| p.port == port && p.server == Some(server.uuid)), "used_ports omitted wildcard publication");
        let collision = executor.network.sync(uuid::Uuid::new_v4(), &target,
            &BTreeMap::from([(listen, BTreeSet::from([port]))])).await.expect_err("overlapping concrete allocation accepted");
        ensure!(collision.to_string().contains("conflicts"), "collision failed for wrong reason: {collision}");
        executor.network.sync(server.uuid, "", &BTreeMap::new()).await?;
        ensure!(tokio::net::TcpStream::connect(SocketAddr::new(listen, port)).await.is_err(), "removed proxy still accepts traffic");
        executor.sync_server(&server, &name).await?;
        eprintln!("PASS wildcard TCP/UDP traffic, client IP preservation, allocation update/removal, and overlap rejection");
        drop(handle);
        let before: InstanceState = executor.client.get(&format!("{}/state", IncusExecutor::instance_path(&name))).await?;
        if std::env::var("INCUS_TEST_RESTART_DAEMON").as_deref() == Ok("1") {
            let restart = tokio::process::Command::new("systemctl").args(["restart", "incus"]).status().await?;
            ensure!(restart.success(), "test Incus daemon restart failed");
        }
        let recovered = Server::new(
            serde_json::from_value(serde_json::to_value(&*server.configuration.read().await)?)?,
            serde_json::from_value(json!({"startup": {"done": ["READY"]}, "stop": {"type": "command", "value": "stop"}, "configs": []}))?,
            server.app_state.clone(),
        );
        recovered.filesystem.disk_checker.abort();
        server.filesystem.close();
        recovered.filesystem.attach().await;
        server = recovered;
        let fresh_executor = IncusExecutor::new(executor.config.clone())?;
        fresh_executor.boot().await?;
        let (reattached, mut status) = fresh_executor.attach_server_process(&server).await?;
        let after: InstanceState = executor.client.get(&format!("{}/state", IncusExecutor::instance_path(&name))).await?;
        ensure!(before.pid == after.pid && after.pid > 0, "recovery replaced the running game");
        let mut stream = tokio::net::TcpStream::connect(SocketAddr::new(listen, port)).await?;
        stream.read_exact(&mut reply).await?;
        ensure!(&reply == b"tcp-ok", "TCP publication failed after recovery");
        udp.send_to(b"recover", SocketAddr::new(listen, port)).await?;
        tokio::time::timeout(Duration::from_secs(10), udp.recv_from(&mut reply)).await??;
        ensure!(&reply == b"udp-ok", "UDP publication failed after recovery");
        ensure!(std::fs::read_to_string(server.filesystem.base_path.join("persist"))? == "volume-data", "recovery changed game data");
        eprintln!("PASS fresh executor/filesystem reattachment, quota mount identity, unchanged PID, and TCP/UDP publication");
        if test_console {
            let settle: u64 = std::env::var("INCUS_TEST_CONSOLE_SETTLE_SECONDS")
                .unwrap_or_else(|_| "0".into()).parse()?;
            ensure!(settle <= 60, "test console settling delay must be at most 60 seconds");
            tokio::time::sleep(Duration::from_secs(settle)).await;
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
        } else {
            reattached.kill().await?;
            let _ = wait_live_exit(&mut status).await?;
            eprintln!("PASS Incus API stop with proxy devices attached");
        }
        drop(reattached);
        age_image_cache(&executor)?;
        ensure!(executor.images.cleanup().await? == 0, "cleanup deleted a stopped instance's base image");
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
        live_backup_and_transfer(&server, &executor, &temp, !quota.is_empty()).await?;
        std::os::unix::fs::chown(&server.filesystem.base_path, Some(0), Some(0))?;
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
        age_image_cache(&executor)?;
        ensure!(executor.images.cleanup().await? > 0, "unused owned images were not collected");
        eprintln!("PASS image cleanup protects stopped instances and removes expired unused owned images");
        ensure!(
            tokio::fs::read_to_string(server.filesystem.base_path.join("scripted")).await?
                == "scripted",
            "script data did not persist"
        );
        eprintln!("PASS installer status/progress mounts and script-helper fast exit");
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if outcome.is_ok() && std::env::var_os("INCUS_TEST_REBOOT_CHECKPOINT").is_some() {
        console_task.abort();
        eprintln!("Retained owned reboot fixture at {}", temp.keep().display());
        return outcome;
    }
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
    let _ = executor.cleanup_server_process(&server).await;
    console_task.abort();
    let _ = executor.cleanup_owned_helpers(server.uuid).await;
    if !quota.is_empty() {
        if let Err(error) = server.filesystem.get_disk_limiter().destroy().await {
            eprintln!("Could not clear test disk limiter: {error:#}");
        }
    }
    server.filesystem.close();
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

fn age_image_cache(executor: &IncusExecutor) -> anyhow::Result<()> {
    let root = executor
        .config
        .resolve_as_path(|cfg| &cfg.system.root_directory)
        .join("incus-images");
    let old = std::time::SystemTime::now() - Duration::from_secs(31 * 86400);
    for entry in std::fs::read_dir(root)? {
        let path = entry?.path();
        if path.extension().and_then(|extension| extension.to_str()) == Some("json") {
            std::fs::OpenOptions::new()
                .write(true)
                .open(path)?
                .set_modified(old)?;
        }
    }
    Ok(())
}

async fn live_backup_and_transfer(
    source: &Server,
    executor: &IncusExecutor,
    temp: &tempfile::TempDir,
    quota: bool,
) -> anyhow::Result<()> {
    use crate::server::backup::{BackupCreateExt, BackupFindExt, adapters::wings::WingsBackup};
    use crate::server::filesystem::archive::create::ArchiveProgress;
    use sha2::Digest;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::sync::atomic::AtomicU64;

    let backups = executor
        .config
        .resolve_as_path(|cfg| &cfg.system.backup_directory);
    tokio::fs::create_dir_all(&backups).await?;
    let data = source.filesystem.base_path.join("backup-fixture");
    std::fs::create_dir_all(&data)?;
    std::fs::write(data.join("payload"), b"backup-and-transfer-data")?;
    std::fs::set_permissions(data.join("payload"), std::fs::Permissions::from_mode(0o640))?;
    std::os::unix::fs::symlink("payload", data.join("link"))?;
    source
        .filesystem
        .async_chown_path_recursive("backup-fixture")
        .await?;
    let backup_id = uuid::Uuid::new_v4();
    WingsBackup::create(
        source,
        backup_id,
        ArchiveProgress::default(),
        Arc::new(AtomicU64::new(0)),
        crate::server::filesystem::ignore_list::IgnoreList::empty(),
        "".into(),
    )
    .await?;
    let backup = WingsBackup::find(&source.app_state, backup_id)
        .await?
        .context("created backup missing")?;
    let (_, backup_path) = WingsBackup::get_first_file_name(&executor.config, backup_id).await?;

    let destination_id = uuid::Uuid::new_v4();
    let mut settings = ServerConfiguration::mock(destination_id);
    settings.container.image = source.configuration.read().await.container.image.clone();
    settings.build.disk_space = 8;
    settings.build.cpu_limit = 100;
    settings.build.memory_limit = 128;
    settings.build.overhead_memory = 0;
    settings.build.swap = 0;
    settings.entrypoint = Some(vec!["python3".into(), "-c".into(), "import os; assert open('/home/container/backup-fixture/payload').read()=='backup-and-transfer-data'; assert os.readlink('/home/container/backup-fixture/link')=='payload'; open('/home/container/destination-write','w').write('mapped-write-ok'); import time; time.sleep(3600)".into()]);
    let panel_settings = serde_json::to_value(&settings)?;
    let process = json!({"startup": {"done": []}, "stop": {"type": "signal", "value": "SIGTERM"}, "configs": []});
    let panel = axum::Router::new()
        .route(
            "/api/remote/servers/{server}",
            axum::routing::get(
                move |axum::extract::Path(server): axum::extract::Path<uuid::Uuid>| {
                    let mut settings = panel_settings.clone();
                    let process = process.clone();
                    settings["uuid"] = json!(server);
                    async move {
                        axum::Json(json!({"settings": settings, "process_configuration": process}))
                    }
                },
            ),
        )
        .fallback(axum::routing::post(|| async {
            axum::http::StatusCode::NO_CONTENT
        }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let panel_address = listener.local_addr()?;
    let panel_task = tokio::spawn(async move { axum::serve(listener, panel).await });
    let mut destination = crate::routes::AppState::mock();
    {
        let cfg = destination.config.mutate_in_place_for_testing();
        *cfg = serde_json::from_value(serde_json::to_value(&**executor.config.load())?)?;
        cfg.system.data_directory = crate::config::SystemPath::new(
            temp.path().join("destination-data").display().to_string(),
        );
        cfg.system.user.uid = 1001;
        cfg.system.user.gid = 1001;
        cfg.remote = format!("http://{panel_address}");
    }
    tokio::fs::create_dir_all(
        destination
            .config
            .resolve_as_path(|cfg| &cfg.system.data_directory),
    )
    .await?;
    let client = crate::remote::client::Client::new(&destination.config.load(), false);
    Arc::get_mut(
        &mut Arc::get_mut(&mut destination)
            .context("shared destination state")?
            .config,
    )
    .context("shared destination config")?
    .client = client;
    let target_executor = IncusExecutor::new(destination.config.clone())?;
    Arc::get_mut(&mut destination)
        .context("shared destination state")?
        .executor = Arc::new(target_executor.clone());
    let (router, _) = crate::routes::api::transfers::router(&destination).split_for_parts();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let route_state = destination.clone();
    let route_task =
        tokio::spawn(async move { axum::serve(listener, router.with_state(route_state)).await });
    let now = chrono::Utc::now().timestamp();
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &json!({"scope":"transfer", "sub":destination_id, "iss":"panel", "aud":["wings"], "exp":now+300, "iat":now, "jti":uuid::Uuid::new_v4()}),
        &jsonwebtoken::EncodingKey::from_secret(destination.config.load().token.as_bytes()),
    )?;
    let bytes = tokio::fs::read(&backup_path).await?;
    let checksum = hex::encode(sha2::Sha256::digest(&bytes));
    let form = reqwest::multipart::Form::new()
        .part(
            "archive",
            reqwest::multipart::Part::bytes(bytes).file_name(
                backup_path
                    .file_name()
                    .context("backup filename")?
                    .to_string_lossy()
                    .to_string(),
            ),
        )
        .text("checksum", checksum);
    let outcome = async {
        let response = reqwest::Client::builder()
            .no_proxy()
            .build()?
            .post(format!("http://{address}/"))
            .bearer_auth(token)
            .multipart(form)
            .send()
            .await?;
        ensure!(
            response.status().is_success(),
            "incoming transfer failed: {}",
            response.text().await?
        );
        let target = destination
            .server_manager
            .get_server(destination_id)
            .await
            .context("incoming transfer did not register destination server")?;
        target.filesystem.disk_checker.abort();
        let path = target.filesystem.base_path.join("backup-fixture/payload");
        ensure!(std::fs::read(&path)? == b"backup-and-transfer-data", "transferred contents changed");
        let metadata = path.metadata()?;
        ensure!(metadata.uid() == 1001 && metadata.gid() == 1001, "transfer retained the source host owner");
        ensure!(metadata.permissions().mode() & 0o777 == 0o640, "transfer changed permissions");
        ensure!(std::fs::read_link(target.filesystem.base_path.join("backup-fixture/link"))? == std::path::Path::new("payload"), "transfer changed symlink");
        std::fs::write(&path, "changed-after-transfer")?;
        backup.restore(&target, ArchiveProgress::default(), Arc::new(AtomicU64::new(0)), None).await?;
        ensure!(std::fs::read(&path)? == b"backup-and-transfer-data", "backup restore did not restore contents");
        ensure!(path.metadata()?.uid() == 1001, "backup restore retained source ownership");
        target.filesystem.async_chown_path_recursive(&target.filesystem.base_path).await?;
        let (handle, mut status) = target_executor.setup_server_process(&target).await?;
        handle.start().await?;
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if target.filesystem.base_path.join("destination-write").is_file() { break; }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }).await.context("restored-data verifier did not write its completion marker")?;
        handle.kill().await?;
        wait_live_exit(&mut status).await?;
        ensure!(std::fs::read_to_string(target.filesystem.base_path.join("destination-write"))? == "mapped-write-ok", "destination mapped user could not write");
        target_executor.cleanup_server_process(&target).await?;
        eprintln!("PASS local backup restore and checksummed node HTTP transfer preserve files, mode, symlink, destination UID/GID, and Incus access");
        if quota {
            let oversized_id = uuid::Uuid::new_v4();
            let mut archive = tar::Builder::new(Vec::new());
            let payload = vec![0u8; 16 * 1024 * 1024];
            let mut header = tar::Header::new_gnu(); header.set_size(payload.len() as u64); header.set_mode(0o640); header.set_cksum();
            archive.append_data(&mut header, "over-limit", payload.as_slice())?;
            let bytes = archive.into_inner()?;
            let checksum = hex::encode(sha2::Sha256::digest(&bytes));
            let token = jsonwebtoken::encode(&jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
                &json!({"scope":"transfer", "sub":oversized_id, "iss":"panel", "aud":["wings"], "exp":now+300, "iat":now, "jti":uuid::Uuid::new_v4()}),
                &jsonwebtoken::EncodingKey::from_secret(destination.config.load().token.as_bytes()))?;
            let form = reqwest::multipart::Form::new().part("archive", reqwest::multipart::Part::bytes(bytes).file_name("archive.tar")).text("checksum", checksum);
            let response = reqwest::Client::builder().no_proxy().build()?.post(format!("http://{address}/")).bearer_auth(token).multipart(form).send().await?;
            ensure!(response.status() == reqwest::StatusCode::EXPECTATION_FAILED, "oversized node transfer was accepted: {}", response.status());
            eprintln!("PASS actual node transfer HTTP receiver rejects over-limit data");
        }
        Ok::<_, anyhow::Error>(())
    }.await;
    route_task.abort();
    panel_task.abort();
    for server in destination.server_manager.get_servers().await.iter() {
        if outcome.is_err() {
            if let Ok(buffer) = target_executor
                .client
                .console_buffer(&IncusExecutor::name(server.uuid))
                .await
            {
                eprintln!(
                    "Destination guest console: {}",
                    String::from_utf8_lossy(&buffer)
                );
            }
        }
        let _ = target_executor.cleanup_server_process(server).await;
        server.filesystem.disk_checker.abort();
        if !server.filesystem.is_uninitialized() {
            server.filesystem.get_disk_limiter().destroy().await?;
        }
        server.filesystem.close();
    }
    outcome
}

#[tokio::test]
#[ignore = "requires a checkpoint from the disposable live test and a real VM reboot"]
async fn live_incus_node_reboot_recovery() -> anyhow::Result<()> {
    use tokio::io::AsyncReadExt;
    let checkpoint =
        std::env::var("INCUS_TEST_REBOOT_RESUME").context("set INCUS_TEST_REBOOT_RESUME")?;
    let record: Value = serde_json::from_slice(&tokio::fs::read(&checkpoint).await?)?;
    ensure!(
        record["boot_id"].as_str()
            != Some(&std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?),
        "the node was not rebooted"
    );
    let mut state = crate::routes::AppState::mock();
    *state.config.mutate_in_place_for_testing() = serde_json::from_value(record["config"].clone())?;
    let panel_settings = record["settings"].clone();
    let panel = axum::Router::new().route("/api/remote/servers/{server}", axum::routing::get(move || {
        let settings = panel_settings.clone();
        async move { axum::Json(json!({"settings": settings, "process_configuration": {"startup": {"done": ["READY"]}, "stop": {"type": "command", "value": "stop"}, "configs": []}})) }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    state.config.mutate_in_place_for_testing().remote =
        format!("http://{}", listener.local_addr()?);
    let panel_task = tokio::spawn(async move { axum::serve(listener, panel).await });
    let client = crate::remote::client::Client::new(&state.config.load(), false);
    Arc::get_mut(
        &mut Arc::get_mut(&mut state)
            .context("shared reboot state")?
            .config,
    )
    .context("shared reboot config")?
    .client = client;
    let executor = IncusExecutor::new(state.config.clone())?;
    ensure!(
        state
            .config
            .load()
            .runtime
            .incus
            .project
            .starts_with("wings-test-"),
        "not a disposable test project"
    );
    Arc::get_mut(&mut state)
        .context("shared recovery fixture")?
        .executor = Arc::new(executor.clone());
    executor.boot().await?;
    let settings: ServerConfiguration = serde_json::from_value(record["settings"].clone())?;
    let uuid = settings.uuid;
    let name = IncusExecutor::name(uuid);
    ensure!(
        executor.instance(&name).await?.status == "Stopped",
        "Incus autostarted the fixture instead of Wings"
    );
    state.server_manager.boot(&state, vec![crate::remote::servers::RawServer {
        settings,
        process_configuration: serde_json::from_value(json!({"startup": {"done": ["READY"]}, "stop": {"type": "command", "value": "stop"}, "configs": []}))?,
    }]).await;
    let server = state
        .server_manager
        .get_server(uuid)
        .await
        .context("reboot server was not recovered")?;
    let address = SocketAddr::new(
        record["listen"]
            .as_str()
            .context("checkpoint listen address")?
            .parse()?,
        record["port"]
            .as_u64()
            .context("checkpoint port")?
            .try_into()?,
    );
    let outcome = async {
        let mut stream = tokio::time::timeout(Duration::from_secs(120), async {
            loop {
                if let Ok(stream) = tokio::net::TcpStream::connect(address).await { return stream }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }).await.context("Wings did not restart the saved running server")?;
        let mut reply = [0;6]; stream.read_exact(&mut reply).await?;
        ensure!(&reply == b"tcp-ok", "TCP allocation failed after node reboot");
        let udp = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        udp.send_to(b"reboot", address).await?;
        tokio::time::timeout(Duration::from_secs(10), udp.recv_from(&mut reply)).await??;
        ensure!(&reply == b"udp-ok", "UDP allocation failed after node reboot");
        let (handle, mut status) = executor.attach_server_process(&server).await?;
        handle.kill().await?; wait_live_exit(&mut status).await?;
        ensure!(std::fs::read_to_string(server.filesystem.base_path.join("persist"))? == "volume-data", "node reboot lost game data");
        eprintln!("PASS real node reboot: saved-state autostart, persistent files, rebuilt quota mount, and TCP/UDP allocations");
        Ok::<_, anyhow::Error>(())
    }.await;
    server.filesystem.disk_checker.abort();
    panel_task.abort();
    executor.cleanup_server_process(&server).await?;
    server.filesystem.get_disk_limiter().destroy().await?;
    server.filesystem.close();
    let images: Vec<Value> = executor.client.get("/1.0/images?recursion=1").await?;
    for image in images {
        executor
            .client
            .mutate(
                Method::DELETE,
                &format!(
                    "/1.0/images/{}",
                    segment(
                        image["fingerprint"]
                            .as_str()
                            .context("test image fingerprint")?
                    )
                ),
                json!({}),
            )
            .await?;
    }
    let mut global = executor.client.clone();
    global.project = "default".into();
    global
        .mutate(
            Method::DELETE,
            &format!(
                "/1.0/networks/{}",
                segment(&state.config.load().runtime.incus.network)
            ),
            json!({}),
        )
        .await?;
    executor
        .client
        .request(
            Method::DELETE,
            &format!(
                "/1.0/projects/{}",
                segment(&state.config.load().runtime.incus.project)
            ),
            None,
            None,
            false,
        )
        .await?;
    tokio::fs::remove_dir_all(
        executor
            .config
            .resolve_as_path(|cfg| &cfg.system.root_directory),
    )
    .await?;
    tokio::fs::remove_file(checkpoint).await?;
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
