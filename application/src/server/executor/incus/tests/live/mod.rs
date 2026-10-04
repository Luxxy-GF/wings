use super::*;

mod backup;
mod recovery;

use backup::live_backup_and_transfer;

#[tokio::test]
#[ignore = "requires an explicitly configured disposable Incus 7.0.x node"]
async fn live_incus_lifecycle_volume_console_and_forwards() -> anyhow::Result<()> {
    live_incus_lifecycle(LiveTest::Console).await
}

#[tokio::test]
#[ignore = "requires an explicitly configured disposable Incus 7.0.x node"]
async fn live_incus_allocation_proxies_and_cleanup() -> anyhow::Result<()> {
    live_incus_lifecycle(LiveTest::Allocations).await
}

#[tokio::test]
#[ignore = "requires an explicitly configured disposable Incus 7.0.x node"]
async fn live_incus_backup_transfer_and_limits() -> anyhow::Result<()> {
    live_incus_lifecycle(LiveTest::Transfer).await
}

#[derive(Clone, Copy)]
enum LiveTest {
    Console,
    Allocations,
    Transfer,
}

async fn live_incus_lifecycle(case: LiveTest) -> anyhow::Result<()> {
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
        if matches!(case, LiveTest::Transfer) {
            executor.prepare_data_mount(&server).await?;
            return live_backup_and_transfer(&server, &executor, &temp, !quota.is_empty()).await;
        }
        let (handle, _status) = executor.setup_server_process(&server).await?;
        eprintln!("Live resources: project={project} instance={}", IncusExecutor::name(server.uuid));

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

        ensure!(std::fs::read_to_string(read_write.join("result"))? == "mount-ok", "writable extra mount failed");
        ensure!(!read_only.join("forbidden").exists(), "read-only extra mount changed");

        if !quota.is_empty() {
            ensure!(std::fs::read_to_string(server.filesystem.base_path.join("quota-result"))? == "quota-ok", "data quota did not reject an over-limit guest write");

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

        if matches!(case, LiveTest::Console) {
            let settle: u64 = std::env::var("INCUS_TEST_CONSOLE_SETTLE_SECONDS")
                .unwrap_or_else(|_| "0".into()).parse()?;
            ensure!(settle <= 60, "test console settling delay must be at most 60 seconds");
            tokio::time::sleep(Duration::from_secs(settle)).await;
            reattached.stop().await?;
            let exit = tokio::time::timeout(Duration::from_secs(60), async {
                while let Some(status) = status.recv().await {
                    if let crate::server::executor::ProcessStatus::Stopped { exit_code, .. } = status {
                        return Ok::<_, anyhow::Error>(exit_code);
                    }
                }
                anyhow::bail!("process status ended without exit")
            })
            .await??;
            ensure!(exit == 7, "game exit code was not preserved");

        } else {
            reattached.kill().await?;
            let _ = wait_live_exit(&mut status).await?;

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

        ensure!(
            tokio::fs::read_to_string(server.filesystem.base_path.join("scripted")).await?
                == "scripted",
            "script data did not persist"
        );

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

async fn wait_live_exit(
    status: &mut crate::server::executor::StatusReceiver,
) -> anyhow::Result<i32> {
    tokio::time::timeout(Duration::from_secs(30), async {
        while let Some(status) = status.recv().await {
            if let crate::server::executor::ProcessStatus::Stopped { exit_code, .. } = status {
                return Ok(exit_code);
            }
        }
        anyhow::bail!("process status ended without exit")
    })
    .await?
}
