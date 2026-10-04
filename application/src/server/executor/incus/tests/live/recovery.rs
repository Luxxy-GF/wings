use super::*;

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
                if let Ok(stream) = tokio::net::TcpStream::connect(address).await {
                    return stream;
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        })
        .await
        .context("Wings did not restart the saved running server")?;
        let mut reply = [0; 6];
        stream.read_exact(&mut reply).await?;
        ensure!(
            &reply == b"tcp-ok",
            "TCP allocation failed after node reboot"
        );
        let udp = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        udp.send_to(b"reboot", address).await?;
        tokio::time::timeout(Duration::from_secs(10), udp.recv_from(&mut reply)).await??;
        ensure!(
            &reply == b"udp-ok",
            "UDP allocation failed after node reboot"
        );
        let (handle, mut status) = executor.attach_server_process(&server).await?;
        handle.kill().await?;
        wait_live_exit(&mut status).await?;
        ensure!(
            std::fs::read_to_string(server.filesystem.base_path.join("persist"))? == "volume-data",
            "node reboot lost game data"
        );

        Ok::<_, anyhow::Error>(())
    }
    .await;
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
