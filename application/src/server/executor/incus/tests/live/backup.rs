use super::*;

pub(super) async fn live_backup_and_transfer(
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
