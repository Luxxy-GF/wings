use super::client::{Client, segment};
use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Weak},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    sync::{Mutex, RwLock, Semaphore},
};

const HEARTBEAT: Duration = Duration::from_secs(15);

async fn tail(mut stream: impl AsyncRead + Unpin, keep_tail: bool) -> std::io::Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0; 8192];
    loop {
        let count = stream.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        output.extend_from_slice(buffer.get(..count).unwrap_or_default());
        if output.len() > 65536 {
            if !keep_tail {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "subprocess stdout exceeded 64 KiB",
                ));
            }
            output.drain(..output.len() - 65536);
        }
    }
    Ok(output)
}

fn report_progress(server: &crate::server::Server, installation: bool, message: &str) {
    let message = format!("[Incus image] {message}");
    if installation {
        server.log_daemon_install(message.into());
    } else {
        server.log_daemon_with_prelude(&message);
    }
}

async fn read_stdout(
    mut stream: impl AsyncRead + Unpin,
    progress: Option<(&crate::server::Server, bool)>,
) -> std::io::Result<Vec<u8>> {
    let Some((server, installation)) = progress else {
        return tail(stream, false).await;
    };
    let mut line = Vec::new();
    let mut previous = String::new();
    let mut last = tokio::time::Instant::now() - Duration::from_secs(1);
    let mut buffer = [0; 8192];
    let started = tokio::time::Instant::now();
    let mut heartbeat = tokio::time::interval(HEARTBEAT);
    heartbeat.tick().await;
    loop {
        let count = tokio::select! {
            count = stream.read(&mut buffer) => count?,
            _ = heartbeat.tick() => {
                if last.elapsed() >= HEARTBEAT {
                    report_progress(
                        server,
                        installation,
                        &format!(
                            "Image operation still running ({} seconds elapsed)...",
                            started.elapsed().as_secs()
                        ),
                    );
                }
                continue;
            }
        };
        for &byte in buffer.get(..count).unwrap_or_default() {
            if byte == b'\r' || byte == b'\n' {
                let message = String::from_utf8_lossy(&line).trim().to_string();
                if !message.is_empty()
                    && message != previous
                    && last.elapsed() >= Duration::from_secs(1)
                {
                    report_progress(server, installation, &message);
                    previous = message;
                    last = tokio::time::Instant::now();
                }
                line.clear();
            } else if !byte.is_ascii_control() && line.len() < 4096 {
                line.push(byte);
            }
        }
        if count == 0 {
            let message = String::from_utf8_lossy(&line).trim().to_string();
            if !message.is_empty() && message != previous {
                report_progress(server, installation, &message);
            }
            return Ok(Vec::new());
        }
    }
}

pub(super) async fn run(
    executable: &str,
    args: &[String],
    timeout: Duration,
    env: Option<&BTreeMap<String, String>>,
) -> anyhow::Result<Vec<u8>> {
    run_with_progress(executable, args, timeout, env, None).await
}

struct ProcessGroup(Option<rustix::process::Pid>);

impl Drop for ProcessGroup {
    fn drop(&mut self) {
        if let Some(pid) = self.0 {
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        }
    }
}

async fn run_with_progress(
    executable: &str,
    args: &[String],
    timeout: Duration,
    env: Option<&BTreeMap<String, String>>,
    progress: Option<(&crate::server::Server, bool)>,
) -> anyhow::Result<Vec<u8>> {
    let mut command = tokio::process::Command::new(executable);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0);
    if let Some(env) = env {
        command.envs(env);
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("starting {executable}"))?;
    let mut group = ProcessGroup(
        child
            .id()
            .and_then(|id| rustix::process::Pid::from_raw(id as i32)),
    );
    let stdout = child.stdout.take().context("subprocess stdout missing")?;
    let stderr = child.stderr.take().context("subprocess stderr missing")?;
    let result = tokio::time::timeout(timeout, async {
        tokio::try_join!(
            child.wait(),
            read_stdout(stdout, progress),
            tail(stderr, true)
        )
    })
    .await;
    let Ok(result) = result else {
        let _ = child.kill().await;
        anyhow::bail!("{executable} timed out");
    };
    let (status, stdout, stderr) = result?;
    ensure!(
        status.success(),
        "{executable} failed: {}",
        String::from_utf8_lossy(&stderr)
    );
    group.0 = None;
    Ok(stdout)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct Image {
    pub fingerprint: String,
    pub digest: String,
    pub args: Vec<String>,
    #[serde(default)]
    pub cmd: Vec<String>,
    pub environment: BTreeMap<String, String>,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Deserialize)]
struct ImageConfig {
    #[serde(default, rename = "Entrypoint")]
    entrypoint: Option<Vec<String>>,
    #[serde(default, rename = "Cmd")]
    cmd: Option<Vec<String>>,
    #[serde(default, rename = "Env")]
    environment: Option<Vec<String>>,
}

fn converted_user(archive: &Path) -> anyhow::Result<(u32, u32)> {
    use std::io::Read;
    let decoder = flate2::read::GzDecoder::new(std::fs::File::open(archive)?);
    let mut archive = tar::Archive::new(decoder.take(4 * 1024 * 1024));
    for entry in archive.entries()? {
        let mut entry = entry?;
        if entry.path()?.as_ref() != Path::new("config.json") {
            continue;
        }
        ensure!(
            entry.header().entry_type().is_file() && entry.size() <= 65536,
            "converted OCI process configuration is not a bounded regular file"
        );
        let mut content = Vec::new();
        entry.read_to_end(&mut content)?;
        let config: Value = serde_json::from_slice(&content)?;
        let user = config
            .pointer("/process/user")
            .context("converted OCI process user missing")?;
        let uid = u32::try_from(
            user.get("uid")
                .and_then(Value::as_u64)
                .context("OCI UID missing")?,
        )?;
        let gid = u32::try_from(
            user.get("gid")
                .and_then(Value::as_u64)
                .context("OCI GID missing")?,
        )?;
        return Ok((uid, gid));
    }
    anyhow::bail!("Incus export did not contain an OCI process configuration")
}

pub(super) struct Images {
    config: Arc<crate::config::Config>,
    client: Client,
    concurrency: Semaphore,
    locks: Mutex<HashMap<String, Weak<Mutex<()>>>>,
    cache_gate: RwLock<()>,
}

impl Images {
    pub(super) fn new(config: Arc<crate::config::Config>, client: Client) -> Self {
        let concurrency = Semaphore::new(config.load().runtime.incus.max_concurrent_imports);
        Self {
            config,
            client,
            concurrency,
            locks: Mutex::new(HashMap::new()),
            cache_gate: RwLock::new(()),
        }
    }

    fn root(&self) -> PathBuf {
        self.config
            .resolve_as_path(|cfg| &cfg.system.root_directory)
            .join("incus-images")
    }

    pub(super) async fn boot(self: &Arc<Self>) -> anyhow::Result<()> {
        let cfg = self.config.load().runtime.incus.clone();
        for path in [&cfg.incus_path, &cfg.skopeo_path] {
            run(path, &["--version".into()], Duration::from_secs(10), None).await?;
        }
        tokio::fs::create_dir_all(self.root()).await?;
        if let Err(error) = self.cleanup().await {
            tracing::warn!(%error, "Incus image cleanup skipped");
        }
        let images = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
                let Some(images) = images.upgrade() else {
                    break;
                };
                if let Err(error) = images.cleanup().await {
                    tracing::warn!(%error, "Incus image cleanup skipped");
                }
            }
        });
        Ok(())
    }

    pub(super) async fn ensure(
        &self,
        source: &str,
        server: &crate::server::Server,
        installation: bool,
    ) -> anyhow::Result<Image> {
        let _cache_guard = self.cache_gate.read().await;
        report_progress(
            server,
            installation,
            "Checking OCI image manifest and local cache...",
        );
        let cfg = self.config.load().runtime.incus.clone();
        let reference = source.trim_end_matches('~').to_string();
        let lock = self.lock(format!("pull:{reference}")).await;
        let _guard = lock.lock().await;
        let _permit = self.concurrency.acquire().await?;
        let timeout = Duration::from_secs(cfg.image_import_timeout_seconds);
        let (registry, repository) = parse_reference(&reference)?;
        let registries = self.config.load().docker.registries.clone();
        let pull =
            super::auth::PullEnvironment::new(&self.root(), &cfg, &registries, &registry).await?;
        let architecture = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            other => other,
        };
        let inspect: Value = serde_json::from_slice(
            &run(
                &cfg.skopeo_path,
                &[
                    "inspect".into(),
                    "--no-tags".into(),
                    "--override-os".into(),
                    "linux".into(),
                    "--override-arch".into(),
                    architecture.into(),
                    format!("docker://{reference}"),
                ],
                timeout,
                Some(&pull.environment),
            )
            .await?,
        )
        .context("decoding OCI registry inspection")?;
        let digest = inspect
            .get("Digest")
            .and_then(Value::as_str)
            .context("OCI image has no manifest digest")?
            .to_owned();
        ensure!(
            digest.starts_with("sha256:")
                && digest.len() == 71
                && digest
                    .trim_start_matches("sha256:")
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit()),
            "invalid OCI digest"
        );
        let base = repository
            .split('@')
            .next()
            .context("OCI repository missing")?;
        let base = base.rsplit_once(':').map_or(base, |(base, _)| base);
        let pinned = format!("{registry}/{base}@{digest}");
        let cache_key = hex::encode(Sha256::digest(
            format!("{pinned}:{architecture}").as_bytes(),
        ));
        let artifact_lock = self.lock(format!("import:{cache_key}")).await;
        let _artifact_guard = artifact_lock.lock().await;
        let path = self.root().join(format!("{cache_key}.json"));
        if let Ok(data) = tokio::fs::read(&path).await
            && let Ok(image) = serde_json::from_slice::<Image>(&data)
            && self
                .client
                .optional::<Value>(&format!("/1.0/images/{}", segment(&image.fingerprint)))
                .await?
                .is_some()
        {
            report_progress(server, installation, "Using cached Incus image.");
            Self::save(&path, &image).await?;
            return Ok(image);
        }
        let spec: Value = serde_json::from_slice(
            &run(
                &cfg.skopeo_path,
                &[
                    "inspect".into(),
                    "--config".into(),
                    format!("docker://{pinned}"),
                ],
                timeout,
                Some(&pull.environment),
            )
            .await?,
        )
        .context("decoding OCI image configuration")?;
        let process: ImageConfig = serde_json::from_value(
            spec.get("config")
                .cloned()
                .context("OCI image config missing")?,
        )?;
        let environment = process
            .environment
            .unwrap_or_default()
            .iter()
            .map(|entry| {
                let (key, value) = entry
                    .split_once('=')
                    .context("invalid OCI environment entry")?;
                Ok((key.to_owned(), value.to_owned()))
            })
            .collect::<anyhow::Result<BTreeMap<_, _>>>()?;
        let cmd = process.cmd.unwrap_or_default();
        let mut args = process.entrypoint.unwrap_or_default();
        args.extend(cmd.clone());
        ensure!(!args.is_empty(), "OCI image has no entrypoint or command");
        let directory = tempfile::tempdir_in(self.root())?;
        let alias = format!("wings-{}", cache_key.get(..58).context("image cache key")?);
        let archive = directory.path().join("image.tar.gz");
        report_progress(
            server,
            installation,
            "Pulling and converting OCI image with Incus...",
        );
        run_with_progress(
            &cfg.incus_path,
            &[
                "image".into(),
                "export".into(),
                format!("oci:{base}@{digest}"),
                archive.display().to_string(),
            ],
            timeout,
            Some(&pull.environment),
            Some((server, installation)),
        )
        .await?;
        let user_archive = archive.clone();
        let (uid, gid) =
            tokio::task::spawn_blocking(move || converted_user(&user_archive)).await??;
        report_progress(
            server,
            installation,
            "Importing converted image into Incus...",
        );
        let existing: Vec<Value> = self.client.get("/1.0/images?recursion=1").await?;
        run_with_progress(
            &cfg.incus_path,
            &[
                "image".into(),
                "import".into(),
                archive.display().to_string(),
                format!("{}.root", archive.display()),
                "local:".into(),
                "--alias".into(),
                alias.clone(),
                "--project".into(),
                cfg.project.clone(),
            ],
            timeout,
            Some(&pull.environment),
            Some((server, installation)),
        )
        .await?;
        let alias_entry: Value = self
            .client
            .get(&format!("/1.0/images/aliases/{}", segment(&alias)))
            .await?;
        let fingerprint = alias_entry
            .get("target")
            .and_then(Value::as_str)
            .context("Incus import did not create image alias")?
            .to_owned();
        let image = Image {
            fingerprint,
            digest,
            args,
            cmd,
            environment,
            uid,
            gid,
        };
        if !existing.iter().any(|old| {
            old.get("fingerprint").and_then(Value::as_str) == Some(image.fingerprint.as_str())
        }) {
            let image_path = format!("/1.0/images/{}", segment(&image.fingerprint));
            let (mut metadata, etag) = self
                .client
                .request(reqwest::Method::GET, &image_path, None, None, true)
                .await?;
            let properties = metadata
                .get_mut("properties")
                .and_then(Value::as_object_mut)
                .context("Incus image properties missing")?;
            properties.insert(
                "user.wings.owner".into(),
                json!(format!("wings:{}", self.config.load().uuid)),
            );
            properties.insert("user.wings.cache".into(), json!(cache_key));
            self.client
                .request(
                    reqwest::Method::PUT,
                    &image_path,
                    Some(&metadata),
                    etag.as_deref(),
                    true,
                )
                .await?;
        }
        Self::save(&path, &image).await?;
        report_progress(server, installation, "Incus image is ready.");
        Ok(image)
    }

    async fn lock(&self, key: String) -> Arc<Mutex<()>> {
        let mut locks = self.locks.lock().await;
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(Mutex::new(()));
        locks.insert(key, Arc::downgrade(&lock));
        lock
    }

    async fn save(path: &Path, image: &Image) -> anyhow::Result<()> {
        let temporary = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
        tokio::fs::write(&temporary, serde_json::to_vec(image)?).await?;
        tokio::fs::rename(temporary, path).await?;
        Ok(())
    }

    pub(super) async fn cleanup(&self) -> anyhow::Result<usize> {
        let days = self.config.load().runtime.incus.image_cache_retention_days;
        if days == 0 {
            return Ok(0);
        }
        let _guard = self.cache_gate.write().await;
        let instances: Vec<super::Instance> = self.client.get("/1.0/instances?recursion=1").await?;
        let images: Vec<Value> = self.client.get("/1.0/images?recursion=1").await?;
        let owner = format!("wings:{}", self.config.load().uuid);
        let retention = Duration::from_secs(u64::from(days) * 86400);
        let mut entries = tokio::fs::read_dir(self.root()).await?;
        let mut removed = 0;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let Some(key) = path.file_stem().and_then(|key| key.to_str()) else {
                continue;
            };
            if path.extension().and_then(|ext| ext.to_str()) != Some("json")
                || key.len() != 64
                || !key.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                continue;
            }
            let file_metadata = entry.metadata().await?;
            if !file_metadata.is_file()
                || file_metadata.modified()?.elapsed().unwrap_or_default() < retention
            {
                continue;
            }
            let Ok(image) = serde_json::from_slice::<Image>(&tokio::fs::read(&path).await?) else {
                continue;
            };
            let Some(cached) = images.iter().find(|candidate| {
                candidate.get("fingerprint").and_then(Value::as_str)
                    == Some(image.fingerprint.as_str())
            }) else {
                tokio::fs::remove_file(&path).await?;
                continue;
            };
            if !collectible(cached, key, &owner, &instances) {
                continue;
            }
            let current: Vec<super::Instance> =
                self.client.get("/1.0/instances?recursion=1").await?;
            let image_path = format!("/1.0/images/{}", segment(&image.fingerprint));
            let metadata: Value = self.client.get(&image_path).await?;
            if !collectible(&metadata, key, &owner, &current) {
                continue;
            }
            self.client
                .request(reqwest::Method::DELETE, &image_path, None, None, true)
                .await?;
            tokio::fs::remove_file(&path).await?;
            removed += 1;
            tracing::info!(fingerprint = %image.fingerprint, "removed unused Incus image");
        }
        Ok(removed)
    }
}

fn collectible(image: &Value, key: &str, owner: &str, instances: &[super::Instance]) -> bool {
    let Some(fingerprint) = image.get("fingerprint").and_then(Value::as_str) else {
        return false;
    };
    let Some(prefix) = key.get(..58) else {
        return false;
    };
    let expected = format!("wings-{prefix}");
    image
        .pointer("/properties/user.wings.owner")
        .and_then(Value::as_str)
        == Some(owner)
        && image
            .pointer("/properties/user.wings.cache")
            .and_then(Value::as_str)
            == Some(key)
        && image
            .get("aliases")
            .and_then(Value::as_array)
            .is_some_and(|aliases| {
                aliases.iter().all(|alias| {
                    alias.get("name").and_then(Value::as_str) == Some(expected.as_str())
                })
            })
        && !instances.iter().any(|instance| {
            instance
                .config
                .get("volatile.base_image")
                .is_none_or(|base| base == fingerprint)
        })
}

pub(super) fn parse_reference(value: &str) -> anyhow::Result<(String, String)> {
    ensure!(
        !value.contains("://") && !value.chars().any(char::is_whitespace),
        "OCI reference must be a registry reference, not a URL"
    );
    let (first, remainder) = value.split_once('/').unwrap_or((value, ""));
    let explicit = !remainder.is_empty()
        && (first.contains('.') || first.contains(':') || first == "localhost");
    let (registry, repository) = if explicit {
        (first.to_string(), remainder.to_string())
    } else {
        (
            "docker.io".into(),
            if remainder.is_empty() {
                format!("library/{value}")
            } else {
                value.into()
            },
        )
    };
    ensure!(
        !repository.is_empty() && !repository.starts_with('-') && !registry.contains('@'),
        "invalid OCI repository"
    );
    Ok((registry, repository))
}
