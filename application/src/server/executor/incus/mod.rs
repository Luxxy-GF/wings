//! Incus 7.0 LTS OCI/LXC runtime. Docker is not used by this backend.
mod client;
mod image;
mod network;
mod process;
mod storage;
#[cfg(test)]
mod tests;

use super::{ProcessHandle, ServerExecutor, StatusReceiver, UsedPort};
use crate::server::{
    Server,
    configuration::ServerConfiguration,
    firewall::{FirewallBackend, FirewallServerSpec},
};
use anyhow::{Context, ensure};
use client::{Client, segment};
use reqwest::Method;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use storage::Storage;

#[derive(Clone, Debug, Deserialize)]
pub struct Instance {
    pub name: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub config: BTreeMap<String, String>,
    #[serde(default)]
    pub devices: BTreeMap<String, BTreeMap<String, String>>,
}
#[derive(Clone, Debug, Deserialize)]
pub struct InstanceState {
    pub status: String,
    #[serde(default)]
    pub pid: i64,
    #[serde(default, deserialize_with = "crate::deserialize::deserialize_nullable")]
    pub cpu: BTreeMap<String, u64>,
    #[serde(default, deserialize_with = "crate::deserialize::deserialize_nullable")]
    pub memory: BTreeMap<String, u64>,
    #[serde(default, deserialize_with = "crate::deserialize::deserialize_nullable")]
    pub network: BTreeMap<String, Value>,
    #[serde(default)]
    pub started_at: Option<String>,
}

#[derive(Clone)]
pub struct IncusExecutor {
    pub config: Arc<crate::config::Config>,
    client: Client,
    images: Arc<image::Images>,
    network: Arc<network::Network>,
    storage: Arc<Storage>,
    firewall: Arc<dyn FirewallBackend>,
    provisioning: Arc<tokio::sync::Mutex<()>>,
    owner: String,
}
impl IncusExecutor {
    pub fn new(config: Arc<crate::config::Config>) -> anyhow::Result<Self> {
        let client = Client::new(&config.load().runtime.incus)?;
        let owner = format!("wings:{}", config.load().uuid);
        let firewall: Arc<dyn FirewallBackend> = match config.load().docker.firewall.backend {
            crate::server::firewall::FirewallBackendKind::Disabled => {
                Arc::new(crate::server::firewall::noop::NoopFirewall::new(false))
            }
            crate::server::firewall::FirewallBackendKind::Auto
            | crate::server::firewall::FirewallBackendKind::Nftables => {
                Arc::new(crate::server::firewall::nftables::NftablesFirewall::new(
                    Vec::new(),
                    crate::server::firewall::runner::CommandRunner::Local,
                    crate::server::firewall::sets::SourceFileLimits::from_config(&config),
                ))
            }
            _ => anyhow::bail!(
                "Incus requires the host nftables firewall backend or explicitly disabled policy"
            ),
        };
        Ok(Self {
            images: Arc::new(image::Images::new(Arc::clone(&config), client.clone())),
            network: Arc::new(network::Network::new(
                client.clone(),
                &config.load().runtime.incus,
                config.load().uuid,
            )),
            storage: Arc::new(Storage::new(client.clone(), Arc::clone(&config))),
            config,
            client,
            firewall,
            owner,
            provisioning: Arc::new(tokio::sync::Mutex::new(())),
        })
    }
    pub fn state_root(&self) -> PathBuf {
        self.config
            .resolve_as_path(|cfg| &cfg.system.root_directory)
            .join("incus")
    }
    fn name(uuid: uuid::Uuid) -> String {
        format!("wgs-{uuid}")
    }
    fn instance_path(name: &str) -> String {
        format!("/1.0/instances/{}", segment(name))
    }
    fn check_owner(&self, instance: &Instance) -> anyhow::Result<()> {
        ensure!(
            instance.config.get("user.wings.owner") == Some(&self.owner),
            "refusing unmanaged Incus instance {}",
            instance.name
        );
        Ok(())
    }
    async fn instance(&self, name: &str) -> anyhow::Result<Instance> {
        let instance = self
            .client
            .get::<Instance>(&Self::instance_path(name))
            .await?;
        self.check_owner(&instance)?;
        Ok(instance)
    }
    pub async fn remove_instance(&self, name: &str) -> anyhow::Result<()> {
        let deadline = tokio::time::Instant::now()
            + Duration::from_secs(self.config.load().runtime.incus.operation_timeout_seconds);
        while let Some(instance) = self
            .client
            .optional::<Instance>(&Self::instance_path(name))
            .await?
        {
            self.check_owner(&instance)?;
            if instance.status != "Stopped" {
                self.client.state(name, "stop", true).await?;
            }
            let deletion = self
                .client
                .mutate(Method::DELETE, &Self::instance_path(name), json!({}))
                .await;
            match deletion {
                Ok(_) => break,
                Err(error) if client::is_status(&error, reqwest::StatusCode::NOT_FOUND) => break,
                Err(error)
                    if error
                        .downcast_ref::<client::ApiError>()
                        .is_some_and(|error| {
                            error.status == reqwest::StatusCode::BAD_REQUEST
                                && error.message == "Instance is running"
                        })
                        && tokio::time::Instant::now() < deadline =>
                {
                    // A fast OCI job can report Stopped while its shutdown hook
                    // still holds the native instance. Wait for deletion to be valid.
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                Err(error) => return Err(error),
            }
        }
        self.storage
            .delete_volume(&Storage::control_name(name))
            .await?;
        if name.starts_with("wgx-") {
            let staging = self.state_root().join("scripts").join(name);
            if tokio::fs::try_exists(&staging).await? {
                tokio::fs::remove_dir_all(staging).await?;
            }
        }
        Ok(())
    }
    fn validate_server(config: &ServerConfiguration) -> anyhow::Result<()> {
        ensure!(
            !config.allocations.force_outgoing_ip,
            "Incus force_outgoing_ip requires an explicit SNAT design; unsupported"
        );
        ensure!(
            !config.build.oom_disabled,
            "Incus does not support disabling the OOM killer"
        );
        ensure!(
            config.devices.is_empty()
                && !config.container.kvm_passthrough_enabled
                && !config.container.hugepages_passthrough_enabled,
            "Incus device passthrough is not implemented"
        );
        ensure!(
            config.container.seccomp.remove_allowed.is_empty(),
            "Incus custom seccomp policy is not implemented"
        );
        if let Some(weight) = config.build.io_weight {
            ensure!(
                weight == 10 || ((100..=1000).contains(&weight) && weight.is_multiple_of(100)),
                "Incus I/O weight must be 10 or a multiple of 100 through 1000"
            );
        }
        ensure!(
            config.features.startup_cpu_boost.is_none()
                && config.features.runtime_cpu_boost.is_none(),
            "Incus CPU boost configuration is not implemented"
        );
        Ok(())
    }
    fn resources(
        &self,
        config: &ServerConfiguration,
        installer: bool,
    ) -> anyhow::Result<BTreeMap<String, String>> {
        let mut result = BTreeMap::new();
        let cfg = self.config.load();
        let memory = if installer {
            cfg.docker.installer_limits.memory.as_mib() as i64
        } else if config.build.memory_limit <= 0 {
            0
        } else {
            config
                .build
                .memory_limit
                .saturating_add(config.build.overhead_memory)
                .max(0)
        };
        let cpu = if installer {
            cfg.docker.installer_limits.cpu as i64
        } else {
            config.build.cpu_limit
        };
        if memory > 0 {
            result.insert("limits.memory".into(), format!("{memory}MiB"));
        }
        if cpu > 0 {
            result.insert("limits.cpu.allowance".into(), format!("{cpu}ms/100ms"));
        }
        if !installer && let Some(threads) = config.build.threads.as_ref() {
            ensure!(
                threads
                    .bytes()
                    .all(|b| b.is_ascii_digit() || matches!(b, b',' | b'-')),
                "invalid CPU pinning list"
            );
            result.insert("limits.cpu".into(), threads.to_string());
        }
        if !installer && let Some(weight) = config.build.io_weight {
            result.insert("limits.disk.priority".into(), (weight / 100).to_string());
        }
        if cfg.docker.container_pid_limit > 0 {
            result.insert(
                "limits.processes".into(),
                cfg.docker.container_pid_limit.to_string(),
            );
        }
        if !installer {
            result.insert(
                "limits.memory.swap".into(),
                match config.build.swap {
                    0 => "false".into(),
                    -1 => "true".into(),
                    value if value > 0 => format!("{value}MiB"),
                    _ => anyhow::bail!("invalid swap limit"),
                },
            );
        }
        Ok(result)
    }
    fn process_config(
        &self,
        config: &ServerConfiguration,
        image: &image::Image,
        installer: bool,
        command: Option<Vec<String>>,
    ) -> anyhow::Result<BTreeMap<String, String>> {
        let mut result = self.resources(config, installer)?;
        let args = match command {
            Some(command) => command,
            None => match config.entrypoint.as_ref() {
                Some(entrypoint) => {
                    let mut args = entrypoint.clone();
                    args.extend(image.cmd.clone());
                    args
                }
                None => image.args.clone(),
            },
        };
        let mut supervised = vec![
            "/bin/sh".into(),
            "-c".into(),
            process::SUPERVISOR.into(),
            "wings-supervisor".into(),
        ];
        supervised.extend(args);
        result.insert(
            "user.wings.launch".into(),
            process::launch_script(&supervised)?,
        );
        result.insert(
            "oci.entrypoint".into(),
            process::encode_argv(&["/bin/sh".into(), "/opt/wings-control/process/launch".into()])?,
        );
        result.insert(
            "oci.cwd".into(),
            if installer {
                "/mnt/server"
            } else {
                "/home/container"
            }
            .into(),
        );
        // Read the user from Incus's converted OCI spec, preserving its resolution.
        // Helpers run as container root, matching the installer/script role in PR #34.
        result.insert(
            "oci.uid".into(),
            if installer { 0 } else { image.uid }.to_string(),
        );
        result.insert(
            "oci.gid".into(),
            if installer { 0 } else { image.gid }.to_string(),
        );
        result.insert("security.privileged".into(), "false".into());
        result.insert("security.nesting".into(), "false".into());
        result.insert("security.idmap.isolated".into(), "true".into());
        result.insert("security.guestapi".into(), "false".into());
        result.insert("boot.autostart".into(), "false".into());
        for (key, value) in &image.environment {
            result.insert(format!("environment.{key}"), value.clone());
        }
        for entry in config.environment(&self.config) {
            let (key, value) = entry.split_once('=').context("invalid environment entry")?;
            result.insert(format!("environment.{key}"), value.into());
        }
        Ok(result)
    }
    async fn create(
        &self,
        server: &Server,
        name: &str,
        image: &image::Image,
        command: Option<Vec<String>>,
        installer: bool,
        extra_env: &HashMap<compact_str::CompactString, Value>,
    ) -> anyhow::Result<()> {
        let _guard = self.provisioning.lock().await;
        let cfg = server.configuration.read().await;
        Self::validate_server(&cfg)?;
        let runtime = self.config.load().runtime.incus.clone();
        if !installer {
            self.network.sync(server.uuid, "", &BTreeMap::new()).await?;
        }
        if let Some(existing) = self
            .client
            .optional::<Instance>(&Self::instance_path(name))
            .await?
        {
            self.check_owner(&existing)?;
            ensure!(
                existing.status == "Stopped",
                "server instance is already running"
            );
            self.remove_instance(name).await?;
        }
        let instances: Vec<Instance> = self.client.get("/1.0/instances?recursion=1").await?;
        let address = self.network.allocate(&instances).await?;
        let control = Storage::control_name(name);
        self.storage
            .ensure_volume(&control, 16 * 1024 * 1024)
            .await?;
        let mut config = self.process_config(&cfg, image, installer, command)?;
        config.extend(BTreeMap::from([
            ("user.wings.owner".into(), self.owner.clone()),
            ("user.wings.server".into(), server.uuid.to_string()),
            ("user.wings.ip".into(), address.to_string()),
            ("user.wings.digest".into(), image.digest.clone()),
            (
                "user.wings.image-env".into(),
                serde_json::to_string(&image.environment)?,
            ),
            (
                "user.wings.allocations".into(),
                serde_json::to_string(&network::allocations(&cfg, &runtime.listen_addresses)?)?,
            ),
        ]));
        for (key, value) in extra_env {
            config.insert(
                format!("environment.{key}"),
                value
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| value.to_string()),
            );
        }
        let data_source = server.filesystem.get_base_fs_mount_path().await;
        ensure!(
            data_source.is_absolute() && data_source.is_dir(),
            "Wings server directory must be initialized before creating an Incus instance"
        );
        let mut devices = json!({
            "root": {"type": "disk", "path": "/", "pool": runtime.storage_pool, "size": runtime.root_disk_size},
            "eth0": {"type": "nic", "network": runtime.network, "name": "eth0", "ipv4.address": address.to_string(), "security.mac_filtering": "true", "security.ipv4_filtering": "true", "security.port_isolation": "true"},
            "data": {"type": "disk", "source": data_source, "path": if installer {"/mnt/server"} else {"/home/container"}},
            "control": {"type": "disk", "pool": runtime.storage_pool, "source": control, "path": "/opt/wings-control"}
        });
        if !installer {
            cfg.ensure_vmounts(&self.config).await?;
            for (index, mount) in cfg
                .mounts(&self.config, &server.filesystem)
                .await
                .into_iter()
                .filter(|mount| mount.target != "/home/container")
                .enumerate()
            {
                // All extra paths still pass Wings's existing administrator allowlist.
                let source = std::path::Path::new(mount.source.as_str());
                ensure!(
                    source.is_absolute() && source.exists(),
                    "Incus mount source is missing"
                );
                let device = serde_json::Map::from_iter([
                    ("type".into(), "disk".into()),
                    ("source".into(), mount.source.to_string().into()),
                    ("path".into(), mount.target.to_string().into()),
                    ("readonly".into(), mount.read_only.to_string().into()),
                ]);
                devices
                    .as_object_mut()
                    .ok_or_else(|| anyhow::anyhow!("invalid Incus devices"))?
                    .insert(format!("mount-{index}"), Value::Object(device));
            }
        }
        self.client.mutate(Method::POST, "/1.0/instances", json!({"name": name, "type": "container", "profiles": [], "source": {"type": "image", "fingerprint": image.fingerprint}, "config": config, "devices": devices})).await?;
        let (value, etag) = self
            .client
            .request(Method::GET, &Self::instance_path(name), None, None, true)
            .await?;
        let mut instance: Instance = serde_json::from_value(value)?;
        self.check_owner(&instance)?;
        let uid: u32 = instance
            .config
            .get("oci.uid")
            .context("Incus did not resolve the OCI UID")?
            .parse()?;
        let gid: u32 = instance
            .config
            .get("oci.gid")
            .context("Incus did not resolve the OCI GID")?
            .parse()?;
        // Incus has no PVE mpN per-mount ID-map syntax. Map the Wings data account
        // into this unprivileged instance at the image's UID/GID instead.
        instance.config.insert(
            "raw.idmap".into(),
            format!(
                "uid {} {uid}\ngid {} {gid}",
                self.config.load().system.user.uid,
                self.config.load().system.user.gid
            ),
        );
        self.client.request(Method::PUT, &Self::instance_path(name), Some(&json!({"config": instance.config, "devices": instance.devices, "profiles": []})), etag.as_deref(), true).await?;
        // Incus ignores ownership/mode for an existing directory, including the
        // volume root. A new private child gets the image user and mode applied.
        self.client
            .directory(
                &self.storage.file_path(&control, "process"),
                uid,
                gid,
                "0700",
            )
            .await?;
        self.client
            .write_file(
                &self.storage.file_path(&control, "process/launch"),
                instance
                    .config
                    .get("user.wings.launch")
                    .context("OCI launch script missing")?
                    .as_bytes()
                    .to_vec(),
                uid,
                gid,
                "0600",
            )
            .await?;
        self.client
            .write_file(
                &self.storage.file_path(&control, "process/exit"),
                Vec::new(),
                uid,
                gid,
                "0600",
            )
            .await?;
        drop(cfg);
        drop(_guard);
        if !installer {
            self.sync_server(server, name).await?;
        }
        Ok(())
    }
    async fn sync_server(
        &self,
        server: &Arc<crate::server::InnerServer>,
        name: &str,
    ) -> anyhow::Result<()> {
        let _guard = self.provisioning.lock().await;
        let cfg = server.configuration.read().await;
        Self::validate_server(&cfg)?;
        let runtime = self.config.load().runtime.incus.clone();
        let (value, etag) = self
            .client
            .request(Method::GET, &Self::instance_path(name), None, None, true)
            .await?;
        let mut instance: Instance = serde_json::from_value(value)?;
        self.check_owner(&instance)?;
        let image_environment: BTreeMap<String, String> = serde_json::from_str(
            instance
                .config
                .get("user.wings.image-env")
                .context("OCI environment metadata missing; recreate this stopped instance")?,
        )?;
        instance
            .config
            .retain(|key, _| !key.starts_with("environment.") && !key.starts_with("limits."));
        for (key, value) in image_environment {
            instance.config.insert(format!("environment.{key}"), value);
        }
        instance.config.extend(self.resources(&cfg, false)?);
        for entry in cfg.environment(&self.config) {
            let (key, value) = entry.split_once('=').context("invalid environment")?;
            instance
                .config
                .insert(format!("environment.{key}"), value.into());
        }
        instance.config.insert(
            "user.wings.allocations".into(),
            serde_json::to_string(&network::allocations(&cfg, &runtime.listen_addresses)?)?,
        );
        let ip: IpAddr = instance
            .config
            .get("user.wings.ip")
            .context("instance address missing")?
            .parse()?;
        let mut spec = firewall_spec(&cfg, ip, &runtime.listen_addresses)?;
        spec.files = Some(crate::server::firewall::sets::FirewallFileAccess {
            filesystem: (*server.filesystem).clone(),
            notifier: Some(server.filesystem.server_notifier().clone()),
            server: Some(Arc::downgrade(server)),
        });
        self.firewall.sync(&spec).await?;
        let body = json!({"config": instance.config, "devices": instance.devices, "profiles": []});
        self.client
            .request(
                Method::PUT,
                &Self::instance_path(name),
                Some(&body),
                etag.as_deref(),
                true,
            )
            .await?;
        if instance.status == "Running" {
            self.publish(name).await?;
        }
        Ok(())
    }
    async fn publish(&self, name: &str) -> anyhow::Result<()> {
        let instance = self.instance(name).await?;
        let uuid: uuid::Uuid = instance
            .config
            .get("user.wings.server")
            .context("instance server missing")?
            .parse()?;
        let ip = instance
            .config
            .get("user.wings.ip")
            .context("instance address missing")?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let state: InstanceState = self
                .client
                .get(&format!("{}/state", Self::instance_path(name)))
                .await?;
            let actual = state
                .network
                .get("eth0")
                .and_then(|nic| nic.get("addresses"))
                .and_then(Value::as_array);
            if actual.is_some_and(|addresses| {
                addresses
                    .iter()
                    .any(|address| address.get("address").and_then(Value::as_str) == Some(ip))
            }) {
                break;
            }
            ensure!(
                state.status == "Running",
                "OCI process exited before network publication"
            );
            ensure!(
                tokio::time::Instant::now() < deadline,
                "Incus instance did not acquire its reserved address"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let desired: BTreeMap<IpAddr, BTreeSet<u16>> = serde_json::from_str(
            instance
                .config
                .get("user.wings.allocations")
                .context("allocation journal missing")?,
        )?;
        self.network.sync(uuid, ip, &desired).await
    }
    async fn setup_helper(
        &self,
        server: &Server,
        script: &crate::server::installation::InstallationScript,
        installation: bool,
    ) -> anyhow::Result<(Arc<dyn ProcessHandle>, StatusReceiver)> {
        let image = self.images.ensure(&script.container_image).await?;
        let name = if installation {
            format!("wgi-{}", server.uuid)
        } else {
            // Instance names are DNS labels (63 characters maximum); leave room
            // for the associated control-volume prefix too.
            let identity = uuid::Uuid::new_v4().simple().to_string();
            format!(
                "wgx-{}-{}",
                server.uuid,
                identity.get(..16).context("helper ID")?
            )
        };
        let staging = if installation {
            self.config.tmp_data_path(server.uuid)
        } else {
            self.state_root().join("scripts").join(&name)
        };
        tokio::fs::create_dir_all(&staging).await?;
        // Existing installation monitoring reads these host-side paths. Stage through an ID-mapped
        // disk device; the script is written into the staging directory before startup.
        if installation {
            for filename in [
                crate::server::installation::INSTALL_STATUS_FILE_NAME,
                crate::server::installation::INSTALL_PROGRESS_FILE_NAME,
            ] {
                tokio::fs::write(staging.join(filename), []).await?;
            }
        }
        let target = if installation {
            "/mnt/install"
        } else {
            "/mnt/script"
        };
        let filename = if installation {
            "install.sh"
        } else {
            "script.sh"
        };
        let mut env = script.environment.clone();
        if installation {
            env.insert(
                "INSTALL_STATUS_FILE".into(),
                Value::String(format!(
                    "{target}/{}",
                    crate::server::installation::INSTALL_STATUS_FILE_NAME
                )),
            );
            env.insert(
                "INSTALL_PROGRESS_FILE".into(),
                Value::String(format!(
                    "{target}/{}",
                    crate::server::installation::INSTALL_PROGRESS_FILE_NAME
                )),
            );
        }
        self.create(
            server,
            &name,
            &image,
            Some(vec![
                script.entrypoint.to_string(),
                format!("{target}/{filename}"),
            ]),
            true,
            &env,
        )
        .await?;
        let (value, etag) = self
            .client
            .request(Method::GET, &Self::instance_path(&name), None, None, true)
            .await?;
        let mut instance: Instance = serde_json::from_value(value)?;
        instance.devices.insert(
            "staging".into(),
            BTreeMap::from([
                ("type".into(), "disk".into()),
                ("source".into(), staging.display().to_string()),
                ("path".into(), target.into()),
                ("shift".into(), "true".into()),
            ]),
        );
        self.client.request(Method::PUT, &Self::instance_path(&name), Some(&json!({"config": instance.config, "devices": instance.devices, "profiles": []})), etag.as_deref(), true).await?;
        tokio::fs::write(staging.join(filename), script.script.replace("\r\n", "\n")).await?;
        process::Handle::connect(self.clone(), server, name, false, false).await
    }
}

pub fn verify_version(version: &str, extensions: &[String]) -> anyhow::Result<()> {
    let release = version
        .split_once('-')
        .map_or(version, |(release, _)| release);
    let mut parts = release.split('.');
    ensure!(
        parts.next() == Some("7") && parts.next() == Some("0"),
        "Incus 7.0 LTS is required; daemon reports {version}"
    );
    let patch = parts.next().and_then(|patch| patch.parse::<u64>().ok());
    ensure!(
        patch.is_some_and(|patch| patch >= 1) && parts.next().is_none(),
        "Incus 7.0.1 or a newer 7.0 LTS maintenance release is required; daemon reports {version}"
    );
    for required in [
        "instance_oci",
        "instance_oci_entrypoint",
        "oci_network_config",
        "network_forward",
        "file_storage_volume",
    ] {
        ensure!(
            extensions.iter().any(|extension| extension == required),
            "Incus daemon is missing API extension {required}"
        );
    }
    Ok(())
}

fn firewall_spec(
    config: &ServerConfiguration,
    private: IpAddr,
    listen: &[IpAddr],
) -> anyhow::Result<FirewallServerSpec> {
    let mappings = network::allocations(config, listen)?;
    Ok(FirewallServerSpec {
        server: config.uuid,
        bindings: mappings
            .iter()
            .flat_map(|(ip, ports)| {
                ports
                    .iter()
                    .map(|port| crate::server::firewall::FirewallBinding {
                        ip: Some(*ip),
                        port: *port,
                    })
            })
            .collect(),
        container_ports: mappings
            .values()
            .flatten()
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        container_ips: vec![private],
        rules: config.firewall.clone(),
        files: None,
    })
}

#[async_trait::async_trait]
impl ServerExecutor for IncusExecutor {
    async fn boot(&self) -> anyhow::Result<()> {
        let runtime = self.config.load().runtime.incus.clone();
        ensure!(
            rustix::process::geteuid().as_raw() == 0,
            "the current Incus OCI importer requires a root Wings service"
        );
        ensure!(
            runtime.network.len() <= 15
                && !runtime.network.is_empty()
                && runtime
                    .network
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')),
            "invalid Incus bridge name"
        );
        ensure!(
            !self.config.load().docker.startup_boost.enabled
                && !self.config.load().docker.runtime_boost.enabled,
            "Incus CPU boosts are not implemented; disable node CPU boosts"
        );
        ensure!(
            self.config.load().system.user.uid != 0 && self.config.load().system.user.gid != 0,
            "Incus requires a non-root Wings data UID/GID for the host bind mount"
        );
        ensure!(
            !self.config.load().uuid.is_nil(),
            "Incus requires a persistent non-nil Wings node UUID"
        );
        ensure!(
            runtime.max_concurrent_imports > 0
                && runtime.operation_timeout_seconds > 0
                && runtime.image_import_timeout_seconds > 0,
            "Incus timeouts and concurrency must be positive"
        );
        ensure!(
            runtime.project != "default" && !runtime.project.is_empty(),
            "use a dedicated Incus project"
        );
        ensure!(
            !self.config.load().system.user.rootless.enabled,
            "Docker rootless settings do not apply to Incus"
        );
        let (server, _) = self
            .client
            .request(Method::GET, "/1.0", None, None, false)
            .await?;
        let version = server
            .pointer("/environment/server_version")
            .and_then(Value::as_str)
            .context("Incus server version missing")?;
        let extensions: Vec<String> = serde_json::from_value(
            server
                .get("api_extensions")
                .cloned()
                .context("Incus extensions missing")?,
        )?;
        verify_version(version, &extensions)?;
        let path = format!("/1.0/projects/{}", segment(&runtime.project));
        let existing = self
            .client
            .request(Method::GET, &path, None, None, false)
            .await;
        match existing {
            Ok((project, _)) => {
                ensure!(
                    project
                        .pointer("/config/user.wings.owner")
                        .and_then(Value::as_str)
                        == Some(&self.owner),
                    "refusing unmanaged Incus project"
                );
                ensure!(
                    project
                        .pointer("/config/features.networks")
                        .and_then(Value::as_str)
                        == Some("false"),
                    "Incus project must share the default project's managed bridge"
                );
            }
            Err(err) if client::is_status(&err, reqwest::StatusCode::NOT_FOUND) => {
                self.client.request(Method::POST, "/1.0/projects", Some(&json!({"name": runtime.project, "description": self.owner, "config": {"features.images": "true", "features.profiles": "true", "features.storage.volumes": "true", "features.networks": "false", "user.wings.owner": self.owner}})), None, false).await?;
            }
            Err(err) => return Err(err),
        }
        tokio::fs::create_dir_all(self.state_root()).await?;
        self.storage.boot().await?;
        self.images.boot().await?;
        self.network.boot().await?;
        self.firewall.boot().await?;
        Ok(())
    }
    async fn setup_server_process(
        &self,
        server: &Server,
    ) -> anyhow::Result<(Arc<dyn ProcessHandle>, StatusReceiver)> {
        let source = server
            .configuration
            .read()
            .await
            .container
            .image
            .to_string();
        let image = self.images.ensure(&source).await?;
        let name = Self::name(server.uuid);
        self.create(server, &name, &image, None, false, &HashMap::new())
            .await?;
        process::Handle::connect(self.clone(), server, name, false, true).await
    }
    async fn attach_server_process(
        &self,
        server: &Server,
    ) -> anyhow::Result<(Arc<dyn ProcessHandle>, StatusReceiver)> {
        let name = Self::name(server.uuid);
        let instance = self.instance(&name).await?;
        ensure!(
            instance.status == "Running" || instance.status == "Frozen",
            "Incus server is not running"
        );
        self.sync_server(server, &name).await?;
        process::Handle::connect(self.clone(), server, name, true, true).await
    }
    async fn cleanup_server_process(&self, server: &Server) -> anyhow::Result<()> {
        let _guard = self.provisioning.lock().await;
        self.network.sync(server.uuid, "", &BTreeMap::new()).await?;
        self.remove_instance(&Self::name(server.uuid)).await?;
        if server.suspended.load(std::sync::atomic::Ordering::SeqCst) {
            self.cleanup_owned_helpers(server.uuid).await?;
        }
        self.firewall.clear(server.uuid).await?;
        Ok(())
    }
    async fn setup_installation_process(
        &self,
        server: &Server,
        script: &crate::server::installation::InstallationScript,
    ) -> anyhow::Result<(Arc<dyn ProcessHandle>, StatusReceiver)> {
        self.setup_helper(server, script, true).await
    }
    async fn attach_installation_process(
        &self,
        server: &Server,
    ) -> anyhow::Result<(Arc<dyn ProcessHandle>, StatusReceiver)> {
        let name = format!("wgi-{}", server.uuid);
        self.instance(&name).await?;
        process::Handle::connect(self.clone(), server, name, true, false).await
    }
    async fn cleanup_installation_process(&self, server: &Server) -> anyhow::Result<()> {
        self.remove_instance(&format!("wgi-{}", server.uuid)).await
    }
    async fn setup_script_process(
        &self,
        server: &Server,
        script: &crate::server::installation::InstallationScript,
    ) -> anyhow::Result<(Arc<dyn ProcessHandle>, StatusReceiver)> {
        self.setup_helper(server, script, false).await
    }
    async fn resolve_internal_target(
        &self,
        server: &Server,
        port: u16,
    ) -> anyhow::Result<Option<SocketAddr>> {
        let instance = self.instance(&Self::name(server.uuid)).await?;
        ensure!(
            instance.status == "Running",
            "Incus target instance is not running"
        );
        Ok(Some(SocketAddr::new(
            instance
                .config
                .get("user.wings.ip")
                .context("instance address missing")?
                .parse()?,
            port,
        )))
    }
    async fn resolve_published_address(&self, server: &Server) -> Option<IpAddr> {
        let cfg = server.configuration.read().await;
        let address: IpAddr = cfg.allocations.default.as_ref()?.ip.parse().ok()?;
        if address.is_unspecified() {
            self.config
                .load()
                .runtime
                .incus
                .listen_addresses
                .iter()
                .copied()
                .find(|candidate| candidate.is_ipv4() == address.is_ipv4())
        } else {
            Some(address)
        }
    }
    async fn container_refs(&self, servers: &[Server]) -> HashMap<uuid::Uuid, String> {
        let mut result = HashMap::new();
        for server in servers {
            let name = Self::name(server.uuid);
            if self.instance(&name).await.is_ok()
                && let Ok(state) = self
                    .client
                    .get::<InstanceState>(&format!("{}/state", Self::instance_path(&name)))
                    .await
                && state.pid > 0
            {
                result.insert(server.uuid, format!("pid:{}", state.pid));
            }
        }
        result
    }
    async fn used_ports(&self, ips: &[IpAddr]) -> anyhow::Result<HashMap<IpAddr, Vec<UsedPort>>> {
        self.network.used_ports(ips).await
    }
    async fn reconcile_firewall(
        &self,
        servers: &[crate::remote::servers::RawServer],
    ) -> anyhow::Result<()> {
        let instances: Vec<Instance> = self.client.get("/1.0/instances?recursion=1").await?;
        let live: BTreeSet<_> = servers.iter().map(|server| server.settings.uuid).collect();
        let mut specs = Vec::new();
        for instance in instances {
            if instance.config.get("user.wings.owner") != Some(&self.owner) {
                continue;
            }
            let Some(uuid) = instance
                .config
                .get("user.wings.server")
                .and_then(|uuid| uuid.parse::<uuid::Uuid>().ok())
            else {
                continue;
            };
            if !live.contains(&uuid) {
                // Clear orphan publication without deleting its recoverable data or running process.
                self.network.sync(uuid, "", &BTreeMap::new()).await?;
                continue;
            }
            if !instance.name.starts_with("wgs-") {
                continue;
            }
            let raw = servers
                .iter()
                .find(|server| server.settings.uuid == uuid)
                .context("server reconciliation mismatch")?;
            let ip: IpAddr = instance
                .config
                .get("user.wings.ip")
                .context("instance address missing")?
                .parse()?;
            let mut spec = firewall_spec(
                &raw.settings,
                ip,
                &self.config.load().runtime.incus.listen_addresses,
            )?;
            if spec.references_files() {
                spec.files = Some(crate::server::firewall::sets::FirewallFileAccess {
                    filesystem: crate::server::filesystem::cap::CapFilesystem::new(
                        &self.config.data_path(uuid),
                    )
                    .await?,
                    notifier: None,
                    server: None,
                });
            }
            specs.push(spec);
        }
        self.firewall.reconcile(&specs).await
    }
}
impl IncusExecutor {
    async fn cleanup_owned_helpers(&self, uuid: uuid::Uuid) -> anyhow::Result<()> {
        let instances: Vec<Instance> = self.client.get("/1.0/instances?recursion=1").await?;
        for instance in instances {
            if instance.config.get("user.wings.owner") == Some(&self.owner)
                && instance.config.get("user.wings.server") == Some(&uuid.to_string())
            {
                self.remove_instance(&instance.name).await?;
            }
        }
        Ok(())
    }
}
