use super::{Devices, IncusExecutor, Instance, client::Client, network, process};
use crate::server::{Server, configuration::NativeInstanceType};
use anyhow::{Context, ensure};
use reqwest::Method;
use serde_json::json;
use std::{collections::BTreeMap, path::Path, process::Stdio, time::Duration};

pub(super) struct FileMount {
    _configuration: tempfile::TempDir,
    child: tokio::process::Child,
}

impl IncusExecutor {
    pub(super) async fn ensure_native(&self, server: &Server) -> anyhow::Result<()> {
        let _guard = self.provisioning.lock().await;
        let cfg = server.configuration.read().await;
        Self::validate_server(&cfg)?;
        let native = cfg
            .instance
            .as_ref()
            .context("missing native instance configuration")?;
        ensure!(
            !native.image.is_empty()
                && native.image.len() <= 255
                && !native.image.bytes().any(|byte| byte.is_ascii_control()),
            "invalid OS image alias"
        );
        ensure!(
            cfg.build.disk_space > 0,
            "native instances require a positive disk size"
        );
        if native.kind == NativeInstanceType::VirtualMachine {
            ensure!(
                !self.tundra_enabled && !self.config.load().tundra.enabled,
                "Tundra private networking does not support native VMs; disable Tundra and restart Wings"
            );
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/kvm")
                .context("Incus virtual machines require KVM access on this node")?;
            ensure!(
                cfg.build.memory_limit >= 256,
                "virtual machines require at least 256 MiB of memory"
            );
        }
        let runtime = self.config.load().runtime.incus.clone();
        let remote = reqwest::Url::parse(&runtime.image_server)?;
        ensure!(
            remote.scheme() == "https"
                && remote.username().is_empty()
                && remote.password().is_none(),
            "Incus image server must be an HTTPS URL without embedded credentials"
        );
        let name = Self::name(server.uuid);
        if let Some(instance) = self
            .client
            .optional::<Instance>(&Self::instance_path(&name))
            .await?
        {
            self.check_owner(&instance)?;
            ensure!(
                instance
                    .config
                    .get("user.wings.instance-kind")
                    .map(String::as_str)
                    == Some(native.kind.incus_type()),
                "existing instance type differs from the server configuration"
            );
            ensure!(
                instance.config.get("user.wings.native-image") == Some(&native.image),
                "changing an OS image requires an explicit reinstall"
            );
            return Ok(());
        }
        let instances: Vec<Instance> = self.client.get("/1.0/instances?recursion=1").await?;
        let ip = self.network.allocate(&instances).await?;
        let mut config = self.resources(&cfg, false)?;
        config.extend(BTreeMap::from([
            ("boot.autostart".into(), "false".into()),
            ("user.wings.owner".into(), self.owner.clone()),
            ("user.wings.server".into(), server.uuid.to_string()),
            (
                "user.wings.instance-kind".into(),
                native.kind.incus_type().into(),
            ),
            ("user.wings.native-image".into(), native.image.clone()),
            ("user.wings.ip".into(), ip.to_string()),
            (
                "user.wings.allocations".into(),
                serde_json::to_string(&network::allocations(&cfg)?)?,
            ),
        ]));
        if native.kind == NativeInstanceType::Container {
            config.insert("security.idmap.isolated".into(), "true".into());
        }
        let devices = Devices::from([
            (
                "root".into(),
                BTreeMap::from([
                    ("type".into(), "disk".into()),
                    ("path".into(), "/".into()),
                    ("pool".into(), runtime.native_storage_pool.clone()),
                    ("size".into(), format!("{}MiB", cfg.build.disk_space)),
                ]),
            ),
            (
                "eth0".into(),
                BTreeMap::from([
                    ("type".into(), "nic".into()),
                    ("network".into(), runtime.network.clone()),
                    ("name".into(), "eth0".into()),
                    ("ipv4.address".into(), ip.to_string()),
                    ("security.mac_filtering".into(), "true".into()),
                    ("security.ipv4_filtering".into(), "true".into()),
                    ("security.port_isolation".into(), "true".into()),
                ]),
            ),
        ]);
        let body = json!({"name":name, "type":native.kind.incus_type(), "profiles":[], "config":config, "devices":devices,
            "source":{"type":"image", "mode":"pull", "protocol":"simplestreams", "server":runtime.image_server, "alias":native.image}});
        drop(cfg);
        server.log_daemon_with_prelude(
            "[Incus image] Pulling OS image and creating persistent instance...",
        );
        let mut import_runtime = runtime;
        import_runtime.operation_timeout_seconds = import_runtime.image_import_timeout_seconds;
        let client = Client::new(&import_runtime)?;
        let creation = client.mutate(Method::POST, "/1.0/instances", body);
        tokio::pin!(creation);
        let mut heartbeat = tokio::time::interval(Duration::from_secs(30));
        heartbeat.tick().await;
        loop {
            tokio::select! {
                result = &mut creation => { result?; break; },
                _ = heartbeat.tick() => server.log_daemon_with_prelude("[Incus image] OS image operation is still running..."),
            }
        }
        server.log_daemon_with_prelude("[Incus image] Persistent OS instance is ready.");
        Ok(())
    }

    pub(super) async fn mount_native_files(
        &self,
        server: &std::sync::Arc<crate::server::InnerServer>,
    ) -> anyhow::Result<()> {
        let mut mounts = self.native_mounts.lock().await;
        if let Some(mount) = mounts.get_mut(&server.uuid) {
            if mount.child.try_wait()?.is_none()
                && mounted(&server.filesystem.base_path, &Self::name(server.uuid))?
            {
                return server.filesystem.connect_native_root().await;
            }
            mounts.remove(&server.uuid);
        }
        let name = Self::name(server.uuid);
        let instance = self.instance(&name).await?;
        ensure!(
            instance.config.contains_key("user.wings.instance-kind"),
            "not a native OS instance"
        );
        if mounted(&server.filesystem.base_path, &name)? {
            if tokio::fs::read_dir(&server.filesystem.base_path)
                .await
                .is_ok()
            {
                return server.filesystem.connect_native_root().await;
            }
            server.filesystem.close();
            let status = tokio::process::Command::new("fusermount3")
                .args(["-uz", &server.filesystem.base_path.display().to_string()])
                .status()
                .await?;
            ensure!(
                status.success(),
                "could not detach stale native filesystem mount"
            );
        }
        let mut directory = tokio::fs::read_dir(&server.filesystem.base_path).await?;
        ensure!(
            directory.next_entry().await?.is_none(),
            "native root file mount directory is not empty"
        );
        let settings = self.config.load().runtime.incus.clone();
        let configuration = tempfile::tempdir_in(self.state_root())?;
        let client_config = json!({"default-remote":"local", "remotes":{"local":{"addr":format!("unix://{}", settings.socket), "public":false, "protocol":"incus"}}});
        tokio::fs::write(
            configuration.path().join("config.yml"),
            serde_norway::to_string(&client_config)?,
        )
        .await?;
        let mut command = tokio::process::Command::new(&settings.incus_path);
        command
            .env("INCUS_CONF", configuration.path())
            .env("INCUS_SOCKET", &settings.socket)
            .args([
                "file",
                "mount",
                &format!("{name}/"),
                &server.filesystem.base_path.display().to_string(),
                "--project",
                &settings.project,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        ensure!(
            tokio::process::Command::new("sshfs")
                .arg("--version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .await
                .context("native filesystem access requires sshfs")?
                .success(),
            "sshfs is unavailable"
        );
        let child = command.spawn().context("starting Incus file mount")?;
        let mut mount = FileMount {
            _configuration: configuration,
            child,
        };
        let deadline =
            tokio::time::Instant::now() + Duration::from_secs(settings.operation_timeout_seconds);
        loop {
            if mount.child.try_wait()?.is_some() {
                ensure!(
                    tokio::time::Instant::now() < deadline,
                    "timed out connecting to the guest filesystem; verify the Incus agent is running"
                );
                tokio::time::sleep(Duration::from_secs(1)).await;
                mount.child = command.spawn().context("retrying Incus guest file mount")?;
            }
            if mounted(&server.filesystem.base_path, &name)? {
                server.filesystem.connect_native_root().await?;
                mounts.insert(server.uuid, mount);
                return Ok(());
            }
            ensure!(
                tokio::time::Instant::now() < deadline,
                "timed out connecting to the guest filesystem"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    pub(super) async fn unmount_native_files(
        &self,
        server: &std::sync::Arc<crate::server::InnerServer>,
    ) -> anyhow::Result<()> {
        server.filesystem.close();
        let mut mounts = self.native_mounts.lock().await;
        if mounted(&server.filesystem.base_path, &Self::name(server.uuid))? {
            let status = tokio::process::Command::new("fusermount3")
                .args(["-uz", &server.filesystem.base_path.display().to_string()])
                .status()
                .await?;
            ensure!(
                status.success(),
                "could not unmount native guest filesystem"
            );
        }
        if let Some(mut mount) = mounts.remove(&server.uuid)
            && mount.child.try_wait()?.is_none()
        {
            mount.child.kill().await?;
        }
        Ok(())
    }

    pub(super) async fn native_handle(
        &self,
        server: &Server,
        attached: bool,
    ) -> anyhow::Result<(
        std::sync::Arc<dyn crate::server::executor::ProcessHandle>,
        crate::server::executor::StatusReceiver,
    )> {
        self.ensure_native(server).await?;
        self.sync_server(server, &Self::name(server.uuid)).await?;
        if attached {
            self.mount_native_files(server).await?;
        }
        process::Handle::connect(
            self.clone(),
            server,
            Self::name(server.uuid),
            attached,
            true,
        )
        .await
    }
}

fn mounted(path: &Path, name: &str) -> anyhow::Result<bool> {
    let mounts = std::fs::read_to_string("/proc/self/mountinfo")?;
    let path = path.to_str().context("native mount path is not UTF-8")?;
    ensure!(
        !path
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte == b'\\'),
        "native mount directory must not contain whitespace or backslashes"
    );
    for line in mounts.lines() {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        if fields.get(4) == Some(&path) {
            let separator = fields
                .iter()
                .position(|field| *field == "-")
                .context("invalid mount information")?;
            ensure!(
                fields.get(separator + 1) == Some(&"fuse.sshfs")
                    && fields
                        .get(separator + 2)
                        .is_some_and(|source| *source == format!("incus.{name}:/")),
                "refusing unrelated filesystem at native file mount directory"
            );
            return Ok(true);
        }
    }
    Ok(false)
}
