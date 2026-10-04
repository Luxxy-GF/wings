use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::{
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};
use tundra_common::hash::Hash32;

pub const DEFAULT_CONFIG_PATH: &str = "/etc/calagopus-tundra/config.yml";
const UNIX_AUTHORITY: &str = "localhost";
const UNIX_ORIGIN: &str = "http://localhost";
const LOCAL_CONFIG_PATH: &str = "config.yml";

fn unloaded_sha256() -> Hash32 {
    Hash32([0; 32])
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct NodeConfig {
    #[serde(skip, default = "unloaded_sha256")]
    pub loaded_sha256: Hash32,
    pub remote: RemoteConfig,

    pub tunnel_bind: SocketAddr,
    pub metrics_bind: SocketAddr,
    pub data_dir: PathBuf,
    /// Names a hosts file the control plane owns and mounts into the container itself,
    /// with `{server}` standing in for the server uuid. Empty falls back to the file the
    /// container engine generates, which is only reachable where its storage is.
    pub hosts_path: String,

    pub restart: RestartConfig,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            loaded_sha256: Hash32([0; 32]),
            remote: RemoteConfig::default(),
            tunnel_bind: SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 7100),
            metrics_bind: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 7101),
            data_dir: PathBuf::from("/var/lib/calagopus-tundra"),
            hosts_path: String::new(),
            restart: RestartConfig::default(),
        }
    }
}

/// Any server implementing the node API can sit on the other end; nothing in here is
/// specific to one implementation.
#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct RemoteConfig {
    pub url: String,
    /// Over the DER encoding, and pinned on every request.
    pub cert_sha256: Hash32,
    pub token: String,
}

impl Default for RemoteConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            cert_sha256: Hash32([0; 32]),
            token: String::new(),
        }
    }
}

impl RemoteConfig {
    /// A `unix://<path>` remote swaps the pinned TLS transport for a local socket; the
    /// bearer token still identifies the node, there is just nothing to pin.
    #[inline]
    pub fn unix_path(&self) -> Option<&Path> {
        self.url.strip_prefix("unix://").map(Path::new)
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct RestartConfig {
    /// Per peer; the whole drain is abandoned at twice this.
    pub drain_timeout: u64,
    /// Must stay comfortably under the application's own read timeout.
    pub peer_resume_timeout: u64,
    pub binary_path: Option<PathBuf>,
}

impl Default for RestartConfig {
    fn default() -> Self {
        Self {
            drain_timeout: 5,
            peer_resume_timeout: 30,
            binary_path: None,
        }
    }
}

impl RestartConfig {
    #[inline]
    pub fn drain_timeout(&self) -> Duration {
        Duration::from_secs(self.drain_timeout)
    }

    #[inline]
    pub fn peer_resume_timeout(&self) -> Duration {
        Duration::from_secs(self.peer_resume_timeout)
    }
}

impl NodeConfig {
    pub fn open(path: &Path) -> Result<Self, anyhow::Error> {
        if !path.exists() {
            Self::write_template(path)?;
            return Err(anyhow::anyhow!(
                "no config found, wrote a template to {}; fill in the remote section",
                path.display()
            ));
        }

        let text =
            std::fs::read_to_string(path).context(format!("failed to read {}", path.display()))?;
        let mut config: Self =
            serde_norway::from_str(&text).context(format!("failed to parse {}", path.display()))?;
        config.validate()?;
        config.loaded_sha256 = tundra_common::hash::sha256(text.as_bytes());

        Ok(config)
    }

    fn write_template(path: &Path) -> Result<(), anyhow::Error> {
        use std::{io::Write, os::unix::fs::OpenOptionsExt};

        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).context(format!("failed to create {}", dir.display()))?;
        }

        let text = serde_norway::to_string(&Self::default())
            .context("failed to serialize the default config")?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .context(format!("failed to create {}", path.display()))?;
        file.write_all(text.as_bytes())
            .context(format!("failed to write {}", path.display()))
    }

    fn validate(&self) -> Result<(), anyhow::Error> {
        match self.remote.unix_path() {
            Some(path) => {
                if path.as_os_str().is_empty() {
                    return Err(anyhow::anyhow!("remote.url is missing a socket path"));
                }
            }
            None => {
                if !self.remote.url.starts_with("https://") {
                    return Err(anyhow::anyhow!(
                        "remote.url must be an https:// or unix:// URL"
                    ));
                }
                if self.remote.cert_sha256 == Hash32([0; 32]) {
                    return Err(anyhow::anyhow!(
                        "remote.cert_sha256 is unset; pin the control plane's certificate fingerprint"
                    ));
                }
            }
        }
        if self.remote.token.trim().is_empty() {
            return Err(anyhow::anyhow!("remote.token is empty"));
        }
        if !self.hosts_path.is_empty() {
            if !Path::new(&self.hosts_path).is_absolute() {
                return Err(anyhow::anyhow!("hosts_path must be an absolute path"));
            }
            // without the placeholder every server would name the same file and the last
            // reconcile would win, quietly handing one container another's names
            if !self
                .hosts_path
                .contains(crate::node::naming::SERVER_PLACEHOLDER)
            {
                return Err(anyhow::anyhow!(
                    "hosts_path must contain {}",
                    crate::node::naming::SERVER_PLACEHOLDER
                ));
            }
        }
        // the resume must have time to finish while every peer still holds our frozen flows
        if self.restart.peer_resume_timeout() <= crate::node::restart::RESUME_BUDGET {
            return Err(anyhow::anyhow!(
                "restart.peer_resume_timeout must exceed {} seconds",
                crate::node::restart::RESUME_BUDGET.as_secs()
            ));
        }

        Ok(())
    }

    /// Over a unix socket the authority is never dialled, so it only has to be a valid one.
    #[inline]
    pub fn api(&self, path: &str) -> String {
        if self.remote.unix_path().is_some() {
            return format!("{UNIX_ORIGIN}{path}");
        }

        format!("{}{path}", self.remote.url.trim_end_matches('/'))
    }

    #[inline]
    pub fn ws_url(&self) -> String {
        if self.remote.unix_path().is_some() {
            return format!("ws://{UNIX_AUTHORITY}/api/node/ws");
        }

        let base = self.remote.url.trim_end_matches('/');
        format!("wss://{}/api/node/ws", base.trim_start_matches("https://"))
    }
}

/// The local `config.yml` fallback exists for development checkouts.
pub fn resolve_config_path(explicit: Option<PathBuf>) -> PathBuf {
    resolve_between(
        explicit,
        Path::new(DEFAULT_CONFIG_PATH),
        Path::new(LOCAL_CONFIG_PATH),
    )
}

fn resolve_between(explicit: Option<PathBuf>, system: &Path, local: &Path) -> PathBuf {
    match explicit {
        Some(path) => path,
        None if !system.exists() && local.exists() => local.to_path_buf(),
        None => system.to_path_buf(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Run(PathBuf),
    Restart(PathBuf),
}

pub fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Command, anyhow::Error> {
    let mut args = args.into_iter().peekable();

    let restart = args.peek().is_some_and(|a| a == "restart");
    if restart {
        args.next();
    }

    let explicit = match args.next() {
        None => None,
        Some(flag) if flag == "--config" || flag == "-c" => {
            let Some(path) = args.next() else {
                return Err(anyhow::anyhow!("--config needs a path"));
            };

            Some(PathBuf::from(path))
        }
        Some(other) => {
            return Err(anyhow::anyhow!(
                "unexpected argument {other:?}, expected [restart] [--config <path>]"
            ));
        }
    };

    if let Some(extra) = args.next() {
        return Err(anyhow::anyhow!("unexpected trailing argument {extra:?}"));
    }

    let path = resolve_config_path(explicit);
    Ok(if restart {
        Command::Restart(path)
    } else {
        Command::Run(path)
    })
}

pub fn command_from_args() -> Result<Command, anyhow::Error> {
    parse_args(std::env::args().skip(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
remote:
  url: https://control.example.net:8443/
  cert_sha256: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
  token: deadbeef
tunnel_bind: 0.0.0.0:7100
metrics_bind: 127.0.0.1:7101
data_dir: /var/lib/calagopus-tundra
"#;

    fn written(tag: &str, body: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("tundra-cfg-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.yml");
        std::fs::write(&path, body).unwrap();

        path
    }

    #[test]
    fn loaded_hash_describes_the_parsed_bytes_after_the_file_changes() {
        let path = written("loaded-hash", SAMPLE);
        let config = NodeConfig::open(&path).unwrap();
        std::fs::write(&path, SAMPLE.replace("7100", "7200")).unwrap();
        assert_eq!(
            config.loaded_sha256,
            tundra_common::hash::sha256(SAMPLE.as_bytes())
        );
        assert_ne!(
            config.loaded_sha256,
            NodeConfig::open(&path).unwrap().loaded_sha256
        );
    }

    // NodeConfig

    #[test]
    fn config_parses_and_derives_both_control_urls() {
        let config = NodeConfig::open(&written("full", SAMPLE)).unwrap();

        assert_eq!(
            config.remote.cert_sha256,
            tundra_common::hash::sha256(b"abc")
        );
        assert_eq!(
            config.api("/api/node/state"),
            "https://control.example.net:8443/api/node/state"
        );
        assert_eq!(
            config.ws_url(),
            "wss://control.example.net:8443/api/node/ws"
        );
        assert_eq!(config.restart.drain_timeout(), Duration::from_secs(5));
        assert_eq!(
            config.restart.peer_resume_timeout(),
            Duration::from_secs(30)
        );
        assert!(config.restart.binary_path.is_none());
    }

    #[test]
    fn restart_section_overrides_only_what_it_names() {
        let config: NodeConfig =
            serde_norway::from_str(&format!("{SAMPLE}\nrestart:\n  peer_resume_timeout: 90\n"))
                .unwrap();

        assert_eq!(
            config.restart.peer_resume_timeout(),
            Duration::from_secs(90)
        );
        assert_eq!(config.restart.drain_timeout(), Duration::from_secs(5));
    }

    #[test]
    fn config_rejects_a_malformed_pin_at_parse_time() {
        let bad = SAMPLE.replace(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "nope",
        );

        assert!(serde_norway::from_str::<NodeConfig>(&bad).is_err());
    }

    #[test]
    fn config_refuses_a_peer_resume_timeout_the_resume_budget_would_outlive() {
        let config: NodeConfig =
            serde_norway::from_str(&format!("{SAMPLE}\nrestart:\n  peer_resume_timeout: 10\n"))
                .unwrap();

        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("peer_resume_timeout")
        );
    }

    #[test]
    fn a_control_plane_owned_hosts_path_must_name_one_file_per_server() {
        let config: NodeConfig = serde_norway::from_str(&format!(
            "{SAMPLE}\nhosts_path: /var/lib/wings/vmounts/{{server}}/hosts\n"
        ))
        .unwrap();
        config.validate().unwrap();

        let shared: NodeConfig =
            serde_norway::from_str(&format!("{SAMPLE}\nhosts_path: /var/lib/wings/hosts\n"))
                .unwrap();
        assert!(
            shared
                .validate()
                .unwrap_err()
                .to_string()
                .contains(crate::node::naming::SERVER_PLACEHOLDER)
        );

        let relative: NodeConfig =
            serde_norway::from_str(&format!("{SAMPLE}\nhosts_path: vmounts/{{server}}/hosts\n"))
                .unwrap();
        assert!(
            relative
                .validate()
                .unwrap_err()
                .to_string()
                .contains("absolute")
        );
    }

    #[test]
    fn the_engines_own_hosts_file_stays_the_default() {
        let config: NodeConfig = serde_norway::from_str(SAMPLE).unwrap();
        config.validate().unwrap();

        assert!(config.hosts_path.is_empty());
    }

    #[test]
    fn a_unix_remote_needs_a_token_but_nothing_to_pin() {
        const UNIX: &str = r#"
remote:
  url: unix:///run/calagopus-wings/tundra.sock
  token: deadbeef
"#;

        let config: NodeConfig = serde_norway::from_str(UNIX).unwrap();
        config.validate().unwrap();

        assert_eq!(
            config.remote.unix_path(),
            Some(Path::new("/run/calagopus-wings/tundra.sock"))
        );
        assert_eq!(
            config.api("/api/node/state"),
            "http://localhost/api/node/state"
        );
        assert_eq!(config.ws_url(), "ws://localhost/api/node/ws");

        let untokened: NodeConfig =
            serde_norway::from_str(&UNIX.replace("  token: deadbeef", "")).unwrap();
        assert!(
            untokened
                .validate()
                .unwrap_err()
                .to_string()
                .contains("remote.token")
        );

        let pathless: NodeConfig = serde_norway::from_str(
            &UNIX.replace("unix:///run/calagopus-wings/tundra.sock", "unix://"),
        )
        .unwrap();
        assert!(pathless.validate().is_err());
    }

    #[test]
    fn config_refuses_a_plaintext_remote_url() {
        let path = written("plaintext", &SAMPLE.replace("https://", "http://"));

        assert!(NodeConfig::open(&path).is_err());
    }

    #[test]
    fn a_missing_config_becomes_a_template_and_a_clear_error() {
        let dir = std::env::temp_dir().join(format!("tundra-cfg-tmpl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("config.yml");

        let err = NodeConfig::open(&path).unwrap_err();
        assert!(err.to_string().contains("wrote a template"));

        let text = std::fs::read_to_string(&path).unwrap();
        let config: NodeConfig = serde_norway::from_str(&text).unwrap();
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("remote.url")
        );

        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    // parse_args

    fn argv(s: &str) -> Vec<String> {
        s.split(' ').map(str::to_owned).collect()
    }

    #[test]
    fn parse_args_separates_restart_from_a_normal_start() {
        assert_eq!(
            parse_args(argv("--config /etc/calagopus-tundra/config.yml")).unwrap(),
            Command::Run("/etc/calagopus-tundra/config.yml".into())
        );
        assert_eq!(
            parse_args(argv("-c /etc/calagopus-tundra/config.yml")).unwrap(),
            Command::Run("/etc/calagopus-tundra/config.yml".into())
        );
        assert_eq!(
            parse_args(argv("restart --config /etc/calagopus-tundra/config.yml")).unwrap(),
            Command::Restart("/etc/calagopus-tundra/config.yml".into())
        );
    }

    #[test]
    fn parse_args_accepts_a_bare_invocation_and_keeps_the_verb() {
        assert!(matches!(parse_args(Vec::new()).unwrap(), Command::Run(_)));
        assert!(matches!(
            parse_args(argv("restart")).unwrap(),
            Command::Restart(_)
        ));
    }

    #[test]
    fn the_system_path_wins_unless_absent_with_a_local_fallback_present() {
        let dir = std::env::temp_dir().join(format!("tundra-cfg-res-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let system = dir.join("system.yml");
        let local = dir.join("local.yml");

        assert_eq!(
            resolve_between(Some("/x.yml".into()), &system, &local),
            PathBuf::from("/x.yml")
        );
        assert_eq!(resolve_between(None, &system, &local), system);

        std::fs::write(&local, "").unwrap();
        assert_eq!(resolve_between(None, &system, &local), local);

        std::fs::write(&system, "").unwrap();
        assert_eq!(resolve_between(None, &system, &local), system);
    }

    #[test]
    fn parse_args_rejects_every_malformed_invocation() {
        assert!(parse_args(argv("--config")).is_err());
        assert!(parse_args(argv("--wat x")).is_err());
        assert!(parse_args(argv("restart --config /a extra")).is_err());
    }
}
