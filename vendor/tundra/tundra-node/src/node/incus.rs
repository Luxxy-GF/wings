//! Local Incus runtime discovery. Namespace binding and tunnel ACLs stay shared.
use super::docker::{ContainerEvent, ContainerInfo};
use anyhow::{Context, ensure};
use futures::Stream;
use serde::Deserialize;
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    net::Ipv4Addr,
    path::PathBuf,
    pin::Pin,
    time::Duration,
};

#[derive(Clone)]
pub struct IncusAdapter {
    http: reqwest::Client,
    project: String,
    owner: String,
}

#[derive(Deserialize)]
struct Instance {
    name: String,
    config: BTreeMap<String, String>,
    #[serde(default)]
    status: String,
}
#[derive(Deserialize)]
struct State {
    pid: i32,
    status: String,
}
impl IncusAdapter {
    pub fn new(socket: PathBuf) -> anyhow::Result<Self> {
        Self::with_runtime(
            socket,
            std::env::var("WINGS_INCUS_PROJECT").context("missing Incus project")?,
            std::env::var("WINGS_INCUS_OWNER").context("missing Wings ownership marker")?,
        )
    }
    pub fn with_runtime(socket: PathBuf, project: String, owner: String) -> anyhow::Result<Self> {
        ensure!(socket.is_absolute(), "Incus socket must be absolute");
        ensure!(
            !project.is_empty() && owner.starts_with("wings:"),
            "invalid Incus ownership scope"
        );
        Ok(Self {
            http: reqwest::Client::builder()
                .unix_socket(socket)
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(10))
                .build()?,
            project,
            owner,
        })
    }
    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        let response: serde_json::Value = self
            .http
            .get(format!("http://localhost{path}"))
            .query(&[("project", &self.project)])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        ensure!(
            response.get("type").and_then(|v| v.as_str()) == Some("sync"),
            "Incus discovery failed"
        );
        Ok(serde_json::from_value(
            response
                .get("metadata")
                .context("missing Incus metadata")?
                .clone(),
        )?)
    }
    fn server(&self, instance: &Instance) -> anyhow::Result<uuid::Uuid> {
        ensure!(
            instance.config.get("user.wings.owner") == Some(&self.owner),
            "instance belongs to another Wings node"
        );
        let uuid: uuid::Uuid = instance
            .config
            .get("user.wings.server")
            .context("instance is not a Wings server")?
            .parse()?;
        ensure!(
            instance.name == format!("wgs-{uuid}"),
            "instance is not a game server"
        );
        Ok(uuid)
    }
    pub async fn inspect(&self, name: &str) -> anyhow::Result<ContainerInfo> {
        let uuid: uuid::Uuid = name
            .strip_prefix("wgs-")
            .context("invalid Incus server reference")?
            .parse()?;
        ensure!(
            name == format!("wgs-{uuid}"),
            "noncanonical Incus instance name"
        );
        let path = format!("/1.0/instances/{name}");
        let instance: Instance = self.get(&path).await?;
        self.server(&instance)?;
        let state: State = self.get(&format!("{path}/state")).await?;
        let running = matches!(state.status.as_str(), "Running" | "Frozen");
        ensure!(
            !running || state.pid > 0,
            "running Incus instance has no host PID"
        );
        let ip: Ipv4Addr = instance
            .config
            .get("user.wings.ip")
            .context("Incus private IP missing")?
            .parse()?;
        Ok(ContainerInfo {
            id: name.into(),
            pid: state.pid,
            running,
            ip: Some(ip),
            // Wings always supplies its own hosts_path template for Incus.
            hosts_path: PathBuf::new(),
        })
    }
    pub fn events(&self) -> Pin<Box<dyn Stream<Item = ContainerEvent> + Send>> {
        // Polling includes native Incus CLI starts and recreations. PID changes emit
        // die/start so Tundra drops sockets attached to the old network namespace.
        Box::pin(futures::stream::unfold(
            (self.clone(), HashMap::<String, i32>::new(), VecDeque::new()),
            |(adapter, mut old, mut pending)| async move {
                loop {
                    if let Some(event) = pending.pop_front() {
                        return Some((event, (adapter, old, pending)));
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    let instances = match adapter
                        .get::<Vec<Instance>>("/1.0/instances?recursion=1")
                        .await
                    {
                        Ok(instances) => instances,
                        Err(err) => {
                            tracing::warn!("Incus discovery: {err:#}");
                            continue;
                        }
                    };
                    let mut current = HashMap::new();
                    let mut failed = false;
                    for instance in instances {
                        if adapter.server(&instance).is_err()
                            || !matches!(instance.status.as_str(), "Running" | "Frozen")
                        {
                            continue;
                        }
                        match adapter.inspect(&instance.name).await {
                            Ok(info) if info.running => {
                                current.insert(info.id, info.pid);
                            }
                            Ok(_) => {}
                            Err(_) => {
                                failed = true;
                                break;
                            }
                        }
                    }
                    if failed {
                        continue;
                    }
                    for (id, pid) in &old {
                        if current.get(id) != Some(pid) {
                            pending.push_back(ContainerEvent::Died {
                                id: id.clone(),
                                name: Some(id.clone()),
                            });
                        }
                    }
                    for (id, pid) in &current {
                        if old.get(id) != Some(pid) {
                            pending.push_back(ContainerEvent::Started {
                                id: id.clone(),
                                name: Some(id.clone()),
                            });
                        }
                    }
                    old = current;
                }
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn discovery_rejects_helpers_and_foreign_nodes() -> anyhow::Result<()> {
        let adapter = IncusAdapter::with_runtime(
            "/tmp/unused-incus.sock".into(),
            "wings".into(),
            "wings:node".into(),
        )?;
        let uuid = uuid::Uuid::new_v4();
        let mut instance = Instance {
            name: format!("wgs-{uuid}"),
            status: "Running".into(),
            config: BTreeMap::from([
                ("user.wings.owner".into(), "wings:node".into()),
                ("user.wings.server".into(), uuid.to_string()),
            ]),
        };
        assert_eq!(adapter.server(&instance)?, uuid);
        instance.name = format!("wgi-{uuid}");
        assert!(adapter.server(&instance).is_err());
        instance.name = format!("wgs-{uuid}");
        instance
            .config
            .insert("user.wings.owner".into(), "wings:foreign".into());
        assert!(adapter.server(&instance).is_err());
        for name in ["pid:123", "../default", "wgs-bad", "wgi-test"] {
            assert!(adapter.inspect(name).await.is_err());
        }
        Ok(())
    }

    #[tokio::test]
    async fn discovery_uses_the_project_and_real_host_pid() -> anyhow::Result<()> {
        use axum::{Json, Router, extract::Query, routing::get};
        let uuid = uuid::Uuid::new_v4();
        let name = format!("wgs-{uuid}");
        let path = std::env::temp_dir().join(format!("tundra-incus-{uuid}.sock"));
        let listener = tokio::net::UnixListener::bind(&path)?;
        let app = Router::new()
            .route(&format!("/1.0/instances/{name}"), get(move |Query(query): Query<HashMap<String,String>>| async move {
                assert_eq!(query.get("project").map(String::as_str), Some("node-project"));
                Json(serde_json::json!({"type":"sync","metadata":{
                    "name":format!("wgs-{uuid}"),"config":{
                        "user.wings.owner":"wings:node","user.wings.server":uuid.to_string(),"user.wings.ip":"10.76.0.2"
                    }
                }}))
            }))
            .route(&format!("/1.0/instances/{name}/state"), get(|| async {
                Json(serde_json::json!({"type":"sync","metadata":{"status":"Running","pid":1234}}))
            }));
        let task = tokio::spawn(async move { axum::serve(listener, app).await });
        let adapter =
            IncusAdapter::with_runtime(path.clone(), "node-project".into(), "wings:node".into())?;
        let result = adapter.inspect(&name).await;
        task.abort();
        std::fs::remove_file(path)?;
        let info = result?;
        assert_eq!(info.pid, 1234);
        assert_eq!(info.ip, Some(Ipv4Addr::new(10, 76, 0, 2)));
        assert!(info.running);
        Ok(())
    }
}
