use super::{
    Instance,
    client::{Client, is_status, segment},
};
use anyhow::{Context, ensure};
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::{IpAddr, Ipv4Addr},
};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct ForwardPort {
    pub protocol: String,
    pub listen_port: String,
    pub target_address: String,
    #[serde(default)]
    pub target_port: String,
    #[serde(default)]
    pub description: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Forward {
    pub listen_address: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub config: BTreeMap<String, String>,
    #[serde(default)]
    pub ports: Vec<ForwardPort>,
}

pub fn ipv4_pool(value: &str) -> anyhow::Result<(u32, u32, u32)> {
    let (address, prefix) = value
        .split_once('/')
        .context("Incus bridge requires IPv4 CIDR")?;
    let gateway = u32::from(address.parse::<Ipv4Addr>()?);
    let prefix: u32 = prefix.parse()?;
    ensure!(
        (16..=30).contains(&prefix),
        "Incus bridge IPv4 prefix must be /16 through /30"
    );
    let mask = u32::MAX << (32 - prefix);
    let network = gateway & mask;
    let broadcast = network | !mask;
    ensure!(
        gateway > network && gateway < broadcast,
        "bridge address must be a usable host address"
    );
    Ok((network, broadcast, gateway))
}

pub fn allocations(
    config: &crate::server::configuration::ServerConfiguration,
    listen: &[IpAddr],
) -> anyhow::Result<BTreeMap<IpAddr, BTreeSet<u16>>> {
    let mut result = BTreeMap::<IpAddr, BTreeSet<u16>>::new();
    for (address, ports) in &config.allocations.mappings {
        let ip: IpAddr = address.parse().context("invalid panel allocation IP")?;
        let addresses = if ip.is_unspecified() {
            let addresses: Vec<_> = listen
                .iter()
                .copied()
                .filter(|candidate| {
                    candidate.is_ipv4() == ip.is_ipv4() && !candidate.is_unspecified()
                })
                .collect();
            ensure!(
                !addresses.is_empty(),
                "wildcard allocation requires concrete runtime.incus.listen_addresses"
            );
            addresses
        } else {
            vec![ip]
        };
        for address in addresses {
            ensure!(
                ports.iter().all(|p| *p > 0),
                "allocation port zero is invalid"
            );
            result
                .entry(address)
                .or_default()
                .extend(ports.iter().copied());
        }
    }
    // The first implementation deliberately refuses IPv6 forwarding onto an IPv4-only bridge.
    ensure!(
        result.keys().all(IpAddr::is_ipv4),
        "IPv6 allocations require an IPv6-enabled Incus network (not implemented yet)"
    );
    Ok(result)
}

fn port_set(value: &str) -> anyhow::Result<BTreeSet<u16>> {
    let mut result = BTreeSet::new();
    for part in value.split(',') {
        if let Some((start, end)) = part.split_once('-') {
            let start: u16 = start.parse()?;
            let end: u16 = end.parse()?;
            ensure!(start > 0 && start <= end, "invalid forward port range");
            result.extend(start..=end);
        } else {
            let port: u16 = part.parse()?;
            ensure!(port > 0, "invalid forward port");
            result.insert(port);
        }
    }
    Ok(result)
}

pub fn merge_ports(
    existing: &[ForwardPort],
    owner: &str,
    target: &str,
    desired: &BTreeSet<u16>,
) -> anyhow::Result<Vec<ForwardPort>> {
    let mut result = Vec::new();
    for entry in existing {
        if entry.description == owner {
            continue;
        }
        ensure!(
            port_set(&entry.listen_port)?.is_disjoint(desired),
            "allocation conflicts with another Incus forward entry"
        );
        result.push(entry.clone());
    }
    if !desired.is_empty() {
        let ports = desired
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(",");
        for protocol in ["tcp", "udp"] {
            result.push(ForwardPort {
                protocol: protocol.into(),
                listen_port: ports.clone(),
                target_address: target.into(),
                target_port: String::new(),
                description: owner.into(),
                extra: BTreeMap::new(),
            });
        }
    }
    Ok(result)
}

pub struct Network {
    client: Client,
    name: String,
    owner: String,
    cidr: String,
    lock: tokio::sync::Mutex<()>,
}
impl Network {
    pub fn new(client: Client, cfg: &crate::config::IncusRuntime, node: uuid::Uuid) -> Self {
        Self {
            client,
            name: cfg.network.clone(),
            owner: format!("wings:{node}"),
            cidr: cfg.ipv4_address.clone(),
            lock: tokio::sync::Mutex::new(()),
        }
    }
    fn path(&self) -> String {
        format!("/1.0/networks/{}", segment(&self.name))
    }
    pub async fn boot(&self) -> anyhow::Result<()> {
        ipv4_pool(&self.cidr)?;
        // With features.networks=false, managed bridges are owned by the default project.
        let mut global = self.client.clone();
        global.project = "default".into();
        if let Some(network) = global.optional::<Value>(&self.path()).await? {
            ensure!(
                network.get("type").and_then(Value::as_str) == Some("bridge"),
                "Incus network is not a bridge"
            );
            ensure!(
                network
                    .pointer("/config/user.wings.owner")
                    .and_then(Value::as_str)
                    == Some(&self.owner),
                "refusing unmanaged Incus network"
            );
            ensure!(
                network
                    .pointer("/config/ipv4.address")
                    .and_then(Value::as_str)
                    == Some(&self.cidr),
                "existing Incus network subnet differs from configuration"
            );
        } else {
            global.mutate(Method::POST, "/1.0/networks", json!({"name": self.name, "type": "bridge", "config": {
                "ipv4.address": self.cidr, "ipv4.nat": "true", "ipv4.dhcp": "true", "ipv6.address": "none", "user.wings.owner": self.owner
            }})).await?;
        }
        Ok(())
    }
    pub async fn allocate(&self, instances: &[Instance]) -> anyhow::Result<Ipv4Addr> {
        let (network, broadcast, gateway) = ipv4_pool(&self.cidr)?;
        let mut used: BTreeSet<u32> = instances
            .iter()
            .filter_map(|i| i.config.get("user.wings.ip"))
            .filter_map(|ip| ip.parse::<Ipv4Addr>().ok())
            .map(u32::from)
            .collect();
        let mut global = self.client.clone();
        global.project = "default".into();
        let leases: Vec<Value> = global.get(&format!("{}/leases", self.path())).await?;
        for lease in leases {
            if let Some(address) = lease
                .get("address")
                .and_then(Value::as_str)
                .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
            {
                used.insert(u32::from(address));
            }
        }
        for forward in self.forwards().await? {
            for entry in forward.ports {
                if let Ok(address) = entry.target_address.parse::<Ipv4Addr>() {
                    used.insert(u32::from(address));
                }
            }
        }
        for address in network + 1..broadcast {
            if address != gateway && !used.contains(&address) {
                return Ok(address.into());
            }
        }
        anyhow::bail!("Incus bridge has no free private IPv4 addresses")
    }
    async fn forwards(&self) -> anyhow::Result<Vec<Forward>> {
        let mut global = self.client.clone();
        global.project = "default".into();
        global
            .get(&format!("{}/forwards?recursion=1", self.path()))
            .await
    }
    pub async fn sync(
        &self,
        server: uuid::Uuid,
        target: &str,
        desired: &BTreeMap<IpAddr, BTreeSet<u16>>,
    ) -> anyhow::Result<()> {
        let _guard = self.lock.lock().await;
        let owner = format!("{}:{server}", self.owner);
        let current = self.forwards().await?;
        let mut addresses: BTreeSet<IpAddr> = desired.keys().copied().collect();
        addresses.extend(
            current
                .iter()
                .filter(|f| f.ports.iter().any(|p| p.description == owner))
                .filter_map(|f| f.listen_address.parse::<IpAddr>().ok()),
        );
        let mut global = self.client.clone();
        global.project = "default".into();
        for ip in addresses {
            let path = format!("{}/forwards/{}", self.path(), segment(&ip.to_string()));
            let wanted = desired.get(&ip).cloned().unwrap_or_default();
            let mut completed = false;
            for _ in 0..5 {
                let (mut forward, etag) =
                    match global.request(Method::GET, &path, None, None, true).await {
                        Ok((value, etag)) => (serde_json::from_value::<Forward>(value)?, etag),
                        Err(err) if is_status(&err, StatusCode::NOT_FOUND) => (
                            Forward {
                                listen_address: ip.to_string(),
                                description: self.owner.clone(),
                                config: BTreeMap::new(),
                                ports: Vec::new(),
                            },
                            None,
                        ),
                        Err(err) => return Err(err),
                    };
                ensure!(
                    !forward.config.contains_key("target_address"),
                    "Incus forward has a conflicting catch-all target"
                );
                forward.ports = merge_ports(&forward.ports, &owner, target, &wanted)?;
                let result = if forward.ports.is_empty()
                    && forward.description == self.owner
                    && etag.is_some()
                {
                    global
                        .request(Method::DELETE, &path, None, etag.as_deref(), true)
                        .await
                } else if etag.is_some() {
                    let body = json!({"description": forward.description, "config": forward.config, "ports": forward.ports});
                    global
                        .request(Method::PUT, &path, Some(&body), etag.as_deref(), true)
                        .await
                } else if wanted.is_empty() {
                    completed = true;
                    break;
                } else {
                    global
                        .request(
                            Method::POST,
                            &format!("{}/forwards", self.path()),
                            Some(&serde_json::to_value(forward)?),
                            None,
                            true,
                        )
                        .await
                };
                match result {
                    Ok(_) => {
                        completed = true;
                        break;
                    }
                    Err(err)
                        if is_status(&err, StatusCode::PRECONDITION_FAILED)
                            || is_status(&err, StatusCode::CONFLICT) =>
                    {
                        continue;
                    }
                    Err(err) => return Err(err),
                }
            }
            ensure!(
                completed,
                "Incus forward changed repeatedly; refusing to overwrite it"
            );
        }
        Ok(())
    }
    pub async fn used_ports(
        &self,
        ips: &[IpAddr],
    ) -> anyhow::Result<HashMap<IpAddr, Vec<super::super::UsedPort>>> {
        let mut result: HashMap<IpAddr, Vec<super::super::UsedPort>> =
            ips.iter().map(|ip| (*ip, Vec::new())).collect();
        for forward in self.forwards().await? {
            let address: IpAddr = forward.listen_address.parse()?;
            for (ip, entries) in &mut result {
                if *ip != address {
                    continue;
                }
                for entry in &forward.ports {
                    let server = entry
                        .description
                        .strip_prefix(&format!("{}:", self.owner))
                        .and_then(|uuid| uuid.parse().ok());
                    for port in port_set(&entry.listen_port)? {
                        if !entries.iter().any(|item| item.port == port) {
                            entries.push(super::super::UsedPort { port, server });
                        }
                    }
                }
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn merge_preserves_other_servers_and_rejects_conflicts() -> anyhow::Result<()> {
        let first = merge_ports(&[], "first", "10.0.0.2", &BTreeSet::from([25565]))?;
        let second = merge_ports(&first, "second", "10.0.0.3", &BTreeSet::from([25566]))?;
        assert_eq!(second.len(), 4);
        assert!(merge_ports(&first, "second", "10.0.0.3", &BTreeSet::from([25565])).is_err());
        let removed = merge_ports(&second, "first", "", &BTreeSet::new())?;
        assert_eq!(removed.len(), 2);
        assert!(removed.iter().all(|p| p.description == "second"));
        Ok(())
    }
    #[test]
    fn bridge_pool_excludes_network_and_broadcast() -> anyhow::Result<()> {
        let (network, broadcast, gateway) = ipv4_pool("10.76.0.1/24")?;
        assert_eq!(Ipv4Addr::from(network), Ipv4Addr::new(10, 76, 0, 0));
        assert_eq!(Ipv4Addr::from(broadcast), Ipv4Addr::new(10, 76, 0, 255));
        assert_eq!(Ipv4Addr::from(gateway), Ipv4Addr::new(10, 76, 0, 1));
        assert!(ipv4_pool("10.76.0.0/24").is_err());
        Ok(())
    }
}
