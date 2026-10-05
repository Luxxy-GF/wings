use super::{Instance, client::Client};
use crate::server::configuration::ExternalNetwork;
use anyhow::{Context, ensure};
use reqwest::Method;
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub(super) fn mac(uuid: uuid::Uuid) -> String {
    let bytes = uuid.as_bytes();
    format!(
        "02:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

pub(super) async fn device(network: &ExternalNetwork) -> anyhow::Result<BTreeMap<String, String>> {
    network.validate()?;
    let path = std::path::Path::new("/sys/class/net").join(&network.parent);
    ensure!(
        tokio::fs::try_exists(&path).await?,
        "external parent interface does not exist"
    );
    ensure!(
        tokio::fs::read_to_string(path.join("type")).await?.trim() == "1",
        "macvlan requires an Ethernet parent interface"
    );
    let mut device = BTreeMap::from([
        ("type".into(), "nic".into()),
        ("nictype".into(), "macvlan".into()),
        ("parent".into(), network.parent.clone()),
        ("mode".into(), network.mode.clone()),
        ("gvrp".into(), network.gvrp.to_string()),
        (
            "hwaddr".into(),
            network
                .mac
                .as_ref()
                .context("external NIC requires a MAC address")?
                .to_ascii_lowercase(),
        ),
    ]);
    if let Some(vlan) = network.vlan {
        device.insert("vlan".into(), vlan.to_string());
    }
    if let Some(mtu) = network.mtu {
        device.insert("mtu".into(), mtu.to_string());
    }
    Ok(device)
}

pub(super) fn check_network(
    instance: &Instance,
    desired: Option<&ExternalNetwork>,
) -> anyhow::Result<()> {
    let existing = instance
        .config
        .get("user.wings.external-network")
        .map(|value| serde_json::from_str::<ExternalNetwork>(value))
        .transpose()?;
    match (existing, desired) {
        (None, None) => Ok(()),
        (Some(existing), Some(desired)) => {
            let mut desired = desired.clone();
            if desired.mac.is_none() {
                desired.mac = existing.mac.clone();
            }
            desired.mac = desired.mac.map(|mac| mac.to_ascii_lowercase());
            ensure!(
                existing == desired,
                "changing an existing instance's network requires a new instance"
            );
            Ok(())
        }
        _ => anyhow::bail!("changing an existing instance's network requires a new instance"),
    }
}

pub(super) async fn configure(
    client: &Client,
    name: &str,
    network: &ExternalNetwork,
) -> anyhow::Result<()> {
    network.validate()?;
    let mut command = vec![
        "/bin/sh".to_string(),
        "-c".into(),
        include_str!("external-network.sh").into(),
        "wings-network".into(),
        network
            .mac
            .as_ref()
            .context("external NIC requires a MAC address")?
            .clone(),
        format!("{}/{}", network.address, network.prefix),
        network.gateway.to_string(),
        network.gateway_onlink.to_string(),
        network
            .dns
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" "),
    ];
    command.push(network.mtu.map(|mtu| mtu.to_string()).unwrap_or_default());
    let result = client.mutate(Method::POST, &format!("{}/exec", super::IncusExecutor::instance_path(name)), json!({
        "command":command, "interactive":false, "wait-for-websocket":false, "record-output":true, "user":0, "group":0,
        "environment":{"PATH":"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
    })).await.context("configuring the guest's external IPv4 network; Linux and iproute2 are required")?;
    if result.pointer("/metadata/return").and_then(Value::as_i64) != Some(0) {
        let mut output = String::new();
        if let Some(path) = result.pointer("/metadata/output/2").and_then(Value::as_str)
            && path.starts_with(&format!(
                "{}/logs/",
                super::IncusExecutor::instance_path(name)
            ))
            && let Ok(bytes) = client.read_file(path).await
        {
            output = String::from_utf8_lossy(&bytes).into_owned();
        }
        anyhow::bail!("guest external network setup failed: {output}");
    }
    Ok(())
}

pub(super) async fn network_inventory(client: &Client, owner: &str) -> anyhow::Result<Value> {
    let instances: Vec<Instance> = client.get("/1.0/instances?recursion=1").await?;
    let mut leases = Vec::new();
    for instance in instances {
        if instance.config.get("user.wings.owner").map(String::as_str) != Some(owner) {
            continue;
        }
        if let Some(value) = instance.config.get("user.wings.external-network") {
            let network: ExternalNetwork = serde_json::from_str(value)?;
            let server: uuid::Uuid = instance
                .config
                .get("user.wings.server")
                .context("direct instance missing server UUID")?
                .parse()?;
            leases.push(json!({"server_uuid":server, "address":network.address}));
        }
    }
    let mut interfaces = Vec::new();
    let mut directory = tokio::fs::read_dir("/sys/class/net").await?;
    while let Some(entry) = directory.next_entry().await? {
        let name = entry.file_name().to_string_lossy().to_string();
        if name == "lo"
            || tokio::fs::read_to_string(entry.path().join("type"))
                .await?
                .trim()
                != "1"
        {
            continue;
        }
        let mtu: u32 = tokio::fs::read_to_string(entry.path().join("mtu"))
            .await?
            .trim()
            .parse()?;
        interfaces.push(json!({"name":name,"mtu":mtu}));
    }
    interfaces.sort_by_key(|value| {
        value
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    });
    Ok(json!({"interfaces":interfaces,"leases":leases}))
}
