//! Incus root storage and private control volumes. Server data remains in Wings's host directory.
use super::client::{Client, is_status, segment};
use anyhow::ensure;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use std::sync::Arc;

pub struct Storage {
    client: Client,
    pool: String,
    owner: String,
}
impl Storage {
    pub fn new(client: Client, config: Arc<crate::config::Config>) -> Self {
        let pool = config.load().runtime.incus.storage_pool.clone();
        let owner = format!("wings:{}", config.load().uuid);
        Self {
            client,
            pool,
            owner,
        }
    }
    pub fn control_name(instance: &str) -> String {
        format!("wgc-{instance}")
    }
    pub fn path(&self, volume: &str) -> String {
        format!(
            "/1.0/storage-pools/{}/volumes/custom/{}",
            segment(&self.pool),
            segment(volume)
        )
    }
    pub fn file_path(&self, volume: &str, name: &str) -> String {
        format!(
            "{}/files?path={}",
            self.path(volume),
            segment(&format!("/{name}"))
        )
    }
    pub async fn boot(&self) -> anyhow::Result<()> {
        let pool: Value = self
            .client
            .get(&format!("/1.0/storage-pools/{}", segment(&self.pool)))
            .await?;
        ensure!(
            matches!(
                pool.get("driver").and_then(Value::as_str),
                Some("zfs" | "btrfs")
            ),
            "Incus storage requires an existing zfs or btrfs pool with native quotas and ID-mapped volume support"
        );
        Ok(())
    }
    pub async fn ensure_volume(&self, name: &str, quota: u64) -> anyhow::Result<()> {
        if let Some(volume) = self.client.optional::<Value>(&self.path(name)).await? {
            self.check_owner(&volume)?;
        } else {
            let mut config = std::collections::BTreeMap::from([
                ("user.wings.owner", self.owner.clone()),
                ("security.shifted", "true".to_owned()),
            ]);
            if quota > 0 {
                config.insert("size", quota.to_string());
            }
            self.client.mutate(Method::POST, &format!("/1.0/storage-pools/{}/volumes/custom", segment(&self.pool)), json!({"name": name, "type": "custom", "content_type": "filesystem", "config": config})).await?;
        }
        Ok(())
    }
    fn check_owner(&self, volume: &Value) -> anyhow::Result<()> {
        ensure!(
            volume
                .pointer("/config/user.wings.owner")
                .and_then(Value::as_str)
                == Some(&self.owner),
            "refusing unmanaged Incus volume"
        );
        ensure!(
            volume.get("content_type").and_then(Value::as_str) == Some("filesystem"),
            "Incus volume is not a filesystem"
        );
        Ok(())
    }
    pub async fn delete_volume(&self, name: &str) -> anyhow::Result<()> {
        let path = self.path(name);
        if let Some(volume) = self.client.optional::<Value>(&path).await? {
            self.check_owner(&volume)?;
            ensure!(
                volume
                    .get("used_by")
                    .and_then(Value::as_array)
                    .is_none_or(Vec::is_empty),
                "Incus volume is still attached"
            );
            match self.client.mutate(Method::DELETE, &path, json!({})).await {
                Ok(_) => {}
                Err(err) if is_status(&err, StatusCode::NOT_FOUND) => {}
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }
}
