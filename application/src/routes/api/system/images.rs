use super::State;
use crate::{
    response::{ApiResponse, ApiResponseResult},
    routes::GetState,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::OnceLock, time::Duration};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

#[derive(Clone, Serialize, ToSchema)]
pub struct NativeImage {
    pub alias: String,
    pub label: String,
    pub kind: crate::server::configuration::NativeInstanceType,
}

#[derive(Deserialize)]
struct Catalog {
    products: BTreeMap<String, Product>,
}

#[derive(Deserialize)]
struct Product {
    aliases: String,
    arch: String,
    os: String,
    release: String,
    #[serde(default)]
    variant: String,
    versions: BTreeMap<String, Version>,
}

#[derive(Deserialize)]
struct Version {
    items: BTreeMap<String, Item>,
}

#[derive(Deserialize)]
struct Item {
    ftype: String,
}

async fn catalog(server: String) -> anyhow::Result<Vec<NativeImage>> {
    use crate::server::configuration::NativeInstanceType;
    use futures::StreamExt;
    let url = reqwest::Url::parse(&server)?;
    anyhow::ensure!(
        url.scheme() == "https" && url.username().is_empty() && url.password().is_none(),
        "OS image server must use HTTPS without embedded credentials"
    );
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?
        .get(format!(
            "{}/streams/v1/images.json",
            server.trim_end_matches('/')
        ))
        .send()
        .await?
        .error_for_status()?;
    let mut stream = response.bytes_stream();
    let mut data = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        anyhow::ensure!(
            data.len() + chunk.len() <= 32 * 1024 * 1024,
            "OS image catalog exceeds 32 MiB"
        );
        data.extend_from_slice(&chunk);
    }
    let catalog: Catalog = serde_json::from_slice(&data)?;
    let mut images = BTreeMap::new();
    for product in catalog.products.into_values() {
        let architecture_matches = match std::env::consts::ARCH {
            "x86_64" => matches!(product.arch.as_str(), "amd64" | "x86_64"),
            "aarch64" => matches!(product.arch.as_str(), "arm64" | "aarch64"),
            architecture => product.arch == architecture,
        };
        if !architecture_matches {
            continue;
        }
        let Some(version) = product
            .versions
            .last_key_value()
            .map(|(_, version)| version)
        else {
            continue;
        };
        let Some(alias) = product.aliases.split(',').find(|alias| !alias.is_empty()) else {
            continue;
        };
        for kind in [
            NativeInstanceType::Container,
            NativeInstanceType::VirtualMachine,
        ] {
            let available = version.items.values().any(|item| match kind {
                NativeInstanceType::Container => {
                    matches!(item.ftype.as_str(), "root.tar.xz" | "squashfs")
                }
                NativeInstanceType::VirtualMachine => matches!(
                    item.ftype.as_str(),
                    "disk-kvm.img" | "disk1.img" | "disk.img"
                ),
            });
            if available {
                images.insert(
                    (alias.to_string(), kind.incus_type()),
                    NativeImage {
                        alias: alias.into(),
                        label: format!("{} {} {}", product.os, product.release, product.variant)
                            .trim()
                            .to_string(),
                        kind,
                    },
                );
            }
        }
    }
    Ok(images.into_values().collect())
}

#[utoipa::path(get, path = "/", responses((status = OK, body = Vec<NativeImage>)))]
async fn route(state: GetState) -> ApiResponseResult {
    static CACHE: OnceLock<moka::future::Cache<String, Vec<NativeImage>>> = OnceLock::new();
    let config = state.config.load();
    if config.runtime.backend != crate::config::RuntimeBackend::Incus {
        return ApiResponse::error("OS images require an Incus node")
            .with_status(axum::http::StatusCode::BAD_REQUEST)
            .ok();
    }
    let server = config.runtime.incus.image_server.clone();
    drop(config);
    let cache = CACHE.get_or_init(|| {
        moka::future::Cache::builder()
            .max_capacity(4)
            .time_to_live(Duration::from_secs(3600))
            .build()
    });
    let images = cache
        .try_get_with(server.clone(), catalog(server))
        .await
        .map_err(|error| anyhow::anyhow!("fetching OS image catalog: {error:#}"))?;
    ApiResponse::new_serialized(images).ok()
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(route))
        .with_state(state.clone())
}
