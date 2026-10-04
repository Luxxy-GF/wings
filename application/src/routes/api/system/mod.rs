use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod backups;
mod config;
mod images;
mod ips;
mod logs;
mod overview;
mod restic;
mod stats;
mod upgrade;

mod get {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::GetState,
    };
    use serde::Serialize;
    use utoipa::ToSchema;

    #[derive(ToSchema, Serialize)]
    struct Response<'a> {
        architecture: &'static str,
        cpu_count: usize,
        kernel_version: String,
        os: &'static str,
        version: &'a str,
        runtime: RuntimeCapabilities,
    }

    #[derive(ToSchema, Serialize)]
    struct RuntimeCapabilities {
        backend: crate::config::RuntimeBackend,
        system_containers: bool,
        virtual_machines: bool,
        image_server: Option<String>,
    }

    #[utoipa::path(get, path = "/", responses(
        (status = OK, body = inline(Response)),
    ))]
    pub async fn route(state: GetState) -> ApiResponseResult {
        ApiResponse::new_serialized(Response {
            architecture: std::env::consts::ARCH,
            cpu_count: rayon::current_num_threads(),
            kernel_version: sysinfo::System::kernel_long_version(),
            os: std::env::consts::OS,
            version: &state.version,
            runtime: {
                let config = state.config.load();
                let incus = config.runtime.backend == crate::config::RuntimeBackend::Incus;
                RuntimeCapabilities {
                    backend: config.runtime.backend,
                    system_containers: incus,
                    virtual_machines: incus
                        && !config.tundra.enabled
                        && std::fs::OpenOptions::new()
                            .read(true)
                            .write(true)
                            .open("/dev/kvm")
                            .is_ok(),
                    image_server: incus.then(|| config.runtime.incus.image_server.clone()),
                }
            },
        })
        .ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(get::route))
        .nest("/overview", overview::router(state))
        .nest("/ips", ips::router(state))
        .nest("/images", images::router(state))
        .nest("/logs", logs::router(state))
        .nest("/upgrade", upgrade::router(state))
        .nest("/config", config::router(state))
        .nest("/stats", stats::router(state))
        .nest("/restic", restic::router(state))
        .nest("/backups", backups::router(state))
        .with_state(state.clone())
}
