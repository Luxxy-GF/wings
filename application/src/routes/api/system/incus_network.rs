use super::State;
use crate::{
    response::{ApiResponse, ApiResponseResult},
    routes::GetState,
};
use utoipa_axum::{router::OpenApiRouter, routes};

#[utoipa::path(get, path = "/", responses((status = OK, body = serde_json::Value)))]
async fn route(state: GetState) -> ApiResponseResult {
    let inventory = state.executor.incus_network_inventory().await?;
    ApiResponse::new_serialized(inventory).ok()
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(route))
        .with_state(state.clone())
}
