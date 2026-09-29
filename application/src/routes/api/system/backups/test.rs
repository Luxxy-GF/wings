use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod post {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::GetState,
        server::backup::BackupTestTarget,
    };
    use serde::Serialize;
    use utoipa::ToSchema;

    const TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
    const MAX_ERROR_LENGTH: usize = 2048;

    #[derive(ToSchema, Serialize)]
    struct Response {
        successful: bool,
        duration_ms: u64,
        error: Option<compact_str::CompactString>,
    }

    #[utoipa::path(post, path = "/", responses(
        (status = OK, body = inline(Response)),
    ), request_body = BackupTestTarget)]
    pub async fn route(
        state: GetState,
        crate::Payload(data): crate::Payload<BackupTestTarget>,
    ) -> ApiResponseResult {
        let started = std::time::Instant::now();
        let result = match tokio::time::timeout(TEST_TIMEOUT, data.test(&state)).await {
            Ok(result) => result,
            Err(_) => Err(anyhow::anyhow!(
                "backup test timed out after {} seconds",
                TEST_TIMEOUT.as_secs()
            )),
        };

        ApiResponse::new_serialized(Response {
            successful: result.is_ok(),
            duration_ms: started.elapsed().as_millis() as u64,
            error: result
                .err()
                .map(|err| format!("{err:#}").chars().take(MAX_ERROR_LENGTH).collect()),
        })
        .ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(post::route))
        .with_state(state.clone())
}
