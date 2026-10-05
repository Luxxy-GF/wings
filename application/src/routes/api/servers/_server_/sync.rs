use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod post {
    use crate::{
        remote::servers::RawServer,
        response::{ApiResponse, ApiResponseResult},
        routes::{GetState, api::servers::_server_::GetServer},
        server::state::ServerState,
    };
    use serde::{Deserialize, Serialize};
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct Payload {
        #[schema(value_type = serde_json::Value)]
        server: Option<Box<RawServer>>,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {}

    #[utoipa::path(post, path = "/", responses(
        (status = OK, body = inline(Response)),
    ), params(
        (
            "server" = uuid::Uuid,
            description = "The server uuid",
            example = "123e4567-e89b-12d3-a456-426614174000",
        ),
    ), request_body = inline(Payload))]
    pub async fn route(
        state: GetState,
        server: GetServer,
        data: Result<crate::Payload<Payload>, crate::payload::PayloadRejection>,
    ) -> ApiResponseResult {
        let data = match data {
            Ok(data) => data.0,
            Err(_) => Payload { server: None },
        };

        if let Some(mut configuration) = data.server {
            if configuration.settings.uuid != server.uuid {
                return ApiResponse::error("server configuration UUID mismatch")
                    .with_status(axum::http::StatusCode::BAD_REQUEST)
                    .ok();
            }
            state
                .config
                .client
                .resolve_incus_metadata(&mut configuration)
                .await?;
            let suspended = configuration.settings.suspended;

            server
                .update_configuration(
                    configuration.settings,
                    configuration.process_configuration,
                    false,
                )
                .await;

            if suspended && server.state.get_state() != ServerState::Offline {
                tokio::spawn(async move {
                    if let Err(err) = server
                        .stop_with_kill_timeout(std::time::Duration::from_secs(30), true)
                        .await
                    {
                        tracing::error!(%err, "failed to stop server after being suspended");
                    }
                });
            }
        } else {
            let configuration = state.config.client.server(server.uuid).await?;
            let suspended = configuration.settings.suspended;

            server
                .update_configuration(
                    configuration.settings,
                    configuration.process_configuration,
                    false,
                )
                .await;

            if suspended && server.state.get_state() != ServerState::Offline {
                tokio::spawn(async move {
                    if let Err(err) = server
                        .stop_with_kill_timeout(std::time::Duration::from_secs(30), true)
                        .await
                    {
                        tracing::error!(%err, "failed to stop server after being suspended");
                    }
                });
            }
        }

        ApiResponse::new_serialized(Response {}).ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(post::route))
        .with_state(state.clone())
}
