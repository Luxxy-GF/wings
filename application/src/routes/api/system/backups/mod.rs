use super::State;
use utoipa_axum::router::OpenApiRouter;

mod test;

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .nest("/test", test::router(state))
        .with_state(state.clone())
}
