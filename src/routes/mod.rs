use axum::{routing::{get, post, put}, Router};
use crate::handlers::{auth, health};
use crate::types::AuthContextStore;

pub fn create_routes(auth_store: AuthContextStore) -> Router {
    Router::new()
        .route("/health", get(health::health_check))
        .route("/status", get(health::status))
        .route("/nausf-auth/v1/ue-authentications", post(auth::initiate_authentication))
        .route("/nausf-auth/v1/ue-authentications/:authCtxId/5g-aka-confirmation", put(auth::confirm_5g_aka))
        .with_state(auth_store)
}
