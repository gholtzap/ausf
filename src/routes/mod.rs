use axum::{routing::{delete, get, patch, post, put}, Router};
use crate::handlers::{admin, auth, health};
use crate::types::AppState;

pub fn create_routes(app_state: AppState) -> Router {
    Router::new()
        .route("/health", get(health::health_check))
        .route("/status", get(health::status))
        .route("/nausf-auth/v1/ue-authentications", post(auth::initiate_authentication))
        .route("/nausf-auth/v1/ue-authentications/deregister", post(auth::deregister))
        .route("/nausf-auth/v1/ue-authentications/:authCtxId/5g-aka-confirmation", put(auth::confirm_5g_aka).delete(auth::delete_5g_aka_confirmation))
        .route("/admin/nf-profile", patch(admin::update_nf_profile))
        .with_state(app_state)
}
