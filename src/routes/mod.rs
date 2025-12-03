use axum::{middleware, routing::{delete, get, patch, post, put}, Router};
use crate::handlers::{admin, auth, health, nrf, sor, upu};
use crate::middleware::{oauth2_auth, validate_request};
use crate::types::AppState;

pub fn create_routes(app_state: AppState) -> Router {
    let protected_routes = Router::new()
        .route("/nausf-auth/v1/ue-authentications", post(auth::initiate_authentication))
        .route("/nausf-auth/v1/ue-authentications/deregister", post(auth::deregister))
        .route("/nausf-auth/v1/ue-authentications/:authCtxId/5g-aka-confirmation", put(auth::confirm_5g_aka).delete(auth::delete_5g_aka_confirmation))
        .route("/nausf-auth/v1/ue-authentications/:authCtxId/eap-session", post(auth::eap_session).delete(auth::delete_eap_session))
        .route("/nausf-sorprotection/v1/:supi/ue-sor", post(sor::ue_sor))
        .route("/nausf-upuprotection/v1/:supi/ue-upu", post(upu::ue_upu))
        .route("/admin/nf-profile", patch(admin::update_nf_profile))
        .route_layer(middleware::from_fn_with_state(app_state.clone(), validate_request))
        .route_layer(middleware::from_fn_with_state(app_state.clone(), oauth2_auth));

    Router::new()
        .route("/health", get(health::health_check))
        .route("/status", get(health::status))
        .route("/nnrf-nfm/v1/nf-status-notify", post(nrf::nf_status_notify))
        .merge(protected_routes)
        .with_state(app_state)
}
