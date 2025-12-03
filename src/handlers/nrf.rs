use axum::{extract::State, http::StatusCode, Json};
use crate::types::{AppState, nrf::NFStatusNotify};

pub async fn nf_status_notify(
    State(state): State<AppState>,
    Json(notification): Json<NFStatusNotify>,
) -> StatusCode {
    tracing::info!("Received NF status notification for subscription: {}", notification.subscription_id);
    tracing::debug!("Notification details: {:?}", notification);

    if let Some(profile) = &notification.nf_profile {
        tracing::info!("NF instance {} status update: {:?}", profile.nf_instance_id, profile.nf_status);
    }

    StatusCode::NO_CONTENT
}
