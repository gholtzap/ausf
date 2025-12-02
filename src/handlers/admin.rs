use axum::{extract::State, http::StatusCode, Json};
use crate::types::{AppState, nrf::NFUpdateRequest};

pub async fn update_nf_profile(
    State(state): State<AppState>,
    Json(update): Json<NFUpdateRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    match state.nrf_client.update_nf(state.nf_instance_id, update).await {
        Ok(_) => {
            tracing::info!("NF profile updated successfully");
            Ok(StatusCode::NO_CONTENT)
        }
        Err(e) => {
            tracing::error!("Failed to update NF profile: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update NF profile: {}", e)))
        }
    }
}
