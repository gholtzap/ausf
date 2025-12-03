use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use crate::crypto::upu::{compute_upu_mac_iausf, increment_counter_upu, upu_mac_to_hex, counter_upu_to_hex};
use crate::types::{
    AppError, AppState, UpuInfo, UpuSecurityInfo, StoredUpuContext,
};

pub async fn ue_upu(
    State(app_state): State<AppState>,
    Path(supi): Path<String>,
    Json(payload): Json<UpuInfo>,
) -> Result<Response, AppError> {
    tracing::info!("Received UPU request for SUPI: {}", supi);

    let stored_ctx = app_state
        .auth_store
        .get_by_supi(&supi)
        .await
        .map_err(|e| AppError::InternalError(format!("Failed to retrieve auth context: {}", e)))?
        .ok_or_else(|| AppError::NotFound(format!("Authentication context not found for SUPI: {}", supi)))?;

    let kausf = stored_ctx.kausf;

    let existing_upu = app_state
        .upu_store
        .get(&supi)
        .await
        .map_err(|e| AppError::InternalError(format!("Failed to retrieve UPU context: {}", e)))?;

    let counter_upu = if let Some(upu_ctx) = existing_upu {
        increment_counter_upu(upu_ctx.counter_upu)
            .map_err(|e| AppError::InternalError(format!("Failed to increment CounterUPU: {}", e)))?
    } else {
        0
    };

    let upu_header_bytes = payload.upu_header.as_ref().and_then(|h| {
        hex::decode(h).ok()
    });

    let upu_mac_iausf = compute_upu_mac_iausf(
        &kausf,
        upu_header_bytes.as_deref(),
        counter_upu,
    )
    .map_err(|e| AppError::InternalError(format!("Failed to compute UPU-MAC-IAUSF: {}", e)))?;

    let upu_mac_hex = upu_mac_to_hex(&upu_mac_iausf);
    let counter_hex = counter_upu_to_hex(counter_upu);

    let upu_context = StoredUpuContext {
        supi: supi.clone(),
        kausf,
        counter_upu,
        upu_info: payload,
        created_at: chrono::Utc::now().timestamp(),
    };

    app_state
        .upu_store
        .insert(upu_context)
        .await
        .map_err(|e| AppError::InternalError(format!("Failed to store UPU context: {}", e)))?;

    tracing::info!("UPU protection successful for SUPI: {}", supi);

    let response = UpuSecurityInfo {
        upu_mac_iausf: upu_mac_hex,
        counter_upu: counter_hex,
        upu_xmac_iue: None,
    };

    Ok((StatusCode::OK, Json(response)).into_response())
}
