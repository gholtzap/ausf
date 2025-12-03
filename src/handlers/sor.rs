use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use crate::crypto::sor::{compute_sor_mac_iausf, increment_counter_sor, sor_mac_to_hex, counter_sor_to_hex};
use crate::types::{
    AppError, AppState, SorInfo, SorSecurityInfo, StoredSorContext,
};

pub async fn ue_sor(
    State(app_state): State<AppState>,
    Path(supi): Path<String>,
    Json(payload): Json<SorInfo>,
) -> Result<Response, AppError> {
    tracing::info!("Received SoR request for SUPI: {}", supi);

    let stored_ctx = app_state
        .auth_store
        .get_by_supi(&supi)
        .await
        .map_err(|e| AppError::InternalError(format!("Failed to retrieve auth context: {}", e)))?
        .ok_or_else(|| AppError::NotFound(format!("Authentication context not found for SUPI: {}", supi)))?;

    let kausf = stored_ctx.kausf;

    let existing_sor = app_state
        .sor_store
        .get(&supi)
        .await
        .map_err(|e| AppError::InternalError(format!("Failed to retrieve SoR context: {}", e)))?;

    let counter_sor = if let Some(sor_ctx) = existing_sor {
        increment_counter_sor(sor_ctx.counter_sor)
            .map_err(|e| AppError::InternalError(format!("Failed to increment CounterSOR: {}", e)))?
    } else {
        0
    };

    let sor_header_bytes = payload.sor_header.as_ref().and_then(|h| {
        hex::decode(h).ok()
    });

    let sor_mac_iausf = compute_sor_mac_iausf(
        &kausf,
        sor_header_bytes.as_deref(),
        counter_sor,
    )
    .map_err(|e| AppError::InternalError(format!("Failed to compute SOR-MAC-IAUSF: {}", e)))?;

    let sor_mac_hex = sor_mac_to_hex(&sor_mac_iausf);
    let counter_hex = counter_sor_to_hex(counter_sor);

    let sor_context = StoredSorContext {
        supi: supi.clone(),
        kausf,
        counter_sor,
        sor_info: payload,
        created_at: chrono::Utc::now().timestamp(),
    };

    app_state
        .sor_store
        .insert(sor_context)
        .await
        .map_err(|e| AppError::InternalError(format!("Failed to store SoR context: {}", e)))?;

    tracing::info!("SoR protection successful for SUPI: {}", supi);

    let response = SorSecurityInfo {
        sor_mac_iausf: sor_mac_hex,
        counter_sor: counter_hex,
        sor_xmac_iue: None,
    };

    Ok((StatusCode::OK, Json(response)).into_response())
}
