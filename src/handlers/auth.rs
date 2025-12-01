use axum::{
    extract::Path,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use std::collections::HashMap;
use uuid::Uuid;

use crate::clients::UdmClient;
use crate::crypto::kdf::compute_hxres_star;
use crate::types::{
    AppError, AuthData5G, AuthType, AuthenticationInfo, Av5gAka, ConfirmationData,
    ConfirmationDataResponse, UEAuthenticationCtx, AuthResult,
};
use crate::types::udm::{AuthenticationVector, ResynchronizationInfo};

pub async fn initiate_authentication(
    Json(payload): Json<AuthenticationInfo>,
) -> Result<Response, AppError> {
    tracing::info!(
        "Received authentication request for UE: {}",
        payload.supi_or_suci
    );

    let udm_client = UdmClient::new()
        .map_err(|e| AppError::InternalError(format!("Failed to create UDM client: {}", e)))?;

    let resync_info = payload.resynchronization_info.as_ref().map(|r| ResynchronizationInfo {
        rand: r.rand.clone(),
        auts: r.auts.clone(),
    });

    let auth_info_result = udm_client
        .get_authentication_info(
            &payload.supi_or_suci,
            &payload.serving_network_name,
            resync_info,
        )
        .await
        .map_err(|e| AppError::InternalError(format!("UDM request failed: {}", e)))?;

    let auth_vector = auth_info_result
        .authentication_vector
        .ok_or_else(|| AppError::InternalError("No authentication vector received from UDM".to_string()))?;

    let AuthenticationVector::Av5gAka(av) = auth_vector else {
        return Err(AppError::InternalError("Unsupported authentication vector type".to_string()));
    };

    let rand_bytes = hex::decode(&av.rand)
        .map_err(|e| AppError::InternalError(format!("Invalid RAND from UDM: {}", e)))?;
    let xres_star_bytes = hex::decode(&av.xres_star)
        .map_err(|e| AppError::InternalError(format!("Invalid XRES* from UDM: {}", e)))?;

    let hxres_star = compute_hxres_star(&rand_bytes, &xres_star_bytes);
    let hxres_star_hex = hex::encode(hxres_star);

    let auth_ctx_id = Uuid::new_v4().to_string();

    let auth_ctx = UEAuthenticationCtx {
        auth_type: AuthType::FiveGAka,
        auth_data_5g: AuthData5G::Av5gAka(Av5gAka {
            rand: av.rand,
            hxres_star: hxres_star_hex,
            autn: av.autn,
        }),
        _links: Some({
            let mut links = HashMap::new();
            links.insert(
                "5g-aka".to_string(),
                crate::types::LinkValue {
                    href: format!("/nausf-auth/v1/ue-authentications/{}/5g-aka-confirmation", auth_ctx_id),
                },
            );
            links
        }),
        serving_network_name: Some(payload.serving_network_name),
    };

    let location = format!("/nausf-auth/v1/ue-authentications/{}", auth_ctx_id);

    Ok((
        StatusCode::CREATED,
        [(axum::http::header::LOCATION, location)],
        Json(auth_ctx),
    )
        .into_response())
}

pub async fn confirm_5g_aka(
    Path(auth_ctx_id): Path<String>,
    Json(_payload): Json<ConfirmationData>,
) -> Result<Json<ConfirmationDataResponse>, AppError> {
    tracing::info!(
        "Received 5G AKA confirmation for authCtxId: {}",
        auth_ctx_id
    );

    Ok(Json(ConfirmationDataResponse {
        auth_result: AuthResult::Success,
        supi: Some("imsi-123456789012345".to_string()),
        kseaf: Some("0123456789ABCDEF0123456789ABCDEF".to_string()),
    }))
}
