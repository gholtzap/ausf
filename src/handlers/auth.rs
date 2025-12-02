use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use std::collections::HashMap;
use uuid::Uuid;

use crate::clients::UdmClient;
use crate::crypto::{compute_hxres_star, derive_kseaf, verify_snn_authorization, validate_authentication_vector};
use crate::types::{
    AppError, AuthContextStore, AuthData5G, AuthType, AuthenticationInfo, Av5gAka, ConfirmationData,
    ConfirmationDataResponse, StoredAuthContext, UEAuthenticationCtx, AuthResult,
};
use crate::types::udm::{AuthenticationVector, ResynchronizationInfo};
use std::env;

pub async fn initiate_authentication(
    State(auth_store): State<AuthContextStore>,
    Json(payload): Json<AuthenticationInfo>,
) -> Result<Response, AppError> {
    tracing::info!(
        "Received authentication request for UE: {}",
        payload.supi_or_suci
    );

    let allowed_plmns = env::var("ALLOWED_PLMNS")
        .ok()
        .map(|s| s.split(',').map(|p| p.trim().to_string()).collect::<Vec<String>>());

    verify_snn_authorization(&payload.serving_network_name, allowed_plmns.as_ref())
        .map_err(|e| AppError::Forbidden(format!("SNN verification failed: {}", e)))?;

    tracing::info!(
        "SNN verification passed for: {}",
        payload.serving_network_name
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

    validate_authentication_vector(&auth_vector)
        .map_err(|e| AppError::InternalError(format!("Authentication vector validation failed: {}", e)))?;

    let AuthenticationVector::Av5gAka(av) = auth_vector else {
        return Err(AppError::InternalError("Unsupported authentication vector type".to_string()));
    };

    let rand_bytes = hex::decode(&av.rand)
        .map_err(|e| AppError::InternalError(format!("Invalid RAND from UDM: {}", e)))?;
    let xres_star_bytes = hex::decode(&av.xres_star)
        .map_err(|e| AppError::InternalError(format!("Invalid XRES* from UDM: {}", e)))?;
    let kausf_bytes = hex::decode(&av.kausf)
        .map_err(|e| AppError::InternalError(format!("Invalid KAUSF from UDM: {}", e)))?;

    let hxres_star = compute_hxres_star(&rand_bytes, &xres_star_bytes);
    let hxres_star_hex = hex::encode(&hxres_star);

    let auth_ctx_id = Uuid::new_v4().to_string();

    let stored_ctx = StoredAuthContext {
        supi_or_suci: payload.supi_or_suci.clone(),
        supi: auth_info_result.supi.clone(),
        rand: rand_bytes,
        xres_star: xres_star_bytes,
        kausf: kausf_bytes,
        serving_network_name: payload.serving_network_name.clone(),
    };

    auth_store
        .lock()
        .unwrap()
        .insert(auth_ctx_id.clone(), stored_ctx);

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
    State(auth_store): State<AuthContextStore>,
    Path(auth_ctx_id): Path<String>,
    Json(payload): Json<ConfirmationData>,
) -> Result<Json<ConfirmationDataResponse>, AppError> {
    tracing::info!(
        "Received 5G AKA confirmation for authCtxId: {}",
        auth_ctx_id
    );

    let stored_ctx = {
        let store = auth_store.lock().unwrap();
        store.get(&auth_ctx_id).cloned()
    };

    let stored_ctx = stored_ctx
        .ok_or_else(|| AppError::NotFound(format!("Authentication context not found: {}", auth_ctx_id)))?;

    let res_star_bytes = hex::decode(&payload.res_star)
        .map_err(|e| AppError::BadRequest(format!("Invalid RES* format: {}", e)))?;

    let hres_star = compute_hxres_star(&stored_ctx.rand, &res_star_bytes);

    let expected_hxres_star = compute_hxres_star(&stored_ctx.rand, &stored_ctx.xres_star);

    if hres_star != expected_hxres_star {
        tracing::warn!("RES* verification failed for authCtxId: {}", auth_ctx_id);
        return Ok(Json(ConfirmationDataResponse {
            auth_result: AuthResult::Failure,
            supi: None,
            kseaf: None,
        }));
    }

    let supi = stored_ctx.supi.or_else(|| Some(stored_ctx.supi_or_suci.clone()));

    let kseaf = derive_kseaf(&stored_ctx.kausf, &supi.clone().unwrap_or_default());
    let kseaf_hex = hex::encode(kseaf);

    auth_store.lock().unwrap().remove(&auth_ctx_id);

    tracing::info!("Authentication successful for authCtxId: {}", auth_ctx_id);

    Ok(Json(ConfirmationDataResponse {
        auth_result: AuthResult::Success,
        supi,
        kseaf: Some(kseaf_hex),
    }))
}
