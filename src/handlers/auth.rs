use axum::{
    extract::Path,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use std::collections::HashMap;
use uuid::Uuid;

use crate::types::{
    AppError, AuthData5G, AuthType, AuthenticationInfo, Av5gAka, ConfirmationData,
    ConfirmationDataResponse, UEAuthenticationCtx, AuthResult,
};

pub async fn initiate_authentication(
    Json(payload): Json<AuthenticationInfo>,
) -> Result<Response, AppError> {
    tracing::info!(
        "Received authentication request for UE: {}",
        payload.supi_or_suci
    );

    let auth_ctx_id = Uuid::new_v4().to_string();

    let auth_ctx = UEAuthenticationCtx {
        auth_type: AuthType::FiveGAka,
        auth_data_5g: AuthData5G::Av5gAka(Av5gAka {
            rand: "00112233445566778899AABBCCDDEEFF".to_string(),
            hxres_star: "FEDCBA9876543210FEDCBA9876543210".to_string(),
            autn: "0011223344556677AABBCCDDEEFF0011".to_string(),
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
    Json(payload): Json<ConfirmationData>,
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
