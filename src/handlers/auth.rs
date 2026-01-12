use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::Engine;
use std::collections::HashMap;
use uuid::Uuid;

use crate::crypto::{compute_hxres_star, derive_kseaf, verify_snn_authorization, validate_authentication_vector, check_home_network, NetworkLocation};
use crate::types::{
    AppError, AppState, AuthData5G, AuthType, AuthenticationInfo, Av5gAka, ConfirmationData,
    ConfirmationDataResponse, StoredAuthContext, UEAuthenticationCtx, AuthResult, SupiOrSuci,
    DeregistrationInfo, EapAkaPrimeSession, EapAkaPrimeState, StateTransition, EapPacket,
    EapCode, EapData, EapRequestResponse, EapType, EapPayload,
};
use crate::types::udm::{AuthenticationVector, ResynchronizationInfo};
use std::env;

pub async fn initiate_authentication(
    State(app_state): State<AppState>,
    Json(payload): Json<AuthenticationInfo>,
) -> Result<Response, AppError> {
    tracing::info!(
        event = "auth_initiation_request",
        supi_or_suci = %payload.supi_or_suci,
        serving_network = %payload.serving_network_name,
        "Received authentication request"
    );

    let identity = SupiOrSuci::parse(&payload.supi_or_suci)
        .map_err(|e| {
            tracing::warn!(
                event = "auth_initiation_failed",
                supi_or_suci = %payload.supi_or_suci,
                reason = "invalid_format",
                error = %e,
                "Authentication initiation failed: Invalid SUPI/SUCI format"
            );
            AppError::BadRequest(format!("Invalid SUPI/SUCI format: {}", e))
        })?;

    if let Some(plmn) = identity.extract_plmn() {
        plmn.validate()
            .map_err(|e| {
                tracing::warn!(
                    event = "auth_initiation_failed",
                    supi_or_suci = %payload.supi_or_suci,
                    reason = "invalid_plmn",
                    error = %e,
                    "Authentication initiation failed: Invalid PLMN"
                );
                AppError::BadRequest(format!("Invalid PLMN: {}", e))
            })?;
        tracing::info!("Extracted and validated PLMN: {}", plmn.to_string());
    }

    let network_location = check_home_network(&identity)
        .map_err(|e| {
            tracing::warn!(
                event = "auth_initiation_failed",
                supi_or_suci = %payload.supi_or_suci,
                reason = "home_network_check_failed",
                error = %e,
                "Authentication initiation failed: Home network check failed"
            );
            AppError::InternalError(format!("Home network check failed: {}", e))
        })?;

    match network_location {
        NetworkLocation::Home => {
            tracing::info!("Home network authentication for UE: {}", payload.supi_or_suci);
        }
        NetworkLocation::Visited => {
            tracing::info!("Visited network authentication (roaming) for UE: {}", payload.supi_or_suci);
        }
    }

    let allowed_plmns = env::var("ALLOWED_PLMNS")
        .ok()
        .map(|s| s.split(',').map(|p| p.trim().to_string()).collect::<Vec<String>>());

    verify_snn_authorization(&payload.serving_network_name, allowed_plmns.as_ref())
        .map_err(|e| {
            tracing::warn!(
                event = "auth_initiation_failed",
                supi_or_suci = %payload.supi_or_suci,
                serving_network = %payload.serving_network_name,
                reason = "snn_verification_failed",
                error = %e,
                "Authentication initiation failed: Serving network not authorized"
            );
            AppError::Forbidden(format!("SNN verification failed: {}", e))
        })?;

    tracing::info!(
        "SNN verification passed for: {}",
        payload.serving_network_name
    );

    let resync_info = payload.resynchronization_info.as_ref().map(|r| ResynchronizationInfo {
        rand: r.rand.clone(),
        auts: r.auts.clone(),
    });

    let supi = identity.to_supi()
        .map_err(|e| AppError::BadRequest(format!("Failed to de-conceal SUCI: {}", e)))?;
    let supi_string = supi.to_string();

    tracing::info!("Calling UDM to get authentication info for UE: {} (SUPI: {})", payload.supi_or_suci, supi_string);
    let auth_info_result = app_state.udm_client
        .get_authentication_info(
            &supi_string,
            &payload.serving_network_name,
            resync_info,
            &app_state.nf_instance_id.to_string(),
        )
        .await
        .map_err(|e| {
            tracing::error!(
                event = "auth_initiation_failed",
                supi = %supi_string,
                serving_network = %payload.serving_network_name,
                reason = "udm_request_failed",
                error = %e,
                "Authentication initiation failed: UDM request failed"
            );
            AppError::InternalError(format!("UDM request failed: {}", e))
        })?;

    tracing::info!("Received authentication info from UDM");
    let auth_vector = auth_info_result
        .authentication_vector
        .ok_or_else(|| {
            tracing::error!("No authentication vector received from UDM");
            AppError::InternalError("No authentication vector received from UDM".to_string())
        })?;

    tracing::info!("Validating authentication vector");
    validate_authentication_vector(&auth_vector)
        .map_err(|e| {
            tracing::error!("Authentication vector validation failed: {}", e);
            AppError::InternalError(format!("Authentication vector validation failed: {}", e))
        })?;

    tracing::info!("Authentication vector validated successfully");
    let AuthenticationVector::Av5gAka(av) = auth_vector else {
        tracing::error!("Unsupported authentication vector type");
        return Err(AppError::InternalError("Unsupported authentication vector type".to_string()));
    };

    tracing::info!("Decoding hex values from UDM (RAND, XRES*, KAUSF)");
    tracing::debug!("UDM response - RAND: {}, AUTN: {}, XRES*: {}", av.rand, av.autn, av.xres_star);
    let rand_bytes = hex::decode(&av.rand)
        .map_err(|e| {
            tracing::error!("Invalid RAND from UDM: {}", e);
            AppError::InternalError(format!("Invalid RAND from UDM: {}", e))
        })?;
    let xres_star_bytes = hex::decode(&av.xres_star)
        .map_err(|e| {
            tracing::error!("Invalid XRES* from UDM: {}", e);
            AppError::InternalError(format!("Invalid XRES* from UDM: {}", e))
        })?;
    let kausf_bytes = hex::decode(&av.kausf)
        .map_err(|e| {
            tracing::error!("Invalid KAUSF from UDM: {}", e);
            AppError::InternalError(format!("Invalid KAUSF from UDM: {}", e))
        })?;

    tracing::info!("Successfully decoded all hex values");
    let hxres_star = compute_hxres_star(&rand_bytes, &xres_star_bytes);
    let hxres_star_hex = hex::encode(&hxres_star);

    let auth_ctx_id = Uuid::new_v4().to_string();

    let stored_ctx = StoredAuthContext {
        auth_ctx_id: auth_ctx_id.clone(),
        supi_or_suci: payload.supi_or_suci.clone(),
        supi: auth_info_result.supi.clone(),
        rand: rand_bytes,
        xres_star: xres_star_bytes,
        kausf: kausf_bytes,
        serving_network_name: payload.serving_network_name.clone(),
        eap_session: None,
    };

    tracing::info!("Storing authentication context in MongoDB with ID: {}", auth_ctx_id);
    app_state
        .auth_store
        .insert(auth_ctx_id.clone(), stored_ctx)
        .await
        .map_err(|e| {
            tracing::error!(
                event = "auth_initiation_failed",
                supi = %supi_string,
                auth_ctx_id = %auth_ctx_id,
                reason = "context_storage_failed",
                error = %e,
                "Authentication initiation failed: Failed to store context"
            );
            AppError::InternalError(format!("Failed to store auth context: {}", e))
        })?;

    tracing::info!(
        event = "auth_initiation_success",
        supi = %supi_string,
        auth_ctx_id = %auth_ctx_id,
        serving_network = %payload.serving_network_name,
        "Authentication context stored successfully"
    );

    let auth_ctx = UEAuthenticationCtx {
        auth_type: AuthType::FiveGAka,
        auth_data_5g: AuthData5G::Av5gAka(Av5gAka {
            rand: av.rand.clone(),
            hxres_star: hxres_star_hex.clone(),
            autn: av.autn.clone(),
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

    tracing::debug!("Sending to AMF - RAND: {}, AUTN: {}, HXRES*: {}", av.rand, av.autn, hxres_star_hex);

    let location = format!("/nausf-auth/v1/ue-authentications/{}", auth_ctx_id);

    Ok((
        StatusCode::CREATED,
        [(axum::http::header::LOCATION, location)],
        Json(auth_ctx),
    )
        .into_response())
}

pub async fn confirm_5g_aka(
    State(app_state): State<AppState>,
    Path(auth_ctx_id): Path<String>,
    Json(payload): Json<ConfirmationData>,
) -> Result<Json<ConfirmationDataResponse>, AppError> {
    tracing::info!(
        event = "auth_confirmation_request",
        auth_ctx_id = %auth_ctx_id,
        "Received 5G AKA confirmation request"
    );

    let stored_ctx = app_state
        .auth_store
        .get(&auth_ctx_id)
        .await
        .map_err(|e| {
            tracing::error!(
                event = "auth_confirmation_failed",
                auth_ctx_id = %auth_ctx_id,
                reason = "context_retrieval_failed",
                error = %e,
                "Authentication confirmation failed: Context retrieval error"
            );
            AppError::InternalError(format!("Failed to retrieve auth context: {}", e))
        })?
        .ok_or_else(|| {
            tracing::warn!(
                event = "auth_confirmation_failed",
                auth_ctx_id = %auth_ctx_id,
                reason = "context_not_found",
                "Authentication confirmation failed: Context not found"
            );
            AppError::NotFound(format!("Authentication context not found: {}", auth_ctx_id))
        })?;

    let res_star_bytes = hex::decode(&payload.res_star)
        .map_err(|e| AppError::BadRequest(format!("Invalid RES* format: {}", e)))?;

    let hres_star = compute_hxres_star(&stored_ctx.rand, &res_star_bytes);

    let expected_hxres_star = compute_hxres_star(&stored_ctx.rand, &stored_ctx.xres_star);

    if hres_star != expected_hxres_star {
        tracing::warn!(
            event = "auth_confirmation_failed",
            auth_ctx_id = %auth_ctx_id,
            supi = stored_ctx.supi.as_ref().unwrap_or(&stored_ctx.supi_or_suci),
            reason = "res_star_mismatch",
            "Authentication confirmation failed: RES* verification failed"
        );
        return Ok(Json(ConfirmationDataResponse {
            auth_result: AuthResult::Failure,
            supi: None,
            kseaf: None,
        }));
    }

    let supi = stored_ctx.supi.or_else(|| Some(stored_ctx.supi_or_suci.clone()));

    tracing::debug!("KSEAF Derivation Inputs:");
    tracing::debug!("  KAUSF ({} bytes): {}", stored_ctx.kausf.len(), hex::encode(&stored_ctx.kausf));
    tracing::debug!("  Serving Network Name: '{}'", stored_ctx.serving_network_name);
    tracing::debug!("  SNN bytes ({} bytes): {}", stored_ctx.serving_network_name.len(), hex::encode(stored_ctx.serving_network_name.as_bytes()));

    let kseaf = derive_kseaf(&stored_ctx.kausf, &stored_ctx.serving_network_name);
    let kseaf_hex = hex::encode(kseaf);

    tracing::debug!("  KSEAF result ({} bytes): {}", kseaf_hex.len() / 2, kseaf_hex);

    app_state
        .auth_store
        .delete(&auth_ctx_id)
        .await
        .map_err(|e| AppError::InternalError(format!("Failed to delete auth context: {}", e)))?;

    tracing::debug!("Derived KSEAF: {}", kseaf_hex);
    tracing::info!(
        event = "auth_confirmation_success",
        auth_ctx_id = %auth_ctx_id,
        supi = supi.as_ref().unwrap_or(&"unknown".to_string()),
        "Authentication confirmed successfully"
    );

    Ok(Json(ConfirmationDataResponse {
        auth_result: AuthResult::Success,
        supi,
        kseaf: Some(kseaf_hex),
    }))
}

pub async fn delete_5g_aka_confirmation(
    State(app_state): State<AppState>,
    Path(auth_ctx_id): Path<String>,
) -> Result<StatusCode, AppError> {
    tracing::info!(
        "Received delete request for 5G AKA confirmation, authCtxId: {}",
        auth_ctx_id
    );

    let exists = app_state
        .auth_store
        .get(&auth_ctx_id)
        .await
        .map_err(|e| AppError::InternalError(format!("Failed to check auth context: {}", e)))?
        .is_some();

    if !exists {
        return Err(AppError::NotFound(format!(
            "Authentication context not found: {}",
            auth_ctx_id
        )));
    }

    app_state
        .auth_store
        .delete(&auth_ctx_id)
        .await
        .map_err(|e| AppError::InternalError(format!("Failed to delete auth context: {}", e)))?;

    tracing::info!("Successfully deleted authentication context: {}", auth_ctx_id);
    Ok(StatusCode::NO_CONTENT)
}

pub async fn deregister(
    State(app_state): State<AppState>,
    Json(payload): Json<DeregistrationInfo>,
) -> Result<StatusCode, AppError> {
    tracing::info!(
        event = "deregistration_request",
        supi = %payload.supi,
        "Received deregistration request"
    );

    let deleted_count = app_state
        .auth_store
        .delete_by_supi(&payload.supi)
        .await
        .map_err(|e| {
            tracing::error!(
                event = "deregistration_failed",
                supi = %payload.supi,
                error = %e,
                "Deregistration failed: Failed to delete auth contexts"
            );
            AppError::InternalError(format!("Failed to delete auth contexts by SUPI: {}", e))
        })?;

    tracing::info!(
        event = "deregistration_success",
        supi = %payload.supi,
        contexts_deleted = deleted_count,
        "Deregistration completed successfully"
    );

    Ok(StatusCode::NO_CONTENT)
}

pub async fn eap_session(
    State(app_state): State<AppState>,
    Path(auth_ctx_id): Path<String>,
    Json(payload): Json<EapPayload>,
) -> Result<Response, AppError> {
    tracing::info!(
        "Received EAP session request for authCtxId: {}",
        auth_ctx_id
    );

    let mut stored_ctx = app_state
        .auth_store
        .get(&auth_ctx_id)
        .await
        .map_err(|e| AppError::InternalError(format!("Failed to retrieve auth context: {}", e)))?
        .ok_or_else(|| AppError::NotFound(format!("Authentication context not found: {}", auth_ctx_id)))?;

    let eap_payload_bytes = base64::engine::general_purpose::STANDARD
        .decode(&payload.eap_payload)
        .map_err(|e| AppError::BadRequest(format!("Invalid EAP payload base64: {}", e)))?;

    let eap_packet = EapPacket::from_bytes(&eap_payload_bytes)
        .map_err(|e| AppError::BadRequest(format!("Invalid EAP packet: {}", e)))?;

    if stored_ctx.eap_session.is_none() {
        let identity = stored_ctx.supi_or_suci.clone();
        let network_name = stored_ctx.serving_network_name.clone();
        stored_ctx.eap_session = Some(EapAkaPrimeSession::new(network_name, identity));
    }

    let session = stored_ctx.eap_session.as_mut().unwrap();

    let response_packet = match eap_packet.data {
        EapData::Response(ref req_resp) if req_resp.eap_type == EapType::EapAkaPrime => {
            let eap_msg = crate::types::EapAkaPrimeMessage::from_bytes(&req_resp.type_data)
                .map_err(|e| AppError::BadRequest(format!("Invalid EAP-AKA' message: {}", e)))?;

            let transition = session.process_response(&eap_msg)
                .map_err(|e| AppError::BadRequest(format!("EAP-AKA' processing failed: {}", e)))?;

            match transition {
                StateTransition::ToSuccess => {
                    session.transition(EapAkaPrimeState::Success);
                    EapPacket::new(
                        EapCode::Success,
                        session.identifier,
                        EapData::Success,
                    )
                }
                StateTransition::ToFailure => {
                    session.transition(EapAkaPrimeState::Failure);
                    EapPacket::new(
                        EapCode::Failure,
                        session.identifier,
                        EapData::Failure,
                    )
                }
                StateTransition::ToChallenge => {
                    session.transition(EapAkaPrimeState::Challenge);
                    let rand = hex::decode(&stored_ctx.rand.clone())
                        .map_err(|_| AppError::InternalError("Invalid RAND in storage".to_string()))?;
                    let autn_bytes = session.autn.clone()
                        .ok_or_else(|| AppError::InternalError("Missing AUTN in session".to_string()))?;

                    let eap_challenge = session.build_challenge_request(rand, autn_bytes)
                        .map_err(|e| AppError::InternalError(format!("Failed to build challenge: {}", e)))?;

                    let identifier = session.next_identifier();
                    EapPacket::new(
                        EapCode::Request,
                        identifier,
                        EapData::Request(EapRequestResponse {
                            eap_type: EapType::EapAkaPrime,
                            type_data: eap_challenge.to_bytes(),
                        }),
                    )
                }
                StateTransition::ToResynchronization => {
                    let rand = session.rand.clone()
                        .ok_or_else(|| AppError::InternalError("Missing RAND in session".to_string()))?;
                    let auts = session.auts.clone()
                        .ok_or_else(|| AppError::InternalError("Missing AUTS in session".to_string()))?;

                    let resync_info = ResynchronizationInfo {
                        rand: hex::encode(&rand),
                        auts: hex::encode(&auts),
                    };

                    let identity = SupiOrSuci::parse(&stored_ctx.supi_or_suci)
                        .map_err(|e| AppError::InternalError(format!("Invalid SUPI/SUCI in stored context: {}", e)))?;
                    let supi = identity.to_supi()
                        .map_err(|e| AppError::InternalError(format!("Failed to de-conceal SUCI during resync: {}", e)))?;
                    let supi_string = supi.to_string();

                    let auth_info_result = app_state.udm_client
                        .get_authentication_info(
                            &supi_string,
                            &stored_ctx.serving_network_name,
                            Some(resync_info),
                            &app_state.nf_instance_id.to_string(),
                        )
                        .await
                        .map_err(|e| AppError::InternalError(format!("UDM resynchronization request failed: {}", e)))?;

                    let auth_vector = auth_info_result
                        .authentication_vector
                        .ok_or_else(|| AppError::InternalError("No authentication vector received from UDM after resync".to_string()))?;

                    let AuthenticationVector::Av5gAka(av) = auth_vector else {
                        return Err(AppError::InternalError("Unsupported authentication vector type".to_string()));
                    };

                    let new_rand = hex::decode(&av.rand)
                        .map_err(|e| AppError::InternalError(format!("Invalid RAND from UDM: {}", e)))?;
                    let new_autn = hex::decode(&av.autn)
                        .map_err(|e| AppError::InternalError(format!("Invalid AUTN from UDM: {}", e)))?;
                    let new_xres_star = hex::decode(&av.xres_star)
                        .map_err(|e| AppError::InternalError(format!("Invalid XRES* from UDM: {}", e)))?;
                    let new_kausf = hex::decode(&av.kausf)
                        .map_err(|e| AppError::InternalError(format!("Invalid KAUSF from UDM: {}", e)))?;

                    stored_ctx.rand = new_rand.clone();
                    stored_ctx.xres_star = new_xres_star;
                    stored_ctx.kausf = new_kausf;

                    let eap_challenge = session.build_challenge_request(new_rand, new_autn)
                        .map_err(|e| AppError::InternalError(format!("Failed to build challenge after resync: {}", e)))?;

                    session.transition(EapAkaPrimeState::Challenge);
                    let identifier = session.next_identifier();
                    EapPacket::new(
                        EapCode::Request,
                        identifier,
                        EapData::Request(EapRequestResponse {
                            eap_type: EapType::EapAkaPrime,
                            type_data: eap_challenge.to_bytes(),
                        }),
                    )
                }
                StateTransition::ToReauthentication => {
                    let eap_reauth = session.build_reauthentication_request()
                        .map_err(|e| AppError::InternalError(format!("Failed to build reauthentication request: {}", e)))?;

                    session.transition(EapAkaPrimeState::Reauthentication);
                    let identifier = session.next_identifier();
                    EapPacket::new(
                        EapCode::Request,
                        identifier,
                        EapData::Request(EapRequestResponse {
                            eap_type: EapType::EapAkaPrime,
                            type_data: eap_reauth.to_bytes(),
                        }),
                    )
                }
                _ => {
                    return Err(AppError::InternalError("Unexpected state transition".to_string()));
                }
            }
        }
        EapData::Response(_) => {
            let identifier = session.next_identifier();
            let identity_req = session.build_identity_request();
            session.transition(EapAkaPrimeState::Identity);

            EapPacket::new(
                EapCode::Request,
                identifier,
                EapData::Request(EapRequestResponse {
                    eap_type: EapType::EapAkaPrime,
                    type_data: identity_req.to_bytes(),
                }),
            )
        }
        _ => {
            return Err(AppError::BadRequest("Invalid EAP packet type".to_string()));
        }
    };

    let serving_network_name = stored_ctx.serving_network_name.clone();

    app_state
        .auth_store
        .insert(auth_ctx_id.clone(), stored_ctx)
        .await
        .map_err(|e| AppError::InternalError(format!("Failed to update auth context: {}", e)))?;

    let response_bytes = response_packet.to_bytes();
    let response_payload = base64::engine::general_purpose::STANDARD.encode(&response_bytes);

    let auth_ctx = UEAuthenticationCtx {
        auth_type: AuthType::EapAkaPrime,
        auth_data_5g: AuthData5G::EapPayload(EapPayload {
            eap_payload: response_payload,
        }),
        _links: Some({
            let mut links = HashMap::new();
            links.insert(
                "eap-session".to_string(),
                crate::types::LinkValue {
                    href: format!("/nausf-auth/v1/ue-authentications/{}/eap-session", auth_ctx_id),
                },
            );
            links
        }),
        serving_network_name: Some(serving_network_name),
    };

    Ok((StatusCode::OK, Json(auth_ctx)).into_response())
}

pub async fn delete_eap_session(
    State(app_state): State<AppState>,
    Path(auth_ctx_id): Path<String>,
) -> Result<StatusCode, AppError> {
    tracing::info!(
        "Received delete request for EAP session, authCtxId: {}",
        auth_ctx_id
    );

    let exists = app_state
        .auth_store
        .get(&auth_ctx_id)
        .await
        .map_err(|e| AppError::InternalError(format!("Failed to check auth context: {}", e)))?
        .is_some();

    if !exists {
        return Err(AppError::NotFound(format!(
            "Authentication context not found: {}",
            auth_ctx_id
        )));
    }

    app_state
        .auth_store
        .delete(&auth_ctx_id)
        .await
        .map_err(|e| AppError::InternalError(format!("Failed to delete auth context: {}", e)))?;

    tracing::info!("Successfully deleted EAP session: {}", auth_ctx_id);
    Ok(StatusCode::NO_CONTENT)
}
