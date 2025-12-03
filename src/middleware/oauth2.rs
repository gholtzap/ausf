use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use crate::types::{AppState, oauth2::TokenClaims, ProblemDetails};

pub async fn oauth2_auth(
    State(state): State<AppState>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, (StatusCode, axum::Json<ProblemDetails>)> {
    if !state.oauth2_config.enabled {
        return Ok(next.run(req).await);
    }

    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok());

    let token = match auth_header {
        Some(header) if header.starts_with("Bearer ") => &header[7..],
        _ => {
            return Err((
                StatusCode::UNAUTHORIZED,
                axum::Json(ProblemDetails {
                    r#type: Some("https://example.com/unauthorized".to_string()),
                    title: Some("Unauthorized".to_string()),
                    status: Some(401),
                    detail: Some("Missing or invalid Authorization header".to_string()),
                    instance: None,
                    cause: None,
                    invalid_params: None,
                    supported_features: None,
                }),
            ));
        }
    };

    let header = decode_header(token).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            axum::Json(ProblemDetails {
                r#type: Some("https://example.com/unauthorized".to_string()),
                title: Some("Unauthorized".to_string()),
                status: Some(401),
                detail: Some("Invalid token format".to_string()),
                instance: None,
                cause: None,
                invalid_params: None,
                supported_features: None,
            }),
        )
    })?;

    let alg = header.alg;

    let secret = std::env::var("OAUTH2_SECRET").unwrap_or_else(|_| "secret".to_string());
    let decoding_key = match alg {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            DecodingKey::from_secret(secret.as_bytes())
        }
        _ => {
            return Err((
                StatusCode::UNAUTHORIZED,
                axum::Json(ProblemDetails {
                    r#type: Some("https://example.com/unauthorized".to_string()),
                    title: Some("Unauthorized".to_string()),
                    status: Some(401),
                    detail: Some("Unsupported algorithm".to_string()),
                    instance: None,
                    cause: None,
                    invalid_params: None,
                    supported_features: None,
                }),
            ));
        }
    };

    let mut validation = Validation::new(alg);

    if let Some(issuer) = &state.oauth2_config.issuer {
        validation.set_issuer(&[issuer]);
    } else {
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.insecure_disable_signature_validation();
    }

    if let Some(audience) = &state.oauth2_config.audience {
        validation.set_audience(&[audience]);
    } else {
        validation.validate_aud = false;
    }

    let token_data = decode::<TokenClaims>(token, &decoding_key, &validation).map_err(|e| {
        tracing::warn!("Token validation failed: {}", e);
        (
            StatusCode::UNAUTHORIZED,
            axum::Json(ProblemDetails {
                r#type: Some("https://example.com/unauthorized".to_string()),
                title: Some("Unauthorized".to_string()),
                status: Some(401),
                detail: Some(format!("Token validation failed: {}", e)),
                instance: None,
                cause: None,
                invalid_params: None,
                supported_features: None,
            }),
        )
    })?;

    req.extensions_mut().insert(token_data.claims);

    Ok(next.run(req).await)
}
