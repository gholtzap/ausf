use axum::{http::StatusCode, Json};
use crate::types::health::{HealthResponse, StatusResponse};

pub async fn health_check() -> (StatusCode, Json<HealthResponse>) {
    (
        StatusCode::OK,
        Json(HealthResponse {
            status: "healthy".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }),
    )
}

pub async fn status() -> (StatusCode, Json<StatusResponse>) {
    (
        StatusCode::OK,
        Json(StatusResponse {
            service: "AUSF".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_seconds: 0,
        }),
    )
}
