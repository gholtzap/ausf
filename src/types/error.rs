use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Internal server error: {0}")]
    InternalError(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub status: u16,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::InternalError(ref msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
            AppError::ConfigError(ref msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
        };

        let body = ErrorResponse {
            error: message,
            status: status.as_u16(),
        };

        (status, Json(body)).into_response()
    }
}
