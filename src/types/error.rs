use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use crate::types::ProblemDetails;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Internal server error: {0}")]
    InternalError(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Bad request: {0}")]
    BadRequest(String),
    #[error("Forbidden: {0}")]
    Forbidden(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, title, detail) = match self {
            AppError::InternalError(ref msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                msg.clone(),
            ),
            AppError::ConfigError(ref msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Configuration Error",
                msg.clone(),
            ),
            AppError::NotFound(ref msg) => (
                StatusCode::NOT_FOUND,
                "Not Found",
                msg.clone(),
            ),
            AppError::BadRequest(ref msg) => (
                StatusCode::BAD_REQUEST,
                "Bad Request",
                msg.clone(),
            ),
            AppError::Forbidden(ref msg) => (
                StatusCode::FORBIDDEN,
                "Forbidden",
                msg.clone(),
            ),
        };

        let problem_details = ProblemDetails::new(status.as_u16(), title, &detail);

        (status, Json(problem_details)).into_response()
    }
}
