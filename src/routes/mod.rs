use axum::{routing::get, Router};
use crate::handlers::health;

pub fn create_routes() -> Router {
    Router::new()
        .route("/health", get(health::health_check))
        .route("/status", get(health::status))
}
