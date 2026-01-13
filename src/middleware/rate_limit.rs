use axum::{
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

const BASE_LIMIT: u32 = 10;
const WINDOW_SECS: u64 = 60;
const BACKOFF_BASE: u32 = 2;
const MAX_BACKOFF_SECS: u64 = 300;

#[derive(Clone)]
pub struct RateLimitState {
    limiters: Arc<RwLock<HashMap<String, RateLimiter>>>,
}

impl RateLimitState {
    pub fn new() -> Self {
        Self {
            limiters: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn cleanup_old_entries(&self) {
        let mut limiters = self.limiters.write().await;
        limiters.retain(|_, limiter| !limiter.is_expired());
    }
}

#[derive(Clone, Debug)]
struct RateLimiter {
    requests: Vec<Instant>,
    failures: u32,
    last_failure: Option<Instant>,
    backoff_until: Option<Instant>,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            requests: Vec::new(),
            failures: 0,
            last_failure: None,
            backoff_until: None,
        }
    }

    fn is_expired(&self) -> bool {
        self.requests.is_empty() && self.backoff_until.is_none()
    }

    fn check_and_update(&mut self, identifier: &str) -> Result<(), StatusCode> {
        let now = Instant::now();

        if let Some(backoff_until) = self.backoff_until {
            if now < backoff_until {
                let remaining = (backoff_until - now).as_secs();
                tracing::warn!(
                    event = "rate_limit_backoff",
                    identifier = identifier,
                    remaining_secs = remaining,
                    "Request blocked due to exponential backoff"
                );
                return Err(StatusCode::TOO_MANY_REQUESTS);
            } else {
                self.backoff_until = None;
                self.failures = 0;
            }
        }

        self.requests.retain(|&t| now.duration_since(t) < Duration::from_secs(WINDOW_SECS));

        if self.requests.len() >= BASE_LIMIT as usize {
            self.record_failure();
            tracing::warn!(
                event = "rate_limit_exceeded",
                identifier = identifier,
                count = self.requests.len(),
                limit = BASE_LIMIT,
                "Rate limit exceeded"
            );
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }

        self.requests.push(now);
        Ok(())
    }

    fn record_failure(&mut self) {
        self.failures += 1;
        self.last_failure = Some(Instant::now());

        let backoff_secs = (BACKOFF_BASE.pow(self.failures) as u64).min(MAX_BACKOFF_SECS);
        self.backoff_until = Some(Instant::now() + Duration::from_secs(backoff_secs));

        tracing::info!(
            event = "rate_limit_backoff_applied",
            failures = self.failures,
            backoff_secs = backoff_secs,
            "Exponential backoff applied"
        );
    }
}

pub async fn rate_limit_auth(
    State(rate_limit_state): State<RateLimitState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Result<Response, impl IntoResponse> {
    let identifier = addr.ip().to_string();

    {
        let mut limiters = rate_limit_state.limiters.write().await;
        let limiter = limiters.entry(identifier.clone()).or_insert_with(RateLimiter::new);

        if let Err(status) = limiter.check_and_update(&identifier) {
            return Err((
                status,
                [("Retry-After", "60")],
                "Rate limit exceeded. Please try again later.",
            ));
        }
    }

    let response = next.run(request).await;

    Ok(response)
}

pub fn spawn_cleanup_task(rate_limit_state: RateLimitState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(300));
        loop {
            interval.tick().await;
            rate_limit_state.cleanup_old_entries().await;
            tracing::debug!("Rate limiter cleanup completed");
        }
    });
}
