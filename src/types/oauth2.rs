use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct OAuth2Config {
    pub enabled: bool,
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub jwks_uri: Option<String>,
    pub secret: String,
}

impl OAuth2Config {
    pub fn from_env() -> Self {
        let enabled = std::env::var("OAUTH2_ENABLED")
            .unwrap_or_else(|_| "false".to_string())
            .parse()
            .unwrap_or(false);

        let secret = if enabled {
            std::env::var("OAUTH2_SECRET")
                .expect("OAUTH2_SECRET must be set when OAUTH2_ENABLED=true")
        } else {
            String::new()
        };

        Self {
            enabled,
            issuer: std::env::var("OAUTH2_ISSUER").ok(),
            audience: std::env::var("OAUTH2_AUDIENCE").ok(),
            jwks_uri: std::env::var("OAUTH2_JWKS_URI").ok(),
            secret,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub iss: Option<String>,
    pub aud: Option<serde_json::Value>,
    pub exp: i64,
    pub iat: Option<i64>,
    pub nbf: Option<i64>,
    pub scope: Option<String>,
    pub nfInstanceId: Option<String>,
    pub nfType: Option<String>,
}
