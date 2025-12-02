mod clients;
mod crypto;
mod handlers;
mod routes;
mod types;

use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::{
    cors::CorsLayer,
    trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer},
};
use tracing::Level;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

use clients::nrf::NrfClient;
use types::{create_auth_store, AppState};
use types::nrf::{NFProfile, NFStatus, NFType, PlmnId};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let host = std::env::var("SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = std::env::var("SERVER_PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()?;

    let nf_instance_id = std::env::var("NF_INSTANCE_ID")
        .ok()
        .and_then(|s| if s.is_empty() { None } else { Some(s) })
        .and_then(|s| Uuid::parse_str(&s).ok())
        .unwrap_or_else(|| {
            let id = Uuid::new_v4();
            tracing::info!("Generated new NF instance ID: {}", id);
            id
        });

    let capacity: u16 = std::env::var("AUSF_CAPACITY")
        .unwrap_or_else(|_| "100".to_string())
        .parse()
        .unwrap_or(100);

    let priority: u16 = std::env::var("AUSF_PRIORITY")
        .unwrap_or_else(|_| "1".to_string())
        .parse()
        .unwrap_or(1);

    let home_plmn = std::env::var("HOME_PLMN").unwrap_or_else(|_| "001001".to_string());
    let mcc = home_plmn[..3].to_string();
    let mnc = home_plmn[3..].to_string();

    let nrf_client = Arc::new(NrfClient::new().map_err(|e| anyhow::anyhow!("Failed to create NRF client: {}", e))?);

    let nf_profile = NFProfile {
        nf_instance_id,
        nf_type: NFType::Ausf,
        nf_status: NFStatus::Registered,
        heart_beat_timer: Some(60),
        plmn_list: Some(vec![PlmnId { mcc, mnc }]),
        s_nssais: None,
        fqdn: None,
        ipv4_addresses: Some(vec![host.clone()]),
        ipv6_addresses: None,
        capacity: Some(capacity),
        load: Some(0),
        locality: None,
        priority: Some(priority),
        ausf_info: None,
    };

    tracing::info!("Registering AUSF with NRF (instance ID: {})", nf_instance_id);
    match nrf_client.register_nf(nf_profile).await {
        Ok(response) => {
            tracing::info!("Successfully registered with NRF");
            tracing::debug!("Registration response: {:?}", response);
        }
        Err(e) => {
            tracing::error!("Failed to register with NRF: {}", e);
            tracing::warn!("Continuing without NRF registration");
        }
    }

    let auth_store = create_auth_store();

    let app_state = AppState {
        auth_store,
        nrf_client,
        nf_instance_id,
    };

    let app = routes::create_routes(app_state)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .layer(CorsLayer::permissive());

    let addr = SocketAddr::from((host.parse::<std::net::IpAddr>()?, port));
    tracing::info!("AUSF server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
