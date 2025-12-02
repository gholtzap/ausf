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
use tokio_rustls::TlsAcceptor;
use hyper_util::rt::{TokioIo, TokioExecutor};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use tokio_stream::wrappers::TcpListenerStream;
use tokio_stream::StreamExt;
use tower::Service;

use clients::mongodb::MongoClient;
use clients::nrf::NrfClient;
use clients::udm::UdmClient;
use types::{AppState, AuthStore};
use types::nrf::{NFProfile, NFStatus, NFType, PlmnId};
use types::tls::TlsConfig;

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

            let heartbeat_timer = response.nf_profile.heart_beat_timer.unwrap_or(60);
            tracing::info!("Heartbeat timer: {} seconds", heartbeat_timer);

            let nrf_client_clone = Arc::clone(&nrf_client);
            let nf_id = nf_instance_id;
            tokio::spawn(async move {
                let interval_seconds = (heartbeat_timer as f64 * 0.8) as u64;
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_seconds));
                interval.tick().await;

                loop {
                    interval.tick().await;
                    tracing::debug!("Sending heartbeat to NRF");

                    let update = types::nrf::NFUpdateRequest {
                        nf_status: None,
                        capacity: None,
                        load: None,
                    };

                    match nrf_client_clone.update_nf(nf_id, update).await {
                        Ok(_) => {
                            tracing::debug!("Heartbeat sent successfully");
                        }
                        Err(e) => {
                            tracing::error!("Failed to send heartbeat: {}", e);
                        }
                    }
                }
            });
        }
        Err(e) => {
            tracing::error!("Failed to register with NRF: {}", e);
            tracing::warn!("Continuing without NRF registration");
        }
    }

    let udm_client = match std::env::var("UDM_URI") {
        Ok(uri) if !uri.is_empty() => {
            tracing::info!("Using UDM_URI from environment: {}", uri);
            Arc::new(UdmClient::with_base_url(uri)
                .map_err(|e| anyhow::anyhow!("Failed to create UDM client: {}", e))?)
        }
        _ => {
            tracing::info!("Discovering UDM via NRF");
            match nrf_client.discover_nf(NFType::Udm, Some(nf_instance_id)).await {
                Ok(search_result) => {
                    if let Some(udm_profile) = search_result.nf_instances.first() {
                        let udm_uri = if let Some(ipv4) = udm_profile.ipv4_addresses.as_ref().and_then(|v| v.first()) {
                            format!("http://{}", ipv4)
                        } else if let Some(fqdn) = &udm_profile.fqdn {
                            format!("http://{}", fqdn)
                        } else {
                            tracing::warn!("UDM discovered but no valid address found, using default");
                            "http://127.0.0.1:8081".to_string()
                        };

                        tracing::info!("Discovered UDM at: {}", udm_uri);
                        Arc::new(UdmClient::with_base_url(udm_uri)
                            .map_err(|e| anyhow::anyhow!("Failed to create UDM client: {}", e))?)
                    } else {
                        tracing::warn!("No UDM instances found via NRF, using default");
                        Arc::new(UdmClient::new()
                            .map_err(|e| anyhow::anyhow!("Failed to create UDM client: {}", e))?)
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to discover UDM via NRF: {}, using default", e);
                    Arc::new(UdmClient::new()
                        .map_err(|e| anyhow::anyhow!("Failed to create UDM client: {}", e))?)
                }
            }
        }
    };

    let mongo_client = Arc::new(
        MongoClient::new()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create MongoDB client: {}", e))?
    );

    let auth_store = Arc::new(AuthStore::new(mongo_client));

    let nrf_client_shutdown = Arc::clone(&nrf_client);
    let shutdown_nf_id = nf_instance_id;

    let app_state = AppState {
        auth_store,
        nrf_client,
        udm_client,
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
    let listener = tokio::net::TcpListener::bind(addr).await?;

    let tls_config = TlsConfig::from_env();

    if let Some(tls_config) = tls_config {
        let rustls_config = tls_config.build_server_config()
            .map_err(|e| anyhow::anyhow!("Failed to build TLS config: {}", e))?;

        if tls_config.client_ca_path.is_some() {
            tracing::info!("AUSF server listening on {} with mTLS", addr);
        } else {
            tracing::info!("AUSF server listening on {} with TLS", addr);
        }

        let tls_acceptor = TlsAcceptor::from(rustls_config);
        let mut tcp_stream = TcpListenerStream::new(listener);
        let make_service = app.into_make_service();

        loop {
            tokio::select! {
                incoming = tcp_stream.next() => {
                    let Some(stream) = incoming else {
                        continue;
                    };
                    let stream = match stream {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::error!("Failed to accept connection: {}", e);
                            continue;
                        }
                    };

                    let tls_acceptor = tls_acceptor.clone();
                    let mut make_service = make_service.clone();
                    let remote_addr = stream.peer_addr().ok();

                    tokio::spawn(async move {
                        let tls_stream = match tls_acceptor.accept(stream).await {
                            Ok(s) => s,
                            Err(e) => {
                                tracing::error!("TLS handshake failed: {}", e);
                                return;
                            }
                        };

                        let tower_service = match make_service.call(remote_addr.as_ref()).await {
                            Ok(s) => s,
                            Err(_) => return,
                        };

                        let hyper_service = TowerToHyperService::new(tower_service);
                        let io = TokioIo::new(tls_stream);

                        if let Err(e) = Builder::new(TokioExecutor::new())
                            .serve_connection(io, hyper_service)
                            .await
                        {
                            tracing::error!("Error serving connection: {}", e);
                        }
                    });
                }
                _ = shutdown_signal() => {
                    tracing::info!("Shutdown signal received, deregistering from NRF...");
                    match nrf_client_shutdown.deregister_nf(shutdown_nf_id).await {
                        Ok(_) => tracing::info!("Successfully deregistered from NRF"),
                        Err(e) => tracing::error!("Failed to deregister from NRF: {}", e),
                    }
                    break;
                }
            }
        }
    } else {
        tracing::info!("AUSF server listening on {} (HTTP only)", addr);

        tokio::select! {
            result = axum::serve(
                listener,
                app.into_make_service()
            ).with_graceful_shutdown(async move {
                shutdown_signal().await;
                tracing::info!("Shutdown signal received, deregistering from NRF...");
                match nrf_client_shutdown.deregister_nf(shutdown_nf_id).await {
                    Ok(_) => tracing::info!("Successfully deregistered from NRF"),
                    Err(e) => tracing::error!("Failed to deregister from NRF: {}", e),
                }
            }) => {
                result?;
            }
        }
    }

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
