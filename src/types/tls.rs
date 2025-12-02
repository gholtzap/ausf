use std::fs::File;
use std::io::{BufReader, Error as IoError};
use std::path::Path;
use std::sync::Arc;
use rustls_pemfile::{certs, pkcs8_private_keys};
use tokio_rustls::rustls::{self, ServerConfig};

pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
    pub client_ca_path: Option<String>,
}

impl TlsConfig {
    pub fn from_env() -> Option<Self> {
        let cert_path = std::env::var("TLS_CERT_PATH").ok()?;
        let key_path = std::env::var("TLS_KEY_PATH").ok()?;
        let client_ca_path = std::env::var("TLS_CLIENT_CA_PATH").ok();

        if cert_path.is_empty() || key_path.is_empty() {
            return None;
        }

        Some(Self {
            cert_path,
            key_path,
            client_ca_path,
        })
    }

    pub fn build_server_config(&self) -> Result<Arc<ServerConfig>, IoError> {
        let cert_file = File::open(&self.cert_path)?;
        let key_file = File::open(&self.key_path)?;

        let mut cert_reader = BufReader::new(cert_file);
        let mut key_reader = BufReader::new(key_file);

        let cert_chain = certs(&mut cert_reader)
            .collect::<Result<Vec<_>, _>>()?;

        let mut keys = pkcs8_private_keys(&mut key_reader)
            .collect::<Result<Vec<_>, _>>()?;

        if keys.is_empty() {
            return Err(IoError::new(
                std::io::ErrorKind::InvalidInput,
                "No private keys found",
            ));
        }

        let key = keys.remove(0);

        let mut config = if let Some(client_ca_path) = &self.client_ca_path {
            let client_ca_file = File::open(client_ca_path)?;
            let mut client_ca_reader = BufReader::new(client_ca_file);

            let client_certs = certs(&mut client_ca_reader)
                .collect::<Result<Vec<_>, _>>()?;

            let mut root_cert_store = rustls::RootCertStore::empty();
            for cert in client_certs {
                root_cert_store.add(cert).map_err(|e| {
                    IoError::new(std::io::ErrorKind::InvalidInput, format!("Failed to add client CA: {}", e))
                })?;
            }

            let client_cert_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_cert_store))
                .build()
                .map_err(|e| IoError::new(std::io::ErrorKind::InvalidInput, format!("Failed to build verifier: {}", e)))?;

            ServerConfig::builder()
                .with_client_cert_verifier(client_cert_verifier)
                .with_single_cert(cert_chain, key.into())
                .map_err(|e| IoError::new(std::io::ErrorKind::InvalidInput, e.to_string()))?
        } else {
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(cert_chain, key.into())
                .map_err(|e| IoError::new(std::io::ErrorKind::InvalidInput, e.to_string()))?
        };

        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        Ok(Arc::new(config))
    }
}
