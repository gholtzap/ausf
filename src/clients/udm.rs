use crate::types::udm::{
    AuthenticationInfoRequest,
    AuthenticationInfoResult,
    ResynchronizationInfo,
};
use reqwest::Client;
use std::env;

pub struct UdmClient {
    client: Client,
    base_url: String,
}

impl UdmClient {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let base_url = env::var("UDM_URI")
            .unwrap_or_else(|_| "http://127.0.0.1:8081".to_string());

        Ok(Self {
            client: Client::new(),
            base_url,
        })
    }

    pub fn with_base_url(base_url: String) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            client: Client::new(),
            base_url,
        })
    }

    pub async fn get_authentication_info(
        &self,
        supi_or_suci: &str,
        serving_network_name: &str,
        resync_info: Option<ResynchronizationInfo>,
    ) -> Result<AuthenticationInfoResult, Box<dyn std::error::Error>> {
        let request = AuthenticationInfoRequest {
            supi_or_suci: supi_or_suci.to_string(),
            serving_network_name: serving_network_name.to_string(),
            resynchronization_info: resync_info,
            ausf_instance_id: None,
        };

        let url = format!("{}/nudm-ueau/v1/suci-{}/security-information/generate-auth-data",
            self.base_url, supi_or_suci);

        let response = self.client
            .post(&url)
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(format!("UDM request failed with status {}: {}", status, error_text).into());
        }

        let auth_info = response.json::<AuthenticationInfoResult>().await?;
        Ok(auth_info)
    }
}
