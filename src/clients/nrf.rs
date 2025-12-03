use crate::types::nrf::{NFProfile, NFRegisterRequest, NFRegisterResponse, NFType, NFUpdateRequest, SearchResult, SubscriptionData};
use reqwest::Client;
use std::env;
use uuid::Uuid;

pub struct NrfClient {
    client: Client,
    base_url: String,
}

impl NrfClient {
    pub fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let base_url = env::var("NRF_URI")
            .unwrap_or_else(|_| "http://127.0.0.1:8000".to_string());

        Ok(Self {
            client: Client::new(),
            base_url,
        })
    }

    pub async fn register_nf(
        &self,
        profile: NFProfile,
    ) -> Result<NFRegisterResponse, Box<dyn std::error::Error + Send + Sync>> {
        let nf_instance_id = profile.nf_instance_id;
        let request = NFRegisterRequest { nf_profile: profile };

        let url = format!(
            "{}/nnrf-nfm/v1/nf-instances/{}",
            self.base_url, nf_instance_id
        );

        let response = self.client
            .put(&url)
            .json(&request)
            .header("Content-Type", "application/json")
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(format!("NRF register failed with status {}: {}", status, error_text).into());
        }

        let register_response = response.json::<NFRegisterResponse>().await?;
        Ok(register_response)
    }

    pub async fn update_nf(
        &self,
        nf_instance_id: Uuid,
        update: NFUpdateRequest,
    ) -> Result<NFProfile, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!(
            "{}/nnrf-nfm/v1/nf-instances/{}",
            self.base_url, nf_instance_id
        );

        let response = self.client
            .patch(&url)
            .json(&update)
            .header("Content-Type", "application/merge-patch+json")
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(format!("NRF update failed with status {}: {}", status, error_text).into());
        }

        let profile = response.json::<NFProfile>().await?;
        Ok(profile)
    }

    pub async fn deregister_nf(
        &self,
        nf_instance_id: Uuid,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let url = format!(
            "{}/nnrf-nfm/v1/nf-instances/{}",
            self.base_url, nf_instance_id
        );

        let response = self.client
            .delete(&url)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(format!("NRF deregister failed with status {}: {}", status, error_text).into());
        }

        Ok(())
    }

    pub async fn get_nf_profile(
        &self,
        nf_instance_id: Uuid,
    ) -> Result<NFProfile, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!(
            "{}/nnrf-nfm/v1/nf-instances/{}",
            self.base_url, nf_instance_id
        );

        let response = self.client
            .get(&url)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(format!("NRF get profile failed with status {}: {}", status, error_text).into());
        }

        let profile = response.json::<NFProfile>().await?;
        Ok(profile)
    }

    pub async fn discover_nf(
        &self,
        target_nf_type: NFType,
        requester_nf_instance_id: Option<Uuid>,
    ) -> Result<SearchResult, Box<dyn std::error::Error + Send + Sync>> {
        let mut url = format!(
            "{}/nnrf-disc/v1/nf-instances?target-nf-type={:?}",
            self.base_url, target_nf_type
        );

        if let Some(requester_id) = requester_nf_instance_id {
            url.push_str(&format!("&requester-nf-instance-id={}", requester_id));
        }

        let response = self.client
            .get(&url)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(format!("NRF discover failed with status {}: {}", status, error_text).into());
        }

        let search_result = response.json::<SearchResult>().await?;
        Ok(search_result)
    }

    pub async fn subscribe_nf_status(
        &self,
        subscription_data: SubscriptionData,
    ) -> Result<SubscriptionData, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!(
            "{}/nnrf-nfm/v1/subscriptions",
            self.base_url
        );

        let response = self.client
            .post(&url)
            .json(&subscription_data)
            .header("Content-Type", "application/json")
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(format!("NRF subscribe failed with status {}: {}", status, error_text).into());
        }

        let subscription_response = response.json::<SubscriptionData>().await?;
        Ok(subscription_response)
    }

    pub async fn update_subscription(
        &self,
        subscription_id: &str,
        subscription_data: SubscriptionData,
    ) -> Result<SubscriptionData, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!(
            "{}/nnrf-nfm/v1/subscriptions/{}",
            self.base_url, subscription_id
        );

        let response = self.client
            .patch(&url)
            .json(&subscription_data)
            .header("Content-Type", "application/merge-patch+json")
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(format!("NRF update subscription failed with status {}: {}", status, error_text).into());
        }

        let subscription_response = response.json::<SubscriptionData>().await?;
        Ok(subscription_response)
    }

    pub async fn delete_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let url = format!(
            "{}/nnrf-nfm/v1/subscriptions/{}",
            self.base_url, subscription_id
        );

        let response = self.client
            .delete(&url)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(format!("NRF delete subscription failed with status {}: {}", status, error_text).into());
        }

        Ok(())
    }
}
