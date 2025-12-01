use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationInfo {
    pub supi_or_suci: String,
    pub serving_network_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resynchronization_info: Option<ResynchronizationInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pei: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing_indicator: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResynchronizationInfo {
    pub rand: String,
    pub auts: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UEAuthenticationCtx {
    pub auth_type: AuthType,
    #[serde(rename = "5gAuthData")]
    pub auth_data_5g: AuthData5G,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub _links: Option<HashMap<String, LinkValue>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serving_network_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthType {
    #[serde(rename = "5G_AKA")]
    FiveGAka,
    EapAkaPrime,
    EapTls,
    EapTtls,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AuthData5G {
    Av5gAka(Av5gAka),
    EapPayload(EapPayload),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Av5gAka {
    pub rand: String,
    pub hxres_star: String,
    pub autn: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EapPayload {
    pub eap_payload: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LinkValue {
    pub href: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmationData {
    pub res_star: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmationDataResponse {
    pub auth_result: AuthResult,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supi: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kseaf: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthResult {
    Success,
    Failure,
}
