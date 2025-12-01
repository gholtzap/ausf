use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationInfoRequest {
    pub supi_or_suci: String,
    pub serving_network_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resynchronization_info: Option<ResynchronizationInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ausf_instance_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResynchronizationInfo {
    pub rand: String,
    pub auts: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationInfoResult {
    pub auth_type: AuthType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication_vector: Option<AuthenticationVector>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supi: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthType {
    #[serde(rename = "5G_AKA")]
    FiveGAka,
    EapAkaPrime,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AuthenticationVector {
    AvEapAkaPrime(AvEapAkaPrime),
    Av5gAka(Av5gAka),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Av5gAka {
    pub rand: String,
    pub autn: String,
    pub xres_star: String,
    pub kausf: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AvEapAkaPrime {
    pub rand: String,
    pub autn: String,
    pub xres: String,
}
