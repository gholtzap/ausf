use serde::{Deserialize, Serialize};
use crate::types::nrf::Snssai;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpuData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sec_packet: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_conf_nssai: Option<Vec<Snssai>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drei: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aol: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpuInfo {
    pub upu_data_list: Vec<UpuData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upu_header: Option<String>,
    pub upu_ack_ind: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_features: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upu_transparent_info: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpuSecurityInfo {
    pub upu_mac_iausf: String,
    pub counter_upu: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upu_xmac_iue: Option<String>,
}
