use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NFType {
    Nrf,
    Udm,
    Amf,
    Smf,
    Ausf,
    Nef,
    Pcf,
    Smsf,
    Nssf,
    Udr,
    Lmf,
    Gmlc,
    #[serde(rename = "5G_EIR")]
    FiveGEir,
    Sepp,
    Upf,
    N3Iwf,
    Af,
    Udsf,
    Bsf,
    Chf,
    Nwdaf,
    Pcscf,
    Cbcf,
    Hss,
    Ucmf,
    SorAf,
    SprAf,
    Upu,
    Pkmf,
    Aanf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NFStatus {
    Registered,
    Suspended,
    Undiscoverable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlmnId {
    pub mcc: String,
    pub mnc: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snssai {
    pub sst: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sd: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpEndPoint {
    pub ipv4_address: Option<String>,
    pub ipv6_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<TransportProtocol>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransportProtocol {
    Tcp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AusfInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supi_ranges: Option<Vec<SupiRange>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing_indicators: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SupiRange {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NFProfile {
    pub nf_instance_id: Uuid,
    pub nf_type: NFType,
    pub nf_status: NFStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub heart_beat_timer: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plmn_list: Option<Vec<PlmnId>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s_nssais: Option<Vec<Snssai>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fqdn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4_addresses: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6_addresses: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capacity: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ausf_info: Option<AusfInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NFRegisterRequest {
    #[serde(flatten)]
    pub nf_profile: NFProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NFRegisterResponse {
    #[serde(flatten)]
    pub nf_profile: NFProfile,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validity_period: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NFUpdateRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nf_status: Option<NFStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capacity: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validity_period: Option<u32>,
    pub nf_instances: Vec<NFProfile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_nf_inst_complete: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NotificationEventType {
    NfRegistered,
    NfDeregistered,
    NfProfileChanged,
    NfStatusChanged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionData {
    pub nf_status_notification_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub req_nf_instance_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscription_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validity_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub req_notif_events: Option<Vec<NotificationEventType>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nf_type: Option<NFType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationData {
    pub event: NotificationEventType,
    pub nf_instance_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nf_profile: Option<NFProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NFStatusNotify {
    pub subscription_id: String,
    pub nf_instance_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nf_profile: Option<NFProfile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_changes: Option<Vec<ChangeItem>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeItem {
    pub op: ChangeOp,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orig_value: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_value: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeOp {
    Add,
    Remove,
    Replace,
    Move,
    Copy,
    Test,
}
