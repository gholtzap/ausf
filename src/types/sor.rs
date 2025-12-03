use serde::{Deserialize, Serialize};
use crate::types::Plmn;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AccessTech {
    Nr,
    EutranInWbs1ModeAndNbs1Mode,
    EutranInNbs1ModeOnly,
    EutranInWbs1ModeOnly,
    Utran,
    GsmAndEcgsmIot,
    GsmWithoutEcgsmIot,
    EcgsmIotOnly,
    Cdma1xrtt,
    CdmaHrpd,
    GsmCompact,
    #[serde(untagged)]
    Other(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SteeringInfo {
    pub plmn_id: PlmnIdSor,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_tech_list: Option<Vec<AccessTech>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlmnIdSor {
    pub mcc: String,
    pub mnc: String,
}

impl From<Plmn> for PlmnIdSor {
    fn from(plmn: Plmn) -> Self {
        PlmnIdSor {
            mcc: plmn.mcc,
            mnc: plmn.mnc,
        }
    }
}

impl From<PlmnIdSor> for Plmn {
    fn from(plmn: PlmnIdSor) -> Self {
        Plmn {
            mcc: plmn.mcc,
            mnc: plmn.mnc,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SteeringContainer {
    SteeringInfoList(Vec<SteeringInfo>),
    SecuredPacket(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SorInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub steering_container: Option<SteeringContainer>,
    pub ack_ind: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sor_header: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sor_transparent_info: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_features: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SorSecurityInfo {
    pub sor_mac_iausf: String,
    pub counter_sor: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sor_xmac_iue: Option<String>,
}
