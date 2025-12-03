use mongodb::bson::Binary;
use serde::{Deserialize, Serialize};

use crate::types::eap_state::EapAkaPrimeSession;
use crate::types::sor::SorInfo;
use crate::types::upu::UpuInfo;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredAuthContext {
    #[serde(rename = "_id")]
    pub auth_ctx_id: String,
    pub supi_or_suci: String,
    pub supi: Option<String>,
    #[serde(with = "bson_binary")]
    pub rand: Vec<u8>,
    #[serde(with = "bson_binary")]
    pub xres_star: Vec<u8>,
    #[serde(with = "bson_binary")]
    pub kausf: Vec<u8>,
    pub serving_network_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eap_session: Option<EapAkaPrimeSession>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredSorContext {
    #[serde(rename = "_id")]
    pub supi: String,
    #[serde(with = "bson_binary")]
    pub kausf: Vec<u8>,
    pub counter_sor: u16,
    pub sor_info: SorInfo,
    pub created_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredUpuContext {
    #[serde(rename = "_id")]
    pub supi: String,
    #[serde(with = "bson_binary")]
    pub kausf: Vec<u8>,
    pub counter_upu: u16,
    pub upu_info: UpuInfo,
    pub created_at: i64,
}

mod bson_binary {
    use mongodb::bson::Binary;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let binary = Binary {
            subtype: mongodb::bson::spec::BinarySubtype::Generic,
            bytes: bytes.clone(),
        };
        Serialize::serialize(&binary, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let binary = Binary::deserialize(deserializer)?;
        Ok(binary.bytes)
    }
}
