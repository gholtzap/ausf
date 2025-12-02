use mongodb::bson::Binary;
use serde::{Deserialize, Serialize};

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
