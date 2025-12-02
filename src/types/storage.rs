use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
pub struct StoredAuthContext {
    pub supi_or_suci: String,
    pub supi: Option<String>,
    pub rand: Vec<u8>,
    pub xres_star: Vec<u8>,
    pub kausf: Vec<u8>,
    pub serving_network_name: String,
}

pub type AuthContextStore = Arc<Mutex<HashMap<String, StoredAuthContext>>>;

pub fn create_auth_store() -> AuthContextStore {
    Arc::new(Mutex::new(HashMap::new()))
}
