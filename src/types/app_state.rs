use crate::clients::nrf::NrfClient;
use crate::types::storage::AuthContextStore;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub auth_store: AuthContextStore,
    pub nrf_client: Arc<NrfClient>,
    pub nf_instance_id: Uuid,
}
