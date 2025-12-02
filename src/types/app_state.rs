use crate::clients::nrf::NrfClient;
use crate::clients::udm::UdmClient;
use crate::types::auth_store::AuthStore;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub auth_store: Arc<AuthStore>,
    pub nrf_client: Arc<NrfClient>,
    pub udm_client: Arc<UdmClient>,
    pub nf_instance_id: Uuid,
}
