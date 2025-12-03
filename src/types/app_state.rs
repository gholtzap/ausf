use crate::clients::nrf::NrfClient;
use crate::clients::udm::UdmClient;
use crate::types::auth_store::AuthStore;
use crate::types::sor_store::SorStore;
use crate::types::oauth2::OAuth2Config;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub auth_store: Arc<AuthStore>,
    pub sor_store: Arc<SorStore>,
    pub nrf_client: Arc<NrfClient>,
    pub udm_client: Arc<UdmClient>,
    pub nf_instance_id: Uuid,
    pub oauth2_config: OAuth2Config,
}
