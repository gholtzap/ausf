use serde::{Deserialize, Serialize};

use crate::types::eap::{EapAkaPrimeAttribute, EapAkaPrimeAttributeType, EapAkaPrimeMessage, EapAkaPrimeSubtype};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EapAkaPrimeState {
    Idle,
    Identity,
    Challenge,
    Success,
    Failure,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EapAkaPrimeSession {
    pub state: EapAkaPrimeState,
    pub identifier: u8,
    pub rand: Option<Vec<u8>>,
    pub autn: Option<Vec<u8>>,
    pub ck: Option<Vec<u8>>,
    pub ik: Option<Vec<u8>>,
    pub res: Option<Vec<u8>>,
    pub ck_prime: Option<Vec<u8>>,
    pub ik_prime: Option<Vec<u8>>,
    pub mk: Option<Vec<u8>>,
    pub k_encr: Option<Vec<u8>>,
    pub k_aut: Option<Vec<u8>>,
    pub k_re: Option<Vec<u8>>,
    pub msk: Option<Vec<u8>>,
    pub emsk: Option<Vec<u8>>,
    pub auts: Option<Vec<u8>>,
    pub network_name: String,
    pub identity: String,
}

#[derive(Debug)]
pub enum StateTransition {
    ToIdentity,
    ToChallenge,
    ToSuccess,
    ToFailure,
    ToResynchronization,
    Stay,
}

impl EapAkaPrimeSession {
    pub fn new(network_name: String, identity: String) -> Self {
        Self {
            state: EapAkaPrimeState::Idle,
            identifier: 0,
            rand: None,
            autn: None,
            ck: None,
            ik: None,
            res: None,
            ck_prime: None,
            ik_prime: None,
            mk: None,
            k_encr: None,
            k_aut: None,
            k_re: None,
            msk: None,
            emsk: None,
            auts: None,
            network_name,
            identity,
        }
    }

    pub fn next_identifier(&mut self) -> u8 {
        self.identifier = self.identifier.wrapping_add(1);
        self.identifier
    }

    pub fn transition(&mut self, next_state: EapAkaPrimeState) {
        tracing::info!(
            "EAP-AKA' state transition: {:?} -> {:?}",
            self.state,
            next_state
        );
        self.state = next_state;
    }

    pub fn process_request(&mut self, message: &EapAkaPrimeMessage) -> Result<StateTransition, String> {
        match (self.state, message.subtype) {
            (EapAkaPrimeState::Idle, EapAkaPrimeSubtype::AkaIdentity) => {
                Ok(StateTransition::ToIdentity)
            }
            (EapAkaPrimeState::Identity, EapAkaPrimeSubtype::AkaChallenge) => {
                self.extract_challenge_data(message)?;
                Ok(StateTransition::ToChallenge)
            }
            (EapAkaPrimeState::Challenge, _) => {
                Ok(StateTransition::Stay)
            }
            _ => {
                tracing::warn!(
                    "Invalid state transition: state={:?}, subtype={:?}",
                    self.state,
                    message.subtype
                );
                Ok(StateTransition::ToFailure)
            }
        }
    }

    pub fn process_response(&mut self, message: &EapAkaPrimeMessage) -> Result<StateTransition, String> {
        match (self.state, message.subtype) {
            (EapAkaPrimeState::Challenge, EapAkaPrimeSubtype::AkaChallenge) => {
                self.validate_challenge_response(message)?;
                Ok(StateTransition::ToSuccess)
            }
            (EapAkaPrimeState::Challenge, EapAkaPrimeSubtype::AkaSynchronizationFailure) => {
                self.extract_auts(message)?;
                Ok(StateTransition::ToResynchronization)
            }
            (EapAkaPrimeState::Challenge, EapAkaPrimeSubtype::ClientError) => {
                Ok(StateTransition::ToFailure)
            }
            (EapAkaPrimeState::Identity, EapAkaPrimeSubtype::AkaIdentity) => {
                Ok(StateTransition::Stay)
            }
            _ => {
                tracing::warn!(
                    "Unexpected response: state={:?}, subtype={:?}",
                    self.state,
                    message.subtype
                );
                Ok(StateTransition::ToFailure)
            }
        }
    }

    fn extract_challenge_data(&mut self, message: &EapAkaPrimeMessage) -> Result<(), String> {
        if let Some(at_rand) = message.find_attribute(EapAkaPrimeAttributeType::AtRand) {
            if at_rand.value.len() >= 2 {
                self.rand = Some(at_rand.value[2..].to_vec());
            }
        }

        if let Some(at_autn) = message.find_attribute(EapAkaPrimeAttributeType::AtAutn) {
            if at_autn.value.len() >= 2 {
                self.autn = Some(at_autn.value[2..].to_vec());
            }
        }

        Ok(())
    }

    fn validate_challenge_response(&mut self, message: &EapAkaPrimeMessage) -> Result<(), String> {
        let at_res = message.find_attribute(EapAkaPrimeAttributeType::AtRes)
            .ok_or_else(|| "Missing AT_RES attribute".to_string())?;

        if at_res.value.len() < 2 {
            return Err("Invalid AT_RES format".to_string());
        }

        let res_length = u16::from_be_bytes([at_res.value[0], at_res.value[1]]);
        let res_bytes = &at_res.value[2..];

        if res_bytes.len() * 8 != res_length as usize {
            return Err("RES length mismatch".to_string());
        }

        self.res = Some(res_bytes.to_vec());

        let at_mac = message.find_attribute(EapAkaPrimeAttributeType::AtMac)
            .ok_or_else(|| "Missing AT_MAC attribute".to_string())?;

        if at_mac.value.len() < 2 {
            return Err("Invalid AT_MAC format".to_string());
        }

        Ok(())
    }

    fn extract_auts(&mut self, message: &EapAkaPrimeMessage) -> Result<(), String> {
        let at_auts = message.find_attribute(EapAkaPrimeAttributeType::AtAuts)
            .ok_or_else(|| "Missing AT_AUTS attribute".to_string())?;

        if at_auts.value.len() < 14 {
            return Err("Invalid AT_AUTS format".to_string());
        }

        self.auts = Some(at_auts.value[..14].to_vec());

        Ok(())
    }

    pub fn build_identity_request(&mut self) -> EapAkaPrimeMessage {
        let attributes = vec![
            EapAkaPrimeAttribute::new(
                EapAkaPrimeAttributeType::AtPermanentIdReq,
                vec![0, 0],
            ),
        ];

        EapAkaPrimeMessage::new(EapAkaPrimeSubtype::AkaIdentity, attributes)
    }

    pub fn build_challenge_request(
        &mut self,
        rand: Vec<u8>,
        autn: Vec<u8>,
    ) -> Result<EapAkaPrimeMessage, String> {
        if rand.len() != 16 {
            return Err(format!("RAND must be 16 bytes, got {}", rand.len()));
        }
        if autn.len() != 16 {
            return Err(format!("AUTN must be 16 bytes, got {}", autn.len()));
        }

        self.rand = Some(rand.clone());
        self.autn = Some(autn.clone());

        let mut at_rand_value = vec![0, 0];
        at_rand_value.extend_from_slice(&rand);

        let mut at_autn_value = vec![0, 0];
        at_autn_value.extend_from_slice(&autn);

        let kdf_value = vec![0, 1];

        let network_name_bytes = self.network_name.as_bytes();
        let mut at_kdf_input_value = Vec::new();
        at_kdf_input_value.extend_from_slice(&(network_name_bytes.len() as u16).to_be_bytes());
        at_kdf_input_value.extend_from_slice(network_name_bytes);

        let mut attributes = vec![
            EapAkaPrimeAttribute::new(EapAkaPrimeAttributeType::AtRand, at_rand_value),
            EapAkaPrimeAttribute::new(EapAkaPrimeAttributeType::AtAutn, at_autn_value),
            EapAkaPrimeAttribute::new(EapAkaPrimeAttributeType::AtKdf, kdf_value),
            EapAkaPrimeAttribute::new(EapAkaPrimeAttributeType::AtKdfInput, at_kdf_input_value),
        ];

        let mut at_mac_value = vec![0, 0];
        at_mac_value.extend_from_slice(&[0u8; 16]);
        attributes.push(EapAkaPrimeAttribute::new(
            EapAkaPrimeAttributeType::AtMac,
            at_mac_value,
        ));

        Ok(EapAkaPrimeMessage::new(
            EapAkaPrimeSubtype::AkaChallenge,
            attributes,
        ))
    }

    pub fn build_authentication_reject(&mut self) -> EapAkaPrimeMessage {
        EapAkaPrimeMessage::new(
            EapAkaPrimeSubtype::AkaAuthenticationReject,
            vec![],
        )
    }
}
