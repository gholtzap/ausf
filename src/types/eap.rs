use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum EapCode {
    Request = 1,
    Response = 2,
    Success = 3,
    Failure = 4,
}

impl From<u8> for EapCode {
    fn from(value: u8) -> Self {
        match value {
            1 => EapCode::Request,
            2 => EapCode::Response,
            3 => EapCode::Success,
            4 => EapCode::Failure,
            _ => EapCode::Failure,
        }
    }
}

impl From<EapCode> for u8 {
    fn from(code: EapCode) -> Self {
        code as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum EapType {
    Identity = 1,
    Notification = 2,
    Nak = 3,
    Md5Challenge = 4,
    EapAkaPrime = 50,
}

impl From<u8> for EapType {
    fn from(value: u8) -> Self {
        match value {
            1 => EapType::Identity,
            2 => EapType::Notification,
            3 => EapType::Nak,
            4 => EapType::Md5Challenge,
            50 => EapType::EapAkaPrime,
            _ => EapType::Nak,
        }
    }
}

impl From<EapType> for u8 {
    fn from(eap_type: EapType) -> Self {
        eap_type as u8
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EapPacket {
    pub code: EapCode,
    pub identifier: u8,
    pub length: u16,
    pub data: EapData,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EapData {
    Request(EapRequestResponse),
    Response(EapRequestResponse),
    Success,
    Failure,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EapRequestResponse {
    pub eap_type: EapType,
    pub type_data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum EapAkaPrimeSubtype {
    AkaChallenge = 1,
    AkaAuthenticationReject = 2,
    AkaSynchronizationFailure = 4,
    AkaIdentity = 5,
    Notification = 12,
    Reauthentication = 13,
    ClientError = 14,
}

impl From<u8> for EapAkaPrimeSubtype {
    fn from(value: u8) -> Self {
        match value {
            1 => EapAkaPrimeSubtype::AkaChallenge,
            2 => EapAkaPrimeSubtype::AkaAuthenticationReject,
            4 => EapAkaPrimeSubtype::AkaSynchronizationFailure,
            5 => EapAkaPrimeSubtype::AkaIdentity,
            12 => EapAkaPrimeSubtype::Notification,
            13 => EapAkaPrimeSubtype::Reauthentication,
            14 => EapAkaPrimeSubtype::ClientError,
            _ => EapAkaPrimeSubtype::ClientError,
        }
    }
}

impl From<EapAkaPrimeSubtype> for u8 {
    fn from(subtype: EapAkaPrimeSubtype) -> Self {
        subtype as u8
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EapAkaPrimeMessage {
    pub subtype: EapAkaPrimeSubtype,
    pub reserved: [u8; 2],
    pub attributes: Vec<EapAkaPrimeAttribute>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum EapAkaPrimeAttributeType {
    AtRand = 1,
    AtAutn = 2,
    AtRes = 3,
    AtAuts = 4,
    AtPadding = 6,
    AtNonceMt = 7,
    AtPermanentIdReq = 10,
    AtMac = 11,
    AtNotification = 12,
    AtAnyIdReq = 13,
    AtIdentity = 14,
    AtVersionList = 15,
    AtSelectedVersion = 16,
    AtFullauthIdReq = 17,
    AtCounter = 19,
    AtCounterTooSmall = 20,
    AtNonceS = 21,
    AtClientErrorCode = 22,
    AtKdf = 24,
    AtKdfInput = 23,
    AtResultInd = 135,
    AtCheckcode = 134,
}

impl From<u8> for EapAkaPrimeAttributeType {
    fn from(value: u8) -> Self {
        match value {
            1 => EapAkaPrimeAttributeType::AtRand,
            2 => EapAkaPrimeAttributeType::AtAutn,
            3 => EapAkaPrimeAttributeType::AtRes,
            4 => EapAkaPrimeAttributeType::AtAuts,
            6 => EapAkaPrimeAttributeType::AtPadding,
            7 => EapAkaPrimeAttributeType::AtNonceMt,
            10 => EapAkaPrimeAttributeType::AtPermanentIdReq,
            11 => EapAkaPrimeAttributeType::AtMac,
            12 => EapAkaPrimeAttributeType::AtNotification,
            13 => EapAkaPrimeAttributeType::AtAnyIdReq,
            14 => EapAkaPrimeAttributeType::AtIdentity,
            15 => EapAkaPrimeAttributeType::AtVersionList,
            16 => EapAkaPrimeAttributeType::AtSelectedVersion,
            17 => EapAkaPrimeAttributeType::AtFullauthIdReq,
            19 => EapAkaPrimeAttributeType::AtCounter,
            20 => EapAkaPrimeAttributeType::AtCounterTooSmall,
            21 => EapAkaPrimeAttributeType::AtNonceS,
            22 => EapAkaPrimeAttributeType::AtClientErrorCode,
            23 => EapAkaPrimeAttributeType::AtKdfInput,
            24 => EapAkaPrimeAttributeType::AtKdf,
            134 => EapAkaPrimeAttributeType::AtCheckcode,
            135 => EapAkaPrimeAttributeType::AtResultInd,
            _ => EapAkaPrimeAttributeType::AtPadding,
        }
    }
}

impl From<EapAkaPrimeAttributeType> for u8 {
    fn from(attr_type: EapAkaPrimeAttributeType) -> Self {
        attr_type as u8
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EapAkaPrimeAttribute {
    pub attr_type: EapAkaPrimeAttributeType,
    pub length: u8,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtRand {
    pub rand: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtAutn {
    pub autn: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtRes {
    pub res_length: u16,
    pub res: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtAuts {
    pub auts: [u8; 14],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtMac {
    pub mac: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtKdf {
    pub kdf: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtKdfInput {
    pub network_name: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtIdentity {
    pub identity_length: u16,
    pub identity: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtCounter {
    pub counter: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtNonceS {
    pub nonce_s: [u8; 16],
}

impl EapPacket {
    pub fn new(code: EapCode, identifier: u8, data: EapData) -> Self {
        let length = Self::calculate_length(&data);
        Self {
            code,
            identifier,
            length,
            data,
        }
    }

    fn calculate_length(data: &EapData) -> u16 {
        let base_length = 4;
        match data {
            EapData::Success | EapData::Failure => base_length,
            EapData::Request(req) | EapData::Response(req) => {
                base_length + 1 + req.type_data.len() as u16
            }
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.code.into());
        bytes.push(self.identifier);
        bytes.extend_from_slice(&self.length.to_be_bytes());

        match &self.data {
            EapData::Request(req) | EapData::Response(req) => {
                bytes.push(req.eap_type.into());
                bytes.extend_from_slice(&req.type_data);
            }
            EapData::Success | EapData::Failure => {}
        }

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 4 {
            return Err("EAP packet too short".to_string());
        }

        let code = EapCode::from(bytes[0]);
        let identifier = bytes[1];
        let length = u16::from_be_bytes([bytes[2], bytes[3]]);

        if bytes.len() < length as usize {
            return Err("EAP packet length mismatch".to_string());
        }

        let data = match code {
            EapCode::Request | EapCode::Response => {
                if bytes.len() < 5 {
                    return Err("EAP request/response too short".to_string());
                }
                let eap_type = EapType::from(bytes[4]);
                let type_data = bytes[5..length as usize].to_vec();
                let req = EapRequestResponse {
                    eap_type,
                    type_data,
                };
                if code == EapCode::Request {
                    EapData::Request(req)
                } else {
                    EapData::Response(req)
                }
            }
            EapCode::Success => EapData::Success,
            EapCode::Failure => EapData::Failure,
        };

        Ok(Self {
            code,
            identifier,
            length,
            data,
        })
    }
}

impl EapAkaPrimeMessage {
    pub fn new(subtype: EapAkaPrimeSubtype, attributes: Vec<EapAkaPrimeAttribute>) -> Self {
        Self {
            subtype,
            reserved: [0, 0],
            attributes,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.subtype.into());
        bytes.extend_from_slice(&self.reserved);

        for attr in &self.attributes {
            bytes.push(attr.attr_type.into());
            bytes.push(attr.length);
            bytes.extend_from_slice(&attr.value);
        }

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 3 {
            return Err("EAP-AKA' message too short".to_string());
        }

        let subtype = EapAkaPrimeSubtype::from(bytes[0]);
        let reserved = [bytes[1], bytes[2]];
        let mut attributes = Vec::new();

        let mut pos = 3;
        while pos < bytes.len() {
            if pos + 2 > bytes.len() {
                break;
            }

            let attr_type = EapAkaPrimeAttributeType::from(bytes[pos]);
            let length = bytes[pos + 1];

            if length < 1 {
                return Err("Invalid attribute length".to_string());
            }

            let value_len = (length as usize * 4) - 2;
            if pos + 2 + value_len > bytes.len() {
                return Err("Attribute value exceeds message length".to_string());
            }

            let value = bytes[pos + 2..pos + 2 + value_len].to_vec();
            attributes.push(EapAkaPrimeAttribute {
                attr_type,
                length,
                value,
            });

            pos += length as usize * 4;
        }

        Ok(Self {
            subtype,
            reserved,
            attributes,
        })
    }

    pub fn find_attribute(&self, attr_type: EapAkaPrimeAttributeType) -> Option<&EapAkaPrimeAttribute> {
        self.attributes.iter().find(|a| a.attr_type == attr_type)
    }
}

impl EapAkaPrimeAttribute {
    pub fn new(attr_type: EapAkaPrimeAttributeType, value: Vec<u8>) -> Self {
        let length = ((value.len() + 2) / 4) as u8 + if (value.len() + 2) % 4 != 0 { 1 } else { 0 };
        Self {
            attr_type,
            length,
            value,
        }
    }
}
