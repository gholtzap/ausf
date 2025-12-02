use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupiOrSuci {
    Supi(Supi),
    Suci(Suci),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Supi {
    Imsi { mcc: String, mnc: String, msin: String },
    Nai { username: String, realm: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suci {
    pub supi_type: SupiType,
    pub mcc: String,
    pub mnc: String,
    pub routing_indicator: String,
    pub protection_scheme: ProtectionScheme,
    pub home_network_public_key_id: String,
    pub scheme_output: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SupiType {
    Imsi,
    Nai,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectionScheme {
    NullScheme,
    ProfileA,
    ProfileB,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plmn {
    pub mcc: String,
    pub mnc: String,
}

impl SupiOrSuci {
    pub fn parse(input: &str) -> Result<Self, String> {
        if input.starts_with("suci-") {
            Suci::parse(input).map(SupiOrSuci::Suci)
        } else if input.starts_with("imsi-") || input.starts_with("nai-") {
            Supi::parse(input).map(SupiOrSuci::Supi)
        } else {
            Err(format!("Invalid SUPI/SUCI format: {}", input))
        }
    }

    pub fn extract_plmn(&self) -> Option<Plmn> {
        match self {
            SupiOrSuci::Supi(supi) => supi.extract_plmn(),
            SupiOrSuci::Suci(suci) => Some(Plmn {
                mcc: suci.mcc.clone(),
                mnc: suci.mnc.clone(),
            }),
        }
    }

    pub fn to_string(&self) -> String {
        match self {
            SupiOrSuci::Supi(supi) => supi.to_string(),
            SupiOrSuci::Suci(suci) => suci.to_string(),
        }
    }
}

impl Supi {
    pub fn parse(input: &str) -> Result<Self, String> {
        if let Some(imsi_part) = input.strip_prefix("imsi-") {
            if imsi_part.len() < 5 {
                return Err("IMSI too short".to_string());
            }

            let mcc = &imsi_part[0..3];

            if imsi_part.len() < 6 {
                return Err("IMSI too short for MNC".to_string());
            }

            let (mnc, msin) = if imsi_part.len() >= 6 {
                let potential_mnc_2 = &imsi_part[3..5];
                let potential_mnc_3 = if imsi_part.len() >= 6 { &imsi_part[3..6] } else { "" };

                if imsi_part.len() >= 6 && (potential_mnc_3.starts_with("0") || imsi_part.len() > 15) {
                    (potential_mnc_2, &imsi_part[5..])
                } else if imsi_part.len() >= 6 {
                    (potential_mnc_3, &imsi_part[6..])
                } else {
                    (potential_mnc_2, &imsi_part[5..])
                }
            } else {
                return Err("Invalid IMSI format".to_string());
            };

            Ok(Supi::Imsi {
                mcc: mcc.to_string(),
                mnc: mnc.to_string(),
                msin: msin.to_string(),
            })
        } else if let Some(nai_part) = input.strip_prefix("nai-") {
            let parts: Vec<&str> = nai_part.split('@').collect();
            if parts.len() != 2 {
                return Err("Invalid NAI format".to_string());
            }
            Ok(Supi::Nai {
                username: parts[0].to_string(),
                realm: parts[1].to_string(),
            })
        } else {
            Err("Invalid SUPI prefix".to_string())
        }
    }

    pub fn extract_plmn(&self) -> Option<Plmn> {
        match self {
            Supi::Imsi { mcc, mnc, .. } => Some(Plmn {
                mcc: mcc.clone(),
                mnc: mnc.clone(),
            }),
            Supi::Nai { .. } => None,
        }
    }

    pub fn to_string(&self) -> String {
        match self {
            Supi::Imsi { mcc, mnc, msin } => format!("imsi-{}{}{}", mcc, mnc, msin),
            Supi::Nai { username, realm } => format!("nai-{}@{}", username, realm),
        }
    }
}

impl Suci {
    pub fn parse(input: &str) -> Result<Self, String> {
        let parts: Vec<&str> = input.split('-').collect();

        if parts.len() != 8 {
            return Err(format!("Invalid SUCI format: expected 8 parts, got {}", parts.len()));
        }

        if parts[0] != "suci" {
            return Err("SUCI must start with 'suci-'".to_string());
        }

        let supi_type = match parts[1] {
            "0" => SupiType::Imsi,
            "1" => SupiType::Nai,
            _ => return Err(format!("Invalid SUPI type: {}", parts[1])),
        };

        let protection_scheme = match parts[4] {
            "0" => ProtectionScheme::NullScheme,
            "1" => ProtectionScheme::ProfileA,
            "2" => ProtectionScheme::ProfileB,
            _ => return Err(format!("Invalid protection scheme: {}", parts[4])),
        };

        Ok(Suci {
            supi_type,
            mcc: parts[2].to_string(),
            mnc: parts[3].to_string(),
            routing_indicator: parts[5].to_string(),
            protection_scheme,
            home_network_public_key_id: parts[6].to_string(),
            scheme_output: parts[7].to_string(),
        })
    }

    pub fn to_string(&self) -> String {
        let supi_type_str = match self.supi_type {
            SupiType::Imsi => "0",
            SupiType::Nai => "1",
        };

        let protection_scheme_str = match self.protection_scheme {
            ProtectionScheme::NullScheme => "0",
            ProtectionScheme::ProfileA => "1",
            ProtectionScheme::ProfileB => "2",
        };

        format!(
            "suci-{}-{}-{}-{}-{}-{}-{}",
            supi_type_str,
            self.mcc,
            self.mnc,
            self.routing_indicator,
            protection_scheme_str,
            self.home_network_public_key_id,
            self.scheme_output
        )
    }
}

impl Plmn {
    pub fn to_string(&self) -> String {
        format!("{}{}", self.mcc, self.mnc)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.mcc.len() != 3 {
            return Err(format!("Invalid MCC length: expected 3, got {}", self.mcc.len()));
        }

        if self.mnc.len() != 2 && self.mnc.len() != 3 {
            return Err(format!("Invalid MNC length: expected 2 or 3, got {}", self.mnc.len()));
        }

        if !self.mcc.chars().all(|c| c.is_ascii_digit()) {
            return Err("MCC must contain only digits".to_string());
        }

        if !self.mnc.chars().all(|c| c.is_ascii_digit()) {
            return Err("MNC must contain only digits".to_string());
        }

        Ok(())
    }
}
