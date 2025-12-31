use regex::Regex;
use std::sync::OnceLock;

static SNN_REGEX: OnceLock<Regex> = OnceLock::new();

pub type PlmnId = (String, String);

pub fn validate_snn(snn: &str) -> Result<PlmnId, String> {
    let regex = SNN_REGEX.get_or_init(|| {
        Regex::new(r"^5G:mnc(\d{2,3})\.mcc(\d{3})\.3gppnetwork\.org$")
            .expect("Invalid SNN regex")
    });

    let captures = regex
        .captures(snn)
        .ok_or_else(|| format!("Invalid Serving Network Name format: {}", snn))?;

    let mnc = captures.get(1)
        .ok_or_else(|| "Missing MNC in SNN".to_string())?
        .as_str()
        .to_string();

    let mcc = captures.get(2)
        .ok_or_else(|| "Missing MCC in SNN".to_string())?
        .as_str()
        .to_string();

    if mcc.len() != 3 {
        return Err(format!("Invalid MCC length: {}", mcc));
    }

    if mnc.len() != 2 && mnc.len() != 3 {
        return Err(format!("Invalid MNC length: {}", mnc));
    }

    Ok((mcc, mnc))
}

pub fn verify_snn_authorization(
    snn: &str,
    allowed_plmns: Option<&Vec<String>>,
) -> Result<PlmnId, String> {
    let (mcc, mnc) = validate_snn(snn)?;

    if let Some(allowed) = allowed_plmns {
        if !allowed.is_empty() {
            let mnc_num: u32 = mnc.parse().map_err(|_| "Invalid MNC format".to_string())?;
            let mnc_normalized = mnc_num.to_string();
            let plmn_id = format!("{}{}", mcc, mnc_normalized);

            if !allowed.iter().any(|allowed_plmn| {
                let normalized = allowed_plmn.replace("-", "");
                normalized == plmn_id ||
                normalized == format!("{}-{}", mcc, mnc_normalized)
            }) {
                return Err(format!(
                    "Serving network {} (PLMN: {}) is not authorized",
                    snn, plmn_id
                ));
            }
        }
    }

    Ok((mcc, mnc))
}
