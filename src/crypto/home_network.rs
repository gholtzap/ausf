use crate::types::identity::{Plmn, SupiOrSuci};
use std::env;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkLocation {
    Home,
    Visited,
}

pub type HomeNetworkResult = Result<NetworkLocation, String>;

pub fn check_home_network(identity: &SupiOrSuci) -> HomeNetworkResult {
    let home_plmn_str = env::var("HOME_PLMN")
        .map_err(|_| "HOME_PLMN environment variable not set".to_string())?;

    let home_plmn = parse_plmn(&home_plmn_str)?;

    let ue_plmn = identity.extract_plmn()
        .ok_or_else(|| "Cannot extract PLMN from identity".to_string())?;

    if home_plmn.mcc == ue_plmn.mcc && home_plmn.mnc == ue_plmn.mnc {
        Ok(NetworkLocation::Home)
    } else {
        Ok(NetworkLocation::Visited)
    }
}

pub fn is_home_network(identity: &SupiOrSuci) -> Result<bool, String> {
    check_home_network(identity).map(|loc| loc == NetworkLocation::Home)
}

fn parse_plmn(plmn_str: &str) -> Result<Plmn, String> {
    if plmn_str.len() < 5 || plmn_str.len() > 6 {
        return Err(format!("Invalid PLMN length: {}", plmn_str.len()));
    }

    let mcc = &plmn_str[0..3];
    let mnc = &plmn_str[3..];

    if mnc.len() != 2 && mnc.len() != 3 {
        return Err(format!("Invalid MNC length: {}", mnc.len()));
    }

    let plmn = Plmn {
        mcc: mcc.to_string(),
        mnc: mnc.to_string(),
    };

    plmn.validate()?;

    Ok(plmn)
}
