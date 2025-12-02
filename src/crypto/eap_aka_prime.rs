use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub fn derive_ck_prime_ik_prime(
    ck: &[u8],
    ik: &[u8],
    network_name: &str,
    sqn_xor_ak: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    if ck.len() != 16 {
        return Err(format!("CK must be 16 bytes, got {}", ck.len()));
    }
    if ik.len() != 16 {
        return Err(format!("IK must be 16 bytes, got {}", ik.len()));
    }
    if sqn_xor_ak.len() != 6 {
        return Err(format!("SQN⊕AK must be 6 bytes, got {}", sqn_xor_ak.len()));
    }

    let mut key = Vec::with_capacity(32);
    key.extend_from_slice(ck);
    key.extend_from_slice(ik);

    let network_name_bytes = network_name.as_bytes();
    let network_name_len = (network_name_bytes.len() as u16).to_be_bytes();

    let mut s = Vec::new();
    s.push(0x20);
    s.extend_from_slice(network_name_bytes);
    s.extend_from_slice(&network_name_len);
    s.extend_from_slice(sqn_xor_ak);
    s.extend_from_slice(&[0x00, 0x06]);

    let output = kdf(&key, &s);

    if output.len() < 32 {
        return Err("KDF output too short".to_string());
    }

    let ck_prime = output[0..16].to_vec();
    let ik_prime = output[16..32].to_vec();

    Ok((ck_prime, ik_prime))
}

pub fn derive_master_key(
    ck_prime: &[u8],
    ik_prime: &[u8],
    identity: &[u8],
) -> Result<Vec<u8>, String> {
    if ck_prime.len() != 16 {
        return Err(format!("CK' must be 16 bytes, got {}", ck_prime.len()));
    }
    if ik_prime.len() != 16 {
        return Err(format!("IK' must be 16 bytes, got {}", ik_prime.len()));
    }

    let mut key = Vec::with_capacity(32);
    key.extend_from_slice(ck_prime);
    key.extend_from_slice(ik_prime);

    let identity_len = (identity.len() as u16).to_be_bytes();

    let mut s = Vec::new();
    s.push(0x00);
    s.extend_from_slice(identity);
    s.extend_from_slice(&identity_len);

    Ok(kdf(&key, &s))
}

pub fn derive_k_encr(mk: &[u8]) -> Result<Vec<u8>, String> {
    if mk.len() != 32 {
        return Err(format!("MK must be 32 bytes, got {}", mk.len()));
    }

    let mut s = Vec::new();
    s.push(0x01);
    s.extend_from_slice(b"EAP-AKA'");
    s.extend_from_slice(&[0x00, 0x08]);

    Ok(kdf(mk, &s)[0..16].to_vec())
}

pub fn derive_k_aut(mk: &[u8]) -> Result<Vec<u8>, String> {
    if mk.len() != 32 {
        return Err(format!("MK must be 32 bytes, got {}", mk.len()));
    }

    let mut s = Vec::new();
    s.push(0x02);
    s.extend_from_slice(b"EAP-AKA'");
    s.extend_from_slice(&[0x00, 0x08]);

    Ok(kdf(mk, &s))
}

pub fn derive_k_re(mk: &[u8]) -> Result<Vec<u8>, String> {
    if mk.len() != 32 {
        return Err(format!("MK must be 32 bytes, got {}", mk.len()));
    }

    let mut s = Vec::new();
    s.push(0x03);
    s.extend_from_slice(b"EAP-AKA'");
    s.extend_from_slice(&[0x00, 0x08]);

    Ok(kdf(mk, &s))
}

pub fn derive_msk(mk: &[u8]) -> Result<Vec<u8>, String> {
    if mk.len() != 32 {
        return Err(format!("MK must be 32 bytes, got {}", mk.len()));
    }

    let mut s1 = Vec::new();
    s1.push(0x04);
    s1.extend_from_slice(b"EAP-AKA'");
    s1.extend_from_slice(&[0x00, 0x08]);

    let mut s2 = Vec::new();
    s2.push(0x04);
    s2.extend_from_slice(b"EAP-AKA'");
    s2.extend_from_slice(&[0x00, 0x08]);
    s2.push(0x01);

    let mut msk = Vec::with_capacity(64);
    msk.extend_from_slice(&kdf(mk, &s1));
    msk.extend_from_slice(&kdf(mk, &s2));

    Ok(msk)
}

pub fn derive_emsk(mk: &[u8]) -> Result<Vec<u8>, String> {
    if mk.len() != 32 {
        return Err(format!("MK must be 32 bytes, got {}", mk.len()));
    }

    let mut s1 = Vec::new();
    s1.push(0x05);
    s1.extend_from_slice(b"EAP-AKA'");
    s1.extend_from_slice(&[0x00, 0x08]);

    let mut s2 = Vec::new();
    s2.push(0x05);
    s2.extend_from_slice(b"EAP-AKA'");
    s2.extend_from_slice(&[0x00, 0x08]);
    s2.push(0x01);

    let mut emsk = Vec::with_capacity(64);
    emsk.extend_from_slice(&kdf(mk, &s1));
    emsk.extend_from_slice(&kdf(mk, &s2));

    Ok(emsk)
}

pub fn compute_mac(k_aut: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    if k_aut.len() != 32 {
        return Err(format!("K_aut must be 32 bytes, got {}", k_aut.len()));
    }

    let mut mac = HmacSha256::new_from_slice(k_aut)
        .map_err(|e| format!("HMAC initialization failed: {}", e))?;
    mac.update(message);
    Ok(mac.finalize().into_bytes()[0..16].to_vec())
}

fn kdf(key: &[u8], input: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(input);
    mac.finalize().into_bytes().to_vec()
}

pub struct EapAkaPrimeKeys {
    pub ck_prime: Vec<u8>,
    pub ik_prime: Vec<u8>,
    pub mk: Vec<u8>,
    pub k_encr: Vec<u8>,
    pub k_aut: Vec<u8>,
    pub k_re: Vec<u8>,
    pub msk: Vec<u8>,
    pub emsk: Vec<u8>,
}

impl EapAkaPrimeKeys {
    pub fn derive(
        ck: &[u8],
        ik: &[u8],
        network_name: &str,
        sqn_xor_ak: &[u8],
        identity: &[u8],
    ) -> Result<Self, String> {
        let (ck_prime, ik_prime) = derive_ck_prime_ik_prime(ck, ik, network_name, sqn_xor_ak)?;
        let mk = derive_master_key(&ck_prime, &ik_prime, identity)?;
        let k_encr = derive_k_encr(&mk)?;
        let k_aut = derive_k_aut(&mk)?;
        let k_re = derive_k_re(&mk)?;
        let msk = derive_msk(&mk)?;
        let emsk = derive_emsk(&mk)?;

        Ok(Self {
            ck_prime,
            ik_prime,
            mk,
            k_encr,
            k_aut,
            k_re,
            msk,
            emsk,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_ck_prime_ik_prime_valid() {
        let ck = [0x01u8; 16];
        let ik = [0x02u8; 16];
        let network_name = "wlan.mnc001.mcc001.3gppnetwork.org";
        let sqn_xor_ak = [0x00u8; 6];

        let result = derive_ck_prime_ik_prime(&ck, &ik, network_name, &sqn_xor_ak);
        assert!(result.is_ok());
        let (ck_prime, ik_prime) = result.unwrap();
        assert_eq!(ck_prime.len(), 16);
        assert_eq!(ik_prime.len(), 16);
    }

    #[test]
    fn test_derive_ck_prime_ik_prime_invalid_ck() {
        let ck = [0x01u8; 15];
        let ik = [0x02u8; 16];
        let network_name = "wlan.mnc001.mcc001.3gppnetwork.org";
        let sqn_xor_ak = [0x00u8; 6];

        let result = derive_ck_prime_ik_prime(&ck, &ik, network_name, &sqn_xor_ak);
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_master_key_valid() {
        let ck_prime = [0x01u8; 16];
        let ik_prime = [0x02u8; 16];
        let identity = b"0001010000000001@wlan.mnc001.mcc001.3gppnetwork.org";

        let result = derive_master_key(&ck_prime, &ik_prime, identity);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn test_derive_k_encr_valid() {
        let mk = [0x42u8; 32];

        let result = derive_k_encr(&mk);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 16);
    }

    #[test]
    fn test_derive_k_aut_valid() {
        let mk = [0x42u8; 32];

        let result = derive_k_aut(&mk);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn test_derive_k_re_valid() {
        let mk = [0x42u8; 32];

        let result = derive_k_re(&mk);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn test_derive_msk_valid() {
        let mk = [0x42u8; 32];

        let result = derive_msk(&mk);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 64);
    }

    #[test]
    fn test_derive_emsk_valid() {
        let mk = [0x42u8; 32];

        let result = derive_emsk(&mk);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 64);
    }

    #[test]
    fn test_compute_mac_valid() {
        let k_aut = [0x42u8; 32];
        let message = b"test message";

        let result = compute_mac(&k_aut, message);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 16);
    }

    #[test]
    fn test_eap_aka_prime_keys_derive() {
        let ck = [0x01u8; 16];
        let ik = [0x02u8; 16];
        let network_name = "wlan.mnc001.mcc001.3gppnetwork.org";
        let sqn_xor_ak = [0x00u8; 6];
        let identity = b"0001010000000001@wlan.mnc001.mcc001.3gppnetwork.org";

        let result = EapAkaPrimeKeys::derive(&ck, &ik, network_name, &sqn_xor_ak, identity);
        assert!(result.is_ok());

        let keys = result.unwrap();
        assert_eq!(keys.ck_prime.len(), 16);
        assert_eq!(keys.ik_prime.len(), 16);
        assert_eq!(keys.mk.len(), 32);
        assert_eq!(keys.k_encr.len(), 16);
        assert_eq!(keys.k_aut.len(), 32);
        assert_eq!(keys.k_re.len(), 32);
        assert_eq!(keys.msk.len(), 64);
        assert_eq!(keys.emsk.len(), 64);
    }
}
