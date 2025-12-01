use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub fn kdf(key: &[u8], input: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(input);
    mac.finalize().into_bytes().to_vec()
}

pub fn derive_kausf(
    ck: &[u8],
    ik: &[u8],
    serving_network_name: &str,
    sqn_xor_ak: &[u8],
) -> Result<Vec<u8>, String> {
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

    let snn_bytes = serving_network_name.as_bytes();
    let snn_len = snn_bytes.len() as u16;

    let mut s = Vec::new();
    s.push(0x6A);
    s.extend_from_slice(snn_bytes);
    s.extend_from_slice(&snn_len.to_be_bytes());
    s.extend_from_slice(sqn_xor_ak);
    s.extend_from_slice(&[0x00, 0x06]);

    Ok(kdf(&key, &s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_basic() {
        let key = b"test_key";
        let input = b"test_input";
        let result = kdf(key, input);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_derive_kausf_valid_inputs() {
        let ck = [0u8; 16];
        let ik = [1u8; 16];
        let snn = "5G:mnc001.mcc001.3gppnetwork.org";
        let sqn_xor_ak = [0xAAu8; 6];

        let result = derive_kausf(&ck, &ik, snn, &sqn_xor_ak);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn test_derive_kausf_invalid_ck_length() {
        let ck = [0u8; 15];
        let ik = [1u8; 16];
        let snn = "5G:mnc001.mcc001.3gppnetwork.org";
        let sqn_xor_ak = [0xAAu8; 6];

        let result = derive_kausf(&ck, &ik, snn, &sqn_xor_ak);
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_kausf_invalid_sqn_length() {
        let ck = [0u8; 16];
        let ik = [1u8; 16];
        let snn = "5G:mnc001.mcc001.3gppnetwork.org";
        let sqn_xor_ak = [0xAAu8; 5];

        let result = derive_kausf(&ck, &ik, snn, &sqn_xor_ak);
        assert!(result.is_err());
    }
}
