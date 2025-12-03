use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const FC_UPU_MAC_IAUSF: u8 = 0x6E;

pub fn compute_upu_mac_iausf(
    kausf: &[u8],
    upu_header: Option<&[u8]>,
    counter_upu: u16,
) -> Result<Vec<u8>, String> {
    if kausf.len() != 32 {
        return Err(format!("KAUSF must be 32 bytes, got {}", kausf.len()));
    }

    let mut s = Vec::new();
    s.push(FC_UPU_MAC_IAUSF);

    if let Some(header) = upu_header {
        s.extend_from_slice(header);
        let header_len = header.len() as u16;
        s.extend_from_slice(&header_len.to_be_bytes());
    } else {
        s.extend_from_slice(&[0x00, 0x00]);
    }

    let counter_bytes = counter_upu.to_be_bytes();
    s.extend_from_slice(&counter_bytes);
    s.extend_from_slice(&[0x00, 0x02]);

    let mut mac = HmacSha256::new_from_slice(kausf)
        .map_err(|e| format!("HMAC initialization failed: {}", e))?;
    mac.update(&s);
    let result = mac.finalize().into_bytes();

    Ok(result[..16].to_vec())
}

pub fn increment_counter_upu(current: u16) -> Result<u16, String> {
    if current == u16::MAX {
        return Err("CounterUPU overflow: maximum value reached".to_string());
    }
    Ok(current.wrapping_add(1))
}

pub fn counter_upu_to_hex(counter: u16) -> String {
    format!("{:04X}", counter)
}

pub fn counter_upu_from_hex(hex: &str) -> Result<u16, String> {
    if hex.len() != 4 {
        return Err(format!("CounterUPU hex must be 4 characters, got {}", hex.len()));
    }
    u16::from_str_radix(hex, 16)
        .map_err(|e| format!("Invalid CounterUPU hex: {}", e))
}

pub fn upu_mac_to_hex(mac: &[u8]) -> String {
    hex::encode(mac)
}

pub fn upu_mac_from_hex(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() != 32 {
        return Err(format!("UPU-MAC hex must be 32 characters, got {}", hex.len()));
    }
    hex::decode(hex)
        .map_err(|e| format!("Invalid UPU-MAC hex: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_upu_mac_iausf_without_header() {
        let kausf = [0x42u8; 32];
        let counter = 0x0001;

        let result = compute_upu_mac_iausf(&kausf, None, counter);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 16);
    }

    #[test]
    fn test_compute_upu_mac_iausf_with_header() {
        let kausf = [0x42u8; 32];
        let header = [0x01, 0x02, 0x03, 0x04];
        let counter = 0x0001;

        let result = compute_upu_mac_iausf(&kausf, Some(&header), counter);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 16);
    }

    #[test]
    fn test_compute_upu_mac_iausf_invalid_kausf_length() {
        let kausf = [0x42u8; 16];
        let counter = 0x0001;

        let result = compute_upu_mac_iausf(&kausf, None, counter);
        assert!(result.is_err());
    }

    #[test]
    fn test_increment_counter_upu() {
        assert_eq!(increment_counter_upu(0).unwrap(), 1);
        assert_eq!(increment_counter_upu(100).unwrap(), 101);
        assert_eq!(increment_counter_upu(u16::MAX - 1).unwrap(), u16::MAX);
    }

    #[test]
    fn test_increment_counter_upu_overflow() {
        let result = increment_counter_upu(u16::MAX);
        assert!(result.is_err());
    }

    #[test]
    fn test_counter_upu_hex_conversion() {
        assert_eq!(counter_upu_to_hex(0), "0000");
        assert_eq!(counter_upu_to_hex(1), "0001");
        assert_eq!(counter_upu_to_hex(255), "00FF");
        assert_eq!(counter_upu_to_hex(65535), "FFFF");
    }

    #[test]
    fn test_counter_upu_from_hex() {
        assert_eq!(counter_upu_from_hex("0000").unwrap(), 0);
        assert_eq!(counter_upu_from_hex("0001").unwrap(), 1);
        assert_eq!(counter_upu_from_hex("00FF").unwrap(), 255);
        assert_eq!(counter_upu_from_hex("FFFF").unwrap(), 65535);
    }

    #[test]
    fn test_counter_upu_from_hex_invalid() {
        assert!(counter_upu_from_hex("000").is_err());
        assert!(counter_upu_from_hex("GGGG").is_err());
    }

    #[test]
    fn test_upu_mac_to_hex() {
        let mac = [0x12u8; 16];
        let hex = upu_mac_to_hex(&mac);
        assert_eq!(hex.len(), 32);
        assert_eq!(hex, "12121212121212121212121212121212");
    }

    #[test]
    fn test_upu_mac_from_hex() {
        let hex = "12121212121212121212121212121212";
        let result = upu_mac_from_hex(hex);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0x12u8; 16]);
    }

    #[test]
    fn test_upu_mac_from_hex_invalid() {
        assert!(upu_mac_from_hex("1212").is_err());
        assert!(upu_mac_from_hex("GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG").is_err());
    }

    #[test]
    fn test_upu_mac_computation_deterministic() {
        let kausf = [0x42u8; 32];
        let header = [0x01, 0x02, 0x03, 0x04];
        let counter = 0x0001;

        let result1 = compute_upu_mac_iausf(&kausf, Some(&header), counter).unwrap();
        let result2 = compute_upu_mac_iausf(&kausf, Some(&header), counter).unwrap();

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_upu_mac_different_counters() {
        let kausf = [0x42u8; 32];
        let header = [0x01, 0x02, 0x03, 0x04];

        let result1 = compute_upu_mac_iausf(&kausf, Some(&header), 1).unwrap();
        let result2 = compute_upu_mac_iausf(&kausf, Some(&header), 2).unwrap();

        assert_ne!(result1, result2);
    }
}
