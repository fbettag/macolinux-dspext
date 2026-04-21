pub const TLV_METHOD: u8 = 0x00;
pub const TLV_IDENTIFIER: u8 = 0x01;
pub const TLV_PUBLIC_KEY: u8 = 0x03;
pub const TLV_ENCRYPTED_DATA: u8 = 0x05;
pub const TLV_STATE: u8 = 0x06;
pub const TLV_ERROR: u8 = 0x07;
pub const TLV_SIGNATURE: u8 = 0x0a;
pub const TLV_APP_FLAGS: u8 = 0x19;

pub const PAIR_VERIFY_ECDH_SALT: &[u8] = b"Pair-Verify-ECDH-Salt";
pub const PAIR_VERIFY_ECDH_INFO: &[u8] = b"Pair-Verify-ECDH-Info";
pub const PAIR_VERIFY_ENCRYPT_SALT: &[u8] = b"Pair-Verify-Encrypt-Salt";
pub const PAIR_VERIFY_ENCRYPT_INFO: &[u8] = b"Pair-Verify-Encrypt-Info";

pub const PAIR_VERIFY_M2_NONCE: &[u8] = b"PV-Msg02";
pub const PAIR_VERIFY_M3_NONCE: &[u8] = b"PV-Msg03";
pub const PAIR_VERIFY_M4_SERVER_NONCE: &[u8] = b"PV-Msg4s";
pub const PAIR_VERIFY_M4_NONCE: &[u8] = b"PV-Msg04";

pub const PAIR_VERIFY_RESUME_SESSION_ID_SALT: &[u8] = b"Pair-Verify-ResumeSessionID-Salt";
pub const PAIR_VERIFY_RESUME_SESSION_ID_INFO: &[u8] = b"Pair-Verify-ResumeSessionID-Info";

pub const MFI_PAIR_VERIFY_SALT: &[u8] = b"MFi-Pair-Verify-Salt";
pub const MFI_PAIR_VERIFY_INFO: &[u8] = b"MFi-Pair-Verify-Info";

pub const PAIRVERIFY_PUBLIC_KEY_LENGTH: usize = 32;
pub const PAIRVERIFY_KEY_LENGTH: usize = 32;
pub const CHACHA20_POLY1305_TAG_LENGTH: usize = 16;

pub fn pairing_stream_info(stream_name: &str, client_to_server: bool) -> Vec<u8> {
    let prefix = if client_to_server {
        "ClientEncrypt"
    } else {
        "ServerEncrypt"
    };
    format!("{prefix}-{stream_name}").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observed_tlv_constants_match_coreutils() {
        assert_eq!(TLV_STATE, 0x06);
        assert_eq!(TLV_PUBLIC_KEY, 0x03);
        assert_eq!(TLV_ENCRYPTED_DATA, 0x05);
        assert_eq!(TLV_APP_FLAGS, 0x19);
    }

    #[test]
    fn hkdf_and_nonce_constants_match_coreutils() {
        assert_eq!(PAIR_VERIFY_ECDH_SALT, b"Pair-Verify-ECDH-Salt");
        assert_eq!(PAIR_VERIFY_ECDH_INFO, b"Pair-Verify-ECDH-Info");
        assert_eq!(PAIR_VERIFY_ENCRYPT_SALT, b"Pair-Verify-Encrypt-Salt");
        assert_eq!(PAIR_VERIFY_ENCRYPT_INFO, b"Pair-Verify-Encrypt-Info");
        assert_eq!(PAIR_VERIFY_M2_NONCE, b"PV-Msg02");
        assert_eq!(PAIR_VERIFY_M3_NONCE, b"PV-Msg03");
    }

    #[test]
    fn stream_info_labels_match_coreutils() {
        assert_eq!(
            pairing_stream_info("main", true),
            b"ClientEncrypt-main".to_vec()
        );
        assert_eq!(
            pairing_stream_info("main", false),
            b"ServerEncrypt-main".to_vec()
        );
    }
}
