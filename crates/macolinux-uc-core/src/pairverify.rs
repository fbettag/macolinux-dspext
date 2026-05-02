use std::error::Error;
use std::fmt;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha512;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::tlv8::{decode_tlv8, encode_tlv8, Tlv8Error};

pub const TLV_METHOD: u8 = 0x00;
pub const TLV_IDENTIFIER: u8 = 0x01;
pub const TLV_PUBLIC_KEY: u8 = 0x03;
pub const TLV_ENCRYPTED_DATA: u8 = 0x05;
pub const TLV_STATE: u8 = 0x06;
pub const TLV_ERROR: u8 = 0x07;
pub const TLV_SIGNATURE: u8 = 0x0a;
pub const TLV_APP_FLAGS: u8 = 0x19;

pub const PAIR_VERIFY_ERROR_AUTHENTICATION: u8 = 0x04;

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

#[derive(Debug)]
pub enum PairVerifyError {
    Tlv8(Tlv8Error),
    MissingField {
        kind: u8,
    },
    InvalidLength {
        kind: u8,
        expected: usize,
        actual: usize,
    },
    InvalidPublicKey,
    HkdfLength,
    Aead,
    Signature,
}

impl fmt::Display for PairVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tlv8(err) => write!(f, "{err}"),
            Self::MissingField { kind } => {
                write!(f, "missing PairVerify TLV field 0x{kind:02x}")
            }
            Self::InvalidLength {
                kind,
                expected,
                actual,
            } => write!(
                f,
                "invalid PairVerify TLV field 0x{kind:02x} length: expected {expected}, got {actual}"
            ),
            Self::InvalidPublicKey => f.write_str("invalid PairVerify public key"),
            Self::HkdfLength => f.write_str("invalid PairVerify HKDF output length"),
            Self::Aead => f.write_str("PairVerify AEAD operation failed"),
            Self::Signature => f.write_str("PairVerify signature verification failed"),
        }
    }
}

impl Error for PairVerifyError {}

impl From<Tlv8Error> for PairVerifyError {
    fn from(value: Tlv8Error) -> Self {
        Self::Tlv8(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairVerifyFields {
    pub method: Option<u64>,
    pub identifier: Option<Vec<u8>>,
    pub public_key: Option<[u8; PAIRVERIFY_PUBLIC_KEY_LENGTH]>,
    pub encrypted_data: Option<Vec<u8>>,
    pub state: Option<u64>,
    pub error: Option<u64>,
    pub signature: Option<[u8; 64]>,
    pub app_flags: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairVerifyM2 {
    pub fields: PairVerifyFields,
    pub decrypted_fields: Option<PairVerifyFields>,
}

pub struct PairVerifyKeyPair {
    secret: StaticSecret,
    public_key: [u8; PAIRVERIFY_PUBLIC_KEY_LENGTH],
}

impl PairVerifyKeyPair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret).to_bytes();
        Self { secret, public_key }
    }

    pub fn from_secret_bytes(secret: [u8; PAIRVERIFY_KEY_LENGTH]) -> Self {
        let secret = StaticSecret::from(secret);
        let public_key = PublicKey::from(&secret).to_bytes();
        Self { secret, public_key }
    }

    pub fn secret_bytes(&self) -> [u8; PAIRVERIFY_KEY_LENGTH] {
        self.secret.to_bytes()
    }

    pub fn public_key(&self) -> [u8; PAIRVERIFY_PUBLIC_KEY_LENGTH] {
        self.public_key
    }

    pub fn shared_secret(
        &self,
        peer_public_key: &[u8],
    ) -> Result<[u8; PAIRVERIFY_KEY_LENGTH], PairVerifyError> {
        let peer_public_key = array_32(TLV_PUBLIC_KEY, peer_public_key)?;
        let peer_public_key = PublicKey::from(peer_public_key);
        let shared = self.secret.diffie_hellman(&peer_public_key).to_bytes();
        if shared.iter().all(|byte| *byte == 0) {
            return Err(PairVerifyError::InvalidPublicKey);
        }
        Ok(shared)
    }
}

pub fn pairing_stream_info(stream_name: &str, client_to_server: bool) -> Vec<u8> {
    let prefix = if client_to_server {
        "ClientEncrypt"
    } else {
        "ServerEncrypt"
    };
    format!("{prefix}-{stream_name}").into_bytes()
}

pub fn build_pairverify_m1(public_key: &[u8; PAIRVERIFY_PUBLIC_KEY_LENGTH]) -> Vec<u8> {
    encode_tlv8(&[
        (TLV_STATE, &[1]),
        (TLV_PUBLIC_KEY, public_key),
        (TLV_APP_FLAGS, &[1]),
    ])
}

pub fn generate_ed25519_seed() -> [u8; PAIRVERIFY_KEY_LENGTH] {
    let mut seed = [0u8; PAIRVERIFY_KEY_LENGTH];
    OsRng.fill_bytes(&mut seed);
    seed
}

pub fn ed25519_public_key_from_seed(
    seed: &[u8],
) -> Result<[u8; PAIRVERIFY_PUBLIC_KEY_LENGTH], PairVerifyError> {
    let seed = array_32(TLV_IDENTIFIER, seed)?;
    Ok(SigningKey::from_bytes(&seed).verifying_key().to_bytes())
}

pub fn parse_pairverify_tlv(data: &[u8]) -> Result<PairVerifyFields, PairVerifyError> {
    let entries = decode_tlv8(data)?;
    let method = uint_field(&entries, TLV_METHOD)?;
    let identifier = bytes_field(&entries, TLV_IDENTIFIER);
    let public_key = match bytes_field(&entries, TLV_PUBLIC_KEY) {
        Some(value) => Some(array_32(TLV_PUBLIC_KEY, &value)?),
        None => None,
    };
    let encrypted_data = bytes_field(&entries, TLV_ENCRYPTED_DATA);
    let state = uint_field(&entries, TLV_STATE)?;
    let error = uint_field(&entries, TLV_ERROR)?;
    let signature = match bytes_field(&entries, TLV_SIGNATURE) {
        Some(value) => Some(array_64(TLV_SIGNATURE, &value)?),
        None => None,
    };
    let app_flags = uint_field(&entries, TLV_APP_FLAGS)?;

    Ok(PairVerifyFields {
        method,
        identifier,
        public_key,
        encrypted_data,
        state,
        error,
        signature,
        app_flags,
    })
}

pub fn derive_pairverify_key(
    shared_secret: &[u8; PAIRVERIFY_KEY_LENGTH],
) -> Result<[u8; PAIRVERIFY_KEY_LENGTH], PairVerifyError> {
    let hkdf = Hkdf::<Sha512>::new(Some(PAIR_VERIFY_ENCRYPT_SALT), shared_secret);
    let mut key = [0u8; PAIRVERIFY_KEY_LENGTH];
    hkdf.expand(PAIR_VERIFY_ENCRYPT_INFO, &mut key)
        .map_err(|_| PairVerifyError::HkdfLength)?;
    Ok(key)
}

pub fn decrypt_pairverify_m2(
    key: &[u8; PAIRVERIFY_KEY_LENGTH],
    encrypted_data: &[u8],
) -> Result<Vec<u8>, PairVerifyError> {
    decrypt_pairverify_data(key, PAIR_VERIFY_M2_NONCE, encrypted_data)
}

pub fn encrypt_pairverify_m2(
    key: &[u8; PAIRVERIFY_KEY_LENGTH],
    plaintext: &[u8],
) -> Result<Vec<u8>, PairVerifyError> {
    encrypt_pairverify_data(key, PAIR_VERIFY_M2_NONCE, plaintext)
}

pub fn encrypt_pairverify_m3(
    key: &[u8; PAIRVERIFY_KEY_LENGTH],
    plaintext: &[u8],
) -> Result<Vec<u8>, PairVerifyError> {
    encrypt_pairverify_data(key, PAIR_VERIFY_M3_NONCE, plaintext)
}

pub fn decrypt_pairverify_m3(
    key: &[u8; PAIRVERIFY_KEY_LENGTH],
    encrypted_data: &[u8],
) -> Result<Vec<u8>, PairVerifyError> {
    decrypt_pairverify_data(key, PAIR_VERIFY_M3_NONCE, encrypted_data)
}

pub fn parse_pairverify_m2(
    key_pair: &PairVerifyKeyPair,
    data: &[u8],
) -> Result<PairVerifyM2, PairVerifyError> {
    let fields = parse_pairverify_tlv(data)?;
    let decrypted_fields = match (&fields.public_key, &fields.encrypted_data) {
        (Some(server_public_key), Some(encrypted_data)) => {
            let shared_secret = key_pair.shared_secret(server_public_key)?;
            let key = derive_pairverify_key(&shared_secret)?;
            let plaintext = decrypt_pairverify_m2(&key, encrypted_data)?;
            Some(parse_pairverify_tlv(&plaintext)?)
        }
        _ => None,
    };
    Ok(PairVerifyM2 {
        fields,
        decrypted_fields,
    })
}

pub fn build_pairverify_m2_plaintext(
    server_public_key: &[u8; PAIRVERIFY_PUBLIC_KEY_LENGTH],
    server_identifier: &[u8],
    client_public_key: &[u8; PAIRVERIFY_PUBLIC_KEY_LENGTH],
    server_signing_key_seed: &[u8],
) -> Result<Vec<u8>, PairVerifyError> {
    build_pairverify_signature_plaintext(
        server_public_key,
        server_identifier,
        client_public_key,
        server_signing_key_seed,
    )
}

pub fn build_pairverify_m3_plaintext(
    client_public_key: &[u8; PAIRVERIFY_PUBLIC_KEY_LENGTH],
    client_identifier: &[u8],
    server_public_key: &[u8; PAIRVERIFY_PUBLIC_KEY_LENGTH],
    client_signing_key_seed: &[u8],
) -> Result<Vec<u8>, PairVerifyError> {
    build_pairverify_signature_plaintext(
        client_public_key,
        client_identifier,
        server_public_key,
        client_signing_key_seed,
    )
}

fn build_pairverify_signature_plaintext(
    signer_public_key: &[u8; PAIRVERIFY_PUBLIC_KEY_LENGTH],
    signer_identifier: &[u8],
    peer_public_key: &[u8; PAIRVERIFY_PUBLIC_KEY_LENGTH],
    signing_key_seed: &[u8],
) -> Result<Vec<u8>, PairVerifyError> {
    let signing_key_seed = array_32(TLV_IDENTIFIER, signing_key_seed)?;
    let signing_key = SigningKey::from_bytes(&signing_key_seed);
    let mut transcript = Vec::with_capacity(
        signer_public_key.len() + signer_identifier.len() + peer_public_key.len(),
    );
    transcript.extend_from_slice(signer_public_key);
    transcript.extend_from_slice(signer_identifier);
    transcript.extend_from_slice(peer_public_key);
    let signature = signing_key.sign(&transcript);

    Ok(encode_tlv8(&[
        (TLV_IDENTIFIER, signer_identifier),
        (TLV_SIGNATURE, &signature.to_bytes()),
    ]))
}

pub fn build_pairverify_m2(
    server_public_key: &[u8; PAIRVERIFY_PUBLIC_KEY_LENGTH],
    key: &[u8; PAIRVERIFY_KEY_LENGTH],
    plaintext: &[u8],
) -> Result<Vec<u8>, PairVerifyError> {
    let encrypted = encrypt_pairverify_m2(key, plaintext)?;
    Ok(encode_tlv8(&[
        (TLV_STATE, &[2]),
        (TLV_PUBLIC_KEY, server_public_key),
        (TLV_ENCRYPTED_DATA, encrypted.as_slice()),
    ]))
}

pub fn build_pairverify_m3(
    key: &[u8; PAIRVERIFY_KEY_LENGTH],
    plaintext: &[u8],
) -> Result<Vec<u8>, PairVerifyError> {
    let encrypted = encrypt_pairverify_m3(key, plaintext)?;
    Ok(encode_tlv8(&[
        (TLV_ENCRYPTED_DATA, encrypted.as_slice()),
        (TLV_STATE, &[3]),
    ]))
}

pub fn build_pairverify_m4() -> Vec<u8> {
    encode_tlv8(&[(TLV_STATE, &[4])])
}

pub fn build_pairverify_error(state: u8, error: u8) -> Vec<u8> {
    encode_tlv8(&[(TLV_ERROR, &[error]), (TLV_STATE, &[state])])
}

pub fn verify_pairverify_m2_signature(
    server_public_key: &[u8; PAIRVERIFY_PUBLIC_KEY_LENGTH],
    server_identifier: &[u8],
    client_public_key: &[u8; PAIRVERIFY_PUBLIC_KEY_LENGTH],
    server_signing_key: &[u8],
    signature: &[u8; 64],
) -> Result<(), PairVerifyError> {
    verify_pairverify_signature(
        server_public_key,
        server_identifier,
        client_public_key,
        server_signing_key,
        signature,
    )
}

pub fn verify_pairverify_m3_signature(
    client_public_key: &[u8; PAIRVERIFY_PUBLIC_KEY_LENGTH],
    client_identifier: &[u8],
    server_public_key: &[u8; PAIRVERIFY_PUBLIC_KEY_LENGTH],
    client_signing_key: &[u8],
    signature: &[u8; 64],
) -> Result<(), PairVerifyError> {
    verify_pairverify_signature(
        client_public_key,
        client_identifier,
        server_public_key,
        client_signing_key,
        signature,
    )
}

fn verify_pairverify_signature(
    signer_public_key: &[u8; PAIRVERIFY_PUBLIC_KEY_LENGTH],
    signer_identifier: &[u8],
    peer_public_key: &[u8; PAIRVERIFY_PUBLIC_KEY_LENGTH],
    signing_public_key: &[u8],
    signature: &[u8; 64],
) -> Result<(), PairVerifyError> {
    let verifying_key = VerifyingKey::from_bytes(&array_32(TLV_PUBLIC_KEY, signing_public_key)?)
        .map_err(|_| PairVerifyError::Signature)?;
    let mut transcript = Vec::with_capacity(
        signer_public_key.len() + signer_identifier.len() + peer_public_key.len(),
    );
    transcript.extend_from_slice(signer_public_key);
    transcript.extend_from_slice(signer_identifier);
    transcript.extend_from_slice(peer_public_key);
    let signature = Signature::from_bytes(signature);
    verifying_key
        .verify(&transcript, &signature)
        .map_err(|_| PairVerifyError::Signature)
}

fn encrypt_pairverify_data(
    key: &[u8; PAIRVERIFY_KEY_LENGTH],
    nonce_label: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, PairVerifyError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(Nonce::from_slice(&pairverify_nonce(nonce_label)), plaintext)
        .map_err(|_| PairVerifyError::Aead)
}

fn decrypt_pairverify_data(
    key: &[u8; PAIRVERIFY_KEY_LENGTH],
    nonce_label: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, PairVerifyError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            Nonce::from_slice(&pairverify_nonce(nonce_label)),
            ciphertext,
        )
        .map_err(|_| PairVerifyError::Aead)
}

fn pairverify_nonce(label: &[u8]) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(label);
    nonce
}

fn bytes_field(entries: &[crate::tlv8::Tlv8Entry], kind: u8) -> Option<Vec<u8>> {
    entries
        .iter()
        .find(|entry| entry.kind == kind)
        .map(|entry| entry.value.clone())
}

fn uint_field(
    entries: &[crate::tlv8::Tlv8Entry],
    kind: u8,
) -> Result<Option<u64>, PairVerifyError> {
    let Some(value) = bytes_field(entries, kind) else {
        return Ok(None);
    };
    if value.len() > 8 {
        return Err(PairVerifyError::InvalidLength {
            kind,
            expected: 8,
            actual: value.len(),
        });
    }
    let mut bytes = [0u8; 8];
    bytes[..value.len()].copy_from_slice(&value);
    Ok(Some(u64::from_le_bytes(bytes)))
}

fn array_32(kind: u8, value: &[u8]) -> Result<[u8; 32], PairVerifyError> {
    value
        .try_into()
        .map_err(|_| PairVerifyError::InvalidLength {
            kind,
            expected: 32,
            actual: value.len(),
        })
}

fn array_64(kind: u8, value: &[u8]) -> Result<[u8; 64], PairVerifyError> {
    value
        .try_into()
        .map_err(|_| PairVerifyError::InvalidLength {
            kind,
            expected: 64,
            actual: value.len(),
        })
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

    #[test]
    fn pairverify_m1_contains_public_key() {
        let public_key = [0xa5; 32];
        let mut expected = Vec::from([TLV_STATE, 1, 1, TLV_PUBLIC_KEY, 32]);
        expected.extend_from_slice(&public_key);
        expected.extend_from_slice(&[TLV_APP_FLAGS, 1, 1]);

        assert_eq!(build_pairverify_m1(&public_key), expected);
    }

    #[test]
    fn parses_error_response() {
        let fields = parse_pairverify_tlv(&[TLV_ERROR, 1, 4, TLV_STATE, 1, 0]).unwrap();

        assert_eq!(fields.error, Some(4));
        assert_eq!(fields.state, Some(0));
    }

    #[test]
    fn pairverify_aead_round_trip() {
        let key = [0x42; 32];
        let plaintext = encode_tlv8(&[(TLV_IDENTIFIER, b"peer"), (TLV_SIGNATURE, &[0x7a; 64])]);
        let encrypted = encrypt_pairverify_m3(&key, &plaintext).unwrap();

        assert_ne!(encrypted, plaintext);
        assert_eq!(
            decrypt_pairverify_data(&key, PAIR_VERIFY_M3_NONCE, &encrypted).unwrap(),
            plaintext
        );
    }

    #[test]
    fn pairverify_server_and_client_messages_round_trip() {
        let client_ephemeral = PairVerifyKeyPair::from_secret_bytes([0x11; 32]);
        let server_ephemeral = PairVerifyKeyPair::from_secret_bytes([0x22; 32]);
        let client_identity_seed = [0x33; 32];
        let server_identity_seed = [0x44; 32];
        let client_signing_public = ed25519_public_key_from_seed(&client_identity_seed).unwrap();
        let server_signing_public = ed25519_public_key_from_seed(&server_identity_seed).unwrap();
        let client_identifier = b"client";
        let server_identifier = b"server";

        let shared_secret = server_ephemeral
            .shared_secret(&client_ephemeral.public_key())
            .unwrap();
        assert_eq!(
            shared_secret,
            client_ephemeral
                .shared_secret(&server_ephemeral.public_key())
                .unwrap()
        );

        let key = derive_pairverify_key(&shared_secret).unwrap();
        let m2_plaintext = build_pairverify_m2_plaintext(
            &server_ephemeral.public_key(),
            server_identifier,
            &client_ephemeral.public_key(),
            &server_identity_seed,
        )
        .unwrap();
        let m2 = build_pairverify_m2(&server_ephemeral.public_key(), &key, &m2_plaintext).unwrap();
        let parsed_m2 = parse_pairverify_m2(&client_ephemeral, &m2).unwrap();
        let decrypted_m2 = parsed_m2.decrypted_fields.unwrap();
        verify_pairverify_m2_signature(
            &server_ephemeral.public_key(),
            server_identifier,
            &client_ephemeral.public_key(),
            &server_signing_public,
            decrypted_m2.signature.as_ref().unwrap(),
        )
        .unwrap();

        let m3_plaintext = build_pairverify_m3_plaintext(
            &client_ephemeral.public_key(),
            client_identifier,
            &server_ephemeral.public_key(),
            &client_identity_seed,
        )
        .unwrap();
        let m3 = build_pairverify_m3(&key, &m3_plaintext).unwrap();
        let m3_fields = parse_pairverify_tlv(&m3).unwrap();
        let decrypted_m3 = parse_pairverify_tlv(
            &decrypt_pairverify_m3(&key, m3_fields.encrypted_data.as_deref().unwrap()).unwrap(),
        )
        .unwrap();
        verify_pairverify_m3_signature(
            &client_ephemeral.public_key(),
            client_identifier,
            &server_ephemeral.public_key(),
            &client_signing_public,
            decrypted_m3.signature.as_ref().unwrap(),
        )
        .unwrap();

        assert_eq!(build_pairverify_m4(), encode_tlv8(&[(TLV_STATE, &[4])]));
        assert_eq!(
            build_pairverify_error(3, PAIR_VERIFY_ERROR_AUTHENTICATION),
            encode_tlv8(&[
                (TLV_ERROR, &[PAIR_VERIFY_ERROR_AUTHENTICATION]),
                (TLV_STATE, &[3])
            ]),
        );
    }
}
