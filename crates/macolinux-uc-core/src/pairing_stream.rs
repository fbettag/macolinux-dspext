use std::error::Error;
use std::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha512;

use crate::opack::{decode_opack, encode_opack, OpackError, OpackValue};
use crate::pairverify::{pairing_stream_info, CHACHA20_POLY1305_TAG_LENGTH, PAIRVERIFY_KEY_LENGTH};
use crate::rapport::{RapportFrame, FRAME_TYPE_E_OPACK};

pub const PAIRING_STREAM_DEFAULT_NAME: &str = "main";
pub const PAIRING_STREAM_NONCE_LENGTH: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingStreamEndpoint {
    Client,
    Server,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingStreamError {
    PskTooSmall { len: usize },
    HkdfLength,
    CiphertextTooSmall { len: usize },
    Aead,
    Opack(OpackError),
    UnexpectedFrameType { frame_type: u8 },
}

impl fmt::Display for PairingStreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PskTooSmall { len } => write!(
                f,
                "PairingStream PSK too small: expected at least {PAIRVERIFY_KEY_LENGTH}, got {len}"
            ),
            Self::HkdfLength => f.write_str("PairingStream HKDF output length failed"),
            Self::CiphertextTooSmall { len } => write!(
                f,
                "PairingStream ciphertext too small for auth tag: {len} bytes"
            ),
            Self::Aead => f.write_str("PairingStream AEAD operation failed"),
            Self::Opack(err) => write!(f, "{err}"),
            Self::UnexpectedFrameType { frame_type } => {
                write!(f, "expected E_OPACK frame, got 0x{frame_type:02x}")
            }
        }
    }
}

impl Error for PairingStreamError {}

impl From<OpackError> for PairingStreamError {
    fn from(value: OpackError) -> Self {
        Self::Opack(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingStreamKeys {
    pub encrypt_key: [u8; PAIRVERIFY_KEY_LENGTH],
    pub decrypt_key: [u8; PAIRVERIFY_KEY_LENGTH],
}

impl PairingStreamKeys {
    pub fn derive(
        stream_name: &str,
        endpoint: PairingStreamEndpoint,
        psk_data: &[u8],
    ) -> Result<Self, PairingStreamError> {
        if psk_data.len() < PAIRVERIFY_KEY_LENGTH {
            return Err(PairingStreamError::PskTooSmall {
                len: psk_data.len(),
            });
        }

        let client_key = derive_key(psk_data, &pairing_stream_info(stream_name, true))?;
        let server_key = derive_key(psk_data, &pairing_stream_info(stream_name, false))?;
        let (encrypt_key, decrypt_key) = match endpoint {
            PairingStreamEndpoint::Client => (client_key, server_key),
            PairingStreamEndpoint::Server => (server_key, client_key),
        };

        Ok(Self {
            encrypt_key,
            decrypt_key,
        })
    }
}

#[derive(Debug, Clone)]
pub struct PairingStream {
    keys: PairingStreamKeys,
    encrypt_nonce: [u8; PAIRING_STREAM_NONCE_LENGTH],
    decrypt_nonce: [u8; PAIRING_STREAM_NONCE_LENGTH],
}

impl PairingStream {
    pub fn new(
        stream_name: &str,
        endpoint: PairingStreamEndpoint,
        psk_data: &[u8],
    ) -> Result<Self, PairingStreamError> {
        Ok(Self {
            keys: PairingStreamKeys::derive(stream_name, endpoint, psk_data)?,
            encrypt_nonce: [0; PAIRING_STREAM_NONCE_LENGTH],
            decrypt_nonce: [0; PAIRING_STREAM_NONCE_LENGTH],
        })
    }

    pub fn main(
        endpoint: PairingStreamEndpoint,
        psk_data: &[u8],
    ) -> Result<Self, PairingStreamError> {
        Self::new(PAIRING_STREAM_DEFAULT_NAME, endpoint, psk_data)
    }

    pub fn encrypt_data(
        &mut self,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, PairingStreamError> {
        let nonce = self.encrypt_nonce;
        let result = ChaCha20Poly1305::new(Key::from_slice(&self.keys.encrypt_key))
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| PairingStreamError::Aead);
        increment_nonce(&mut self.encrypt_nonce);
        result
    }

    pub fn decrypt_data(
        &mut self,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, PairingStreamError> {
        if ciphertext.len() < CHACHA20_POLY1305_TAG_LENGTH {
            return Err(PairingStreamError::CiphertextTooSmall {
                len: ciphertext.len(),
            });
        }

        let nonce = self.decrypt_nonce;
        let result = ChaCha20Poly1305::new(Key::from_slice(&self.keys.decrypt_key))
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| PairingStreamError::Aead);
        increment_nonce(&mut self.decrypt_nonce);
        result
    }

    pub fn encrypt_opack_value(
        &mut self,
        value: &OpackValue,
    ) -> Result<Vec<u8>, PairingStreamError> {
        self.encrypt_opack_value_with_aad(value, &[])
    }

    pub fn encrypt_opack_value_with_aad(
        &mut self,
        value: &OpackValue,
        aad: &[u8],
    ) -> Result<Vec<u8>, PairingStreamError> {
        self.encrypt_data(&encode_opack(value)?, aad)
    }

    pub fn decrypt_opack_value(
        &mut self,
        ciphertext: &[u8],
    ) -> Result<OpackValue, PairingStreamError> {
        self.decrypt_opack_value_with_aad(ciphertext, &[])
    }

    pub fn decrypt_opack_value_with_aad(
        &mut self,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<OpackValue, PairingStreamError> {
        Ok(decode_opack(&self.decrypt_data(ciphertext, aad)?)?)
    }

    pub fn encrypt_e_opack_frame(
        &mut self,
        value: &OpackValue,
    ) -> Result<RapportFrame, PairingStreamError> {
        Ok(RapportFrame {
            frame_type: FRAME_TYPE_E_OPACK,
            body: self.encrypt_opack_value(value)?,
        })
    }

    pub fn decrypt_e_opack_frame(
        &mut self,
        frame: &RapportFrame,
    ) -> Result<OpackValue, PairingStreamError> {
        if frame.frame_type != FRAME_TYPE_E_OPACK {
            return Err(PairingStreamError::UnexpectedFrameType {
                frame_type: frame.frame_type,
            });
        }
        self.decrypt_opack_value(&frame.body)
    }

    pub fn encrypt_nonce(&self) -> [u8; PAIRING_STREAM_NONCE_LENGTH] {
        self.encrypt_nonce
    }

    pub fn decrypt_nonce(&self) -> [u8; PAIRING_STREAM_NONCE_LENGTH] {
        self.decrypt_nonce
    }
}

fn derive_key(
    psk_data: &[u8],
    info: &[u8],
) -> Result<[u8; PAIRVERIFY_KEY_LENGTH], PairingStreamError> {
    let hkdf = Hkdf::<Sha512>::new(Some(&[]), psk_data);
    let mut key = [0u8; PAIRVERIFY_KEY_LENGTH];
    hkdf.expand(info, &mut key)
        .map_err(|_| PairingStreamError::HkdfLength)?;
    Ok(key)
}

fn increment_nonce(nonce: &mut [u8; PAIRING_STREAM_NONCE_LENGTH]) {
    for byte in nonce {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::companion::CompanionRequest;
    use crate::opack::dict;

    #[test]
    fn derives_opposite_endpoint_keys() {
        let psk = [0x41; PAIRVERIFY_KEY_LENGTH];
        let client =
            PairingStreamKeys::derive("main", PairingStreamEndpoint::Client, &psk).unwrap();
        let server =
            PairingStreamKeys::derive("main", PairingStreamEndpoint::Server, &psk).unwrap();

        assert_eq!(client.encrypt_key, server.decrypt_key);
        assert_eq!(client.decrypt_key, server.encrypt_key);
        assert_ne!(client.encrypt_key, client.decrypt_key);
    }

    #[test]
    fn rejects_short_psk() {
        assert_eq!(
            PairingStream::main(PairingStreamEndpoint::Client, &[0; 31]).unwrap_err(),
            PairingStreamError::PskTooSmall { len: 31 }
        );
    }

    #[test]
    fn round_trips_encrypted_opack_between_client_and_server() {
        let psk = [0x37; PAIRVERIFY_KEY_LENGTH];
        let mut client = PairingStream::main(PairingStreamEndpoint::Client, &psk).unwrap();
        let mut server = PairingStream::main(PairingStreamEndpoint::Server, &psk).unwrap();
        let value = CompanionRequest::new("probe", dict([("value", OpackValue::Int(7))]))
            .with_message_id("1")
            .with_transaction_id(1)
            .to_opack_value();

        let frame = client.encrypt_e_opack_frame(&value).unwrap();
        assert_eq!(frame.frame_type, FRAME_TYPE_E_OPACK);
        assert_ne!(frame.body, encode_opack(&value).unwrap());

        let decrypted = server.decrypt_e_opack_frame(&frame).unwrap();
        assert_eq!(decrypted, value);
        assert_eq!(client.encrypt_nonce()[0], 1);
        assert_eq!(server.decrypt_nonce()[0], 1);
    }

    #[test]
    fn little_endian_nonce_carries() {
        let mut nonce = [0xff; PAIRING_STREAM_NONCE_LENGTH];
        increment_nonce(&mut nonce);
        assert_eq!(nonce, [0; PAIRING_STREAM_NONCE_LENGTH]);

        let mut nonce = [0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        increment_nonce(&mut nonce);
        assert_eq!(nonce[0], 0);
        assert_eq!(nonce[1], 1);
    }
}
