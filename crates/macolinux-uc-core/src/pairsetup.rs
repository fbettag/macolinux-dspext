use std::error::Error;
use std::fmt;

use rand_core::{OsRng, RngCore};
use sha2_011::Sha512;
use srp::{groups::G3072, Client};

use crate::tlv8::{decode_tlv8, encode_tlv8, Tlv8Entry, Tlv8Error};

pub const TLV_METHOD: u8 = 0x00;
pub const TLV_IDENTIFIER: u8 = 0x01;
pub const TLV_SALT: u8 = 0x02;
pub const TLV_PUBLIC_KEY: u8 = 0x03;
pub const TLV_PROOF: u8 = 0x04;
pub const TLV_ENCRYPTED_DATA: u8 = 0x05;
pub const TLV_STATE: u8 = 0x06;
pub const TLV_ERROR: u8 = 0x07;
pub const TLV_RETRY_DELAY: u8 = 0x08;

pub const PAIRSETUP_PUBLIC_KEY_LENGTH: usize = 384;
pub const PAIRSETUP_EPHEMERAL_SECRET_LENGTH: usize = 48;

#[derive(Debug)]
pub enum PairSetupError {
    Tlv8(Tlv8Error),
    InvalidLength {
        kind: u8,
        expected: usize,
        actual: usize,
    },
    Srp(srp::AuthError),
}

impl fmt::Display for PairSetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tlv8(err) => write!(f, "{err}"),
            Self::InvalidLength {
                kind,
                expected,
                actual,
            } => write!(
                f,
                "invalid PairSetup TLV field 0x{kind:02x} length: expected at most {expected}, got {actual}"
            ),
            Self::Srp(err) => write!(f, "PairSetup SRP failed: {err}"),
        }
    }
}

impl Error for PairSetupError {}

impl From<Tlv8Error> for PairSetupError {
    fn from(value: Tlv8Error) -> Self {
        Self::Tlv8(value)
    }
}

impl From<srp::AuthError> for PairSetupError {
    fn from(value: srp::AuthError) -> Self {
        Self::Srp(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairSetupFields {
    pub method: Option<u64>,
    pub identifier: Option<Vec<u8>>,
    pub salt: Option<Vec<u8>>,
    pub public_key: Option<Vec<u8>>,
    pub proof: Option<Vec<u8>>,
    pub encrypted_data: Option<Vec<u8>>,
    pub state: Option<u64>,
    pub error: Option<u64>,
    pub retry_delay: Option<u64>,
    pub unknown: Vec<Tlv8Entry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairSetupM3 {
    pub public_key: [u8; PAIRSETUP_PUBLIC_KEY_LENGTH],
    pub proof: Vec<u8>,
    pub premaster_key: Vec<u8>,
}

pub fn build_pairsetup_m1(method: u8) -> Vec<u8> {
    encode_tlv8(&[(TLV_METHOD, &[method]), (TLV_STATE, &[1])])
}

pub fn build_pairsetup_m3_tlv(public_key: &[u8], proof: &[u8]) -> Vec<u8> {
    encode_tlv8(&[
        (TLV_STATE, &[3]),
        (TLV_PUBLIC_KEY, public_key),
        (TLV_PROOF, proof),
    ])
}

pub fn compute_pairsetup_m3(
    username: &[u8],
    password: &[u8],
    salt: &[u8],
    server_public_key: &[u8],
) -> Result<PairSetupM3, PairSetupError> {
    let mut ephemeral_secret = [0u8; PAIRSETUP_EPHEMERAL_SECRET_LENGTH];
    OsRng.fill_bytes(&mut ephemeral_secret);
    compute_pairsetup_m3_with_secret(
        username,
        password,
        salt,
        server_public_key,
        &ephemeral_secret,
    )
}

pub fn compute_pairsetup_m3_with_secret(
    username: &[u8],
    password: &[u8],
    salt: &[u8],
    server_public_key: &[u8],
    ephemeral_secret: &[u8],
) -> Result<PairSetupM3, PairSetupError> {
    let client = Client::<G3072, Sha512>::new_with_options(false);
    let verifier = client.process_reply(
        ephemeral_secret,
        username,
        password,
        salt,
        server_public_key,
    )?;
    let public_key = left_pad_384(&client.compute_public_ephemeral(ephemeral_secret))?;
    Ok(PairSetupM3 {
        public_key,
        proof: verifier.proof().to_vec(),
        premaster_key: verifier.key().to_vec(),
    })
}

pub fn parse_pairsetup_tlv(data: &[u8]) -> Result<PairSetupFields, PairSetupError> {
    let entries = decode_tlv8(data)?;
    let known = [
        TLV_METHOD,
        TLV_IDENTIFIER,
        TLV_SALT,
        TLV_PUBLIC_KEY,
        TLV_PROOF,
        TLV_ENCRYPTED_DATA,
        TLV_STATE,
        TLV_ERROR,
        TLV_RETRY_DELAY,
    ];
    Ok(PairSetupFields {
        method: uint_field(&entries, TLV_METHOD)?,
        identifier: bytes_field(&entries, TLV_IDENTIFIER),
        salt: bytes_field(&entries, TLV_SALT),
        public_key: bytes_field(&entries, TLV_PUBLIC_KEY),
        proof: bytes_field(&entries, TLV_PROOF),
        encrypted_data: bytes_field(&entries, TLV_ENCRYPTED_DATA),
        state: uint_field(&entries, TLV_STATE)?,
        error: uint_field(&entries, TLV_ERROR)?,
        retry_delay: uint_field(&entries, TLV_RETRY_DELAY)?,
        unknown: entries
            .iter()
            .filter(|entry| !known.contains(&entry.kind))
            .cloned()
            .collect(),
    })
}

fn left_pad_384(value: &[u8]) -> Result<[u8; PAIRSETUP_PUBLIC_KEY_LENGTH], PairSetupError> {
    if value.len() > PAIRSETUP_PUBLIC_KEY_LENGTH {
        return Err(PairSetupError::InvalidLength {
            kind: TLV_PUBLIC_KEY,
            expected: PAIRSETUP_PUBLIC_KEY_LENGTH,
            actual: value.len(),
        });
    }
    let mut out = [0u8; PAIRSETUP_PUBLIC_KEY_LENGTH];
    out[PAIRSETUP_PUBLIC_KEY_LENGTH - value.len()..].copy_from_slice(value);
    Ok(out)
}

fn bytes_field(entries: &[Tlv8Entry], kind: u8) -> Option<Vec<u8>> {
    entries
        .iter()
        .find(|entry| entry.kind == kind)
        .map(|entry| entry.value.clone())
}

fn uint_field(entries: &[Tlv8Entry], kind: u8) -> Result<Option<u64>, PairSetupError> {
    let Some(value) = bytes_field(entries, kind) else {
        return Ok(None);
    };
    if value.len() > 8 {
        return Err(PairSetupError::InvalidLength {
            kind,
            expected: 8,
            actual: value.len(),
        });
    }
    let mut bytes = [0u8; 8];
    bytes[..value.len()].copy_from_slice(&value);
    Ok(Some(u64::from_le_bytes(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_method_zero_m1() {
        assert_eq!(build_pairsetup_m1(0), hex_bytes("000100060101"));
    }

    #[test]
    fn builds_m3_tlv() {
        assert_eq!(
            build_pairsetup_m3_tlv(b"abc", b"def"),
            hex_bytes("06010303036162630403646566")
        );
    }

    #[test]
    fn parses_observed_srp_m2_with_split_public_key() {
        let fields = parse_pairsetup_tlv(&hex_bytes(
            "06010202107720120e8fdfa0bf49f7a16f84bd663c03ffdb626fb3fceef23369171cd1702516c8cd6f759683e124923f31f9f82c504e9e9abab49fd18613a18b1be2d390738e4819ed4f8ef394ef7605a0a4bdec36b3bba577f113c600f975d787e7d5ea5011911daa7d4802e4e36ac0afa915cd052eb978045138282e779c5b0b8c534f8d4aaa5c023fd5c72e742942d43bc0199f50a3112c89b1f9659f8187e363fde869bf8793854cd0ecf351b810d7d2eb2afa5b69a8a5e2c783b1d8d5d31988f95d39da3c78c62501d11ec58261af4f79a736acc5360dbbc0bb64cbf5a5f6297053ae4b0e3f88a84d29cb287c689c8f297ad0a02940af446e35c27b75ce7672074632724ad04b22203ecd6fffaf8a30926fbda00381f6ad9ba24cc06e6f2e750315b45c1520fc6f61701ea76d326acccb1abec1b5b129224413b2062e5ed1ce770f1f925ff49d79e36833a2b0a45bacf2608ee6b48f50a3fbccfdfa076b49129cd0dbb2a335bbd239e6c4655bdafc526d098cf7d9fe5dc62452833a48963a92dd70c5fafb9398319ddf1d3c572a0e5820e0266f3aeb66",
        ))
        .unwrap();

        assert_eq!(fields.state, Some(2));
        assert_eq!(fields.salt.as_ref().unwrap().len(), 16);
        assert_eq!(fields.public_key.as_ref().unwrap().len(), 384);
    }

    fn hex_bytes(hex: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for pair in hex.as_bytes().chunks_exact(2) {
            let s = std::str::from_utf8(pair).unwrap();
            out.push(u8::from_str_radix(s, 16).unwrap());
        }
        out
    }
}
