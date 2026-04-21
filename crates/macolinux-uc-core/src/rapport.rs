use std::error::Error;
use std::fmt;

pub const FRAME_HEADER_LEN: usize = 4;
pub const STATUS_FLAG_BASE: u64 = 1 << 2;
pub const STATUS_FLAG_APPLE_PAY: u64 = 1 << 23;
pub const STATUS_FLAG_DEVICE_INFO_PAIRING_HINT: u64 = 1 << 24;
pub const STATUS_PRESERVE_MASK: u64 = 0xFBF2_7EBA_7FFF_F7FB;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RapportFrame {
    pub frame_type: u8,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RapportError {
    FrameTooShort { len: usize },
    IncompleteFrame { expected: usize, actual: usize },
    BodyTooLarge { len: usize },
}

impl fmt::Display for RapportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooShort { len } => write!(f, "frame too short: {len} bytes"),
            Self::IncompleteFrame { expected, actual } => {
                write!(
                    f,
                    "incomplete frame: expected {expected} bytes, got {actual}"
                )
            }
            Self::BodyTooLarge { len } => write!(f, "Rapport frame body too large: {len} bytes"),
        }
    }
}

impl Error for RapportError {}

impl RapportFrame {
    pub fn name(&self) -> &'static str {
        frame_type_name(self.frame_type)
    }

    pub fn encode(&self) -> Result<Vec<u8>, RapportError> {
        if self.body.len() > 0x00ff_ffff {
            return Err(RapportError::BodyTooLarge {
                len: self.body.len(),
            });
        }

        let len = self.body.len();
        let mut out = Vec::with_capacity(FRAME_HEADER_LEN + len);
        out.push(self.frame_type);
        out.push(((len >> 16) & 0xff) as u8);
        out.push(((len >> 8) & 0xff) as u8);
        out.push((len & 0xff) as u8);
        out.extend_from_slice(&self.body);
        Ok(out)
    }

    pub fn decode_complete(data: &[u8]) -> Result<Self, RapportError> {
        if data.len() < FRAME_HEADER_LEN {
            return Err(RapportError::FrameTooShort { len: data.len() });
        }
        let body_len = ((data[1] as usize) << 16) | ((data[2] as usize) << 8) | data[3] as usize;
        let expected = FRAME_HEADER_LEN + body_len;
        if data.len() != expected {
            return Err(RapportError::IncompleteFrame {
                expected,
                actual: data.len(),
            });
        }
        Ok(Self {
            frame_type: data[0],
            body: data[FRAME_HEADER_LEN..].to_vec(),
        })
    }
}

pub fn frame_type_name(frame_type: u8) -> &'static str {
    match frame_type {
        0x00 => "Invalid",
        0x01 => "NoOp",
        0x07 => "U_OPACK",
        0x08 => "E_OPACK",
        0x09 => "P_OPACK",
        0x0a => "PA_Req",
        0x0b => "PA_Rsp",
        0x12 => "FamilyIdentityRequest",
        0x20 => "FamilyIdentityUpdate",
        0x21 => "FamilyIdentityResponse",
        0x22 => "FriendIdentityUpdate",
        0x30 => "WatchIdentityRequest",
        0x31 => "WatchIdentityResponse",
        0x40 => "FriendIdentityRequest",
        0x41 => "FriendIdentityResponse",
        0x42 => "FriendIdentityUpdate",
        _ => "Unknown",
    }
}

pub fn decode_many(mut data: &[u8]) -> Result<Vec<RapportFrame>, RapportError> {
    let mut out = Vec::new();
    while !data.is_empty() {
        if data.len() < FRAME_HEADER_LEN {
            return Err(RapportError::FrameTooShort { len: data.len() });
        }
        let body_len = ((data[1] as usize) << 16) | ((data[2] as usize) << 8) | data[3] as usize;
        let frame_len = FRAME_HEADER_LEN + body_len;
        if data.len() < frame_len {
            return Err(RapportError::IncompleteFrame {
                expected: frame_len,
                actual: data.len(),
            });
        }
        out.push(RapportFrame::decode_complete(&data[..frame_len])?);
        data = &data[frame_len..];
    }
    Ok(out)
}

pub fn status_flags_from_bonjour_rpfl(
    rpfl: u64,
    previous: u64,
    supports_apple_pay: bool,
    device_info: u64,
) -> u64 {
    let mut status = previous & STATUS_PRESERVE_MASK;
    status |= STATUS_FLAG_BASE;

    if supports_apple_pay {
        status |= STATUS_FLAG_APPLE_PAY;
    }
    if device_info & 0x18 != 0 {
        status |= STATUS_FLAG_DEVICE_INFO_PAIRING_HINT;
    }

    status |= (rpfl << 4) & (1 << 35);
    status |= (rpfl << 18) & (1 << 32);
    status |= (rpfl << 34) & (1 << 22);
    status |= (rpfl << 10) & (1 << 42);
    status |= (rpfl >> 2) & (1 << 11);
    status |= ((rpfl >> 19) & 1) << 31;
    status |= 0x50000 & (rpfl << 2);
    status |= ((rpfl >> 23) & 1) << 34;
    status
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_complete() {
        let frame = RapportFrame {
            frame_type: 0x08,
            body: vec![1, 2, 3],
        };
        let encoded = frame.encode().unwrap();

        assert_eq!(encoded, vec![0x08, 0, 0, 3, 1, 2, 3]);
        let decoded = RapportFrame::decode_complete(&encoded).unwrap();
        assert_eq!(decoded.frame_type, 0x08);
        assert_eq!(decoded.name(), "E_OPACK");
        assert_eq!(decoded.body, vec![1, 2, 3]);
    }

    #[test]
    fn decode_multiple_frames() {
        let first = RapportFrame {
            frame_type: 0x0a,
            body: b"abc".to_vec(),
        }
        .encode()
        .unwrap();
        let second = RapportFrame {
            frame_type: 0x0b,
            body: b"defg".to_vec(),
        }
        .encode()
        .unwrap();
        let frames = decode_many(&[first, second].concat()).unwrap();

        assert_eq!(
            frames
                .iter()
                .map(|frame| (frame.frame_type, frame.body.as_slice()))
                .collect::<Vec<_>>(),
            vec![(0x0a, b"abc".as_slice()), (0x0b, b"defg".as_slice())]
        );
    }

    #[test]
    fn status_flags_from_empty_rpfl() {
        assert_eq!(status_flags_from_bonjour_rpfl(0, 0, false, 0), 1 << 2);
    }

    #[test]
    fn status_flags_from_scalar_bits() {
        for (rpfl_bit, status_bit) in [
            (13, 11),
            (14, 16),
            (14, 32),
            (16, 18),
            (19, 31),
            (23, 34),
            (31, 35),
            (32, 42),
        ] {
            let status = status_flags_from_bonjour_rpfl(1 << rpfl_bit, 0, false, 0);
            assert_ne!(status & (1 << status_bit), 0);
        }
    }

    #[test]
    fn status_flags_from_context_bits() {
        assert_ne!(
            status_flags_from_bonjour_rpfl(0, 0, false, 0x18)
                & STATUS_FLAG_DEVICE_INFO_PAIRING_HINT,
            0
        );
        assert_ne!(
            status_flags_from_bonjour_rpfl(0, 0, true, 0) & STATUS_FLAG_APPLE_PAY,
            0
        );
    }

    #[test]
    fn status_flags_preserves_masked_previous_bits() {
        assert_ne!(
            status_flags_from_bonjour_rpfl(0, 1 << 19, false, 0) & (1 << 19),
            0
        );
    }
}
