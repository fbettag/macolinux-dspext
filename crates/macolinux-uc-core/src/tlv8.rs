use std::error::Error;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv8Entry {
    pub kind: u8,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tlv8Error {
    TruncatedHeader,
    TruncatedValue { kind: u8, need: usize, have: usize },
}

impl fmt::Display for Tlv8Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedHeader => write!(f, "truncated TLV8 header"),
            Self::TruncatedValue { kind, need, have } => write!(
                f,
                "truncated TLV8 value for type 0x{kind:02x}: need {need} bytes, have {have}"
            ),
        }
    }
}

impl Error for Tlv8Error {}

pub fn encode_tlv8(entries: &[(u8, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();

    for (kind, value) in entries {
        let mut offset = 0;
        while offset < value.len() || (offset == 0 && value.is_empty()) {
            let end = usize::min(offset + 255, value.len());
            let chunk = &value[offset..end];
            out.push(*kind);
            out.push(chunk.len() as u8);
            out.extend_from_slice(chunk);
            offset = end;
            if chunk.is_empty() {
                break;
            }
        }
    }

    out
}

pub fn decode_tlv8(data: &[u8]) -> Result<Vec<Tlv8Entry>, Tlv8Error> {
    let mut out: Vec<Tlv8Entry> = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        if offset + 2 > data.len() {
            return Err(Tlv8Error::TruncatedHeader);
        }
        let kind = data[offset];
        let len = data[offset + 1] as usize;
        offset += 2;

        if offset + len > data.len() {
            return Err(Tlv8Error::TruncatedValue {
                kind,
                need: len,
                have: data.len() - offset,
            });
        }

        let value = &data[offset..offset + len];
        if let Some(existing) = out.iter_mut().find(|entry| entry.kind == kind) {
            existing.value.extend_from_slice(value);
        } else {
            out.push(Tlv8Entry {
                kind,
                value: value.to_vec(),
            });
        }
        offset += len;
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let encoded = encode_tlv8(&[(0x06, b"\x01"), (0x03, b"abc")]);
        assert_eq!(encoded, hex_bytes("0601010303616263"));
        assert_eq!(
            decode_tlv8(&encoded).unwrap(),
            vec![
                Tlv8Entry {
                    kind: 0x06,
                    value: vec![1],
                },
                Tlv8Entry {
                    kind: 0x03,
                    value: b"abc".to_vec(),
                },
            ]
        );
    }

    #[test]
    fn reassembles_split_values() {
        let value: Vec<u8> = (0..=255).collect();
        let encoded = encode_tlv8(&[(0x05, &value)]);

        assert_eq!(&encoded[..2], &[0x05, 0xff]);
        assert_eq!(&encoded[257..259], &[0x05, 0x01]);
        assert_eq!(decode_tlv8(&encoded).unwrap()[0].value, value);
    }

    #[test]
    fn truncated_value_fails() {
        assert!(matches!(
            decode_tlv8(&hex_bytes("0502aa")),
            Err(Tlv8Error::TruncatedValue { .. })
        ));
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
