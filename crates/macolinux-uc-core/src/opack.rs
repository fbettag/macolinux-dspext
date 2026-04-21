use std::error::Error;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpackValue {
    Null,
    Bool(bool),
    Int(i64),
    String(String),
    Data(Vec<u8>),
    Array(Vec<OpackValue>),
    Dict(Vec<(String, OpackValue)>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpackError {
    TrailingBytes { count: usize },
    UnexpectedEof,
    UnsupportedMarker(u8),
    LengthTooLarge { len: usize },
    NonStringDictKey,
    InvalidUtf8,
}

impl fmt::Display for OpackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TrailingBytes { count } => write!(f, "OPACK trailing bytes: {count}"),
            Self::UnexpectedEof => f.write_str("OPACK unexpected end of input"),
            Self::UnsupportedMarker(marker) => write!(f, "unsupported OPACK marker 0x{marker:02x}"),
            Self::LengthTooLarge { len } => write!(f, "OPACK length too large: {len}"),
            Self::NonStringDictKey => f.write_str("OPACK dictionary key is not a string"),
            Self::InvalidUtf8 => f.write_str("OPACK string is not valid UTF-8"),
        }
    }
}

impl Error for OpackError {}

pub fn encode_opack(value: &OpackValue) -> Result<Vec<u8>, OpackError> {
    let mut out = Vec::new();
    encode_value(value, &mut out)?;
    Ok(out)
}

pub fn decode_opack(data: &[u8]) -> Result<OpackValue, OpackError> {
    let mut offset = 0;
    let value = decode_value(data, &mut offset)?;
    if offset != data.len() {
        return Err(OpackError::TrailingBytes {
            count: data.len() - offset,
        });
    }
    Ok(value)
}

pub fn dict(entries: impl IntoIterator<Item = (impl Into<String>, OpackValue)>) -> OpackValue {
    OpackValue::Dict(
        entries
            .into_iter()
            .map(|(key, value)| (key.into(), value))
            .collect(),
    )
}

pub fn empty_dict() -> OpackValue {
    OpackValue::Dict(Vec::new())
}

fn encode_value(value: &OpackValue, out: &mut Vec<u8>) -> Result<(), OpackError> {
    match value {
        OpackValue::Null => out.push(0x04),
        OpackValue::Bool(true) => out.push(0x01),
        OpackValue::Bool(false) => out.push(0x02),
        OpackValue::Int(value) if (0..=39).contains(value) => out.push(0x08 + *value as u8),
        OpackValue::Int(value) if (0..=0xffff).contains(value) => {
            out.push(0x31);
            out.extend_from_slice(&(*value as u16).to_le_bytes());
        }
        OpackValue::Int(value) if (0..=0xffff_ffff).contains(value) => {
            out.push(0x32);
            out.extend_from_slice(&(*value as u32).to_le_bytes());
        }
        OpackValue::Int(value) => {
            out.push(0x33);
            out.extend_from_slice(&value.to_le_bytes());
        }
        OpackValue::String(value) => encode_len_prefixed(0x40, value.as_bytes(), out)?,
        OpackValue::Data(value) => encode_len_prefixed(0x70, value, out)?,
        OpackValue::Array(values) => {
            encode_count_marker(0xd0, values.len(), out)?;
            for value in values {
                encode_value(value, out)?;
            }
        }
        OpackValue::Dict(entries) => {
            encode_count_marker(0xe0, entries.len(), out)?;
            for (key, value) in entries {
                encode_value(&OpackValue::String(key.clone()), out)?;
                encode_value(value, out)?;
            }
        }
    }
    Ok(())
}

fn encode_len_prefixed(base: u8, bytes: &[u8], out: &mut Vec<u8>) -> Result<(), OpackError> {
    if bytes.len() <= 0x20 {
        out.push(base + bytes.len() as u8);
    } else if bytes.len() <= u8::MAX as usize {
        out.push(base + 0x21);
        out.push(bytes.len() as u8);
    } else if bytes.len() <= u16::MAX as usize {
        out.push(base + 0x22);
        out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
    } else if bytes.len() <= u32::MAX as usize {
        out.push(base + 0x23);
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    } else {
        return Err(OpackError::LengthTooLarge { len: bytes.len() });
    }
    out.extend_from_slice(bytes);
    Ok(())
}

fn encode_count_marker(base: u8, count: usize, out: &mut Vec<u8>) -> Result<(), OpackError> {
    if count < 0x10 {
        out.push(base + count as u8);
        Ok(())
    } else {
        Err(OpackError::LengthTooLarge { len: count })
    }
}

fn decode_value(data: &[u8], offset: &mut usize) -> Result<OpackValue, OpackError> {
    let marker = read_u8(data, offset)?;
    match marker {
        0x01 => Ok(OpackValue::Bool(true)),
        0x02 => Ok(OpackValue::Bool(false)),
        0x04 => Ok(OpackValue::Null),
        0x08..=0x30 => Ok(OpackValue::Int((marker - 0x08) as i64)),
        0x31 => Ok(OpackValue::Int(read_u16_le(data, offset)? as i64)),
        0x32 => Ok(OpackValue::Int(read_u32_le(data, offset)? as i64)),
        0x33 => Ok(OpackValue::Int(read_i64_le(data, offset)?)),
        0x40..=0x63 => {
            let len = decode_inline_or_extended_len(marker, 0x40, data, offset)?;
            let bytes = read_bytes(data, offset, len)?;
            let text = std::str::from_utf8(bytes).map_err(|_| OpackError::InvalidUtf8)?;
            Ok(OpackValue::String(text.to_string()))
        }
        0x70..=0x93 => {
            let len = decode_inline_or_extended_len(marker, 0x70, data, offset)?;
            Ok(OpackValue::Data(read_bytes(data, offset, len)?.to_vec()))
        }
        0xd0..=0xdf => {
            let count = (marker - 0xd0) as usize;
            let mut values = Vec::with_capacity(count);
            for _ in 0..count {
                values.push(decode_value(data, offset)?);
            }
            Ok(OpackValue::Array(values))
        }
        0xe0..=0xef => {
            let count = (marker - 0xe0) as usize;
            let mut values = Vec::with_capacity(count);
            for _ in 0..count {
                let key = match decode_value(data, offset)? {
                    OpackValue::String(key) => key,
                    _ => return Err(OpackError::NonStringDictKey),
                };
                let value = decode_value(data, offset)?;
                values.push((key, value));
            }
            Ok(OpackValue::Dict(values))
        }
        other => Err(OpackError::UnsupportedMarker(other)),
    }
}

fn decode_inline_or_extended_len(
    marker: u8,
    base: u8,
    data: &[u8],
    offset: &mut usize,
) -> Result<usize, OpackError> {
    let inline = marker - base;
    match inline {
        0x00..=0x20 => Ok(inline as usize),
        0x21 => Ok(read_u8(data, offset)? as usize),
        0x22 => Ok(read_u16_le(data, offset)? as usize),
        0x23 => Ok(read_u32_le(data, offset)? as usize),
        _ => Err(OpackError::UnsupportedMarker(marker)),
    }
}

fn read_u8(data: &[u8], offset: &mut usize) -> Result<u8, OpackError> {
    if *offset >= data.len() {
        return Err(OpackError::UnexpectedEof);
    }
    let value = data[*offset];
    *offset += 1;
    Ok(value)
}

fn read_bytes<'a>(data: &'a [u8], offset: &mut usize, len: usize) -> Result<&'a [u8], OpackError> {
    if *offset + len > data.len() {
        return Err(OpackError::UnexpectedEof);
    }
    let out = &data[*offset..*offset + len];
    *offset += len;
    Ok(out)
}

fn read_u16_le(data: &[u8], offset: &mut usize) -> Result<u16, OpackError> {
    let bytes = read_bytes(data, offset, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32_le(data: &[u8], offset: &mut usize) -> Result<u32, OpackError> {
    let bytes = read_bytes(data, offset, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_i64_le(data: &[u8], offset: &mut usize) -> Result<i64, OpackError> {
    let bytes = read_bytes(data, offset, 8)?;
    Ok(i64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_apple_fixture() {
        let value = dict([
            ("_i", OpackValue::String("probe".into())),
            ("value", OpackValue::Int(1)),
        ]);

        assert_eq!(
            hex(&encode_opack(&value).unwrap()),
            "e2425f694570726f62654576616c756509"
        );
    }

    #[test]
    fn encodes_nested_request_fixture() {
        let value = dict([
            ("_i", OpackValue::String("1".into())),
            (
                "requestID",
                OpackValue::String("rppairing-bonjour-resolve".into()),
            ),
            ("_x", OpackValue::Int(1)),
            ("request", empty_dict()),
        ]);

        assert_eq!(
            hex(&encode_opack(&value).unwrap()),
            "e4425f6941314972657175657374494459727070616972696e672d626f6e6a6f75722d7265736f6c7665425f78094772657175657374e0"
        );
        assert_eq!(decode_opack(&encode_opack(&value).unwrap()).unwrap(), value);
    }

    #[test]
    fn decodes_scalars_and_arrays() {
        let decoded = decode_opack(&from_hex(
            "e7416740416304416408416531ff004161014166310001416202",
        ))
        .unwrap();

        assert_eq!(
            decoded,
            dict([
                ("g", OpackValue::String("".into())),
                ("c", OpackValue::Null),
                ("d", OpackValue::Int(0)),
                ("e", OpackValue::Int(255)),
                ("a", OpackValue::Bool(true)),
                ("f", OpackValue::Int(256)),
                ("b", OpackValue::Bool(false)),
            ])
        );
    }

    #[test]
    fn encodes_data_length_boundaries() {
        assert_eq!(
            hex(&encode_opack(&OpackValue::Data(vec![0xaa; 32])).unwrap()),
            format!("90{}", "aa".repeat(32))
        );
        assert_eq!(
            hex(&encode_opack(&OpackValue::Data(vec![0xbb; 33])).unwrap()),
            format!("9121{}", "bb".repeat(33))
        );
    }

    #[test]
    fn decodes_data_length_boundaries() {
        assert_eq!(
            decode_opack(&from_hex(&format!("90{}", "aa".repeat(32)))).unwrap(),
            OpackValue::Data(vec![0xaa; 32])
        );
        assert_eq!(
            decode_opack(&from_hex(&format!("9121{}", "bb".repeat(33)))).unwrap(),
            OpackValue::Data(vec![0xbb; 33])
        );
    }

    fn hex(data: &[u8]) -> String {
        data.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn from_hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(text, 16).unwrap()
            })
            .collect()
    }
}
