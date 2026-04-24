use std::error::Error;
use std::fmt;
use std::str::FromStr;

use crate::opack::{decode_opack, dict, encode_opack, OpackError, OpackValue};

pub const REQUEST_ID_STREAM_START: &str = "_streamStart";
pub const REQUEST_ID_STREAM_STOP: &str = "_streamStop";

pub const KEY_STREAM_ID: &str = "_streamID";
pub const KEY_STREAM_TYPE: &str = "_streamType";
pub const KEY_STREAM_FLAGS: &str = "_streamFlags";
pub const KEY_STREAM_ADDR: &str = "_streamAddr";
pub const KEY_STREAM_MAC_ADDR: &str = "_streamMACAddr";
pub const KEY_STREAM_PORT: &str = "_streamPort";
pub const KEY_STREAM_SRV: &str = "_streamSrv";
pub const KEY_STREAM_KEY: &str = "_streamKey";
pub const KEY_PSK_DATA: &str = "pskD";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamError {
    Opack(OpackError),
    ExpectedDict,
    MissingField(&'static str),
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    InvalidStreamId(String),
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Opack(err) => write!(f, "{err}"),
            Self::ExpectedDict => f.write_str("expected OPACK dictionary"),
            Self::MissingField(field) => write!(f, "missing stream field {field}"),
            Self::InvalidField { field, reason } => {
                write!(f, "invalid stream field {field}: {reason}")
            }
            Self::InvalidStreamId(value) => {
                write!(f, "invalid Universal Control stream ID: {value}")
            }
        }
    }
}

impl Error for StreamError {}

impl From<OpackError> for StreamError {
    fn from(value: OpackError) -> Self {
        Self::Opack(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UniversalControlStreamRole {
    Sync,
    Events,
    Clipboard,
    Drag,
}

impl UniversalControlStreamRole {
    pub const ALL: [Self; 4] = [Self::Sync, Self::Events, Self::Clipboard, Self::Drag];

    pub fn as_code(self) -> &'static str {
        match self {
            Self::Sync => "SYNC",
            Self::Events => "EVNT",
            Self::Clipboard => "CLIP",
            Self::Drag => "DRAG",
        }
    }

    pub fn from_code(value: &str) -> Option<Self> {
        match value {
            "SYNC" => Some(Self::Sync),
            "EVNT" => Some(Self::Events),
            "CLIP" => Some(Self::Clipboard),
            "DRAG" => Some(Self::Drag),
            _ => None,
        }
    }
}

impl fmt::Display for UniversalControlStreamRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_code())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UniversalControlStreamId {
    pub role: UniversalControlStreamRole,
    pub session_uuid: String,
}

impl UniversalControlStreamId {
    pub fn new(
        role: UniversalControlStreamRole,
        session_uuid: impl Into<String>,
    ) -> Result<Self, StreamError> {
        let session_uuid = normalize_uuid(session_uuid.into())?;
        Ok(Self { role, session_uuid })
    }

    pub fn as_wire_string(&self) -> String {
        format!("{}:{}", self.role.as_code(), self.session_uuid)
    }
}

impl fmt::Display for UniversalControlStreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_wire_string())
    }
}

impl FromStr for UniversalControlStreamId {
    type Err = StreamError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (role, session_uuid) = value
            .split_once(':')
            .ok_or_else(|| StreamError::InvalidStreamId(value.to_string()))?;
        let role = UniversalControlStreamRole::from_code(role)
            .ok_or_else(|| StreamError::InvalidStreamId(value.to_string()))?;
        Self::new(role, session_uuid)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RpStreamType {
    UdpSocket,
    RpcConnection,
    UdpNetworkPath,
}

impl RpStreamType {
    pub fn wire_value(self) -> i64 {
        match self {
            Self::UdpSocket => 1,
            Self::RpcConnection => 2,
            Self::UdpNetworkPath => 3,
        }
    }

    pub fn from_wire_value(value: i64) -> Option<Self> {
        match value {
            1 => Some(Self::UdpSocket),
            2 => Some(Self::RpcConnection),
            3 => Some(Self::UdpNetworkPath),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::UdpSocket => "UDPSocket",
            Self::RpcConnection => "RPCnx",
            Self::UdpNetworkPath => "UDPNWPath",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamStartRequest {
    pub stream_id: UniversalControlStreamId,
    pub stream_type: RpStreamType,
    pub stream_flags: Option<u32>,
}

impl StreamStartRequest {
    pub fn new(stream_id: UniversalControlStreamId, stream_type: RpStreamType) -> Self {
        Self {
            stream_id,
            stream_type,
            stream_flags: None,
        }
    }

    pub fn with_flags(mut self, stream_flags: u32) -> Self {
        self.stream_flags = Some(stream_flags);
        self
    }

    pub fn to_opack_value(&self) -> OpackValue {
        let mut entries = vec![
            (
                KEY_STREAM_ID,
                OpackValue::String(self.stream_id.as_wire_string()),
            ),
            (
                KEY_STREAM_TYPE,
                OpackValue::Int(self.stream_type.wire_value()),
            ),
        ];
        if let Some(stream_flags) = self.stream_flags {
            entries.push((KEY_STREAM_FLAGS, OpackValue::Int(stream_flags as i64)));
        }
        dict(entries)
    }

    pub fn encode_opack(&self) -> Result<Vec<u8>, StreamError> {
        Ok(encode_opack(&self.to_opack_value())?)
    }

    pub fn decode_opack(data: &[u8]) -> Result<Self, StreamError> {
        Self::from_opack_value(&decode_opack(data)?)
    }

    pub fn from_opack_value(value: &OpackValue) -> Result<Self, StreamError> {
        let stream_id = string_field(value, KEY_STREAM_ID)?;
        let stream_type = int_field(value, KEY_STREAM_TYPE)?;
        let stream_type =
            RpStreamType::from_wire_value(stream_type).ok_or(StreamError::InvalidField {
                field: KEY_STREAM_TYPE,
                reason: "unsupported RPStreamType value",
            })?;
        let stream_flags = optional_int_field(value, KEY_STREAM_FLAGS)?
            .map(|value| {
                u32::try_from(value).map_err(|_| StreamError::InvalidField {
                    field: KEY_STREAM_FLAGS,
                    reason: "must fit in u32",
                })
            })
            .transpose()?;

        Ok(Self {
            stream_id: stream_id.parse()?,
            stream_type,
            stream_flags,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamStartResponse {
    pub port: u16,
    pub address: Option<String>,
    pub mac_address: Option<Vec<u8>>,
    pub stream_key: Option<Vec<u8>>,
}

impl StreamStartResponse {
    pub fn new(port: u16) -> Self {
        Self {
            port,
            address: None,
            mac_address: None,
            stream_key: None,
        }
    }

    pub fn with_address(mut self, address: impl Into<String>) -> Self {
        self.address = Some(address.into());
        self
    }

    pub fn with_mac_address(mut self, mac_address: impl Into<Vec<u8>>) -> Self {
        self.mac_address = Some(mac_address.into());
        self
    }

    pub fn with_stream_key(mut self, stream_key: impl Into<Vec<u8>>) -> Self {
        self.stream_key = Some(stream_key.into());
        self
    }

    pub fn to_opack_value(&self) -> OpackValue {
        let mut entries = vec![(KEY_STREAM_PORT, OpackValue::Int(self.port as i64))];
        if let Some(address) = &self.address {
            entries.push((KEY_STREAM_ADDR, OpackValue::String(address.clone())));
        }
        if let Some(mac_address) = &self.mac_address {
            entries.push((KEY_STREAM_MAC_ADDR, OpackValue::Data(mac_address.clone())));
        }
        if let Some(stream_key) = &self.stream_key {
            entries.push((KEY_STREAM_KEY, OpackValue::Data(stream_key.clone())));
        }
        dict(entries)
    }

    pub fn encode_opack(&self) -> Result<Vec<u8>, StreamError> {
        Ok(encode_opack(&self.to_opack_value())?)
    }

    pub fn decode_opack(data: &[u8]) -> Result<Self, StreamError> {
        Self::from_opack_value(&decode_opack(data)?)
    }

    pub fn from_opack_value(value: &OpackValue) -> Result<Self, StreamError> {
        let port = int_field(value, KEY_STREAM_PORT)?;
        let port = u16::try_from(port).map_err(|_| StreamError::InvalidField {
            field: KEY_STREAM_PORT,
            reason: "must fit in u16",
        })?;

        Ok(Self {
            port,
            address: optional_string_field(value, KEY_STREAM_ADDR)?,
            mac_address: optional_data_field(value, KEY_STREAM_MAC_ADDR)?,
            stream_key: optional_data_field(value, KEY_STREAM_KEY)?,
        })
    }
}

fn normalize_uuid(value: String) -> Result<String, StreamError> {
    if value.len() != 36 {
        return Err(StreamError::InvalidStreamId(value));
    }
    for (index, byte) in value.bytes().enumerate() {
        let is_hyphen = matches!(index, 8 | 13 | 18 | 23);
        if is_hyphen {
            if byte != b'-' {
                return Err(StreamError::InvalidStreamId(value));
            }
        } else if !byte.is_ascii_hexdigit() {
            return Err(StreamError::InvalidStreamId(value));
        }
    }
    Ok(value.to_ascii_uppercase())
}

fn dict_entries(value: &OpackValue) -> Result<&[(String, OpackValue)], StreamError> {
    match value {
        OpackValue::Dict(entries) => Ok(entries),
        _ => Err(StreamError::ExpectedDict),
    }
}

fn field<'a>(value: &'a OpackValue, key: &'static str) -> Result<&'a OpackValue, StreamError> {
    dict_entries(value)?
        .iter()
        .find_map(|(entry_key, entry_value)| (entry_key == key).then_some(entry_value))
        .ok_or(StreamError::MissingField(key))
}

fn optional_field<'a>(
    value: &'a OpackValue,
    key: &'static str,
) -> Result<Option<&'a OpackValue>, StreamError> {
    Ok(dict_entries(value)?
        .iter()
        .find_map(|(entry_key, entry_value)| (entry_key == key).then_some(entry_value)))
}

fn string_field(value: &OpackValue, key: &'static str) -> Result<String, StreamError> {
    match field(value, key)? {
        OpackValue::String(value) => Ok(value.clone()),
        _ => Err(StreamError::InvalidField {
            field: key,
            reason: "expected string",
        }),
    }
}

fn optional_string_field(
    value: &OpackValue,
    key: &'static str,
) -> Result<Option<String>, StreamError> {
    optional_field(value, key)?
        .map(|value| match value {
            OpackValue::String(value) => Ok(value.clone()),
            _ => Err(StreamError::InvalidField {
                field: key,
                reason: "expected string",
            }),
        })
        .transpose()
}

fn int_field(value: &OpackValue, key: &'static str) -> Result<i64, StreamError> {
    match field(value, key)? {
        OpackValue::Int(value) => Ok(*value),
        _ => Err(StreamError::InvalidField {
            field: key,
            reason: "expected integer",
        }),
    }
}

fn optional_int_field(value: &OpackValue, key: &'static str) -> Result<Option<i64>, StreamError> {
    optional_field(value, key)?
        .map(|value| match value {
            OpackValue::Int(value) => Ok(*value),
            _ => Err(StreamError::InvalidField {
                field: key,
                reason: "expected integer",
            }),
        })
        .transpose()
}

fn optional_data_field(
    value: &OpackValue,
    key: &'static str,
) -> Result<Option<Vec<u8>>, StreamError> {
    optional_field(value, key)?
        .map(|value| match value {
            OpackValue::Data(value) => Ok(value.clone()),
            _ => Err(StreamError::InvalidField {
                field: key,
                reason: "expected data",
            }),
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opack::OpackValue;

    const SESSION_UUID: &str = "6843EBDE-86D7-4842-8AF1-FE691AA0F913";

    #[test]
    fn role_codes_match_universal_control_stream_names() {
        assert_eq!(
            UniversalControlStreamRole::ALL.map(UniversalControlStreamRole::as_code),
            ["SYNC", "EVNT", "CLIP", "DRAG"]
        );
        assert_eq!(
            UniversalControlStreamRole::from_code("EVNT"),
            Some(UniversalControlStreamRole::Events)
        );
        assert_eq!(UniversalControlStreamRole::from_code("NOPE"), None);
    }

    #[test]
    fn parses_and_formats_uppercase_stream_id() {
        let parsed: UniversalControlStreamId = format!("EVNT:{SESSION_UUID}").parse().unwrap();
        assert_eq!(parsed.role, UniversalControlStreamRole::Events);
        assert_eq!(parsed.session_uuid, SESSION_UUID);
        assert_eq!(parsed.to_string(), format!("EVNT:{SESSION_UUID}"));
    }

    #[test]
    fn normalizes_uuid_case() {
        let stream_id = UniversalControlStreamId::new(
            UniversalControlStreamRole::Sync,
            "6843ebde-86d7-4842-8af1-fe691aa0f913",
        )
        .unwrap();
        assert_eq!(stream_id.session_uuid, SESSION_UUID);
        assert_eq!(stream_id.to_string(), format!("SYNC:{SESSION_UUID}"));
    }

    #[test]
    fn rejects_bad_stream_id() {
        assert!("evnt:6843EBDE-86D7-4842-8AF1-FE691AA0F913"
            .parse::<UniversalControlStreamId>()
            .is_err());
        assert!("SYNC:not-a-uuid"
            .parse::<UniversalControlStreamId>()
            .is_err());
        assert!("NOPE:6843EBDE-86D7-4842-8AF1-FE691AA0F913"
            .parse::<UniversalControlStreamId>()
            .is_err());
    }

    #[test]
    fn stream_type_wire_values_match_rapport_table() {
        assert_eq!(RpStreamType::UdpSocket.wire_value(), 1);
        assert_eq!(RpStreamType::RpcConnection.wire_value(), 2);
        assert_eq!(RpStreamType::UdpNetworkPath.wire_value(), 3);
        assert_eq!(RpStreamType::from_wire_value(0), None);
        assert_eq!(RpStreamType::from_wire_value(2).unwrap().label(), "RPCnx");
    }

    #[test]
    fn encodes_and_decodes_stream_start_request() {
        let stream_id =
            UniversalControlStreamId::new(UniversalControlStreamRole::Sync, SESSION_UUID).unwrap();
        let request = StreamStartRequest::new(stream_id, RpStreamType::RpcConnection).with_flags(2);
        let encoded = request.encode_opack().unwrap();
        let decoded = StreamStartRequest::decode_opack(&encoded).unwrap();

        assert_eq!(
            decoded.stream_id.to_string(),
            format!("SYNC:{SESSION_UUID}")
        );
        assert_eq!(decoded.stream_type, RpStreamType::RpcConnection);
        assert_eq!(decoded.stream_flags, Some(2));
    }

    #[test]
    fn rejects_unknown_stream_type() {
        let value = dict([
            (
                KEY_STREAM_ID,
                OpackValue::String(format!("SYNC:{SESSION_UUID}")),
            ),
            (KEY_STREAM_TYPE, OpackValue::Int(4)),
        ]);
        assert!(matches!(
            StreamStartRequest::from_opack_value(&value),
            Err(StreamError::InvalidField {
                field: KEY_STREAM_TYPE,
                ..
            })
        ));
    }

    #[test]
    fn encodes_and_decodes_stream_start_response() {
        let response = StreamStartResponse::new(60237)
            .with_address("fe80::405d:5dff:fe32:ba47")
            .with_mac_address(vec![0x40, 0x5d, 0x5d, 0x32, 0xba, 0x47])
            .with_stream_key(vec![0xaa; 32]);

        let decoded = StreamStartResponse::decode_opack(&response.encode_opack().unwrap()).unwrap();
        assert_eq!(decoded.port, 60237);
        assert_eq!(
            decoded.address.as_deref(),
            Some("fe80::405d:5dff:fe32:ba47")
        );
        assert_eq!(decoded.mac_address.unwrap().len(), 6);
        assert_eq!(decoded.stream_key.unwrap(), vec![0xaa; 32]);
    }
}
