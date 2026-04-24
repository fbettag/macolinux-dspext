use std::error::Error;
use std::fmt;

use crate::opack::{decode_opack, dict, empty_dict, encode_opack, OpackError, OpackValue};

pub const KEY_MESSAGE_ID: &str = "_i";
pub const KEY_TRANSACTION_ID: &str = "_x";
pub const KEY_REQUEST_ID: &str = "requestID";
pub const KEY_REQUEST: &str = "request";
pub const KEY_RESPONSE: &str = "response";
pub const KEY_ERROR: &str = "error";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompanionError {
    Opack(OpackError),
    ExpectedDict,
    MissingField(&'static str),
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
}

impl fmt::Display for CompanionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Opack(err) => write!(f, "{err}"),
            Self::ExpectedDict => f.write_str("expected CompanionLink OPACK dictionary"),
            Self::MissingField(field) => write!(f, "missing CompanionLink field {field}"),
            Self::InvalidField { field, reason } => {
                write!(f, "invalid CompanionLink field {field}: {reason}")
            }
        }
    }
}

impl Error for CompanionError {}

impl From<OpackError> for CompanionError {
    fn from(value: OpackError) -> Self {
        Self::Opack(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompanionRequest {
    pub message_id: Option<String>,
    pub transaction_id: Option<i64>,
    pub request_id: String,
    pub request: OpackValue,
}

impl CompanionRequest {
    pub fn new(request_id: impl Into<String>, request: OpackValue) -> Self {
        Self {
            message_id: None,
            transaction_id: None,
            request_id: request_id.into(),
            request,
        }
    }

    pub fn with_message_id(mut self, message_id: impl Into<String>) -> Self {
        self.message_id = Some(message_id.into());
        self
    }

    pub fn with_transaction_id(mut self, transaction_id: i64) -> Self {
        self.transaction_id = Some(transaction_id);
        self
    }

    pub fn to_opack_value(&self) -> OpackValue {
        let mut entries = Vec::new();
        if let Some(message_id) = &self.message_id {
            entries.push((KEY_MESSAGE_ID, OpackValue::String(message_id.clone())));
        }
        entries.push((KEY_REQUEST_ID, OpackValue::String(self.request_id.clone())));
        if let Some(transaction_id) = self.transaction_id {
            entries.push((KEY_TRANSACTION_ID, OpackValue::Int(transaction_id)));
        }
        entries.push((KEY_REQUEST, self.request.clone()));
        dict(entries)
    }

    pub fn encode_opack(&self) -> Result<Vec<u8>, CompanionError> {
        Ok(encode_opack(&self.to_opack_value())?)
    }

    pub fn decode_opack(data: &[u8]) -> Result<Self, CompanionError> {
        Self::from_opack_value(&decode_opack(data)?)
    }

    pub fn from_opack_value(value: &OpackValue) -> Result<Self, CompanionError> {
        Ok(Self {
            message_id: optional_string_field(value, KEY_MESSAGE_ID)?,
            transaction_id: optional_int_field(value, KEY_TRANSACTION_ID)?,
            request_id: string_field(value, KEY_REQUEST_ID)?,
            request: optional_field(value, KEY_REQUEST)?
                .cloned()
                .unwrap_or_else(empty_dict),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompanionResponse {
    pub message_id: Option<String>,
    pub transaction_id: Option<i64>,
    pub response: OpackValue,
    pub error: Option<OpackValue>,
}

impl CompanionResponse {
    pub fn for_request(request: &CompanionRequest, response: OpackValue) -> Self {
        Self {
            message_id: request.message_id.clone(),
            transaction_id: request.transaction_id,
            response,
            error: None,
        }
    }

    pub fn with_error(mut self, error: OpackValue) -> Self {
        self.error = Some(error);
        self
    }

    pub fn to_opack_value(&self) -> OpackValue {
        let mut entries = Vec::new();
        if let Some(message_id) = &self.message_id {
            entries.push((KEY_MESSAGE_ID, OpackValue::String(message_id.clone())));
        }
        if let Some(transaction_id) = self.transaction_id {
            entries.push((KEY_TRANSACTION_ID, OpackValue::Int(transaction_id)));
        }
        entries.push((KEY_RESPONSE, self.response.clone()));
        if let Some(error) = &self.error {
            entries.push((KEY_ERROR, error.clone()));
        }
        dict(entries)
    }

    pub fn encode_opack(&self) -> Result<Vec<u8>, CompanionError> {
        Ok(encode_opack(&self.to_opack_value())?)
    }
}

fn dict_entries(value: &OpackValue) -> Result<&[(String, OpackValue)], CompanionError> {
    match value {
        OpackValue::Dict(entries) => Ok(entries),
        _ => Err(CompanionError::ExpectedDict),
    }
}

fn field<'a>(value: &'a OpackValue, key: &'static str) -> Result<&'a OpackValue, CompanionError> {
    dict_entries(value)?
        .iter()
        .find_map(|(entry_key, entry_value)| (entry_key == key).then_some(entry_value))
        .ok_or(CompanionError::MissingField(key))
}

fn optional_field<'a>(
    value: &'a OpackValue,
    key: &'static str,
) -> Result<Option<&'a OpackValue>, CompanionError> {
    Ok(dict_entries(value)?
        .iter()
        .find_map(|(entry_key, entry_value)| (entry_key == key).then_some(entry_value)))
}

fn string_field(value: &OpackValue, key: &'static str) -> Result<String, CompanionError> {
    match field(value, key)? {
        OpackValue::String(value) => Ok(value.clone()),
        _ => Err(CompanionError::InvalidField {
            field: key,
            reason: "expected string",
        }),
    }
}

fn optional_string_field(
    value: &OpackValue,
    key: &'static str,
) -> Result<Option<String>, CompanionError> {
    optional_field(value, key)?
        .map(|value| match value {
            OpackValue::String(value) => Ok(value.clone()),
            _ => Err(CompanionError::InvalidField {
                field: key,
                reason: "expected string",
            }),
        })
        .transpose()
}

fn optional_int_field(
    value: &OpackValue,
    key: &'static str,
) -> Result<Option<i64>, CompanionError> {
    optional_field(value, key)?
        .map(|value| match value {
            OpackValue::Int(value) => Ok(*value),
            _ => Err(CompanionError::InvalidField {
                field: key,
                reason: "expected integer",
            }),
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opack::OpackValue;

    #[test]
    fn decodes_companion_request_fixture() {
        let request = CompanionRequest::decode_opack(&hex_bytes(
            "e4425f6941314972657175657374494459727070616972696e672d626f6e6a6f75722d7265736f6c7665425f78094772657175657374e0",
        ))
        .unwrap();

        assert_eq!(request.message_id.as_deref(), Some("1"));
        assert_eq!(request.transaction_id, Some(1));
        assert_eq!(request.request_id, "rppairing-bonjour-resolve");
        assert_eq!(request.request, empty_dict());
    }

    #[test]
    fn encodes_response_for_request() {
        let request = CompanionRequest::new("_streamStart", empty_dict())
            .with_message_id("7")
            .with_transaction_id(42);
        let response = CompanionResponse::for_request(
            &request,
            dict([("_streamPort", OpackValue::Int(60237))]),
        );
        let value = response.to_opack_value();

        assert_eq!(
            value,
            dict([
                (KEY_MESSAGE_ID, OpackValue::String("7".into())),
                (KEY_TRANSACTION_ID, OpackValue::Int(42)),
                (
                    KEY_RESPONSE,
                    dict([("_streamPort", OpackValue::Int(60237))]),
                ),
            ])
        );
        assert!(response.encode_opack().unwrap().len() > 8);
    }

    fn hex_bytes(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(text, 16).unwrap()
            })
            .collect()
    }
}
