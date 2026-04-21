use std::error::Error;
use std::fmt;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use macolinux_uc_core::opack::{decode_opack, dict, empty_dict, encode_opack, OpackValue};
use macolinux_uc_core::rapport::{frame_type_name, RapportFrame};

const REQUEST_ID: &str = "rppairing-bonjour-resolve";

#[derive(Debug, Clone)]
struct ResolveConfig {
    addr: String,
    timeout: Duration,
    shape: RequestShape,
    frame_type: u8,
    preauth: bool,
    data_key: String,
    pairing_info: Option<Vec<u8>>,
    opack_data: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestShape {
    RequestIdOnly,
    CompanionRequest,
    CompanionRequestWithEmptyRequest,
}

pub fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
    match args.first().map(String::as_str) {
        Some("resolve") => run_resolve(&args[1..]),
        Some("-h") | Some("--help") | None => {
            println!("{}", usage());
            Ok(())
        }
        Some(other) => Err(PairingError(format!("unknown pairing command: {other}")).into()),
    }
}

fn run_resolve(args: &[String]) -> Result<(), Box<dyn Error>> {
    let config = ResolveConfig::parse(args)?;
    let addr = resolve_addr(&config.addr)?;

    println!(
        "connecting to {addr} shape={} frame=0x{:02x} ({}) timeout={}ms",
        config.shape.name(),
        config.frame_type,
        frame_type_name(config.frame_type),
        config.timeout.as_millis()
    );

    let mut stream = TcpStream::connect_timeout(&addr, config.timeout)?;
    stream.set_read_timeout(Some(config.timeout))?;
    stream.set_write_timeout(Some(config.timeout))?;

    if config.preauth {
        let preauth = encode_opack(&dict([("_i", OpackValue::String("1".into()))]))?;
        println!("preauth_opack={}", to_hex(&preauth));
        send_frame(&mut stream, 0x0a, preauth)?;
        read_until_preauth_response(&mut stream)?;
    }

    let request = config.opack_value();
    let body = encode_opack(&request)?;
    println!("request_opack={}", to_hex(&body));
    send_frame(&mut stream, config.frame_type, body)?;

    read_frames(&mut stream)
}

impl ResolveConfig {
    fn parse(args: &[String]) -> Result<Self, PairingError> {
        let mut config = Self {
            addr: "127.0.0.1:49152".into(),
            timeout: Duration::from_secs(5),
            shape: RequestShape::CompanionRequestWithEmptyRequest,
            frame_type: 0x07,
            preauth: true,
            data_key: "_pd".into(),
            pairing_info: None,
            opack_data: None,
        };

        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--addr" => config.addr = next_value(&mut iter, arg)?,
                "--timeout-ms" => {
                    let value = next_value(&mut iter, arg)?;
                    let millis = value
                        .parse::<u64>()
                        .map_err(|err| PairingError(format!("invalid timeout {value:?}: {err}")))?;
                    config.timeout = Duration::from_millis(millis);
                }
                "--shape" => {
                    let value = next_value(&mut iter, arg)?;
                    config.shape = RequestShape::parse(&value)?;
                }
                "--frame" => {
                    let value = next_value(&mut iter, arg)?;
                    config.frame_type = parse_u8(&value)?;
                }
                "--pairing-info-hex" => {
                    let value = next_value(&mut iter, arg)?;
                    config.pairing_info = Some(parse_hex(&value)?);
                }
                "--data-key" => config.data_key = next_value(&mut iter, arg)?,
                "--opack-data-hex" => {
                    let value = next_value(&mut iter, arg)?;
                    config.opack_data = Some(parse_hex(&value)?);
                }
                "--no-preauth" => config.preauth = false,
                "-h" | "--help" => return Err(PairingError(usage())),
                other => return Err(PairingError(format!("unknown resolve option: {other}"))),
            }
        }

        Ok(config)
    }

    fn opack_value(&self) -> OpackValue {
        if let Some(opack_data) = &self.opack_data {
            return OpackValue::Data(opack_data.clone());
        }

        if let Some(pairing_info) = &self.pairing_info {
            return dict([(
                self.data_key.as_str(),
                OpackValue::Data(pairing_info.clone()),
            )]);
        }

        match self.shape {
            RequestShape::RequestIdOnly => {
                dict([("requestID", OpackValue::String(REQUEST_ID.into()))])
            }
            RequestShape::CompanionRequest => dict([
                ("_i", OpackValue::String("1".into())),
                ("requestID", OpackValue::String(REQUEST_ID.into())),
                ("_x", OpackValue::Int(1)),
            ]),
            RequestShape::CompanionRequestWithEmptyRequest => dict([
                ("_i", OpackValue::String("1".into())),
                ("requestID", OpackValue::String(REQUEST_ID.into())),
                ("_x", OpackValue::Int(1)),
                ("request", empty_dict()),
            ]),
        }
    }
}

impl RequestShape {
    fn parse(value: &str) -> Result<Self, PairingError> {
        match value {
            "request-id-only" => Ok(Self::RequestIdOnly),
            "companion" => Ok(Self::CompanionRequest),
            "companion-empty-request" => Ok(Self::CompanionRequestWithEmptyRequest),
            other => Err(PairingError(format!("unknown request shape: {other}"))),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::RequestIdOnly => "request-id-only",
            Self::CompanionRequest => "companion",
            Self::CompanionRequestWithEmptyRequest => "companion-empty-request",
        }
    }
}

fn send_frame(stream: &mut TcpStream, frame_type: u8, body: Vec<u8>) -> Result<(), Box<dyn Error>> {
    let frame = RapportFrame { frame_type, body }.encode()?;
    stream.write_all(&frame)?;
    stream.flush()?;
    Ok(())
}

fn read_until_preauth_response(stream: &mut TcpStream) -> Result<(), Box<dyn Error>> {
    loop {
        let Some((frame_type, body)) = read_one_frame(stream)? else {
            return Err(PairingError("preauth timed out before PA_Rsp".into()).into());
        };
        println!(
            "preauth response: type=0x{frame_type:02x} name={} body_len={} body_hex={}",
            frame_type_name(frame_type),
            body.len(),
            to_hex(&body)
        );
        if let Ok(value) = decode_opack(&body) {
            println!("preauth response opack={}", format_opack(&value));
        }
        if frame_type == 0x0b {
            return Ok(());
        }
    }
}

fn read_frames(stream: &mut TcpStream) -> Result<(), Box<dyn Error>> {
    let mut count = 0usize;
    loop {
        let Some((frame_type, body)) = read_one_frame(stream)? else {
            if count == 0 {
                println!("no response before timeout");
            } else {
                println!("response timeout after {count} frame(s)");
            }
            return Ok(());
        };

        println!(
            "response #{count}: type=0x{:02x} name={} body_len={} body_hex={}",
            frame_type,
            frame_type_name(frame_type),
            body.len(),
            to_hex(&body)
        );

        match decode_opack(&body) {
            Ok(value) => println!("response #{count} opack={}", format_opack(&value)),
            Err(err) => println!("response #{count} opack_decode_error={err}"),
        }
        count += 1;
    }
}

fn read_one_frame(stream: &mut TcpStream) -> Result<Option<(u8, Vec<u8>)>, Box<dyn Error>> {
    let mut header = [0u8; 4];
    match stream.read_exact(&mut header) {
        Ok(()) => {}
        Err(err)
            if err.kind() == std::io::ErrorKind::WouldBlock
                || err.kind() == std::io::ErrorKind::TimedOut =>
        {
            return Ok(None);
        }
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err.into()),
    }

    let body_len = ((header[1] as usize) << 16) | ((header[2] as usize) << 8) | header[3] as usize;
    if body_len > 16 * 1024 * 1024 {
        return Err(PairingError(format!("response body too large: {body_len}")).into());
    }
    let mut body = vec![0u8; body_len];
    stream.read_exact(&mut body)?;
    Ok(Some((header[0], body)))
}

fn resolve_addr(addr: &str) -> Result<SocketAddr, Box<dyn Error>> {
    addr.to_socket_addrs()?
        .next()
        .ok_or_else(|| PairingError(format!("could not resolve {addr:?}")).into())
}

fn next_value<'a>(
    iter: &mut impl Iterator<Item = &'a String>,
    flag: &str,
) -> Result<String, PairingError> {
    iter.next()
        .cloned()
        .ok_or_else(|| PairingError(format!("missing value for {flag}")))
}

fn parse_u8(value: &str) -> Result<u8, PairingError> {
    let parsed = if let Some(hex) = value.strip_prefix("0x") {
        u8::from_str_radix(hex, 16)
    } else {
        value.parse::<u8>()
    }
    .map_err(|err| PairingError(format!("invalid u8 {value:?}: {err}")))?;
    Ok(parsed)
}

fn parse_hex(value: &str) -> Result<Vec<u8>, PairingError> {
    let mut cleaned = value
        .trim()
        .strip_prefix("0x")
        .unwrap_or(value.trim())
        .to_string();
    cleaned.retain(|ch| !ch.is_whitespace() && ch != ':' && ch != '-');

    if cleaned.len() % 2 != 0 {
        return Err(PairingError(format!(
            "hex input has odd length: {}",
            cleaned.len()
        )));
    }

    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for index in (0..cleaned.len()).step_by(2) {
        let byte = u8::from_str_radix(&cleaned[index..index + 2], 16)
            .map_err(|err| PairingError(format!("invalid hex at offset {index}: {err}")))?;
        out.push(byte);
    }
    Ok(out)
}

fn format_opack(value: &OpackValue) -> String {
    match value {
        OpackValue::Null => "null".into(),
        OpackValue::Bool(value) => value.to_string(),
        OpackValue::Int(value) => value.to_string(),
        OpackValue::String(value) => format!("{value:?}"),
        OpackValue::Data(value) => format!("<data:{}:{}>", value.len(), to_hex(value)),
        OpackValue::Array(values) => {
            let inner = values
                .iter()
                .map(format_opack)
                .collect::<Vec<_>>()
                .join(", ");
            format!("[{inner}]")
        }
        OpackValue::Dict(values) => {
            let inner = values
                .iter()
                .map(|(key, value)| format!("{key:?}: {}", format_opack(value)))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{{{inner}}}")
        }
    }
}

fn to_hex(data: &[u8]) -> String {
    data.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn usage() -> String {
    "usage:
  macolinux-ucd pairing resolve --addr HOST:PORT [--timeout-ms MS]
                              [--frame 0x03|0x05|0x07|0x09]
                              [--shape request-id-only|companion|companion-empty-request]
                              [--pairing-info-hex TLV8_HEX] [--data-key KEY]
                              [--opack-data-hex HEX]
                              [--no-preauth]"
        .into()
}

#[derive(Debug)]
struct PairingError(String);

impl fmt::Display for PairingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for PairingError {}
