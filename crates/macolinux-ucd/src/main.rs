use std::env;
use std::error::Error;
use std::fmt;
use std::process;

use macolinux_uc_core::opack::OpackValue;
use macolinux_uc_core::pairing_stream::{PairingStream, PairingStreamEndpoint};
use macolinux_uc_core::pairverify::PAIRVERIFY_KEY_LENGTH;
use macolinux_uc_core::rapport::{decode_many, RapportFrame};
use macolinux_uc_core::tlv8::{decode_tlv8, encode_tlv8};

mod ble;
mod identity;
mod input;
mod mdns;
mod pairing;
mod relay;
mod serve;
mod stream_server;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    if let Err(err) = run(env::args().collect()) {
        eprintln!("macolinux-ucd: {err}");
        process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<(), Box<dyn Error>> {
    match args.get(1).map(String::as_str) {
        Some("--version") | Some("version") => {
            println!("macolinux-ucd {VERSION}");
            Ok(())
        }
        Some("tlv8") => run_tlv8(&args[2..]),
        Some("rapport") => run_rapport(&args[2..]),
        Some("eopack") => run_eopack(&args[2..]),
        Some("identity") => identity::run(&args[2..]),
        Some("input") => input::run(&args[2..]),
        Some("pairing") => pairing::run(&args[2..]),
        Some("relay") => relay::run(&args[2..]),
        Some("serve") => serve::run(&args[2..]),
        Some("stream") => stream_server::run(&args[2..]),
        Some("-h") | Some("--help") | None => {
            print_help();
            Ok(())
        }
        Some(other) => Err(CliError(format!("unknown command: {other}")).into()),
    }
}

#[derive(Debug, Clone)]
struct EopackDecryptConfig {
    psk: [u8; PAIRVERIFY_KEY_LENGTH],
    endpoint: PairingStreamEndpoint,
    stream_name: String,
    input: EopackInput,
}

#[derive(Debug, Clone)]
enum EopackInput {
    Frames(Vec<u8>),
    Body(Vec<u8>),
}

fn run_eopack(args: &[String]) -> Result<(), Box<dyn Error>> {
    match args.first().map(String::as_str) {
        Some("decrypt") => {
            let config = EopackDecryptConfig::parse(&args[1..])?;
            let mut stream = PairingStream::new(&config.stream_name, config.endpoint, &config.psk)?;
            let frames = match config.input {
                EopackInput::Frames(data) => decode_many(&data)?,
                EopackInput::Body(body) => vec![RapportFrame {
                    frame_type: macolinux_uc_core::rapport::FRAME_TYPE_E_OPACK,
                    body,
                }],
            };

            for (index, frame) in frames.iter().enumerate() {
                println!(
                    "#{index} type=0x{:02x} name={} body_len={}",
                    frame.frame_type,
                    frame.name(),
                    frame.body.len()
                );
                match stream.decrypt_e_opack_frame(frame) {
                    Ok(value) => {
                        println!("#{index} opack={}", format_opack(&value));
                        println!("#{index} decrypt_nonce={}", to_hex(&stream.decrypt_nonce()));
                    }
                    Err(err) => println!("#{index} decrypt_error={err}"),
                }
            }
            Ok(())
        }
        Some("-h") | Some("--help") | None => {
            println!("{}", eopack_usage());
            Ok(())
        }
        Some(other) => Err(CliError(format!("unknown eopack command: {other}")).into()),
    }
}

impl EopackDecryptConfig {
    fn parse(args: &[String]) -> Result<Self, Box<dyn Error>> {
        let mut psk = None;
        let mut endpoint = PairingStreamEndpoint::Client;
        let mut stream_name = "main".to_string();
        let mut input = None;

        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--psk-hex" => psk = Some(parse_fixed_32(&next_value(&mut iter, arg)?, "PSK")?),
                "--endpoint" => endpoint = parse_endpoint(&next_value(&mut iter, arg)?)?,
                "--stream-name" => stream_name = next_value(&mut iter, arg)?,
                "--frame-hex" => {
                    input = Some(EopackInput::Frames(parse_hex(&next_value(
                        &mut iter, arg,
                    )?)?))
                }
                "--body-hex" => {
                    input = Some(EopackInput::Body(parse_hex(&next_value(&mut iter, arg)?)?))
                }
                "-h" | "--help" => return Err(CliError(eopack_usage()).into()),
                other => {
                    return Err(CliError(format!("unknown eopack decrypt option: {other}")).into())
                }
            }
        }

        Ok(Self {
            psk: psk.ok_or_else(|| CliError("missing --psk-hex".into()))?,
            endpoint,
            stream_name,
            input: input.ok_or_else(|| CliError("missing --frame-hex or --body-hex".into()))?,
        })
    }
}

fn run_tlv8(args: &[String]) -> Result<(), Box<dyn Error>> {
    match args.first().map(String::as_str) {
        Some("decode") => {
            let hex = args
                .get(1)
                .ok_or_else(|| CliError("missing TLV8 hex".into()))?;
            let data = parse_hex(hex)?;
            for entry in decode_tlv8(&data)? {
                println!(
                    "0x{:02x} {:<13} len={:>3} hex={}",
                    entry.kind,
                    tlv8_name(entry.kind),
                    entry.value.len(),
                    to_hex(&entry.value)
                );
            }
            Ok(())
        }
        Some("encode") => {
            if args.len() < 2 {
                return Err(CliError("missing TYPE=HEX entries".into()).into());
            }
            let mut owned = Vec::new();
            for item in &args[1..] {
                let (kind, value) = parse_typed_hex(item)?;
                owned.push((kind, value));
            }
            let borrowed = owned
                .iter()
                .map(|(kind, value)| (*kind, value.as_slice()))
                .collect::<Vec<_>>();
            println!("{}", to_hex(&encode_tlv8(&borrowed)));
            Ok(())
        }
        _ => Err(
            CliError("usage: macolinux-ucd tlv8 decode HEX | encode TYPE=HEX ...".into()).into(),
        ),
    }
}

fn run_rapport(args: &[String]) -> Result<(), Box<dyn Error>> {
    match args.first().map(String::as_str) {
        Some("dump") => {
            let hex = args
                .get(1)
                .ok_or_else(|| CliError("missing Rapport frame hex".into()))?;
            let data = parse_hex(hex)?;
            for (index, frame) in decode_many(&data)?.iter().enumerate() {
                println!(
                    "#{index} type=0x{:02x} name={} body_len={} body_hex={}",
                    frame.frame_type,
                    frame.name(),
                    frame.body.len(),
                    to_hex(&frame.body)
                );
            }
            Ok(())
        }
        Some("encode") => {
            let frame_type = args
                .get(1)
                .ok_or_else(|| CliError("missing frame type".into()))
                .map_err(|err| -> Box<dyn Error> { Box::new(err) })
                .and_then(|value| parse_u8(value))?;
            let body = args
                .get(2)
                .map(|value| parse_hex(value))
                .transpose()?
                .unwrap_or_default();
            let encoded = RapportFrame { frame_type, body }.encode()?;
            println!("{}", to_hex(&encoded));
            Ok(())
        }
        _ => Err(CliError(
            "usage: macolinux-ucd rapport dump HEX | encode FRAME_TYPE [BODY_HEX]".into(),
        )
        .into()),
    }
}

fn print_help() {
    println!(
        "macolinux-ucd {VERSION}

Usage:
  macolinux-ucd --version
  macolinux-ucd tlv8 decode HEX
  macolinux-ucd tlv8 encode TYPE=HEX ...
  macolinux-ucd rapport dump HEX
  macolinux-ucd rapport encode FRAME_TYPE [BODY_HEX]
  macolinux-ucd eopack decrypt --psk-hex HEX (--frame-hex HEX | --body-hex HEX)
  macolinux-ucd identity create [--path PATH] [--identifier TEXT] [--force]
  macolinux-ucd identity show [--path PATH] [--show-secret]
  macolinux-ucd identity export-peer [--path PATH]
  macolinux-ucd input listen [--bind ADDR:PORT] [--device /dev/uinput] [--dry-run]
  macolinux-ucd pairing resolve --addr HOST:PORT [--frame 0x07] [--shape companion-empty-request]
  macolinux-ucd relay listen [--bind ADDR:PORT] [--send-text TEXT] [--echo]
  macolinux-ucd stream prepare --request-opack-hex HEX [--bind ADDR:PORT]
                              [--advertise-addr ADDR] [--accept-timeout-ms MS]
  macolinux-ucd serve [--instance NAME] [--hostname NAME.local] [--port PORT]
                     [--ipv4 ADDR] [--multicast-ipv4 ADDR]
                     [--ble-address MAC] [--txt KEY=VALUE]
                     [--identity PATH] [--trusted-peer PATH]...
                     [--allow-unknown-peer]
                     [--stream-bind ADDR:PORT]
                     [--stream-advertise-addr ADDR]
                     [--ble-enable]
"
    );
}

fn tlv8_name(kind: u8) -> &'static str {
    match kind {
        0x00 => "Method",
        0x01 => "Identifier",
        0x02 => "Salt",
        0x03 => "PublicKey",
        0x04 => "Proof",
        0x05 => "EncryptedData",
        0x06 => "State",
        0x07 => "Error",
        0x08 => "RetryDelay",
        0x09 => "Certificate",
        0x0a => "Signature",
        0x0b => "Permissions",
        0x0c => "FragmentData",
        0x0d => "FragmentLast",
        0x19 => "AppFlags",
        _ => "Unknown",
    }
}

fn parse_typed_hex(value: &str) -> Result<(u8, Vec<u8>), Box<dyn Error>> {
    let (kind, hex) = value
        .split_once('=')
        .ok_or_else(|| CliError(format!("expected TYPE=HEX, got {value:?}")))?;
    Ok((parse_u8(kind)?, parse_hex(hex)?))
}

fn next_value<'a>(
    iter: &mut impl Iterator<Item = &'a String>,
    flag: &str,
) -> Result<String, CliError> {
    iter.next()
        .cloned()
        .ok_or_else(|| CliError(format!("missing value for {flag}")))
}

fn parse_u8(value: &str) -> Result<u8, Box<dyn Error>> {
    let text = value.trim();
    let parsed = if let Some(hex) = text.strip_prefix("0x") {
        u8::from_str_radix(hex, 16)?
    } else {
        text.parse::<u8>()?
    };
    Ok(parsed)
}

fn parse_endpoint(value: &str) -> Result<PairingStreamEndpoint, CliError> {
    match value {
        "client" => Ok(PairingStreamEndpoint::Client),
        "server" => Ok(PairingStreamEndpoint::Server),
        other => Err(CliError(format!("invalid endpoint {other:?}"))),
    }
}

fn parse_hex(value: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut cleaned = value
        .trim()
        .strip_prefix("0x")
        .unwrap_or(value.trim())
        .to_string();
    cleaned.retain(|ch| !ch.is_whitespace() && ch != ':' && ch != '-');
    cleaned.make_ascii_lowercase();

    if cleaned.len() % 2 != 0 {
        return Err(CliError("hex input must have an even number of digits".into()).into());
    }

    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for pair in cleaned.as_bytes().chunks_exact(2) {
        let text = std::str::from_utf8(pair)?;
        out.push(u8::from_str_radix(text, 16)?);
    }
    Ok(out)
}

fn parse_fixed_32(value: &str, label: &str) -> Result<[u8; PAIRVERIFY_KEY_LENGTH], Box<dyn Error>> {
    let bytes = parse_hex(value)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        CliError(format!("{label} must be 32 bytes, got {}", bytes.len())).into()
    })
}

fn to_hex(data: &[u8]) -> String {
    data.iter().map(|byte| format!("{byte:02x}")).collect()
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

fn eopack_usage() -> String {
    "usage:
  macolinux-ucd eopack decrypt --psk-hex HEX [--endpoint client|server]
                              [--stream-name NAME]
                              (--frame-hex HEX | --body-hex HEX)"
        .into()
}

#[derive(Debug)]
struct CliError(String);

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for CliError {}
