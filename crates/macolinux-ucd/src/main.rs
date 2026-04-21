use std::env;
use std::error::Error;
use std::fmt;
use std::process;

use macolinux_uc_core::rapport::{decode_many, RapportFrame};
use macolinux_uc_core::tlv8::{decode_tlv8, encode_tlv8};

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
        Some("serve") => {
            println!("daemon skeleton only; discovery/pairverify runtime is not implemented yet");
            Ok(())
        }
        Some("-h") | Some("--help") | None => {
            print_help();
            Ok(())
        }
        Some(other) => Err(CliError(format!("unknown command: {other}")).into()),
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
  macolinux-ucd serve
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

fn parse_u8(value: &str) -> Result<u8, Box<dyn Error>> {
    let text = value.trim();
    let parsed = if let Some(hex) = text.strip_prefix("0x") {
        u8::from_str_radix(hex, 16)?
    } else {
        text.parse::<u8>()?
    };
    Ok(parsed)
}

fn parse_hex(value: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut cleaned = value
        .trim()
        .strip_prefix("0x")
        .unwrap_or(value.trim())
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
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

fn to_hex(data: &[u8]) -> String {
    data.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Debug)]
struct CliError(String);

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for CliError {}
