use std::env;
use std::error::Error;
use std::fmt;
use std::fs;
use std::process;

use macolinux_uc_core::pairverify::{
    build_pairverify_m1, build_pairverify_m3, build_pairverify_m3_plaintext, derive_pairverify_key,
    parse_pairverify_m2, PairVerifyKeyPair, PAIRVERIFY_KEY_LENGTH,
};
use serde::Deserialize;

fn main() {
    if let Err(err) = run(env::args().collect()) {
        eprintln!("pairverify-actor-helper: {err}");
        process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<(), Box<dyn Error>> {
    match args.get(1).map(String::as_str) {
        Some("m1") => run_m1(),
        Some("m3") => run_m3(&args[2..]),
        Some("-h") | Some("--help") | None => {
            print_help();
            Ok(())
        }
        Some(other) => Err(HelperError(format!("unknown command: {other}")).into()),
    }
}

fn run_m1() -> Result<(), Box<dyn Error>> {
    let key_pair = PairVerifyKeyPair::generate();
    let public_key = key_pair.public_key();
    let m1 = build_pairverify_m1(&public_key);

    println!("secret_key_hex={}", to_hex(&key_pair.secret_bytes()));
    println!("public_key_hex={}", to_hex(&public_key));
    println!("m1_hex={}", to_hex(&m1));
    Ok(())
}

fn run_m3(args: &[String]) -> Result<(), Box<dyn Error>> {
    let mut secret_key_hex = None;
    let mut m2_hex = None;
    let mut identity_path = None;

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--secret-key-hex" => secret_key_hex = Some(next_value(&mut iter, arg)?),
            "--m2-hex" => m2_hex = Some(next_value(&mut iter, arg)?),
            "--identity" => identity_path = Some(next_value(&mut iter, arg)?),
            "-h" | "--help" => return Err(HelperError(usage()).into()),
            other => return Err(HelperError(format!("unknown m3 option: {other}")).into()),
        }
    }

    let secret_key = parse_fixed_32(
        &secret_key_hex.ok_or_else(|| HelperError("missing --secret-key-hex".into()))?,
        "secret key",
    )?;
    let m2 = parse_hex(&m2_hex.ok_or_else(|| HelperError("missing --m2-hex".into()))?)?;
    let identity_path = identity_path.ok_or_else(|| HelperError("missing --identity".into()))?;
    let identity = LinuxIdentity::load(identity_path)?;
    let seed = parse_fixed_32(&identity.ed25519_seed_hex, "identity seed")?;

    let key_pair = PairVerifyKeyPair::from_secret_bytes(secret_key);
    let parsed = parse_pairverify_m2(&key_pair, &m2)?;
    let server_public_key = parsed
        .fields
        .public_key
        .ok_or_else(|| HelperError("M2 is missing server public key".into()))?;
    let encrypted_data = parsed
        .fields
        .encrypted_data
        .ok_or_else(|| HelperError("M2 is missing encrypted data".into()))?;
    let shared_secret = key_pair.shared_secret(&server_public_key)?;
    let encryption_key = derive_pairverify_key(&shared_secret)?;
    let plaintext = build_pairverify_m3_plaintext(
        &key_pair.public_key(),
        identity.identifier.as_bytes(),
        &server_public_key,
        &seed,
    )?;
    let m3 = build_pairverify_m3(&encryption_key, &plaintext)?;

    println!("server_public_key_hex={}", to_hex(&server_public_key));
    println!("m2_encrypted_data_hex={}", to_hex(&encrypted_data));
    println!("shared_secret_hex={}", to_hex(&shared_secret));
    println!("pairverify_encryption_key_hex={}", to_hex(&encryption_key));
    if let Some(decrypted) = parsed.decrypted_fields {
        if let Some(identifier) = decrypted.identifier {
            println!(
                "server_identifier_utf8={}",
                String::from_utf8_lossy(&identifier)
            );
        }
    }
    println!("m3_hex={}", to_hex(&m3));
    Ok(())
}

#[derive(Debug, Deserialize)]
struct LinuxIdentity {
    identifier: String,
    ed25519_seed_hex: String,
}

impl LinuxIdentity {
    fn load(path: impl AsRef<str>) -> Result<Self, Box<dyn Error>> {
        let text = fs::read_to_string(path.as_ref())?;
        Ok(serde_json::from_str(&text)?)
    }
}

fn next_value<'a>(
    iter: &mut impl Iterator<Item = &'a String>,
    flag: &str,
) -> Result<String, HelperError> {
    iter.next()
        .cloned()
        .ok_or_else(|| HelperError(format!("missing value for {flag}")))
}

fn parse_fixed_32(value: &str, label: &str) -> Result<[u8; PAIRVERIFY_KEY_LENGTH], Box<dyn Error>> {
    let bytes = parse_hex(value)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        HelperError(format!("{label} must be 32 bytes, got {}", bytes.len())).into()
    })
}

fn parse_hex(value: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut cleaned = value
        .trim()
        .strip_prefix("0x")
        .unwrap_or(value.trim())
        .to_string();
    cleaned.retain(|ch| !ch.is_whitespace() && ch != ':' && ch != '-');

    if cleaned.len() % 2 != 0 {
        return Err(HelperError(format!("hex input has odd length: {}", cleaned.len())).into());
    }

    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for index in (0..cleaned.len()).step_by(2) {
        let byte = u8::from_str_radix(&cleaned[index..index + 2], 16)
            .map_err(|err| HelperError(format!("invalid hex at offset {index}: {err}")))?;
        out.push(byte);
    }
    Ok(out)
}

fn to_hex(data: &[u8]) -> String {
    data.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn print_help() {
    println!("{}", usage());
}

fn usage() -> String {
    "usage:
  pairverify_actor_helper m1
  pairverify_actor_helper m3 --secret-key-hex HEX --m2-hex HEX --identity PATH"
        .into()
}

#[derive(Debug)]
struct HelperError(String);

impl fmt::Display for HelperError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for HelperError {}
