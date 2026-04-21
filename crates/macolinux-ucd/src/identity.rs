use std::error::Error;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use macolinux_uc_core::pairverify::{ed25519_public_key_from_seed, generate_ed25519_seed};
use serde::{Deserialize, Serialize};

const IDENTITY_VERSION: u32 = 1;
const DEFAULT_IDENTITY_PATH: &str = "./macolinux-uc.identity.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxIdentity {
    pub version: u32,
    pub identifier: String,
    pub ed25519_seed_hex: String,
    pub ed25519_public_key_hex: String,
    pub created_unix_seconds: u64,
}

#[derive(Debug, Clone, Serialize)]
struct PublicPeerIdentity<'a> {
    version: u32,
    identifier: &'a str,
    ed25519_public_key_hex: &'a str,
}

pub fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
    match args.first().map(String::as_str) {
        Some("create") => run_create(&args[1..]),
        Some("show") => run_show(&args[1..]),
        Some("export-peer") => run_export_peer(&args[1..]),
        Some("-h") | Some("--help") | None => {
            println!("{}", usage());
            Ok(())
        }
        Some(other) => Err(IdentityError(format!("unknown identity command: {other}")).into()),
    }
}

impl LinuxIdentity {
    pub fn generate(identifier: Option<String>) -> Result<Self, Box<dyn Error>> {
        let seed = generate_ed25519_seed();
        let public_key = ed25519_public_key_from_seed(&seed)?;
        let public_key_hex = to_hex(&public_key);
        let identifier =
            identifier.unwrap_or_else(|| format!("macolinux-{}", &public_key_hex[..16]));
        Ok(Self {
            version: IDENTITY_VERSION,
            identifier,
            ed25519_seed_hex: to_hex(&seed),
            ed25519_public_key_hex: public_key_hex,
            created_unix_seconds: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|err| IdentityError(format!("system time is before Unix epoch: {err}")))?
                .as_secs(),
        })
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, Box<dyn Error>> {
        let text = fs::read_to_string(path.as_ref())?;
        let identity: Self = serde_json::from_str(&text)?;
        identity.validate()?;
        Ok(identity)
    }

    pub fn save_new(&self, path: impl AsRef<Path>, force: bool) -> Result<(), Box<dyn Error>> {
        let path = path.as_ref();
        self.validate()?;
        if path.exists() && !force {
            return Err(
                IdentityError(format!("identity file already exists: {}", path.display())).into(),
            );
        }

        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }

        let mut options = OpenOptions::new();
        options.create(true).write(true).truncate(true);
        #[cfg(unix)]
        options.mode(0o600);

        let mut file = options.open(path)?;
        file.write_all(serde_json::to_string_pretty(self)?.as_bytes())?;
        file.write_all(b"\n")?;
        Ok(())
    }

    pub fn validate(&self) -> Result<(), Box<dyn Error>> {
        if self.version != IDENTITY_VERSION {
            return Err(
                IdentityError(format!("unsupported identity version: {}", self.version)).into(),
            );
        }
        if self.identifier.is_empty() {
            return Err(IdentityError("identity identifier must not be empty".into()).into());
        }
        let seed = self.ed25519_seed()?;
        let public_key = ed25519_public_key_from_seed(&seed)?;
        let expected_public_key_hex = to_hex(&public_key);
        if self.ed25519_public_key_hex != expected_public_key_hex {
            return Err(IdentityError(format!(
                "identity public key does not match seed: expected {expected_public_key_hex}, got {}",
                self.ed25519_public_key_hex
            ))
            .into());
        }
        Ok(())
    }

    pub fn identifier_bytes(&self) -> Vec<u8> {
        self.identifier.as_bytes().to_vec()
    }

    pub fn ed25519_seed(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let seed = parse_hex(&self.ed25519_seed_hex)?;
        if seed.len() != 32 {
            return Err(IdentityError(format!(
                "identity seed must be 32 bytes, got {}",
                seed.len()
            ))
            .into());
        }
        Ok(seed)
    }
}

fn run_create(args: &[String]) -> Result<(), Box<dyn Error>> {
    let mut path = PathBuf::from(DEFAULT_IDENTITY_PATH);
    let mut identifier = None;
    let mut force = false;

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--path" => path = PathBuf::from(next_value(&mut iter, arg)?),
            "--identifier" => identifier = Some(next_value(&mut iter, arg)?),
            "--force" => force = true,
            "-h" | "--help" => return Err(IdentityError(usage()).into()),
            other => return Err(IdentityError(format!("unknown create option: {other}")).into()),
        }
    }

    let identity = LinuxIdentity::generate(identifier)?;
    identity.save_new(&path, force)?;
    print_identity_summary(&path, &identity, false);
    Ok(())
}

fn run_show(args: &[String]) -> Result<(), Box<dyn Error>> {
    let mut path = PathBuf::from(DEFAULT_IDENTITY_PATH);
    let mut show_secret = false;

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--path" => path = PathBuf::from(next_value(&mut iter, arg)?),
            "--show-secret" => show_secret = true,
            "-h" | "--help" => return Err(IdentityError(usage()).into()),
            other => return Err(IdentityError(format!("unknown show option: {other}")).into()),
        }
    }

    let identity = LinuxIdentity::load(&path)?;
    print_identity_summary(&path, &identity, show_secret);
    Ok(())
}

fn run_export_peer(args: &[String]) -> Result<(), Box<dyn Error>> {
    let mut path = PathBuf::from(DEFAULT_IDENTITY_PATH);

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--path" => path = PathBuf::from(next_value(&mut iter, arg)?),
            "-h" | "--help" => return Err(IdentityError(usage()).into()),
            other => {
                return Err(IdentityError(format!("unknown export-peer option: {other}")).into())
            }
        }
    }

    let identity = LinuxIdentity::load(&path)?;
    let public = PublicPeerIdentity {
        version: identity.version,
        identifier: &identity.identifier,
        ed25519_public_key_hex: &identity.ed25519_public_key_hex,
    };
    println!("{}", serde_json::to_string_pretty(&public)?);
    Ok(())
}

fn print_identity_summary(path: &Path, identity: &LinuxIdentity, show_secret: bool) {
    println!("path={}", path.display());
    println!("version={}", identity.version);
    println!("identifier={}", identity.identifier);
    println!("ed25519_public_key_hex={}", identity.ed25519_public_key_hex);
    println!("created_unix_seconds={}", identity.created_unix_seconds);
    if show_secret {
        println!("ed25519_seed_hex={}", identity.ed25519_seed_hex);
    }
}

fn next_value<'a>(
    iter: &mut impl Iterator<Item = &'a String>,
    flag: &str,
) -> Result<String, IdentityError> {
    iter.next()
        .cloned()
        .ok_or_else(|| IdentityError(format!("missing value for {flag}")))
}

fn parse_hex(value: &str) -> Result<Vec<u8>, IdentityError> {
    let mut cleaned = value
        .trim()
        .strip_prefix("0x")
        .unwrap_or(value.trim())
        .to_string();
    cleaned.retain(|ch| !ch.is_whitespace() && ch != ':' && ch != '-');

    if cleaned.len() % 2 != 0 {
        return Err(IdentityError(format!(
            "hex input has odd length: {}",
            cleaned.len()
        )));
    }

    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for index in (0..cleaned.len()).step_by(2) {
        let byte = u8::from_str_radix(&cleaned[index..index + 2], 16)
            .map_err(|err| IdentityError(format!("invalid hex at offset {index}: {err}")))?;
        out.push(byte);
    }
    Ok(out)
}

fn to_hex(data: &[u8]) -> String {
    data.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn usage() -> String {
    "usage:
  macolinux-ucd identity create [--path PATH] [--identifier TEXT] [--force]
  macolinux-ucd identity show [--path PATH] [--show-secret]
  macolinux-ucd identity export-peer [--path PATH]"
        .into()
}

#[derive(Debug)]
struct IdentityError(String);

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for IdentityError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_identity_validates_and_has_derived_public_key() {
        let identity = LinuxIdentity::generate(Some("fistel-test".into())).unwrap();

        assert_eq!(identity.version, IDENTITY_VERSION);
        assert_eq!(identity.identifier, "fistel-test");
        assert_eq!(parse_hex(&identity.ed25519_seed_hex).unwrap().len(), 32);
        assert_eq!(
            parse_hex(&identity.ed25519_public_key_hex).unwrap().len(),
            32
        );
        identity.validate().unwrap();
    }
}
