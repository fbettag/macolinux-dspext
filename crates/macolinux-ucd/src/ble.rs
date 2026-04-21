use std::error::Error;
use std::fmt;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const APPLE_COMPANY_ID_LE: [u8; 2] = [0x4c, 0x00];
const AD_TYPE_FLAGS: u8 = 0x01;
const AD_TYPE_MANUFACTURER: u8 = 0xff;
const CONTINUITY_NEARBY_ACTION: u8 = 0x0f;
const CONTINUITY_NEARBY_INFO: u8 = 0x10;
const BTMGMT_COMMAND_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone)]
pub struct BleConfig {
    pub enabled: bool,
    pub btmgmt_path: String,
    pub index: String,
    pub instance: u8,
    pub duration: u32,
    pub flags: Option<String>,
    pub length_flags: u8,
    pub nearby_info: Option<String>,
    pub nearby_action: Option<String>,
    pub tlvs: Vec<String>,
}

impl BleConfig {
    pub fn start(self) -> thread::JoinHandle<()> {
        thread::spawn(move || loop {
            match self.run() {
                Ok(()) => return,
                Err(err) => {
                    eprintln!("BLE advertiser failed: {err}; retrying in 5s");
                    thread::sleep(Duration::from_secs(5));
                }
            }
        })
    }

    fn run(&self) -> Result<(), Box<dyn Error>> {
        if !self.enabled {
            return Ok(());
        }

        let adv = self.advertising_data()?;
        let adv_hex = to_hex(&adv);
        println!(
            "BLE Continuity advertiser: index={} instance={} duration={} adv_hex={}",
            self.index, self.instance, self.duration, adv_hex
        );

        loop {
            self.apply_advertisement(&adv_hex)?;
            if self.duration == 0 {
                return Ok(());
            }

            let refresh_after = self.duration.saturating_sub(5).max(1);
            thread::sleep(Duration::from_secs(refresh_after.into()));
        }
    }

    fn advertising_data(&self) -> Result<Vec<u8>, BleError> {
        let mut continuity = Vec::new();

        for item in &self.tlvs {
            let (kind, payload) = item
                .split_once(':')
                .ok_or_else(|| BleError(format!("expected BLE TLV TYPE:HEX, got {item:?}")))?;
            let kind = parse_u8(kind)?;
            continuity.extend(continuity_tlv(
                kind,
                &clean_hex(payload)?,
                self.length_flags,
            )?);
        }

        if let Some(value) = &self.nearby_info {
            continuity.extend(continuity_tlv(
                CONTINUITY_NEARBY_INFO,
                &clean_hex(value)?,
                self.length_flags,
            )?);
        }
        if let Some(value) = &self.nearby_action {
            continuity.extend(continuity_tlv(
                CONTINUITY_NEARBY_ACTION,
                &clean_hex(value)?,
                self.length_flags,
            )?);
        }

        if continuity.is_empty() {
            return Err(BleError(
                "provide --ble-nearby-info, --ble-nearby-action, or --ble-tlv".into(),
            ));
        }

        let mut out = Vec::new();
        if let Some(flags) = &self.flags {
            if !flags.is_empty() {
                out.extend(ad_structure(AD_TYPE_FLAGS, &clean_hex(flags)?)?);
            }
        }

        let mut manufacturer = Vec::with_capacity(APPLE_COMPANY_ID_LE.len() + continuity.len());
        manufacturer.extend_from_slice(&APPLE_COMPANY_ID_LE);
        manufacturer.extend_from_slice(&continuity);
        out.extend(ad_structure(AD_TYPE_MANUFACTURER, &manufacturer)?);

        if out.len() > 31 {
            return Err(BleError(format!(
                "legacy BLE advertising data is {} bytes; maximum is 31",
                out.len()
            )));
        }
        Ok(out)
    }

    fn apply_advertisement(&self, adv_hex: &str) -> Result<(), Box<dyn Error>> {
        let instance = self.instance.to_string();
        let duration = self.duration.to_string();
        let mut add_adv = vec!["add-adv", "-c", "-d", adv_hex];
        if self.duration != 0 {
            add_adv.push("-t");
            add_adv.push(&duration);
        }
        add_adv.push(&instance);
        run_btmgmt(&self.btmgmt_path, &self.index, &add_adv, false)?;
        run_btmgmt(
            &self.btmgmt_path,
            &self.index,
            &["advertising", "on"],
            false,
        )?;
        run_btmgmt(&self.btmgmt_path, &self.index, &["info"], false)?;
        run_btmgmt(&self.btmgmt_path, &self.index, &["advinfo"], false)?;
        Ok(())
    }
}

fn run_btmgmt(
    btmgmt_path: &str,
    index: &str,
    args: &[&str],
    allow_failure: bool,
) -> Result<(), Box<dyn Error>> {
    println!("running btmgmt --index {index} {}", args.join(" "));
    let mut child = Command::new(btmgmt_path)
        .arg("--index")
        .arg(index)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    let _stdin_guard = child.stdin.take();

    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= BTMGMT_COMMAND_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            if allow_failure {
                eprintln!(
                    "btmgmt {} timed out after {}s",
                    args.join(" "),
                    BTMGMT_COMMAND_TIMEOUT.as_secs()
                );
                return Ok(());
            }
            return Err(BleError(format!(
                "btmgmt {} timed out after {}s",
                args.join(" "),
                BTMGMT_COMMAND_TIMEOUT.as_secs()
            ))
            .into());
        }
        thread::sleep(Duration::from_millis(50));
    };

    if !status.success() && !allow_failure {
        return Err(BleError(format!(
            "btmgmt {} failed with status {}",
            args.join(" "),
            status
        ))
        .into());
    }
    Ok(())
}

fn ad_structure(ad_type: u8, payload: &[u8]) -> Result<Vec<u8>, BleError> {
    let len = 1 + payload.len();
    if len > u8::MAX as usize {
        return Err(BleError("BLE AD structure too long".into()));
    }

    let mut out = Vec::with_capacity(1 + len);
    out.push(len as u8);
    out.push(ad_type);
    out.extend_from_slice(payload);
    Ok(out)
}

fn continuity_tlv(kind: u8, payload: &[u8], length_flags: u8) -> Result<Vec<u8>, BleError> {
    if payload.len() > 0x1f {
        return Err(BleError(
            "Continuity TLV payload length must fit in five bits".into(),
        ));
    }
    if length_flags & 0x1f != 0 {
        return Err(BleError(
            "Continuity TLV length flags occupy only the high three bits".into(),
        ));
    }

    let mut out = Vec::with_capacity(2 + payload.len());
    out.push(kind);
    out.push(length_flags | payload.len() as u8);
    out.extend_from_slice(payload);
    Ok(out)
}

fn clean_hex(value: &str) -> Result<Vec<u8>, BleError> {
    let mut cleaned = value
        .chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .collect::<String>();
    cleaned.make_ascii_lowercase();
    if cleaned.len() % 2 != 0 {
        return Err(BleError(format!("odd-length hex: {value:?}")));
    }

    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for pair in cleaned.as_bytes().chunks_exact(2) {
        let text = std::str::from_utf8(pair).map_err(|err| BleError(err.to_string()))?;
        out.push(u8::from_str_radix(text, 16).map_err(|err| BleError(err.to_string()))?);
    }
    Ok(out)
}

fn parse_u8(value: &str) -> Result<u8, BleError> {
    let text = value.trim();
    let parsed = if let Some(hex) = text.strip_prefix("0x") {
        u8::from_str_radix(hex, 16)
    } else {
        u8::from_str_radix(text, 16).or_else(|_| text.parse::<u8>())
    };
    parsed.map_err(|err| BleError(format!("invalid u8 {value:?}: {err}")))
}

fn to_hex(data: &[u8]) -> String {
    data.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BleError(String);

impl fmt::Display for BleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for BleError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_observed_continuity_payload() {
        let config = BleConfig {
            enabled: true,
            btmgmt_path: "btmgmt".into(),
            index: "0".into(),
            instance: 1,
            duration: 0,
            flags: Some("06".into()),
            length_flags: 0,
            nearby_info: Some("2204".into()),
            nearby_action: Some("900045d546".into()),
            tlvs: Vec::new(),
        };

        assert_eq!(
            to_hex(&config.advertising_data().unwrap()),
            "0201060eff4c00100222040f05900045d546"
        );
    }

    #[test]
    fn custom_tlvs_preserve_order() {
        let config = BleConfig {
            enabled: true,
            btmgmt_path: "btmgmt".into(),
            index: "0".into(),
            instance: 1,
            duration: 0,
            flags: None,
            length_flags: 0,
            nearby_info: None,
            nearby_action: None,
            tlvs: vec!["10:0000".into(), "0f:0102030405".into()],
        };

        assert_eq!(
            to_hex(&config.advertising_data().unwrap()),
            "0eff4c00100200000f050102030405"
        );
    }
}
