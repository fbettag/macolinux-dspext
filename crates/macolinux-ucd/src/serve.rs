use std::error::Error;
use std::fmt;
use std::io::{self, Read};
use std::net::{Ipv4Addr, TcpListener, TcpStream, UdpSocket};
use std::thread;
use std::time::Duration;

use macolinux_uc_core::rapport::frame_type_name;

use crate::ble::BleConfig;
use crate::mdns::MdnsAdvert;

const SERVICE_TYPE: &str = "_companion-link._tcp.local";

#[derive(Debug, Clone)]
struct ServeConfig {
    instance: String,
    hostname: String,
    port: u16,
    ipv4: Option<Ipv4Addr>,
    multicast_ipv4: Option<Ipv4Addr>,
    ble_address: Option<String>,
    txt_overrides: Vec<String>,
    ble: BleConfig,
}

pub fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("{}", usage());
        return Ok(());
    }

    let config = ServeConfig::parse(args)?;
    let ipv4 = config.ipv4.or_else(default_ipv4).ok_or_else(|| {
        ServeError("could not determine IPv4 address; pass --ipv4 explicitly".into())
    })?;
    let multicast_ipv4 = config.multicast_ipv4.unwrap_or(ipv4);
    let txt = config.txt_records();

    println!(
        "serving CompanionLink probe: instance={} host={} addr={} port={}",
        config.instance, config.hostname, ipv4, config.port
    );
    println!("TXT {}", txt.join(" "));

    if config.ble.enabled {
        config.ble.clone().start();
    }

    let listener_config = config.clone();
    thread::spawn(move || {
        if let Err(err) = run_tcp_listener(listener_config.port) {
            eprintln!("TCP listener failed: {err}");
        }
    });

    MdnsAdvert {
        service_type: SERVICE_TYPE.into(),
        instance: config.instance,
        hostname: config.hostname,
        port: config.port,
        ipv4,
        multicast_ipv4,
        txt,
    }
    .run()
}

impl ServeConfig {
    fn parse(args: &[String]) -> Result<Self, ServeError> {
        let mut config = Self {
            instance: "linux-peer".into(),
            hostname: String::new(),
            port: 49152,
            ipv4: None,
            multicast_ipv4: None,
            ble_address: None,
            txt_overrides: Vec::new(),
            ble: BleConfig {
                enabled: false,
                btmgmt_path: "btmgmt".into(),
                index: "0".into(),
                instance: 1,
                duration: 0,
                flags: Some("06".into()),
                length_flags: 0,
                nearby_info: Some("0000".into()),
                nearby_action: Some("0102030405".into()),
                tlvs: Vec::new(),
            },
        };

        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--instance" => config.instance = next_value(&mut iter, arg)?,
                "--hostname" => config.hostname = next_value(&mut iter, arg)?,
                "--port" => config.port = parse_port(&next_value(&mut iter, arg)?)?,
                "--ipv4" => config.ipv4 = Some(parse_ipv4(&next_value(&mut iter, arg)?)?),
                "--multicast-ipv4" => {
                    config.multicast_ipv4 = Some(parse_ipv4(&next_value(&mut iter, arg)?)?)
                }
                "--ble-address" => config.ble_address = Some(next_value(&mut iter, arg)?),
                "--txt" => config.txt_overrides.push(next_value(&mut iter, arg)?),
                "--ble-enable" => config.ble.enabled = true,
                "--btmgmt-path" => config.ble.btmgmt_path = next_value(&mut iter, arg)?,
                "--ble-index" => config.ble.index = next_value(&mut iter, arg)?,
                "--ble-instance" => {
                    config.ble.instance = parse_u8_decimal(&next_value(&mut iter, arg)?)?
                }
                "--ble-duration" => config.ble.duration = parse_u32(&next_value(&mut iter, arg)?)?,
                "--ble-flags" => {
                    let value = next_value(&mut iter, arg)?;
                    config.ble.flags = if value.is_empty() { None } else { Some(value) };
                }
                "--ble-length-flags" => {
                    config.ble.length_flags = parse_u8_auto(&next_value(&mut iter, arg)?)?
                }
                "--ble-nearby-info" => config.ble.nearby_info = Some(next_value(&mut iter, arg)?),
                "--ble-nearby-action" => {
                    config.ble.nearby_action = Some(next_value(&mut iter, arg)?)
                }
                "--ble-tlv" => config.ble.tlvs.push(next_value(&mut iter, arg)?),
                other => return Err(ServeError(format!("unknown serve option: {other}"))),
            }
        }

        if config.hostname.is_empty() {
            config.hostname = format!("{}.local", config.instance);
        }
        Ok(config)
    }

    fn txt_records(&self) -> Vec<String> {
        let mac = self.ble_address.clone().unwrap_or_else(|| {
            let bytes = synthetic_mac_bytes(&self.instance);
            format_mac(&bytes)
        });
        let compact_mac = mac.replace(':', "");
        let mut txt = vec![
            "rpMac=0".to_string(),
            format!("rpHN={}", self.instance),
            "rpFl=0x20000".to_string(),
            format!("rpHA={compact_mac}"),
            "rpVr=715.2".to_string(),
            "rpAD=0102030405".to_string(),
            "rpHI=0000".to_string(),
            format!("rpBA={mac}"),
        ];

        for override_item in &self.txt_overrides {
            if let Some((key, _)) = override_item.split_once('=') {
                if let Some(existing) = txt
                    .iter_mut()
                    .find(|item| item.split_once('=').map(|(k, _)| k == key).unwrap_or(false))
                {
                    *existing = override_item.clone();
                    continue;
                }
            }
            txt.push(override_item.clone());
        }
        txt
    }
}

fn run_tcp_listener(port: u16) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind(("0.0.0.0", port))?;
    println!("TCP listener ready on 0.0.0.0:{port}");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    if let Err(err) = handle_tcp_client(stream) {
                        eprintln!("TCP client ended: {err}");
                    }
                });
            }
            Err(err) => eprintln!("TCP accept failed: {err}"),
        }
    }
    Ok(())
}

fn handle_tcp_client(mut stream: TcpStream) -> Result<(), Box<dyn Error>> {
    let peer = stream.peer_addr()?;
    println!("TCP client connected: {peer}");
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;

    loop {
        let mut header = [0u8; 4];
        match stream.read_exact(&mut header) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                println!("TCP client disconnected: {peer}");
                return Ok(());
            }
            Err(err) => return Err(err.into()),
        }

        let body_len =
            ((header[1] as usize) << 16) | ((header[2] as usize) << 8) | header[3] as usize;
        if body_len > 16 * 1024 * 1024 {
            return Err(ServeError(format!("refusing oversized Rapport body: {body_len}")).into());
        }

        let mut body = vec![0u8; body_len];
        stream.read_exact(&mut body)?;
        println!(
            "Rapport frame from {peer}: type=0x{:02x} name={} body_len={} body_prefix={}",
            header[0],
            frame_type_name(header[0]),
            body_len,
            hex_prefix(&body, 64)
        );
    }
}

fn default_ipv4() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect((Ipv4Addr::new(8, 8, 8, 8), 80)).ok()?;
    match socket.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(addr) => Some(addr),
        std::net::IpAddr::V6(_) => None,
    }
}

fn synthetic_mac_bytes(seed: &str) -> [u8; 6] {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in seed.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let mut out = [0u8; 6];
    out.copy_from_slice(&hash.to_be_bytes()[2..]);
    out[0] = (out[0] | 0x02) & 0xfe;
    out
}

fn format_mac(bytes: &[u8; 6]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn parse_ipv4(value: &str) -> Result<Ipv4Addr, ServeError> {
    value
        .parse()
        .map_err(|err| ServeError(format!("invalid IPv4 address {value:?}: {err}")))
}

fn parse_port(value: &str) -> Result<u16, ServeError> {
    value
        .parse()
        .map_err(|err| ServeError(format!("invalid TCP port {value:?}: {err}")))
}

fn parse_u32(value: &str) -> Result<u32, ServeError> {
    value
        .parse()
        .map_err(|err| ServeError(format!("invalid u32 {value:?}: {err}")))
}

fn parse_u8_decimal(value: &str) -> Result<u8, ServeError> {
    value
        .parse()
        .map_err(|err| ServeError(format!("invalid u8 {value:?}: {err}")))
}

fn parse_u8_auto(value: &str) -> Result<u8, ServeError> {
    let text = value.trim();
    if let Some(hex) = text.strip_prefix("0x") {
        u8::from_str_radix(hex, 16)
    } else {
        text.parse()
    }
    .map_err(|err| ServeError(format!("invalid u8 {value:?}: {err}")))
}

fn next_value<'a>(
    iter: &mut impl Iterator<Item = &'a String>,
    flag: &str,
) -> Result<String, ServeError> {
    iter.next()
        .cloned()
        .ok_or_else(|| ServeError(format!("missing value for {flag}")))
}

fn hex_prefix(data: &[u8], limit: usize) -> String {
    let mut text = data
        .iter()
        .take(limit)
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if data.len() > limit {
        text.push_str("...");
    }
    text
}

fn usage() -> &'static str {
    "usage: macolinux-ucd serve [--instance NAME] [--hostname NAME.local] [--port PORT] [--ipv4 ADDR] [--multicast-ipv4 ADDR] [--ble-address MAC] [--txt KEY=VALUE] [--ble-enable] [--btmgmt-path PATH] [--ble-index N] [--ble-instance N] [--ble-duration SECONDS] [--ble-nearby-action HEX] [--ble-nearby-info HEX] [--ble-tlv TYPE:HEX]"
}

#[derive(Debug, Clone)]
struct ServeError(String);

impl fmt::Display for ServeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for ServeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txt_overrides_replace_defaults() {
        let config = ServeConfig::parse(&[
            "--instance".into(),
            "probe".into(),
            "--ble-address".into(),
            "02:00:00:00:00:31".into(),
            "--txt".into(),
            "rpFl=0xffffffff".into(),
            "--txt".into(),
            "rpMd=MacBookPro18,3".into(),
        ])
        .unwrap();

        let txt = config.txt_records();
        assert!(txt.contains(&"rpHN=probe".into()));
        assert!(txt.contains(&"rpFl=0xffffffff".into()));
        assert!(txt.contains(&"rpBA=02:00:00:00:00:31".into()));
        assert!(txt.contains(&"rpMd=MacBookPro18,3".into()));
        assert!(!txt.contains(&"rpFl=0x20000".into()));
    }

    #[test]
    fn synthetic_mac_is_locally_administered_unicast() {
        let mac = synthetic_mac_bytes("linux-peer");
        assert_eq!(mac[0] & 0x02, 0x02);
        assert_eq!(mac[0] & 0x01, 0);
    }

    #[test]
    fn parses_ble_options() {
        let config = ServeConfig::parse(&[
            "--ble-enable".into(),
            "--btmgmt-path".into(),
            "/run/current-system/sw/bin/btmgmt".into(),
            "--ble-index".into(),
            "1".into(),
            "--ble-instance".into(),
            "2".into(),
            "--ble-duration".into(),
            "30".into(),
            "--ble-nearby-action".into(),
            "900045d546".into(),
            "--ble-nearby-info".into(),
            "2204".into(),
        ])
        .unwrap();

        assert!(config.ble.enabled);
        assert_eq!(config.ble.btmgmt_path, "/run/current-system/sw/bin/btmgmt");
        assert_eq!(config.ble.index, "1");
        assert_eq!(config.ble.instance, 2);
        assert_eq!(config.ble.duration, 30);
        assert_eq!(config.ble.nearby_action.as_deref(), Some("900045d546"));
        assert_eq!(config.ble.nearby_info.as_deref(), Some("2204"));
    }
}
