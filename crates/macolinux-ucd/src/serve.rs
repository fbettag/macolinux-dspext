use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use macolinux_uc_core::companion::{CompanionRequest, CompanionResponse};
use macolinux_uc_core::opack::{decode_opack, dict, empty_dict, encode_opack, OpackValue};
use macolinux_uc_core::pairing_stream::{PairingStream, PairingStreamEndpoint};
use macolinux_uc_core::pairverify::{
    build_pairverify_error, build_pairverify_m2, build_pairverify_m2_plaintext,
    build_pairverify_m4, decrypt_pairverify_m3, derive_pairverify_key, parse_pairverify_tlv,
    verify_pairverify_m3_signature, PairVerifyFields, PairVerifyKeyPair,
    PAIR_VERIFY_ERROR_AUTHENTICATION, PAIRVERIFY_KEY_LENGTH,
};
use macolinux_uc_core::rapport::{frame_type_name, RapportFrame, FRAME_TYPE_E_OPACK};

use crate::ble::BleConfig;
use crate::identity::{LinuxIdentity, PublicPeerIdentity};
use crate::mdns::MdnsAdvert;
use crate::stream_server::{StreamBindConfig, StreamManager};

const SERVICE_TYPE: &str = "_companion-link._tcp.local";
const PAIRING_DATA_KEY: &str = "_pd";
const PREAUTH_VERSION: &str = "715.2";

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
    identity_path: Option<PathBuf>,
    trusted_peer_paths: Vec<PathBuf>,
    allow_unknown_peer: bool,
    stream_bind: SocketAddr,
    stream_advertise_addr: Option<String>,
}

#[derive(Debug, Clone)]
struct ServeRuntime {
    stream_bind: StreamBindConfig,
    pairverify: Option<PairVerifyRuntime>,
}

#[derive(Debug, Clone)]
struct PairVerifyRuntime {
    identity: LoadedServeIdentity,
    trusted_peers: HashMap<Vec<u8>, TrustedPeer>,
    allow_unknown_peer: bool,
}

#[derive(Debug, Clone)]
struct LoadedServeIdentity {
    identifier: String,
    seed: [u8; PAIRVERIFY_KEY_LENGTH],
    public_key_hex: String,
}

#[derive(Debug, Clone)]
struct TrustedPeer {
    signing_public_key: [u8; PAIRVERIFY_KEY_LENGTH],
}

struct PendingPairVerify {
    client_public_key: [u8; PAIRVERIFY_KEY_LENGTH],
    server_ephemeral: PairVerifyKeyPair,
    shared_secret: [u8; PAIRVERIFY_KEY_LENGTH],
    encryption_key: [u8; PAIRVERIFY_KEY_LENGTH],
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
    let runtime = Arc::new(config.runtime(ipv4)?);

    println!(
        "serving CompanionLink peer: instance={} host={} addr={} port={}",
        config.instance, config.hostname, ipv4, config.port
    );
    println!("TXT {}", txt.join(" "));
    if let Some(pairverify) = &runtime.pairverify {
        println!(
            "PairVerify server enabled: identifier={} public_key={} trusted_peers={} allow_unknown_peer={}",
            pairverify.identity.identifier,
            pairverify.identity.public_key_hex,
            pairverify.trusted_peers.len(),
            pairverify.allow_unknown_peer
        );
    } else {
        println!("PairVerify server disabled: no --identity configured");
    }

    if config.ble.enabled {
        config.ble.clone().start();
    }

    let listener_runtime = runtime.clone();
    thread::spawn(move || {
        if let Err(err) = run_tcp_listener(config.port, listener_runtime) {
            eprintln!("TCP listener failed: {err}");
        }
    });

    run_mdns_advertiser(MdnsAdvert {
        service_type: SERVICE_TYPE.into(),
        instance: config.instance,
        hostname: config.hostname,
        port: config.port,
        ipv4,
        multicast_ipv4,
        txt,
    })
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
            identity_path: None,
            trusted_peer_paths: Vec::new(),
            allow_unknown_peer: false,
            stream_bind: SocketAddr::from(([0, 0, 0, 0], 0)),
            stream_advertise_addr: None,
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
                "--identity" => config.identity_path = Some(PathBuf::from(next_value(&mut iter, arg)?)),
                "--trusted-peer" => {
                    config
                        .trusted_peer_paths
                        .push(PathBuf::from(next_value(&mut iter, arg)?))
                }
                "--allow-unknown-peer" => config.allow_unknown_peer = true,
                "--stream-bind" => {
                    config.stream_bind = parse_socket_addr(&next_value(&mut iter, arg)?)?
                }
                "--stream-advertise-addr" => {
                    config.stream_advertise_addr = Some(next_value(&mut iter, arg)?)
                }
                other => return Err(ServeError(format!("unknown serve option: {other}"))),
            }
        }

        if config.hostname.is_empty() {
            config.hostname = format!("{}.local", config.instance);
        }
        Ok(config)
    }

    fn runtime(&self, ipv4: Ipv4Addr) -> Result<ServeRuntime, Box<dyn Error>> {
        if self.identity_path.is_none()
            && (!self.trusted_peer_paths.is_empty() || self.allow_unknown_peer)
        {
            return Err(ServeError(
                "--trusted-peer and --allow-unknown-peer require --identity".into(),
            )
            .into());
        }

        let pairverify = match &self.identity_path {
            Some(path) => Some(PairVerifyRuntime::load(
                path,
                &self.trusted_peer_paths,
                self.allow_unknown_peer,
            )?),
            None => None,
        };

        Ok(ServeRuntime {
            stream_bind: StreamBindConfig {
                bind_addr: self.stream_bind,
                advertise_addr: Some(
                    self.stream_advertise_addr
                        .clone()
                        .unwrap_or_else(|| ipv4.to_string()),
                ),
            },
            pairverify,
        })
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
            format!("rpVr={PREAUTH_VERSION}"),
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

impl PairVerifyRuntime {
    fn load(
        identity_path: &PathBuf,
        trusted_peer_paths: &[PathBuf],
        allow_unknown_peer: bool,
    ) -> Result<Self, Box<dyn Error>> {
        let identity = LinuxIdentity::load(identity_path)?;
        let seed = fixed_32(identity.ed25519_seed()?, "identity seed")?;
        let mut trusted_peers = HashMap::new();

        for path in trusted_peer_paths {
            let peer = PublicPeerIdentity::load(path)?;
            let signing_public_key =
                fixed_32(peer.ed25519_public_key()?, "trusted peer public key")?;
            trusted_peers.insert(peer.identifier.as_bytes().to_vec(), TrustedPeer {
                signing_public_key,
            });
        }

        Ok(Self {
            identity: LoadedServeIdentity {
                identifier: identity.identifier,
                seed,
                public_key_hex: identity.ed25519_public_key_hex,
            },
            trusted_peers,
            allow_unknown_peer,
        })
    }
}

fn run_tcp_listener(port: u16, runtime: Arc<ServeRuntime>) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind(("0.0.0.0", port))?;
    println!("TCP listener ready on 0.0.0.0:{port}");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let runtime = runtime.clone();
                thread::spawn(move || {
                    if let Err(err) = handle_tcp_client(stream, runtime) {
                        eprintln!("TCP client ended: {err}");
                    }
                });
            }
            Err(err) => eprintln!("TCP accept failed: {err}"),
        }
    }
    Ok(())
}

fn run_mdns_advertiser(advert: MdnsAdvert) -> ! {
    loop {
        if let Err(err) = advert.run() {
            eprintln!("mDNS advertiser failed: {err}; retrying in 5s");
            thread::sleep(Duration::from_secs(5));
        }
    }
}

fn handle_tcp_client(mut stream: TcpStream, runtime: Arc<ServeRuntime>) -> Result<(), Box<dyn Error>> {
    let peer = stream.peer_addr()?;
    let mut pending_pairverify = None;
    let mut pairing_stream = None;
    let mut stream_manager = StreamManager::new(runtime.stream_bind.clone());

    println!("TCP client connected: {peer}");
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;

    loop {
        let Some(frame) = read_rapport_frame(&mut stream)? else {
            println!("TCP client disconnected: {peer}");
            return Ok(());
        };

        println!(
            "Rapport frame from {peer}: type=0x{:02x} name={} body_len={} body_prefix={}",
            frame.frame_type,
            frame_type_name(frame.frame_type),
            frame.body.len(),
            hex_prefix(&frame.body, 64)
        );

        match frame.frame_type {
            0x0a => handle_preauth(&mut stream, &frame)?,
            0x05 => {
                let Some(pairverify) = &runtime.pairverify else {
                    println!("ignoring PairVerifyStart without configured server identity");
                    send_pairverify_result(
                        &mut stream,
                        0x06,
                        build_pairverify_error(0, PAIR_VERIFY_ERROR_AUTHENTICATION),
                    )?;
                    continue;
                };
                pending_pairverify = Some(handle_pairverify_m1(&mut stream, pairverify, &frame)?);
            }
            0x06 if pending_pairverify.is_some() => {
                let pairverify = runtime.pairverify.as_ref().ok_or_else(|| {
                    ServeError("internal error: PairVerify state without runtime".into())
                })?;
                let pending = pending_pairverify.take().unwrap();
                pairing_stream = handle_pairverify_m3(
                    &mut stream,
                    pairverify,
                    pending,
                    &frame,
                )?;
            }
            FRAME_TYPE_E_OPACK => {
                let Some(pairing_stream) = pairing_stream.as_mut() else {
                    println!("dropping encrypted frame before PairVerify completed");
                    continue;
                };
                handle_encrypted_frame(
                    &mut stream,
                    pairing_stream,
                    &mut stream_manager,
                    &frame,
                )?;
            }
            _ => {
                if let Ok(value) = decode_opack(&frame.body) {
                    println!("plain opack={}", format_opack(&value));
                }
            }
        }
    }
}

fn handle_preauth(stream: &mut TcpStream, frame: &RapportFrame) -> Result<(), Box<dyn Error>> {
    if let Ok(value) = decode_opack(&frame.body) {
        println!("preauth request opack={}", format_opack(&value));
    }
    let body = encode_opack(&dict([(
        "_sv",
        OpackValue::String(PREAUTH_VERSION.into()),
    )]))?;
    write_rapport_frame(
        stream,
        &RapportFrame {
            frame_type: 0x0b,
            body,
        },
    )
}

fn handle_pairverify_m1(
    stream: &mut TcpStream,
    pairverify: &PairVerifyRuntime,
    frame: &RapportFrame,
) -> Result<PendingPairVerify, Box<dyn Error>> {
    let value = decode_opack(&frame.body)?;
    println!("pairverify m1 opack={}", format_opack(&value));
    let pairing_data = opack_dict_data(&value, PAIRING_DATA_KEY)
        .ok_or_else(|| ServeError("PairVerify M1 is missing _pd".into()))?;
    let fields = parse_pairverify_tlv(&pairing_data)?;
    print_pairverify_fields("pairverify m1", &fields);

    let client_public_key = fields
        .public_key
        .ok_or_else(|| ServeError("PairVerify M1 is missing client public key".into()))?;
    let server_ephemeral = PairVerifyKeyPair::generate();
    let shared_secret = server_ephemeral.shared_secret(&client_public_key)?;
    let encryption_key = derive_pairverify_key(&shared_secret)?;
    let m2_plaintext = build_pairverify_m2_plaintext(
        &server_ephemeral.public_key(),
        pairverify.identity.identifier.as_bytes(),
        &client_public_key,
        &pairverify.identity.seed,
    )?;
    let m2_tlv = build_pairverify_m2(&server_ephemeral.public_key(), &encryption_key, &m2_plaintext)?;
    send_pairverify_result(stream, 0x06, m2_tlv)?;

    Ok(PendingPairVerify {
        client_public_key,
        server_ephemeral,
        shared_secret,
        encryption_key,
    })
}

fn handle_pairverify_m3(
    stream: &mut TcpStream,
    pairverify: &PairVerifyRuntime,
    pending: PendingPairVerify,
    frame: &RapportFrame,
) -> Result<Option<PairingStream>, Box<dyn Error>> {
    let value = decode_opack(&frame.body)?;
    println!("pairverify m3 opack={}", format_opack(&value));
    let pairing_data = opack_dict_data(&value, PAIRING_DATA_KEY)
        .ok_or_else(|| ServeError("PairVerify M3 is missing _pd".into()))?;
    let fields = parse_pairverify_tlv(&pairing_data)?;
    print_pairverify_fields("pairverify m3 outer", &fields);

    let encrypted_data = fields
        .encrypted_data
        .ok_or_else(|| ServeError("PairVerify M3 is missing encrypted data".into()))?;
    let decrypted = decrypt_pairverify_m3(&pending.encryption_key, &encrypted_data)?;
    let decrypted_fields = parse_pairverify_tlv(&decrypted)?;
    print_pairverify_fields("pairverify m3 decrypted", &decrypted_fields);

    let client_identifier = decrypted_fields
        .identifier
        .as_deref()
        .ok_or_else(|| ServeError("PairVerify M3 is missing client identifier".into()))?;
    let client_signature = decrypted_fields
        .signature
        .as_ref()
        .ok_or_else(|| ServeError("PairVerify M3 is missing client signature".into()))?;

    match pairverify.trusted_peers.get(client_identifier) {
        Some(trusted_peer) => verify_pairverify_m3_signature(
            &pending.client_public_key,
            client_identifier,
            &pending.server_ephemeral.public_key(),
            &trusted_peer.signing_public_key,
            client_signature,
        )?,
        None if pairverify.allow_unknown_peer => {
            println!(
                "pairverify allowing unknown client identifier={}",
                String::from_utf8_lossy(client_identifier)
            );
        }
        None => {
            println!(
                "pairverify rejecting unknown client identifier={}",
                String::from_utf8_lossy(client_identifier)
            );
            send_pairverify_result(
                stream,
                0x06,
                build_pairverify_error(3, PAIR_VERIFY_ERROR_AUTHENTICATION),
            )?;
            return Ok(None);
        }
    }

    send_pairverify_result(stream, 0x06, build_pairverify_m4())?;
    println!(
        "pairverify complete: client_identifier={} stream_psk={}",
        String::from_utf8_lossy(client_identifier),
        to_hex(&pending.shared_secret)
    );
    Ok(Some(PairingStream::main(
        PairingStreamEndpoint::Server,
        &pending.shared_secret,
    )?))
}

fn handle_encrypted_frame(
    stream: &mut TcpStream,
    pairing_stream: &mut PairingStream,
    stream_manager: &mut StreamManager,
    frame: &RapportFrame,
) -> Result<(), Box<dyn Error>> {
    let value = pairing_stream.decrypt_e_opack_frame(frame)?;
    println!(
        "encrypted request decrypt_nonce={} opack={}",
        to_hex(&pairing_stream.decrypt_nonce()),
        format_opack(&value)
    );

    let request = CompanionRequest::from_opack_value(&value)?;
    if request.request_id == macolinux_uc_core::stream::REQUEST_ID_STREAM_START {
        if let Some(handled) = stream_manager.handle_companion_request(request)? {
            let response_frame =
                pairing_stream.encrypt_e_opack_frame(&handled.response.to_opack_value())?;
            write_rapport_frame(stream, &response_frame)?;
            let stream_id = handled.prepared.stream_id.to_string();
            let _ = stream_manager.spawn_accept_for_stream(&stream_id)?;
            println!(
                "stream prepared: id={} role={} listen={} response_port={}",
                handled.prepared.stream_id,
                handled.prepared.stream_id.role,
                handled.prepared.local_addr,
                handled.prepared.response.port
            );
        }
        return Ok(());
    }

    let response = CompanionResponse::for_request(&request, empty_dict());
    let response_frame = pairing_stream.encrypt_e_opack_frame(&response.to_opack_value())?;
    write_rapport_frame(stream, &response_frame)?;
    println!("encrypted request replied with empty response: {}", request.request_id);
    Ok(())
}

fn send_pairverify_result(
    stream: &mut TcpStream,
    frame_type: u8,
    tlv: Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    let body = encode_opack(&dict([(PAIRING_DATA_KEY, OpackValue::Data(tlv))]))?;
    write_rapport_frame(stream, &RapportFrame { frame_type, body })
}

fn read_rapport_frame(stream: &mut TcpStream) -> Result<Option<RapportFrame>, Box<dyn Error>> {
    let mut header = [0u8; 4];
    match stream.read_exact(&mut header) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err.into()),
    }

    let body_len = ((header[1] as usize) << 16) | ((header[2] as usize) << 8) | header[3] as usize;
    if body_len > 16 * 1024 * 1024 {
        return Err(ServeError(format!("refusing oversized Rapport body: {body_len}")).into());
    }

    let mut body = vec![0u8; body_len];
    stream.read_exact(&mut body)?;
    Ok(Some(RapportFrame {
        frame_type: header[0],
        body,
    }))
}

fn write_rapport_frame(stream: &mut TcpStream, frame: &RapportFrame) -> Result<(), Box<dyn Error>> {
    stream.write_all(&frame.encode()?)?;
    stream.flush()?;
    Ok(())
}

fn opack_dict_data(value: &OpackValue, key: &str) -> Option<Vec<u8>> {
    let OpackValue::Dict(entries) = value else {
        return None;
    };
    entries.iter().find_map(
        |(entry_key, entry_value)| match (entry_key.as_str(), entry_value) {
            (candidate, OpackValue::Data(data)) if candidate == key => Some(data.clone()),
            _ => None,
        },
    )
}

fn print_pairverify_fields(label: &str, fields: &PairVerifyFields) {
    println!("{label}:");
    print_optional_u64("method", fields.method);
    print_optional_u64("state", fields.state);
    print_optional_u64("error", fields.error);
    print_optional_u64("app_flags", fields.app_flags);
    if let Some(identifier) = &fields.identifier {
        println!("  identifier={}", String::from_utf8_lossy(identifier));
        println!("  identifier_hex={}", to_hex(identifier));
    }
    if let Some(public_key) = &fields.public_key {
        println!("  public_key={}", to_hex(public_key));
    }
    if let Some(encrypted_data) = &fields.encrypted_data {
        println!(
            "  encrypted_data_len={} encrypted_data={}",
            encrypted_data.len(),
            to_hex(encrypted_data)
        );
    }
    if let Some(signature) = &fields.signature {
        println!("  signature={}", to_hex(signature));
    }
}

fn print_optional_u64(label: &str, value: Option<u64>) {
    if let Some(value) = value {
        println!("  {label}={value} 0x{value:x}");
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

fn parse_socket_addr(value: &str) -> Result<SocketAddr, ServeError> {
    value
        .parse()
        .map_err(|err| ServeError(format!("invalid socket address {value:?}: {err}")))
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

fn fixed_32(value: Vec<u8>, label: &str) -> Result<[u8; PAIRVERIFY_KEY_LENGTH], Box<dyn Error>> {
    value.try_into().map_err(|value: Vec<u8>| {
        ServeError(format!("{label} must be 32 bytes, got {}", value.len())).into()
    })
}

fn next_value<'a>(
    iter: &mut impl Iterator<Item = &'a String>,
    flag: &str,
) -> Result<String, ServeError> {
    iter.next()
        .cloned()
        .ok_or_else(|| ServeError(format!("missing value for {flag}")))
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
    "usage: macolinux-ucd serve [--instance NAME] [--hostname NAME.local] [--port PORT] [--ipv4 ADDR] [--multicast-ipv4 ADDR] [--ble-address MAC] [--txt KEY=VALUE] [--identity PATH] [--trusted-peer PATH]... [--allow-unknown-peer] [--stream-bind ADDR:PORT] [--stream-advertise-addr ADDR] [--ble-enable] [--btmgmt-path PATH] [--ble-index N] [--ble-instance N] [--ble-duration SECONDS] [--ble-nearby-action HEX] [--ble-nearby-info HEX] [--ble-tlv TYPE:HEX]"
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

    #[test]
    fn parses_pairverify_and_stream_options() {
        let config = ServeConfig::parse(&[
            "--identity".into(),
            "/var/lib/macolinux/identity.json".into(),
            "--trusted-peer".into(),
            "/var/lib/macolinux/peer.json".into(),
            "--allow-unknown-peer".into(),
            "--stream-bind".into(),
            "0.0.0.0:60237".into(),
            "--stream-advertise-addr".into(),
            "192.0.2.44".into(),
        ])
        .unwrap();

        assert_eq!(
            config.identity_path,
            Some(PathBuf::from("/var/lib/macolinux/identity.json"))
        );
        assert_eq!(
            config.trusted_peer_paths,
            vec![PathBuf::from("/var/lib/macolinux/peer.json")]
        );
        assert!(config.allow_unknown_peer);
        assert_eq!(config.stream_bind, SocketAddr::from(([0, 0, 0, 0], 60237)));
        assert_eq!(config.stream_advertise_addr.as_deref(), Some("192.0.2.44"));
    }
}
