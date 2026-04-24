use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::io::{self, Read};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use macolinux_uc_core::companion::{CompanionRequest, CompanionResponse};
use macolinux_uc_core::pairing_stream::PairingStream;
use macolinux_uc_core::rapport::{frame_type_name, RapportFrame, FRAME_HEADER_LEN};
use macolinux_uc_core::stream::{
    RpStreamType, StreamStartRequest, StreamStartResponse, UniversalControlStreamId,
    UniversalControlStreamRole, REQUEST_ID_STREAM_START,
};

#[derive(Debug, Clone)]
struct StreamConfig {
    request_opack: Vec<u8>,
    bind: StreamBindConfig,
    accept_timeout: Option<Duration>,
}

#[derive(Debug, Clone)]
struct StreamEnvelopeConfig {
    opack: Vec<u8>,
    bind: StreamBindConfig,
    accept_timeout: Option<Duration>,
}

#[derive(Debug, Clone)]
struct StreamBatchConfig {
    session_uuid: String,
    roles: Vec<UniversalControlStreamRole>,
    bind: StreamBindConfig,
    accept_timeout: Option<Duration>,
}

#[derive(Debug, Clone)]
pub struct StreamBindConfig {
    pub bind_addr: SocketAddr,
    pub advertise_addr: Option<String>,
}

pub fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
    match args.first().map(String::as_str) {
        Some("prepare") => run_prepare(&args[1..]),
        Some("handle-request") => run_handle_request(&args[1..]),
        Some("prepare-batch") => run_prepare_batch(&args[1..]),
        Some("-h") | Some("--help") | None => {
            println!("{}", usage());
            Ok(())
        }
        Some(other) => Err(StreamServerError(format!("unknown stream command: {other}")).into()),
    }
}

fn run_handle_request(args: &[String]) -> Result<(), Box<dyn Error>> {
    let config = StreamEnvelopeConfig::parse(args)?;
    let mut manager = StreamManager::new(config.bind.clone());
    let handled = manager.handle_companion_opack(&config.opack)?;

    match handled {
        Some(handled) => {
            println!(
                "companion request handled: request_id={} id={} role={} type={} listen={} response_port={} response_xid={} response_opack_hex={} envelope_response_opack_hex={}",
                handled.request_id,
                handled.prepared.stream_id,
                handled.prepared.role,
                handled.prepared.stream_type.label(),
                handled.prepared.local_addr,
                handled.prepared.response.port,
                handled.response.transaction_id.unwrap_or_default(),
                to_hex(&handled.prepared.response_opack),
                to_hex(&handled.response_opack)
            );
        }
        None => println!("companion request ignored: unsupported requestID"),
    }

    if let Some(timeout) = config.accept_timeout {
        manager.accept_until_timeout(timeout)
    } else {
        manager.accept_forever()
    }
}

fn run_prepare(args: &[String]) -> Result<(), Box<dyn Error>> {
    let config = StreamConfig::parse(args)?;
    let mut manager = StreamManager::new(config.bind.clone());
    let prepared = manager.prepare_opack_request(&config.request_opack)?;

    println!(
        "stream prepared: id={} role={} type={} flags={:?} listen={} response_port={} response_opack_hex={}",
        prepared.stream_id,
        prepared.role,
        prepared.stream_type.label(),
        prepared.stream_flags,
        prepared.local_addr,
        prepared.response.port,
        to_hex(&prepared.response_opack)
    );

    if let Some(timeout) = config.accept_timeout {
        manager.accept_until_timeout(timeout)
    } else {
        manager.accept_forever()
    }
}

fn run_prepare_batch(args: &[String]) -> Result<(), Box<dyn Error>> {
    let config = StreamBatchConfig::parse(args)?;
    let mut manager = StreamManager::new(config.bind.clone());

    for role in &config.roles {
        let stream_id = UniversalControlStreamId::new(*role, &config.session_uuid)?;
        let request = StreamStartRequest::new(stream_id, RpStreamType::RpcConnection);
        let request_opack = request.encode_opack()?;
        let prepared = manager.prepare_opack_request(&request_opack)?;
        println!(
            "stream prepared: id={} role={} type={} flags={:?} listen={} response_port={} request_opack_hex={} response_opack_hex={}",
            prepared.stream_id,
            prepared.role,
            prepared.stream_type.label(),
            prepared.stream_flags,
            prepared.local_addr,
            prepared.response.port,
            to_hex(&request_opack),
            to_hex(&prepared.response_opack)
        );
    }

    if let Some(timeout) = config.accept_timeout {
        manager.accept_until_timeout(timeout)
    } else {
        manager.accept_forever()
    }
}

impl StreamConfig {
    fn parse(args: &[String]) -> Result<Self, StreamServerError> {
        let mut request_opack = None;
        let mut bind_addr = SocketAddr::from(([0, 0, 0, 0], 0));
        let mut advertise_addr = None;
        let mut accept_timeout = None;

        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--request-opack-hex" => {
                    request_opack = Some(parse_hex(&next_value(&mut iter, arg)?)?)
                }
                "--bind" => bind_addr = parse_socket_addr(&next_value(&mut iter, arg)?)?,
                "--advertise-addr" => advertise_addr = Some(next_value(&mut iter, arg)?),
                "--accept-timeout-ms" => {
                    let millis = parse_u64(&next_value(&mut iter, arg)?)?;
                    accept_timeout = Some(Duration::from_millis(millis));
                }
                "--no-accept" => accept_timeout = Some(Duration::ZERO),
                other => return Err(StreamServerError(format!("unknown stream option: {other}"))),
            }
        }

        Ok(Self {
            request_opack: request_opack
                .ok_or_else(|| StreamServerError("missing required --request-opack-hex".into()))?,
            bind: StreamBindConfig {
                bind_addr,
                advertise_addr,
            },
            accept_timeout,
        })
    }
}

impl StreamEnvelopeConfig {
    fn parse(args: &[String]) -> Result<Self, StreamServerError> {
        let mut opack = None;
        let mut bind_addr = SocketAddr::from(([0, 0, 0, 0], 0));
        let mut advertise_addr = None;
        let mut accept_timeout = None;

        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--opack-hex" => opack = Some(parse_hex(&next_value(&mut iter, arg)?)?),
                "--bind" => bind_addr = parse_socket_addr(&next_value(&mut iter, arg)?)?,
                "--advertise-addr" => advertise_addr = Some(next_value(&mut iter, arg)?),
                "--accept-timeout-ms" => {
                    let millis = parse_u64(&next_value(&mut iter, arg)?)?;
                    accept_timeout = Some(Duration::from_millis(millis));
                }
                "--no-accept" => accept_timeout = Some(Duration::ZERO),
                other => return Err(StreamServerError(format!("unknown stream option: {other}"))),
            }
        }

        Ok(Self {
            opack: opack.ok_or_else(|| StreamServerError("missing required --opack-hex".into()))?,
            bind: StreamBindConfig {
                bind_addr,
                advertise_addr,
            },
            accept_timeout,
        })
    }
}

impl StreamBatchConfig {
    fn parse(args: &[String]) -> Result<Self, StreamServerError> {
        let mut session_uuid = None;
        let mut roles = Vec::new();
        let mut bind_addr = SocketAddr::from(([0, 0, 0, 0], 0));
        let mut advertise_addr = None;
        let mut accept_timeout = None;

        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--session-uuid" => session_uuid = Some(next_value(&mut iter, arg)?),
                "--role" => roles.push(parse_role(&next_value(&mut iter, arg)?)?),
                "--bind" => bind_addr = parse_socket_addr(&next_value(&mut iter, arg)?)?,
                "--advertise-addr" => advertise_addr = Some(next_value(&mut iter, arg)?),
                "--accept-timeout-ms" => {
                    let millis = parse_u64(&next_value(&mut iter, arg)?)?;
                    accept_timeout = Some(Duration::from_millis(millis));
                }
                "--no-accept" => accept_timeout = Some(Duration::ZERO),
                other => return Err(StreamServerError(format!("unknown stream option: {other}"))),
            }
        }

        if roles.is_empty() {
            roles.extend(UniversalControlStreamRole::ALL);
        }

        Ok(Self {
            session_uuid: session_uuid
                .ok_or_else(|| StreamServerError("missing required --session-uuid".into()))?,
            roles,
            bind: StreamBindConfig {
                bind_addr,
                advertise_addr,
            },
            accept_timeout,
        })
    }
}

#[derive(Debug, Clone)]
pub struct PreparedStreamInfo {
    pub stream_id: UniversalControlStreamId,
    role: UniversalControlStreamRole,
    pub stream_type: RpStreamType,
    pub stream_flags: Option<u32>,
    pub local_addr: SocketAddr,
    pub response: StreamStartResponse,
    pub response_opack: Vec<u8>,
}

struct PreparedStream {
    role: UniversalControlStreamRole,
    listener: TcpListener,
    local_addr: SocketAddr,
}

impl PreparedStream {
    fn bind(
        request: &StreamStartRequest,
        config: &StreamBindConfig,
    ) -> Result<Self, Box<dyn Error>> {
        let listener = TcpListener::bind(config.bind_addr)?;
        let local_addr = listener.local_addr()?;

        Ok(Self {
            role: request.stream_id.role,
            listener,
            local_addr,
        })
    }
}

pub struct StreamManager {
    bind: StreamBindConfig,
    streams: HashMap<String, PreparedStream>,
}

#[derive(Debug, Clone)]
pub struct HandledCompanionStreamStart {
    pub request_id: String,
    pub prepared: PreparedStreamInfo,
    pub response: CompanionResponse,
    pub response_opack: Vec<u8>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct HandledEncryptedCompanionStreamStart {
    pub handled: HandledCompanionStreamStart,
    pub response_frame: RapportFrame,
}

impl StreamManager {
    pub fn new(bind: StreamBindConfig) -> Self {
        Self {
            bind,
            streams: HashMap::new(),
        }
    }

    pub fn prepare_opack_request(
        &mut self,
        request_opack: &[u8],
    ) -> Result<PreparedStreamInfo, Box<dyn Error>> {
        let request = StreamStartRequest::decode_opack(request_opack)?;
        self.prepare_request(request)
    }

    pub fn prepare_request(
        &mut self,
        request: StreamStartRequest,
    ) -> Result<PreparedStreamInfo, Box<dyn Error>> {
        let stream = PreparedStream::bind(&request, &self.bind)?;
        let mut response = StreamStartResponse::new(stream.local_addr.port());
        if let Some(address) = advertised_address(&self.bind, stream.local_addr) {
            response = response.with_address(address);
        }
        let response_opack = response.encode_opack()?;
        let info = PreparedStreamInfo {
            stream_id: request.stream_id.clone(),
            role: request.stream_id.role,
            stream_type: request.stream_type,
            stream_flags: request.stream_flags,
            local_addr: stream.local_addr,
            response,
            response_opack,
        };
        self.streams.insert(request.stream_id.to_string(), stream);
        Ok(info)
    }

    pub fn handle_companion_opack(
        &mut self,
        opack: &[u8],
    ) -> Result<Option<HandledCompanionStreamStart>, Box<dyn Error>> {
        let request = CompanionRequest::decode_opack(opack)?;
        self.handle_companion_request(request)
    }

    pub fn handle_companion_request(
        &mut self,
        request: CompanionRequest,
    ) -> Result<Option<HandledCompanionStreamStart>, Box<dyn Error>> {
        if request.request_id != REQUEST_ID_STREAM_START {
            return Ok(None);
        }

        let stream_request = StreamStartRequest::from_opack_value(&request.request)?;
        let prepared = self.prepare_request(stream_request)?;
        let response = CompanionResponse::for_request(&request, prepared.response.to_opack_value());
        let response_opack = response.encode_opack()?;
        Ok(Some(HandledCompanionStreamStart {
            request_id: request.request_id,
            prepared,
            response,
            response_opack,
        }))
    }

    pub fn spawn_accept_for_stream(&mut self, stream_id: &str) -> Result<bool, Box<dyn Error>> {
        let Some(stream) = self.streams.remove(stream_id) else {
            return Ok(false);
        };
        spawn_accept_thread(stream);
        Ok(true)
    }

    #[allow(dead_code)]
    pub fn handle_encrypted_companion_frame(
        &mut self,
        session: &mut PairingStream,
        frame: &RapportFrame,
    ) -> Result<Option<HandledEncryptedCompanionStreamStart>, Box<dyn Error>> {
        let request_value = session.decrypt_e_opack_frame(frame)?;
        let request = CompanionRequest::from_opack_value(&request_value)?;
        let Some(handled) = self.handle_companion_request(request)? else {
            return Ok(None);
        };
        let response_frame = session.encrypt_e_opack_frame(&handled.response.to_opack_value())?;
        Ok(Some(HandledEncryptedCompanionStreamStart {
            handled,
            response_frame,
        }))
    }

    pub fn accept_forever(self) -> Result<(), Box<dyn Error>> {
        if self.streams.is_empty() {
            return Ok(());
        }

        let mut handles = Vec::new();
        for (_, stream) in self.streams {
            handles.push(thread::spawn(move || {
                if let Err(err) = accept_forever(stream) {
                    eprintln!("stream accept thread ended: {err}");
                }
            }));
        }
        for handle in handles {
            handle
                .join()
                .map_err(|_| StreamServerError("stream accept thread panicked".into()))?;
        }
        Ok(())
    }

    pub fn accept_until_timeout(self, timeout: Duration) -> Result<(), Box<dyn Error>> {
        if timeout.is_zero() {
            return Ok(());
        }

        let mut handles = Vec::new();
        for (_, stream) in self.streams {
            stream.listener.set_nonblocking(true)?;
            handles.push(thread::spawn(move || {
                if let Err(err) = accept_until_timeout(stream, timeout) {
                    eprintln!("stream accept thread ended: {err}");
                }
            }));
        }
        for handle in handles {
            handle
                .join()
                .map_err(|_| StreamServerError("stream accept thread panicked".into()))?;
        }
        Ok(())
    }
}

fn advertised_address(config: &StreamBindConfig, local_addr: SocketAddr) -> Option<String> {
    if let Some(address) = &config.advertise_addr {
        return Some(address.clone());
    }
    match local_addr.ip() {
        IpAddr::V4(addr) if !addr.is_unspecified() => Some(addr.to_string()),
        IpAddr::V6(addr) if !addr.is_unspecified() => Some(addr.to_string()),
        _ => None,
    }
}

fn accept_forever(prepared: PreparedStream) -> Result<(), Box<dyn Error>> {
    println!(
        "stream listener ready: role={} listen={}",
        prepared.role, prepared.local_addr
    );
    for stream in prepared.listener.incoming() {
        match stream {
            Ok(stream) => spawn_stream_dump(prepared.role, stream),
            Err(err) => eprintln!("stream accept failed: {err}"),
        }
    }
    Ok(())
}

fn accept_until_timeout(prepared: PreparedStream, timeout: Duration) -> Result<(), Box<dyn Error>> {
    if timeout.is_zero() {
        return Ok(());
    }

    let start = std::time::Instant::now();
    println!(
        "stream listener ready: role={} listen={} timeout_ms={}",
        prepared.role,
        prepared.local_addr,
        timeout.as_millis()
    );
    while start.elapsed() < timeout {
        match prepared.listener.accept() {
            Ok((stream, _)) => spawn_stream_dump(prepared.role, stream),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(err) => return Err(err.into()),
        }
    }
    Ok(())
}

fn spawn_stream_dump(role: UniversalControlStreamRole, stream: TcpStream) {
    thread::spawn(move || {
        if let Err(err) = dump_stream(role, stream) {
            eprintln!("stream {role} ended: {err}");
        }
    });
}

fn spawn_accept_thread(prepared: PreparedStream) {
    thread::spawn(move || {
        if let Err(err) = accept_forever(prepared) {
            eprintln!("stream accept thread ended: {err}");
        }
    });
}

fn dump_stream(
    role: UniversalControlStreamRole,
    mut stream: TcpStream,
) -> Result<(), Box<dyn Error>> {
    let peer = stream.peer_addr()?;
    println!("stream {role} connected: {peer}");
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;

    loop {
        let mut header = [0u8; FRAME_HEADER_LEN];
        match stream.read_exact(&mut header) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                println!("stream {role} disconnected: {peer}");
                return Ok(());
            }
            Err(err) => return Err(err.into()),
        }

        let body_len =
            ((header[1] as usize) << 16) | ((header[2] as usize) << 8) | header[3] as usize;
        if body_len > 16 * 1024 * 1024 {
            return Err(StreamServerError(format!(
                "refusing oversized Rapport stream body: {body_len}"
            ))
            .into());
        }

        let mut body = vec![0u8; body_len];
        stream.read_exact(&mut body)?;
        let frame = RapportFrame {
            frame_type: header[0],
            body,
        };
        println!(
            "stream {role} frame: type=0x{:02x} name={} body_len={} body_prefix={}",
            frame.frame_type,
            frame_type_name(frame.frame_type),
            frame.body.len(),
            hex_prefix(&frame.body, 64)
        );
    }
}

fn parse_socket_addr(value: &str) -> Result<SocketAddr, StreamServerError> {
    value
        .parse()
        .map_err(|err| StreamServerError(format!("invalid socket address {value:?}: {err}")))
}

fn parse_u64(value: &str) -> Result<u64, StreamServerError> {
    value
        .parse()
        .map_err(|err| StreamServerError(format!("invalid u64 {value:?}: {err}")))
}

fn parse_role(value: &str) -> Result<UniversalControlStreamRole, StreamServerError> {
    UniversalControlStreamRole::from_code(value).ok_or_else(|| {
        StreamServerError(format!("invalid Universal Control stream role {value:?}"))
    })
}

fn next_value<'a>(
    iter: &mut impl Iterator<Item = &'a String>,
    flag: &str,
) -> Result<String, StreamServerError> {
    iter.next()
        .cloned()
        .ok_or_else(|| StreamServerError(format!("missing value for {flag}")))
}

fn parse_hex(value: &str) -> Result<Vec<u8>, StreamServerError> {
    let mut cleaned = value
        .trim()
        .strip_prefix("0x")
        .unwrap_or(value.trim())
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    cleaned.make_ascii_lowercase();

    if cleaned.len() % 2 != 0 {
        return Err(StreamServerError(
            "hex input must have an even number of digits".into(),
        ));
    }

    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for pair in cleaned.as_bytes().chunks_exact(2) {
        let text = std::str::from_utf8(pair)
            .map_err(|err| StreamServerError(format!("invalid hex text: {err}")))?;
        out.push(
            u8::from_str_radix(text, 16)
                .map_err(|err| StreamServerError(format!("invalid hex byte {text:?}: {err}")))?,
        );
    }
    Ok(out)
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
    "usage: macolinux-ucd stream prepare --request-opack-hex HEX [--bind ADDR:PORT] [--advertise-addr ADDR] [--accept-timeout-ms MS] [--no-accept]\n       macolinux-ucd stream handle-request --opack-hex HEX [--bind ADDR:PORT] [--advertise-addr ADDR] [--accept-timeout-ms MS] [--no-accept]\n       macolinux-ucd stream prepare-batch --session-uuid UUID [--role SYNC|EVNT|CLIP|DRAG]... [--bind ADDR:PORT] [--advertise-addr ADDR] [--accept-timeout-ms MS] [--no-accept]"
}

#[derive(Debug, Clone)]
struct StreamServerError(String);

impl fmt::Display for StreamServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for StreamServerError {}

#[cfg(test)]
mod tests {
    use super::*;
    use macolinux_uc_core::companion::CompanionRequest;
    use macolinux_uc_core::opack::{dict, OpackValue};
    use macolinux_uc_core::pairing_stream::{PairingStream, PairingStreamEndpoint};
    use macolinux_uc_core::pairverify::PAIRVERIFY_KEY_LENGTH;
    use macolinux_uc_core::rapport::FRAME_TYPE_E_OPACK;
    use macolinux_uc_core::stream::{
        RpStreamType, UniversalControlStreamId, UniversalControlStreamRole,
    };

    const SESSION_UUID: &str = "6843EBDE-86D7-4842-8AF1-FE691AA0F913";

    #[test]
    fn config_requires_request() {
        assert!(StreamConfig::parse(&[]).is_err());
    }

    #[test]
    fn prepares_listener_response_from_stream_start_request() {
        let stream_id =
            UniversalControlStreamId::new(UniversalControlStreamRole::Sync, SESSION_UUID).unwrap();
        let request = StreamStartRequest::new(stream_id, RpStreamType::RpcConnection);
        let request_opack = request.encode_opack().unwrap();
        let config = StreamConfig {
            request_opack,
            bind: StreamBindConfig {
                bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
                advertise_addr: Some("127.0.0.1".into()),
            },
            accept_timeout: Some(Duration::ZERO),
        };

        let mut manager = StreamManager::new(config.bind.clone());
        let prepared = manager
            .prepare_opack_request(&config.request_opack)
            .unwrap();
        assert_eq!(prepared.role, UniversalControlStreamRole::Sync);
        assert_ne!(prepared.local_addr.port(), 0);
        assert_eq!(prepared.response.port, prepared.local_addr.port());
        assert_eq!(prepared.response.address.as_deref(), Some("127.0.0.1"));
    }

    #[test]
    fn batch_defaults_to_all_stream_roles() {
        let config = StreamBatchConfig::parse(&[
            "--session-uuid".into(),
            SESSION_UUID.into(),
            "--bind".into(),
            "127.0.0.1:0".into(),
            "--no-accept".into(),
        ])
        .unwrap();

        assert_eq!(config.roles, UniversalControlStreamRole::ALL);
        assert_eq!(config.bind.bind_addr, SocketAddr::from(([127, 0, 0, 1], 0)));
        assert_eq!(config.accept_timeout, Some(Duration::ZERO));
    }

    #[test]
    fn handles_companion_stream_start_envelope() {
        let stream_id =
            UniversalControlStreamId::new(UniversalControlStreamRole::Events, SESSION_UUID)
                .unwrap();
        let stream_request = StreamStartRequest::new(stream_id, RpStreamType::RpcConnection);
        let companion_request =
            CompanionRequest::new(REQUEST_ID_STREAM_START, stream_request.to_opack_value())
                .with_message_id("9")
                .with_transaction_id(77);
        let config = StreamBindConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            advertise_addr: Some("127.0.0.1".into()),
        };
        let mut manager = StreamManager::new(config);
        let handled = manager
            .handle_companion_opack(&companion_request.encode_opack().unwrap())
            .unwrap()
            .unwrap();

        assert_eq!(handled.request_id, REQUEST_ID_STREAM_START);
        assert_eq!(
            handled.prepared.stream_id.to_string(),
            format!("EVNT:{SESSION_UUID}")
        );
        assert_eq!(handled.response.message_id.as_deref(), Some("9"));
        assert_eq!(handled.response.transaction_id, Some(77));
        assert_eq!(
            handled.response.response,
            dict([
                (
                    "_streamPort",
                    OpackValue::Int(handled.prepared.local_addr.port() as i64)
                ),
                ("_streamAddr", OpackValue::String("127.0.0.1".into())),
            ])
        );
    }

    #[test]
    fn ignores_non_stream_start_envelope() {
        let config = StreamBindConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            advertise_addr: None,
        };
        let mut manager = StreamManager::new(config);
        let companion_request =
            CompanionRequest::new("com.apple.universalcontrol", OpackValue::Dict(Vec::new()));

        assert!(manager
            .handle_companion_opack(&companion_request.encode_opack().unwrap())
            .unwrap()
            .is_none());
    }

    #[test]
    fn handles_encrypted_companion_stream_start_frame() {
        let stream_id =
            UniversalControlStreamId::new(UniversalControlStreamRole::Sync, SESSION_UUID).unwrap();
        let stream_request = StreamStartRequest::new(stream_id, RpStreamType::RpcConnection);
        let companion_request =
            CompanionRequest::new(REQUEST_ID_STREAM_START, stream_request.to_opack_value())
                .with_message_id("10")
                .with_transaction_id(88);
        let psk = [0x55; PAIRVERIFY_KEY_LENGTH];
        let mut client = PairingStream::main(PairingStreamEndpoint::Client, &psk).unwrap();
        let mut server = PairingStream::main(PairingStreamEndpoint::Server, &psk).unwrap();
        let request_frame = client
            .encrypt_e_opack_frame(&companion_request.to_opack_value())
            .unwrap();
        let config = StreamBindConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            advertise_addr: Some("127.0.0.1".into()),
        };
        let mut manager = StreamManager::new(config);

        let handled = manager
            .handle_encrypted_companion_frame(&mut server, &request_frame)
            .unwrap()
            .unwrap();

        assert_eq!(handled.handled.request_id, REQUEST_ID_STREAM_START);
        assert_eq!(handled.response_frame.frame_type, FRAME_TYPE_E_OPACK);
        assert_ne!(handled.response_frame.body, handled.handled.response_opack);

        let response_value = client
            .decrypt_e_opack_frame(&handled.response_frame)
            .unwrap();
        assert_eq!(response_value, handled.handled.response.to_opack_value());
        assert_eq!(
            response_value,
            dict([
                ("_i", OpackValue::String("10".into())),
                ("_x", OpackValue::Int(88)),
                (
                    "response",
                    dict([
                        (
                            "_streamPort",
                            OpackValue::Int(handled.handled.prepared.local_addr.port() as i64),
                        ),
                        ("_streamAddr", OpackValue::String("127.0.0.1".into())),
                    ]),
                ),
            ])
        );
    }
}
