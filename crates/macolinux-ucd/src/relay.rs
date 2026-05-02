use std::error::Error;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use macolinux_uc_core::opack::{decode_opack, OpackValue};
use macolinux_uc_core::rapport::{frame_type_name, FRAME_HEADER_LEN};

const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_MAX_BYTES: usize = 1024 * 1024;
const MAX_RAPPORT_BODY: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
struct RelayListenConfig {
    bind: SocketAddr,
    send: Vec<u8>,
    echo: bool,
    accept_timeout: Option<Duration>,
    read_timeout: Duration,
    max_bytes: usize,
}

pub fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
    match args.first().map(String::as_str) {
        Some("listen") => run_listen(&args[1..]),
        Some("-h") | Some("--help") | None => {
            println!("{}", usage());
            Ok(())
        }
        Some(other) => Err(RelayError(format!("unknown relay command: {other}")).into()),
    }
}

fn run_listen(args: &[String]) -> Result<(), Box<dyn Error>> {
    let config = RelayListenConfig::parse(args)?;
    let listener = TcpListener::bind(config.bind)?;
    let local_addr = listener.local_addr()?;
    println!(
        "relay listener ready: listen={} echo={} send_len={} read_timeout_ms={} max_bytes={}",
        local_addr,
        config.echo,
        config.send.len(),
        config.read_timeout.as_millis(),
        config.max_bytes
    );

    if let Some(timeout) = config.accept_timeout {
        listener.set_nonblocking(true)?;
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((stream, _)) => spawn_connection(config.clone(), stream),
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(err) => return Err(err.into()),
            }
        }
        return Ok(());
    }

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => spawn_connection(config.clone(), stream),
            Err(err) => eprintln!("relay accept failed: {err}"),
        }
    }
    Ok(())
}

fn spawn_connection(config: RelayListenConfig, stream: TcpStream) {
    thread::spawn(move || {
        if let Err(err) = handle_connection(config, stream) {
            eprintln!("relay connection ended: {err}");
        }
    });
}

fn handle_connection(
    config: RelayListenConfig,
    mut stream: TcpStream,
) -> Result<(), Box<dyn Error>> {
    let peer = stream.peer_addr()?;
    println!("relay connected: peer={peer}");
    stream.set_read_timeout(Some(config.read_timeout))?;

    if !config.send.is_empty() {
        stream.write_all(&config.send)?;
        stream.flush()?;
        println!(
            "relay sent: peer={} bytes={} hex={} utf8={:?}",
            peer,
            config.send.len(),
            hex_prefix(&config.send, 128),
            printable_utf8(&config.send)
        );
    }

    let mut total = 0usize;
    let mut raw = [0u8; 16 * 1024];
    let mut rapport_buffer = Vec::new();
    loop {
        match stream.read(&mut raw) {
            Ok(0) => {
                println!("relay disconnected: peer={peer} total_bytes={total}");
                return Ok(());
            }
            Ok(n) => {
                total += n;
                let chunk = &raw[..n];
                println!(
                    "relay recv: peer={} bytes={} total={} hex={} utf8={:?}",
                    peer,
                    n,
                    total,
                    hex_prefix(chunk, 256),
                    printable_utf8(chunk)
                );
                rapport_buffer.extend_from_slice(chunk);
                print_rapport_frames(&mut rapport_buffer);
                if rapport_buffer.len() > 256 * 1024 {
                    println!(
                        "relay rapport_buffer_clear: unparsed_bytes={}",
                        rapport_buffer.len()
                    );
                    rapport_buffer.clear();
                }
                if config.echo {
                    stream.write_all(chunk)?;
                    stream.flush()?;
                    println!("relay echo: peer={peer} bytes={n}");
                }
                if total >= config.max_bytes {
                    println!("relay max_bytes reached: peer={peer} total_bytes={total}");
                    return Ok(());
                }
            }
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                println!("relay read timeout: peer={peer} total_bytes={total}");
                return Ok(());
            }
            Err(err) => return Err(err.into()),
        }
    }
}

fn print_rapport_frames(buffer: &mut Vec<u8>) {
    loop {
        if buffer.len() < FRAME_HEADER_LEN {
            return;
        }

        let body_len =
            ((buffer[1] as usize) << 16) | ((buffer[2] as usize) << 8) | buffer[3] as usize;
        if body_len > MAX_RAPPORT_BODY {
            return;
        }

        let frame_len = FRAME_HEADER_LEN + body_len;
        if buffer.len() < frame_len {
            return;
        }

        let frame_type = buffer[0];
        let body = buffer[FRAME_HEADER_LEN..frame_len].to_vec();
        println!(
            "relay rapport: type=0x{:02x} name={} body_len={} body_prefix={}",
            frame_type,
            frame_type_name(frame_type),
            body.len(),
            hex_prefix(&body, 128)
        );
        if let Ok(value) = decode_opack(&body) {
            println!("relay rapport.opack={}", format_opack(&value));
        }
        buffer.drain(..frame_len);
    }
}

impl RelayListenConfig {
    fn parse(args: &[String]) -> Result<Self, RelayError> {
        let mut config = Self {
            bind: SocketAddr::from(([127, 0, 0, 1], 4711)),
            send: Vec::new(),
            echo: false,
            accept_timeout: None,
            read_timeout: DEFAULT_READ_TIMEOUT,
            max_bytes: DEFAULT_MAX_BYTES,
        };

        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--bind" => config.bind = parse_socket_addr(&next_value(&mut iter, arg)?)?,
                "--send-text" => config
                    .send
                    .extend_from_slice(next_value(&mut iter, arg)?.as_bytes()),
                "--send-hex" => config.send.extend(parse_hex(&next_value(&mut iter, arg)?)?),
                "--echo" => config.echo = true,
                "--accept-timeout-ms" => {
                    config.accept_timeout = Some(Duration::from_millis(parse_u64(&next_value(
                        &mut iter, arg,
                    )?)?));
                }
                "--read-timeout-ms" => {
                    config.read_timeout =
                        Duration::from_millis(parse_u64(&next_value(&mut iter, arg)?)?);
                }
                "--max-bytes" => {
                    let value = parse_u64(&next_value(&mut iter, arg)?)?;
                    config.max_bytes = usize::try_from(value)
                        .map_err(|_| RelayError(format!("--max-bytes too large: {value}")))?;
                }
                "-h" | "--help" => return Err(RelayError(usage().into())),
                other => return Err(RelayError(format!("unknown relay listen option: {other}"))),
            }
        }

        if config.read_timeout.is_zero() {
            return Err(RelayError("--read-timeout-ms must be at least 1".into()));
        }
        if config.max_bytes == 0 {
            return Err(RelayError("--max-bytes must be at least 1".into()));
        }
        Ok(config)
    }
}

fn parse_socket_addr(value: &str) -> Result<SocketAddr, RelayError> {
    value
        .parse()
        .map_err(|err| RelayError(format!("invalid socket address {value:?}: {err}")))
}

fn parse_u64(value: &str) -> Result<u64, RelayError> {
    value
        .parse()
        .map_err(|err| RelayError(format!("invalid u64 {value:?}: {err}")))
}

fn parse_hex(value: &str) -> Result<Vec<u8>, RelayError> {
    let mut cleaned = value
        .trim()
        .strip_prefix("0x")
        .unwrap_or(value.trim())
        .to_string();
    cleaned.retain(|ch| !ch.is_whitespace() && ch != ':' && ch != '-');
    cleaned.make_ascii_lowercase();

    if cleaned.len() % 2 != 0 {
        return Err(RelayError(
            "hex input must have an even number of digits".into(),
        ));
    }

    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for pair in cleaned.as_bytes().chunks_exact(2) {
        let text = std::str::from_utf8(pair)
            .map_err(|err| RelayError(format!("invalid hex text: {err}")))?;
        out.push(
            u8::from_str_radix(text, 16)
                .map_err(|err| RelayError(format!("invalid hex byte {text:?}: {err}")))?,
        );
    }
    Ok(out)
}

fn next_value<'a>(
    iter: &mut impl Iterator<Item = &'a String>,
    flag: &str,
) -> Result<String, RelayError> {
    iter.next()
        .cloned()
        .ok_or_else(|| RelayError(format!("missing value for {flag}")))
}

fn printable_utf8(data: &[u8]) -> String {
    String::from_utf8_lossy(data)
        .chars()
        .flat_map(|ch| ch.escape_debug())
        .collect()
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

fn usage() -> &'static str {
    "usage: macolinux-ucd relay listen [--bind ADDR:PORT] [--send-text TEXT] [--send-hex HEX] [--echo] [--accept-timeout-ms MS] [--read-timeout-ms MS] [--max-bytes N]"
}

#[derive(Debug, Clone)]
struct RelayError(String);

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for RelayError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_defaults() {
        let config = RelayListenConfig::parse(&[]).unwrap();
        assert_eq!(config.bind, SocketAddr::from(([127, 0, 0, 1], 4711)));
        assert!(!config.echo);
        assert!(config.send.is_empty());
    }

    #[test]
    fn parses_send_and_timeouts() {
        let config = RelayListenConfig::parse(&[
            "--bind".into(),
            "127.0.0.1:4999".into(),
            "--send-text".into(),
            "hi".into(),
            "--send-hex".into(),
            "0a0b".into(),
            "--echo".into(),
            "--accept-timeout-ms".into(),
            "25".into(),
            "--read-timeout-ms".into(),
            "50".into(),
            "--max-bytes".into(),
            "128".into(),
        ])
        .unwrap();

        assert_eq!(config.bind, SocketAddr::from(([127, 0, 0, 1], 4999)));
        assert_eq!(config.send, b"hi\x0a\x0b");
        assert!(config.echo);
        assert_eq!(config.accept_timeout, Some(Duration::from_millis(25)));
        assert_eq!(config.read_timeout, Duration::from_millis(50));
        assert_eq!(config.max_bytes, 128);
    }
}
