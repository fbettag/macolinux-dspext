use std::error::Error;
use std::fmt;
use std::io::{self, BufRead, BufReader};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
struct InputListenConfig {
    bind: SocketAddr,
    device: String,
    dry_run: bool,
    accept_timeout: Option<Duration>,
    read_timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum InputCommand {
    Move { dx: i32, dy: i32 },
    Scroll { vertical: i32, horizontal: i32 },
    Button { button: Button, action: PressAction },
    Key { code: u16, action: PressAction },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Button {
    Left,
    Right,
    Middle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PressAction {
    Down,
    Up,
    Click,
}

pub fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
    match args.first().map(String::as_str) {
        Some("listen") => run_listen(&args[1..]),
        Some("-h") | Some("--help") | None => {
            println!("{}", usage());
            Ok(())
        }
        Some(other) => Err(InputError(format!("unknown input command: {other}")).into()),
    }
}

fn run_listen(args: &[String]) -> Result<(), Box<dyn Error>> {
    let config = InputListenConfig::parse(args)?;
    let listener = TcpListener::bind(config.bind)?;
    let local_addr = listener.local_addr()?;
    println!(
        "input listener ready: listen={} device={} dry_run={} read_timeout_ms={}",
        local_addr,
        config.device,
        config.dry_run,
        config.read_timeout.as_millis()
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
            Err(err) => eprintln!("input accept failed: {err}"),
        }
    }
    Ok(())
}

fn spawn_connection(config: InputListenConfig, stream: TcpStream) {
    thread::spawn(move || {
        if let Err(err) = handle_connection(config, stream) {
            eprintln!("input connection ended: {err}");
        }
    });
}

fn handle_connection(config: InputListenConfig, stream: TcpStream) -> Result<(), Box<dyn Error>> {
    let peer = stream.peer_addr()?;
    println!("input connected: peer={peer}");
    stream.set_read_timeout(Some(config.read_timeout))?;
    let reader = BufReader::new(stream);

    let mut sink = InputSink::open(&config.device, config.dry_run)?;
    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let command = parse_input_command(trimmed)?;
        println!("input command: peer={peer} {command:?}");
        sink.apply(&command)?;
    }
    println!("input disconnected: peer={peer}");
    Ok(())
}

impl InputListenConfig {
    fn parse(args: &[String]) -> Result<Self, InputError> {
        let mut config = Self {
            bind: SocketAddr::from(([127, 0, 0, 1], 4720)),
            device: "/dev/uinput".into(),
            dry_run: false,
            accept_timeout: None,
            read_timeout: DEFAULT_READ_TIMEOUT,
        };

        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--bind" => config.bind = parse_socket_addr(&next_value(&mut iter, arg)?)?,
                "--device" => config.device = next_value(&mut iter, arg)?,
                "--dry-run" => config.dry_run = true,
                "--accept-timeout-ms" => {
                    config.accept_timeout = Some(Duration::from_millis(parse_u64(&next_value(
                        &mut iter, arg,
                    )?)?));
                }
                "--read-timeout-ms" => {
                    config.read_timeout =
                        Duration::from_millis(parse_u64(&next_value(&mut iter, arg)?)?);
                }
                "-h" | "--help" => return Err(InputError(usage().into())),
                other => return Err(InputError(format!("unknown input listen option: {other}"))),
            }
        }

        if config.read_timeout.is_zero() {
            return Err(InputError("--read-timeout-ms must be at least 1".into()));
        }
        Ok(config)
    }
}

fn parse_input_command(line: &str) -> Result<InputCommand, InputError> {
    let parts = line.split_whitespace().collect::<Vec<_>>();
    match parts.as_slice() {
        ["MOVE", dx, dy] => Ok(InputCommand::Move {
            dx: parse_i32(dx)?,
            dy: parse_i32(dy)?,
        }),
        ["SCROLL", vertical] => Ok(InputCommand::Scroll {
            vertical: parse_i32(vertical)?,
            horizontal: 0,
        }),
        ["SCROLL", vertical, horizontal] => Ok(InputCommand::Scroll {
            vertical: parse_i32(vertical)?,
            horizontal: parse_i32(horizontal)?,
        }),
        ["BTN", button, action] => Ok(InputCommand::Button {
            button: parse_button(button)?,
            action: parse_press_action(action)?,
        }),
        ["KEY", code, action] => Ok(InputCommand::Key {
            code: parse_key_code(code)?,
            action: parse_press_action(action)?,
        }),
        _ => Err(InputError(format!("invalid input command: {line:?}"))),
    }
}

fn parse_button(value: &str) -> Result<Button, InputError> {
    match value.to_ascii_lowercase().as_str() {
        "left" => Ok(Button::Left),
        "right" => Ok(Button::Right),
        "middle" => Ok(Button::Middle),
        _ => Err(InputError(format!("invalid button {value:?}"))),
    }
}

fn parse_press_action(value: &str) -> Result<PressAction, InputError> {
    match value.to_ascii_lowercase().as_str() {
        "down" => Ok(PressAction::Down),
        "up" => Ok(PressAction::Up),
        "click" | "tap" => Ok(PressAction::Click),
        _ => Err(InputError(format!("invalid press action {value:?}"))),
    }
}

fn parse_key_code(value: &str) -> Result<u16, InputError> {
    if let Ok(parsed) = value.parse::<u16>() {
        return Ok(parsed);
    }
    key_name(value).ok_or_else(|| InputError(format!("unknown key name {value:?}")))
}

fn key_name(value: &str) -> Option<u16> {
    let upper = value.to_ascii_uppercase();
    let code = match upper.as_str() {
        "ESC" | "ESCAPE" => 1,
        "1" => 2,
        "2" => 3,
        "3" => 4,
        "4" => 5,
        "5" => 6,
        "6" => 7,
        "7" => 8,
        "8" => 9,
        "9" => 10,
        "0" => 11,
        "MINUS" => 12,
        "EQUAL" => 13,
        "BACKSPACE" => 14,
        "TAB" => 15,
        "Q" => 16,
        "W" => 17,
        "E" => 18,
        "R" => 19,
        "T" => 20,
        "Y" => 21,
        "U" => 22,
        "I" => 23,
        "O" => 24,
        "P" => 25,
        "LEFTBRACE" | "LBRACKET" => 26,
        "RIGHTBRACE" | "RBRACKET" => 27,
        "ENTER" | "RETURN" => 28,
        "LEFTCTRL" | "CTRL" => 29,
        "A" => 30,
        "S" => 31,
        "D" => 32,
        "F" => 33,
        "G" => 34,
        "H" => 35,
        "J" => 36,
        "K" => 37,
        "L" => 38,
        "SEMICOLON" => 39,
        "APOSTROPHE" => 40,
        "GRAVE" => 41,
        "LEFTSHIFT" | "SHIFT" => 42,
        "BACKSLASH" => 43,
        "Z" => 44,
        "X" => 45,
        "C" => 46,
        "V" => 47,
        "B" => 48,
        "N" => 49,
        "M" => 50,
        "COMMA" => 51,
        "DOT" | "PERIOD" => 52,
        "SLASH" => 53,
        "RIGHTSHIFT" => 54,
        "LEFTALT" | "ALT" => 56,
        "SPACE" => 57,
        "CAPSLOCK" => 58,
        "F1" => 59,
        "F2" => 60,
        "F3" => 61,
        "F4" => 62,
        "F5" => 63,
        "F6" => 64,
        "F7" => 65,
        "F8" => 66,
        "F9" => 67,
        "F10" => 68,
        "F11" => 87,
        "F12" => 88,
        "RIGHTCTRL" => 97,
        "RIGHTALT" => 100,
        "HOME" => 102,
        "UP" => 103,
        "PAGEUP" => 104,
        "LEFT" => 105,
        "RIGHT" => 106,
        "END" => 107,
        "DOWN" => 108,
        "PAGEDOWN" => 109,
        "INSERT" => 110,
        "DELETE" => 111,
        "LEFTMETA" | "META" | "SUPER" | "CMD" => 125,
        "RIGHTMETA" => 126,
        _ => return None,
    };
    Some(code)
}

fn parse_socket_addr(value: &str) -> Result<SocketAddr, InputError> {
    value
        .parse()
        .map_err(|err| InputError(format!("invalid socket address {value:?}: {err}")))
}

fn parse_i32(value: &str) -> Result<i32, InputError> {
    value
        .parse()
        .map_err(|err| InputError(format!("invalid i32 {value:?}: {err}")))
}

fn parse_u64(value: &str) -> Result<u64, InputError> {
    value
        .parse()
        .map_err(|err| InputError(format!("invalid u64 {value:?}: {err}")))
}

fn next_value<'a>(
    iter: &mut impl Iterator<Item = &'a String>,
    flag: &str,
) -> Result<String, InputError> {
    iter.next()
        .cloned()
        .ok_or_else(|| InputError(format!("missing value for {flag}")))
}

fn usage() -> &'static str {
    "usage: macolinux-ucd input listen [--bind ADDR:PORT] [--device /dev/uinput] [--dry-run] [--accept-timeout-ms MS] [--read-timeout-ms MS]\n\nline protocol: MOVE dx dy | SCROLL vertical [horizontal] | BTN left|right|middle down|up|click | KEY CODE_OR_NAME down|up|tap"
}

struct InputSink {
    dry_run: bool,
    #[cfg(target_os = "linux")]
    device: Option<linux_uinput::UinputDevice>,
}

impl InputSink {
    fn open(device_path: &str, dry_run: bool) -> Result<Self, Box<dyn Error>> {
        if dry_run {
            return Ok(Self {
                dry_run,
                #[cfg(target_os = "linux")]
                device: None,
            });
        }

        #[cfg(target_os = "linux")]
        {
            return Ok(Self {
                dry_run,
                device: Some(linux_uinput::UinputDevice::open(device_path)?),
            });
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = device_path;
            Err(InputError("uinput injection is only available on Linux".into()).into())
        }
    }

    fn apply(&mut self, command: &InputCommand) -> Result<(), Box<dyn Error>> {
        if self.dry_run {
            println!("input dry_run: {command:?}");
            return Ok(());
        }

        #[cfg(target_os = "linux")]
        {
            let device = self
                .device
                .as_mut()
                .ok_or_else(|| InputError("uinput device not open".into()))?;
            device.apply(command)?;
            return Ok(());
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = command;
            Err(InputError("uinput injection is only available on Linux".into()).into())
        }
    }
}

#[cfg(target_os = "linux")]
mod linux_uinput {
    use super::{Button, InputCommand, InputError, PressAction};
    use std::fs::{File, OpenOptions};
    use std::io::{self, Write};
    use std::mem;
    use std::os::fd::AsRawFd;
    use std::slice;

    const EV_SYN: u16 = 0x00;
    const EV_KEY: u16 = 0x01;
    const EV_REL: u16 = 0x02;
    const SYN_REPORT: u16 = 0x00;
    const REL_X: u16 = 0x00;
    const REL_Y: u16 = 0x01;
    const REL_HWHEEL: u16 = 0x06;
    const REL_WHEEL: u16 = 0x08;
    const BTN_LEFT: u16 = 0x110;
    const BTN_RIGHT: u16 = 0x111;
    const BTN_MIDDLE: u16 = 0x112;
    const BUS_USB: u16 = 0x03;

    const UI_DEV_CREATE: libc::Ioctl = io(UINPUT_IOCTL_BASE, 1);
    const UI_DEV_DESTROY: libc::Ioctl = io(UINPUT_IOCTL_BASE, 2);
    const UI_SET_EVBIT: libc::Ioctl = iow::<libc::c_int>(UINPUT_IOCTL_BASE, 100);
    const UI_SET_KEYBIT: libc::Ioctl = iow::<libc::c_int>(UINPUT_IOCTL_BASE, 101);
    const UI_SET_RELBIT: libc::Ioctl = iow::<libc::c_int>(UINPUT_IOCTL_BASE, 102);
    const UINPUT_IOCTL_BASE: u8 = b'U';

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct InputId {
        bustype: u16,
        vendor: u16,
        product: u16,
        version: u16,
    }

    #[repr(C)]
    struct UinputUserDev {
        name: [u8; 80],
        id: InputId,
        ff_effects_max: u32,
        absmax: [i32; 64],
        absmin: [i32; 64],
        absfuzz: [i32; 64],
        absflat: [i32; 64],
    }

    #[repr(C)]
    struct InputEvent {
        time: libc::timeval,
        type_: u16,
        code: u16,
        value: i32,
    }

    pub struct UinputDevice {
        file: File,
    }

    impl UinputDevice {
        pub fn open(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
            let mut file = OpenOptions::new().read(true).write(true).open(path)?;
            let fd = file.as_raw_fd();

            ioctl_set(fd, UI_SET_EVBIT, EV_KEY)?;
            ioctl_set(fd, UI_SET_EVBIT, EV_REL)?;
            ioctl_set(fd, UI_SET_RELBIT, REL_X)?;
            ioctl_set(fd, UI_SET_RELBIT, REL_Y)?;
            ioctl_set(fd, UI_SET_RELBIT, REL_WHEEL)?;
            ioctl_set(fd, UI_SET_RELBIT, REL_HWHEEL)?;
            ioctl_set(fd, UI_SET_KEYBIT, BTN_LEFT)?;
            ioctl_set(fd, UI_SET_KEYBIT, BTN_RIGHT)?;
            ioctl_set(fd, UI_SET_KEYBIT, BTN_MIDDLE)?;
            for code in 1..=255u16 {
                ioctl_set(fd, UI_SET_KEYBIT, code)?;
            }

            let mut user_dev = UinputUserDev {
                name: [0; 80],
                id: InputId {
                    bustype: BUS_USB,
                    vendor: 0x2342,
                    product: 0x0001,
                    version: 1,
                },
                ff_effects_max: 0,
                absmax: [0; 64],
                absmin: [0; 64],
                absfuzz: [0; 64],
                absflat: [0; 64],
            };
            let name = b"macolinux-uc virtual input";
            user_dev.name[..name.len()].copy_from_slice(name);
            write_struct(&mut file, &user_dev)?;
            ioctl_plain(fd, UI_DEV_CREATE)?;
            Ok(Self { file })
        }

        pub fn apply(&mut self, command: &InputCommand) -> Result<(), Box<dyn std::error::Error>> {
            match command {
                InputCommand::Move { dx, dy } => {
                    if *dx != 0 {
                        self.emit(EV_REL, REL_X, *dx)?;
                    }
                    if *dy != 0 {
                        self.emit(EV_REL, REL_Y, *dy)?;
                    }
                    self.sync()?;
                }
                InputCommand::Scroll {
                    vertical,
                    horizontal,
                } => {
                    if *vertical != 0 {
                        self.emit(EV_REL, REL_WHEEL, *vertical)?;
                    }
                    if *horizontal != 0 {
                        self.emit(EV_REL, REL_HWHEEL, *horizontal)?;
                    }
                    self.sync()?;
                }
                InputCommand::Button { button, action } => {
                    self.press(button_code(*button), *action)?;
                }
                InputCommand::Key { code, action } => {
                    self.press(*code, *action)?;
                }
            }
            Ok(())
        }

        fn press(&mut self, code: u16, action: PressAction) -> io::Result<()> {
            match action {
                PressAction::Down => {
                    self.emit(EV_KEY, code, 1)?;
                    self.sync()
                }
                PressAction::Up => {
                    self.emit(EV_KEY, code, 0)?;
                    self.sync()
                }
                PressAction::Click => {
                    self.emit(EV_KEY, code, 1)?;
                    self.sync()?;
                    self.emit(EV_KEY, code, 0)?;
                    self.sync()
                }
            }
        }

        fn emit(&mut self, type_: u16, code: u16, value: i32) -> io::Result<()> {
            let event = InputEvent {
                time: libc::timeval {
                    tv_sec: 0,
                    tv_usec: 0,
                },
                type_,
                code,
                value,
            };
            write_struct(&mut self.file, &event)
        }

        fn sync(&mut self) -> io::Result<()> {
            self.emit(EV_SYN, SYN_REPORT, 0)
        }
    }

    impl Drop for UinputDevice {
        fn drop(&mut self) {
            let _ = unsafe { libc::ioctl(self.file.as_raw_fd(), UI_DEV_DESTROY) };
        }
    }

    fn button_code(button: Button) -> u16 {
        match button {
            Button::Left => BTN_LEFT,
            Button::Right => BTN_RIGHT,
            Button::Middle => BTN_MIDDLE,
        }
    }

    fn write_struct<T>(file: &mut File, value: &T) -> io::Result<()> {
        let bytes =
            unsafe { slice::from_raw_parts(value as *const T as *const u8, mem::size_of::<T>()) };
        file.write_all(bytes)
    }

    fn ioctl_plain(fd: libc::c_int, request: libc::Ioctl) -> io::Result<()> {
        let rc = unsafe { libc::ioctl(fd, request) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn ioctl_set(fd: libc::c_int, request: libc::Ioctl, value: u16) -> io::Result<()> {
        let value = libc::c_int::from(value);
        let rc = unsafe { libc::ioctl(fd, request, value) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    const fn io(type_: u8, nr: u8) -> libc::Ioctl {
        ioc(0, type_, nr, 0)
    }

    const fn iow<T>(type_: u8, nr: u8) -> libc::Ioctl {
        ioc(1, type_, nr, mem::size_of::<T>() as u32)
    }

    const fn ioc(dir: u8, type_: u8, nr: u8, size: u32) -> libc::Ioctl {
        (((dir as u64) << 30) | ((type_ as u64) << 8) | (nr as u64) | ((size as u64) << 16))
            as libc::Ioctl
    }

    impl From<InputError> for io::Error {
        fn from(value: InputError) -> Self {
            io::Error::new(io::ErrorKind::InvalidInput, value)
        }
    }
}

#[derive(Debug, Clone)]
struct InputError(String);

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for InputError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_listener_defaults() {
        let config = InputListenConfig::parse(&[]).unwrap();
        assert_eq!(config.bind, SocketAddr::from(([127, 0, 0, 1], 4720)));
        assert_eq!(config.device, "/dev/uinput");
        assert!(!config.dry_run);
    }

    #[test]
    fn parses_listener_options() {
        let config = InputListenConfig::parse(&[
            "--bind".into(),
            "0.0.0.0:4777".into(),
            "--device".into(),
            "/tmp/uinput".into(),
            "--dry-run".into(),
            "--accept-timeout-ms".into(),
            "25".into(),
            "--read-timeout-ms".into(),
            "50".into(),
        ])
        .unwrap();

        assert_eq!(config.bind, SocketAddr::from(([0, 0, 0, 0], 4777)));
        assert_eq!(config.device, "/tmp/uinput");
        assert!(config.dry_run);
        assert_eq!(config.accept_timeout, Some(Duration::from_millis(25)));
        assert_eq!(config.read_timeout, Duration::from_millis(50));
    }

    #[test]
    fn parses_input_commands() {
        assert_eq!(
            parse_input_command("MOVE -3 4").unwrap(),
            InputCommand::Move { dx: -3, dy: 4 }
        );
        assert_eq!(
            parse_input_command("SCROLL -1 2").unwrap(),
            InputCommand::Scroll {
                vertical: -1,
                horizontal: 2
            }
        );
        assert_eq!(
            parse_input_command("BTN left click").unwrap(),
            InputCommand::Button {
                button: Button::Left,
                action: PressAction::Click
            }
        );
        assert_eq!(
            parse_input_command("KEY A down").unwrap(),
            InputCommand::Key {
                code: 30,
                action: PressAction::Down
            }
        );
        assert_eq!(
            parse_input_command("KEY 57 tap").unwrap(),
            InputCommand::Key {
                code: 57,
                action: PressAction::Click
            }
        );
    }
}
