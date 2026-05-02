use std::env;
use std::error::Error;
use std::fmt;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

fn main() {
    if let Err(err) = run(env::args().collect()) {
        eprintln!("macolinux-uc-bootstrap: {err}");
        process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<(), Box<dyn Error>> {
    match args.get(1).map(String::as_str) {
        Some("pairverify-m3") => run_pairverify_m3(&args[2..]),
        Some("companion-stream") => run_companion_stream(&args[2..]),
        Some("-h") | Some("--help") | None => {
            print_help();
            Ok(())
        }
        Some(other) => Err(BootstrapError(format!("unknown command: {other}")).into()),
    }
}

fn run_pairverify_m3(args: &[String]) -> Result<(), Box<dyn Error>> {
    let config = PairVerifyM3Config::parse(args)?;
    let call_id_start = uuidgen()?;
    let call_id_m1 = uuidgen()?;
    let call_id_m3 = uuidgen()?;
    let helper_path = config.helper_path()?;
    let probe_path = config.probe_path()?;
    let identity_path = canonicalize_lossy(&config.identity_path)?;
    let (actor_id, actor_id_source) = config.actor_id()?;
    let payload = format!(
        "pairverify-m3-sequence:{call_id_start}|{call_id_m1}|{call_id_m3}|{}|{}|{}|{}|{}",
        config.actor_name,
        actor_id,
        bool_word(config.create_stream),
        helper_path.display(),
        identity_path.display()
    );

    let command = vec![
        "connect-service".to_string(),
        config.peer_name.clone(),
        config.service_type.clone(),
        config.domain.clone(),
        config.seconds.to_string(),
        "3".into(),
        "0".into(),
        payload.clone(),
        config.transport.clone(),
        "stack".into(),
        "actor".into(),
        config.interface.clone(),
    ];

    println!("probe={}", probe_path.display());
    println!("helper={}", helper_path.display());
    println!("identity={}", identity_path.display());
    println!("actor_name={}", config.actor_name);
    println!("actor_id={actor_id}");
    println!("actor_id_source={actor_id_source}");
    println!("peer_name={}", config.peer_name);
    println!("service_type={}", config.service_type);
    println!("domain={}", config.domain);
    println!("transport={}", config.transport);
    println!("interface={}", config.interface);
    println!("create_stream={}", bool_word(config.create_stream));
    println!("resolve_timeout_seconds={}", config.resolve_timeout_seconds);
    println!("appsvc_service={}", config.appsvc_service);
    println!(
        "appsvc_bundle_id={}",
        config.appsvc_bundle_id.as_deref().unwrap_or("(disabled)")
    );
    println!("call_id_start={call_id_start}");
    println!("call_id_m1={call_id_m1}");
    println!("call_id_m3={call_id_m3}");
    println!("payload={payload}");
    println!(
        "command={} {}",
        shell_escape_path(&probe_path),
        command
            .iter()
            .map(|arg| shell_escape(arg))
            .collect::<Vec<_>>()
            .join(" ")
    );

    if config.dry_run {
        return Ok(());
    }

    let status = Command::new(&probe_path)
        .args(&command)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;
    if !status.success() {
        return Err(BootstrapError(format!("probe exited with status {status}")).into());
    }
    Ok(())
}

fn run_companion_stream(args: &[String]) -> Result<(), Box<dyn Error>> {
    match args.first().map(String::as_str) {
        Some("publish") => run_companion_publish(&args[1..]),
        Some("connect-b64") => run_companion_connect_b64(&args[1..]),
        Some("-h") | Some("--help") | None => {
            println!("{}", companion_stream_usage());
            Ok(())
        }
        Some(other) => {
            Err(BootstrapError(format!("unknown companion-stream command: {other}")).into())
        }
    }
}

fn run_companion_publish(args: &[String]) -> Result<(), Box<dyn Error>> {
    let config = CompanionPublishConfig::parse(args)?;
    let probe_path = config.probe_path()?;

    println!("probe={}", probe_path.display());
    println!("manager_id={}", config.manager_id);
    println!("service={}", config.service);
    println!("seconds={}", config.seconds);
    println!(
        "bonjour_name_requested={}",
        config.bonjour_name.as_deref().unwrap_or("auto")
    );
    println!(
        "always_send_payload={}",
        bool_word(config.always_send_payload)
    );
    println!("relay={}", config.relay.as_deref().unwrap_or("(disabled)"));

    if config.dry_run {
        println!("dry_run=true");
        return Ok(());
    }

    let bonjour_name = resolve_companion_bonjour_name(&config)?;
    println!("bonjour_name={}", bonjour_name);

    let mut changed_pref = false;
    if config.always_send_payload {
        run_status(
            "defaults",
            &[
                "write",
                "com.apple.Sharing",
                "AlwaysSendPayload",
                "-bool",
                "true",
            ],
        )?;
        changed_pref = true;
        let _ = run_status("killall", &["sharingd"]);
    }

    let mut command = Command::new(&probe_path);
    command
        .arg("enable-full")
        .arg(&config.manager_id)
        .arg(&config.service)
        .arg(config.seconds.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    command.env("UC_BONJOUR_NAME", &bonjour_name);
    if let Some(reply) = &config.reply {
        command.env("UC_STREAM_REPLY", reply);
    }
    if let Some(relay) = &config.relay {
        command.env("UC_STREAM_RELAY", relay);
    }

    let status = command.status()?;
    if changed_pref {
        let _ = run_status(
            "defaults",
            &["delete", "com.apple.Sharing", "AlwaysSendPayload"],
        );
        let _ = run_status("killall", &["sharingd"]);
    }
    if !status.success() {
        return Err(BootstrapError(format!(
            "companion stream publish helper exited with status {status}"
        ))
        .into());
    }
    Ok(())
}

fn run_companion_connect_b64(args: &[String]) -> Result<(), Box<dyn Error>> {
    let config = CompanionConnectConfig::parse(args)?;
    let probe_path = config.probe_path()?;

    println!("probe={}", probe_path.display());
    println!("seconds={}", config.seconds);
    println!("message_b64_len={}", config.message_b64.len());
    println!("relay={}", config.relay.as_deref().unwrap_or("(disabled)"));

    if config.dry_run {
        println!("dry_run=true");
        return Ok(());
    }

    let mut command = Command::new(&probe_path);
    command
        .arg("connect-b64")
        .arg(&config.message_b64)
        .arg(config.seconds.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if let Some(write) = &config.write {
        command.env("UC_STREAM_WRITE", write);
    }
    if let Some(relay) = &config.relay {
        command.env("UC_STREAM_RELAY", relay);
    }
    let status = command.status()?;
    if !status.success() {
        return Err(BootstrapError(format!(
            "companion stream connect helper exited with status {status}"
        ))
        .into());
    }
    Ok(())
}

fn resolve_companion_bonjour_name(
    config: &CompanionPublishConfig,
) -> Result<String, BootstrapError> {
    match config.bonjour_name.as_deref() {
        Some("auto") | None => Err(BootstrapError(
            "missing --bonjour-name; use the active _continuity._tcp instance from `dns-sd -B _continuity._tcp local.`".into(),
        )),
        Some(name) => Ok(name.to_string()),
    }
}

#[derive(Debug, Clone)]
struct PairVerifyM3Config {
    peer_name: String,
    service_type: String,
    domain: String,
    seconds: u64,
    actor_name: String,
    actor_id: Option<String>,
    identity_path: PathBuf,
    transport: String,
    interface: String,
    create_stream: bool,
    resolve_timeout_seconds: u64,
    appsvc_service: String,
    appsvc_bundle_id: Option<String>,
    appsvc_probe_override: Option<PathBuf>,
    probe_override: Option<PathBuf>,
    helper_override: Option<PathBuf>,
    dry_run: bool,
}

#[derive(Debug, Clone)]
struct CompanionPublishConfig {
    manager_id: String,
    service: String,
    seconds: u64,
    bonjour_name: Option<String>,
    reply: Option<String>,
    relay: Option<String>,
    probe_override: Option<PathBuf>,
    always_send_payload: bool,
    dry_run: bool,
}

#[derive(Debug, Clone)]
struct CompanionConnectConfig {
    message_b64: String,
    seconds: u64,
    write: Option<String>,
    relay: Option<String>,
    probe_override: Option<PathBuf>,
    dry_run: bool,
}

impl CompanionPublishConfig {
    fn parse(args: &[String]) -> Result<Self, BootstrapError> {
        let mut config = Self {
            manager_id: "com.apple.CompanionAuthentication".into(),
            service: "com.apple.CompanionAuthentication".into(),
            seconds: 60,
            bonjour_name: None,
            reply: None,
            relay: None,
            probe_override: None,
            always_send_payload: true,
            dry_run: false,
        };

        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--manager-id" => config.manager_id = next_value(&mut iter, arg)?,
                "--service" => config.service = next_value(&mut iter, arg)?,
                "--seconds" => {
                    let value = next_value(&mut iter, arg)?;
                    config.seconds = value.parse::<u64>().map_err(|err| {
                        BootstrapError(format!("invalid --seconds value {value:?}: {err}"))
                    })?;
                }
                "--bonjour-name" => config.bonjour_name = Some(next_value(&mut iter, arg)?),
                "--reply" => config.reply = Some(next_value(&mut iter, arg)?),
                "--relay" => config.relay = Some(next_value(&mut iter, arg)?),
                "--probe" => {
                    config.probe_override = Some(PathBuf::from(next_value(&mut iter, arg)?))
                }
                "--always-send-payload" => {
                    let value = next_value(&mut iter, arg)?;
                    config.always_send_payload = parse_bool(&value)?;
                }
                "--dry-run" => config.dry_run = true,
                "-h" | "--help" => return Err(BootstrapError(companion_stream_usage())),
                other => {
                    return Err(BootstrapError(format!(
                        "unknown companion-stream publish option: {other}"
                    )))
                }
            }
        }

        if config.seconds == 0 {
            return Err(BootstrapError("--seconds must be at least 1".into()));
        }
        Ok(config)
    }

    fn probe_path(&self) -> Result<PathBuf, BootstrapError> {
        resolve_tool(
            self.probe_override.as_deref(),
            "macolinux-companion-service-probe",
            "companion service probe",
        )
    }
}

impl CompanionConnectConfig {
    fn parse(args: &[String]) -> Result<Self, BootstrapError> {
        let mut config = Self {
            message_b64: String::new(),
            seconds: 30,
            write: None,
            relay: None,
            probe_override: None,
            dry_run: false,
        };

        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--message-b64" => config.message_b64 = next_value(&mut iter, arg)?,
                "--seconds" => {
                    let value = next_value(&mut iter, arg)?;
                    config.seconds = value.parse::<u64>().map_err(|err| {
                        BootstrapError(format!("invalid --seconds value {value:?}: {err}"))
                    })?;
                }
                "--write" => config.write = Some(next_value(&mut iter, arg)?),
                "--relay" => config.relay = Some(next_value(&mut iter, arg)?),
                "--probe" => {
                    config.probe_override = Some(PathBuf::from(next_value(&mut iter, arg)?))
                }
                "--dry-run" => config.dry_run = true,
                "-h" | "--help" => return Err(BootstrapError(companion_stream_usage())),
                other => {
                    return Err(BootstrapError(format!(
                        "unknown companion-stream connect-b64 option: {other}"
                    )))
                }
            }
        }

        if config.message_b64.is_empty() {
            return Err(BootstrapError("missing --message-b64".into()));
        }
        if config.seconds == 0 {
            return Err(BootstrapError("--seconds must be at least 1".into()));
        }
        Ok(config)
    }

    fn probe_path(&self) -> Result<PathBuf, BootstrapError> {
        resolve_tool(
            self.probe_override.as_deref(),
            "macolinux-companion-service-probe",
            "companion service probe",
        )
    }
}

impl PairVerifyM3Config {
    fn parse(args: &[String]) -> Result<Self, BootstrapError> {
        let mut config = Self {
            peer_name: String::new(),
            service_type: "_appSvcPrePair._tcp".into(),
            domain: "local.".into(),
            seconds: 22,
            actor_name: "RPPairingDistributedActor".into(),
            actor_id: None,
            identity_path: PathBuf::new(),
            transport: "tls".into(),
            interface: "awdl0".into(),
            create_stream: true,
            resolve_timeout_seconds: 8,
            appsvc_service: "com.apple.universalcontrol".into(),
            appsvc_bundle_id: Some("com.apple.universalcontrol".into()),
            appsvc_probe_override: None,
            probe_override: None,
            helper_override: None,
            dry_run: false,
        };

        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--peer-name" => config.peer_name = next_value(&mut iter, arg)?,
                "--service-type" => config.service_type = next_value(&mut iter, arg)?,
                "--domain" => config.domain = next_value(&mut iter, arg)?,
                "--seconds" => {
                    let value = next_value(&mut iter, arg)?;
                    config.seconds = value.parse::<u64>().map_err(|err| {
                        BootstrapError(format!("invalid --seconds value {value:?}: {err}"))
                    })?;
                }
                "--actor-name" => config.actor_name = next_value(&mut iter, arg)?,
                "--actor-id" => config.actor_id = Some(next_value(&mut iter, arg)?),
                "--identity" => config.identity_path = PathBuf::from(next_value(&mut iter, arg)?),
                "--transport" => config.transport = next_value(&mut iter, arg)?,
                "--interface" => config.interface = next_value(&mut iter, arg)?,
                "--create-stream" => {
                    let value = next_value(&mut iter, arg)?;
                    config.create_stream = parse_bool(&value)?;
                }
                "--resolve-timeout-seconds" => {
                    let value = next_value(&mut iter, arg)?;
                    config.resolve_timeout_seconds = value.parse::<u64>().map_err(|err| {
                        BootstrapError(format!(
                            "invalid --resolve-timeout-seconds value {value:?}: {err}"
                        ))
                    })?;
                }
                "--appsvc-service" => config.appsvc_service = next_value(&mut iter, arg)?,
                "--appsvc-bundle-id" => config.appsvc_bundle_id = Some(next_value(&mut iter, arg)?),
                "--no-appsvc-resolve" => config.appsvc_bundle_id = None,
                "--appsvc-probe" => {
                    config.appsvc_probe_override = Some(PathBuf::from(next_value(&mut iter, arg)?))
                }
                "--probe" => {
                    config.probe_override = Some(PathBuf::from(next_value(&mut iter, arg)?))
                }
                "--helper" => {
                    config.helper_override = Some(PathBuf::from(next_value(&mut iter, arg)?))
                }
                "--dry-run" => config.dry_run = true,
                "-h" | "--help" => return Err(BootstrapError(pairverify_usage())),
                other => {
                    return Err(BootstrapError(format!(
                        "unknown pairverify-m3 option: {other}"
                    )))
                }
            }
        }

        if config.peer_name.is_empty() {
            return Err(BootstrapError("missing --peer-name".into()));
        }
        if config.identity_path.as_os_str().is_empty() {
            return Err(BootstrapError("missing --identity".into()));
        }
        if config.resolve_timeout_seconds == 0 {
            return Err(BootstrapError(
                "--resolve-timeout-seconds must be at least 1".into(),
            ));
        }

        for value in std::iter::once(&config.actor_name).chain(config.actor_id.iter()) {
            if value.contains('|') {
                return Err(BootstrapError(format!(
                    "value contains unsupported '|' separator: {value}"
                )));
            }
        }

        Ok(config)
    }

    fn actor_id(&self) -> Result<(String, &'static str), BootstrapError> {
        if let Some(actor_id) = &self.actor_id {
            return Ok((actor_id.clone(), "explicit"));
        }
        let bonjour_result = resolve_actor_id_bonjour(
            &self.peer_name,
            &self.service_type,
            &self.domain,
            self.resolve_timeout_seconds,
        );
        if let Ok(actor_id) = bonjour_result {
            return Ok((actor_id, "bonjour-sid"));
        }
        let bonjour_err = bonjour_result.expect_err("bonjour resolution should have failed");

        if let Some(bundle_id) = &self.appsvc_bundle_id {
            let appsvc_probe_path = self.appsvc_probe_path()?;
            let appsvc_result = resolve_actor_id_appsvc(
                &appsvc_probe_path,
                &self.appsvc_service,
                bundle_id,
                self.resolve_timeout_seconds,
                &self.interface,
            );
            if let Ok(actor_id) = appsvc_result {
                return Ok((actor_id, "appsvc-bundle"));
            }
            let appsvc_err = appsvc_result.expect_err("appsvc resolution should have failed");
            return Err(BootstrapError(format!(
                "{bonjour_err}; appsvc fallback failed: {appsvc_err}"
            )));
        }

        Err(bonjour_err)
    }

    fn helper_path(&self) -> Result<PathBuf, BootstrapError> {
        resolve_tool(
            self.helper_override.as_deref(),
            "pairverify_actor_helper",
            "pairverify actor helper",
        )
    }

    fn probe_path(&self) -> Result<PathBuf, BootstrapError> {
        resolve_tool(
            self.probe_override.as_deref(),
            "macolinux-network-actor-framer-probe",
            "network actor framer probe",
        )
    }

    fn appsvc_probe_path(&self) -> Result<PathBuf, BootstrapError> {
        resolve_tool(
            self.appsvc_probe_override.as_deref(),
            "macolinux-network-endpoint-c-probe",
            "network endpoint C probe",
        )
    }
}

fn resolve_tool(
    override_path: Option<&Path>,
    sibling_name: &str,
    label: &str,
) -> Result<PathBuf, BootstrapError> {
    if let Some(path) = override_path {
        return validate_existing_tool(path.to_path_buf(), label);
    }
    if let Some(path) = sibling_tool_path(sibling_name) {
        return validate_existing_tool(path, label);
    }
    Ok(PathBuf::from(sibling_name))
}

fn validate_existing_tool(path: PathBuf, label: &str) -> Result<PathBuf, BootstrapError> {
    if path.exists() {
        return Ok(path);
    }
    Err(BootstrapError(format!(
        "{label} not found at {}",
        path.display()
    )))
}

fn sibling_tool_path(name: &str) -> Option<PathBuf> {
    let exe = env::current_exe().ok()?;
    let dir = exe.parent()?;
    let candidate = dir.join(name);
    candidate.exists().then_some(candidate)
}

fn uuidgen() -> Result<String, BootstrapError> {
    let output = Command::new("uuidgen")
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()
        .map_err(|err| BootstrapError(format!("failed to run uuidgen: {err}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(BootstrapError(format!(
            "uuidgen failed with status {}: {}",
            output.status,
            stderr.trim()
        )));
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|err| BootstrapError(format!("uuidgen returned non-UTF-8 output: {err}")))?;
    Ok(text.trim().to_string())
}

fn canonicalize_lossy(path: &Path) -> Result<PathBuf, BootstrapError> {
    std::fs::canonicalize(path)
        .map_err(|err| BootstrapError(format!("failed to resolve {}: {err}", path.display())))
}

fn resolve_actor_id_bonjour(
    peer_name: &str,
    service_type: &str,
    domain: &str,
    timeout_seconds: u64,
) -> Result<String, BootstrapError> {
    let mut child = Command::new("dns-sd")
        .arg("-L")
        .arg(peer_name)
        .arg(service_type)
        .arg(domain)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| BootstrapError(format!("failed to run dns-sd -L: {err}")))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| BootstrapError("dns-sd stdout pipe unavailable".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| BootstrapError("dns-sd stderr pipe unavailable".into()))?;

    let (tx, rx) = mpsc::channel();
    spawn_line_reader(stdout, tx.clone());
    spawn_line_reader(stderr, tx);

    let deadline = Instant::now() + Duration::from_secs(timeout_seconds);
    let mut transcript = Vec::new();

    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let remaining = deadline.saturating_duration_since(now);
        match rx.recv_timeout(remaining) {
            Ok(line) => {
                if !line.trim().is_empty() {
                    transcript.push(line.clone());
                }
                if let Some(actor_id) = extract_sid_value(&line) {
                    terminate_child(&mut child);
                    let _ = child.wait();
                    return Ok(actor_id);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => break,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if child
                    .try_wait()
                    .map_err(|err| BootstrapError(format!("failed waiting for dns-sd: {err}")))?
                    .is_some()
                {
                    break;
                }
            }
        }
    }

    terminate_child(&mut child);
    let status = child
        .wait()
        .map_err(|err| BootstrapError(format!("failed to wait for dns-sd: {err}")))?;
    let details = if transcript.is_empty() {
        "no output captured".to_string()
    } else {
        transcript.join("\n")
    };
    Err(BootstrapError(format!(
        "failed to resolve actor id from dns-sd -L {} {} {} within {}s (status: {}): {}",
        peer_name, service_type, domain, timeout_seconds, status, details
    )))
}

fn resolve_actor_id_appsvc(
    probe_path: &Path,
    service: &str,
    bundle_id: &str,
    timeout_seconds: u64,
    interface: &str,
) -> Result<String, BootstrapError> {
    let mut command = Command::new(probe_path);
    command
        .arg("browse-appsvc-bundle")
        .arg(service)
        .arg(bundle_id)
        .arg(timeout_seconds.to_string())
        .arg("endpoints-only")
        .arg("1");
    if interface != "any" {
        command.arg("require-interface").arg(interface);
    }

    let output = command
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()
        .map_err(|err| {
            BootstrapError(format!(
                "failed to run appsvc browse probe {}: {err}",
                probe_path.display()
            ))
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    for line in stdout.lines().chain(stderr.lines()) {
        if let Some(actor_id) = extract_service_identifier_value(line) {
            return Ok(actor_id);
        }
    }

    let mut details = String::new();
    if !stdout.trim().is_empty() {
        details.push_str(stdout.trim());
    }
    if !stderr.trim().is_empty() {
        if !details.is_empty() {
            details.push('\n');
        }
        details.push_str(stderr.trim());
    }
    if details.is_empty() {
        details.push_str("no output captured");
    }

    Err(BootstrapError(format!(
        "failed to resolve actor id from {} browse-appsvc-bundle {} {} within {}s (status: {}): {}",
        probe_path.display(),
        service,
        bundle_id,
        timeout_seconds,
        output.status,
        details
    )))
}

fn spawn_line_reader<R>(reader: R, tx: mpsc::Sender<String>)
where
    R: std::io::Read + Send + 'static,
{
    thread::spawn(move || {
        let reader = BufReader::new(reader);
        for line in reader.lines() {
            match line {
                Ok(line) => {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
}

fn terminate_child(child: &mut std::process::Child) {
    match child.try_wait() {
        Ok(Some(_)) => {}
        Ok(None) => {
            let _ = child.kill();
        }
        Err(_) => {}
    }
}

fn extract_sid_value(text: &str) -> Option<String> {
    let (_, suffix) = text.split_once("sid=")?;
    let candidate: String = suffix
        .chars()
        .take_while(|ch| ch.is_ascii_hexdigit() || *ch == '-')
        .collect();
    looks_like_uuid(&candidate).then(|| candidate.to_ascii_uppercase())
}

fn extract_service_identifier_value(text: &str) -> Option<String> {
    let marker = "\"service_identifier\" => ";
    let (_, suffix) = text.split_once(marker)?;
    let candidate: String = suffix
        .chars()
        .skip_while(|ch| !ch.is_ascii_hexdigit())
        .take_while(|ch| ch.is_ascii_hexdigit() || *ch == '-')
        .collect();
    looks_like_uuid(&candidate).then(|| candidate.to_ascii_uppercase())
}

fn looks_like_uuid(value: &str) -> bool {
    if value.len() != 36 {
        return false;
    }
    for (index, ch) in value.chars().enumerate() {
        let valid = match index {
            8 | 13 | 18 | 23 => ch == '-',
            _ => ch.is_ascii_hexdigit(),
        };
        if !valid {
            return false;
        }
    }
    true
}

fn next_value<'a>(
    iter: &mut impl Iterator<Item = &'a String>,
    flag: &str,
) -> Result<String, BootstrapError> {
    iter.next()
        .cloned()
        .ok_or_else(|| BootstrapError(format!("missing value for {flag}")))
}

fn parse_bool(value: &str) -> Result<bool, BootstrapError> {
    match value {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err(BootstrapError(format!(
            "invalid boolean {value:?}, expected true/false"
        ))),
    }
}

fn bool_word(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn shell_escape(value: &str) -> String {
    if value.is_empty() {
        return "''".into();
    }
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || "-_./:@".contains(ch))
    {
        return value.into();
    }
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn shell_escape_path(path: &Path) -> String {
    shell_escape(&path.display().to_string())
}

fn run_status(program: &str, args: &[&str]) -> Result<(), BootstrapError> {
    let output = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()
        .map_err(|err| BootstrapError(format!("failed to run {program}: {err}")))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut details = stderr.trim().to_string();
    if details.is_empty() {
        details = stdout.trim().to_string();
    }
    if details.is_empty() {
        details = "no output captured".into();
    }
    Err(BootstrapError(format!(
        "{program} exited with status {}: {details}",
        output.status
    )))
}

fn print_help() {
    println!(
        "usage:
  macolinux-uc-bootstrap pairverify-m3 --peer-name NAME --identity PATH [options]
  macolinux-uc-bootstrap companion-stream publish [options]
  macolinux-uc-bootstrap companion-stream connect-b64 --message-b64 B64 [options]

{}

{}",
        pairverify_usage(),
        companion_stream_usage()
    );
}

fn companion_stream_usage() -> String {
    "companion-stream commands:
  publish [options]
      Hold an SFCompanionService open through sharingd and print its message plist.
      By default this temporarily enables com.apple.Sharing AlwaysSendPayload so
      sharingd publishes the _continuity._tcp listener.

  connect-b64 --message-b64 B64 [options]
      Ask sharingd to resolve/open the _continuity._tcp stream described by the
      binary-plist base64 printed by publish.

publish options:
  --manager-id ID          Manager identifier (default: com.apple.CompanionAuthentication)
  --service NAME           Service type (default: com.apple.CompanionAuthentication)
  --seconds N              Hold-open lifetime (default: 60)
  --bonjour-name NAME      Required: active _continuity._tcp instance name
  --reply TEXT             Write TEXT to each accepted stream for smoke testing
  --relay HOST:PORT        Relay each accepted stream to a TCP endpoint
  --always-send-payload BOOL
                           Temporarily set AlwaysSendPayload and restart sharingd
                           (default: true)
  --probe PATH             Override macolinux-companion-service-probe path
  --dry-run                Print resolved options without executing

connect-b64 options:
  --message-b64 B64        Binary plist base64 from publish output
  --seconds N              Connection timeout/lifetime (default: 30)
  --write TEXT             Write TEXT to the opened stream for smoke testing
  --relay HOST:PORT        Relay the opened stream to a TCP endpoint
  --probe PATH             Override macolinux-companion-service-probe path
  --dry-run                Print resolved options without executing"
        .into()
}

fn pairverify_usage() -> String {
    "pairverify-m3 options:
  --peer-name NAME          Bonjour instance name, e.g. endor
  --actor-id UUID           Pairing listener service_id UUID (optional; defaults to TXT sid lookup)
  --identity PATH           Linux identity JSON used for PairVerify M3 signing
  --service-type TYPE       Bonjour service type (default: _appSvcPrePair._tcp)
  --domain DOMAIN           Bonjour domain (default: local.)
  --seconds N               Probe timeout/connection lifetime (default: 22)
  --resolve-timeout-seconds N
                            Bonjour sid lookup timeout for actor-id resolution (default: 8)
  --appsvc-service NAME     Application-service name for explicit-bundle browse fallback
                            (default: com.apple.universalcontrol)
  --appsvc-bundle-id BUNDLE Bundle identifier for explicit-bundle browse fallback
                            (default: com.apple.universalcontrol)
  --no-appsvc-resolve       Disable explicit-bundle application-service fallback
  --appsvc-probe PATH       Override macolinux-network-endpoint-c-probe path
  --actor-name NAME         Distributed actor name (default: RPPairingDistributedActor)
  --transport MODE          Transport passed to the probe (default: tls)
  --interface IFACE         Interface passed to the probe (default: awdl0)
  --create-stream BOOL      PairVerify createEncryptionStream flag (default: true)
  --probe PATH              Override macolinux-network-actor-framer-probe path
  --helper PATH             Override pairverify_actor_helper path
  --dry-run                 Print the generated command without executing it"
        .into()
}

#[derive(Debug)]
struct BootstrapError(String);

impl fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for BootstrapError {}

#[cfg(test)]
mod tests {
    use super::{extract_service_identifier_value, extract_sid_value, looks_like_uuid};

    #[test]
    fn extracts_sid_from_dns_sd_txt_line() {
        let line = r#"18:32:44.123  Add     2  10 local. "at=582dbb113b78" "sid=162B00AD-B278-4D39-B1D0-ED0E69A56D01" "sn=com.apple.universalcontrol""#;
        assert_eq!(
            extract_sid_value(line).as_deref(),
            Some("162B00AD-B278-4D39-B1D0-ED0E69A56D01")
        );
    }

    #[test]
    fn extracts_sid_from_plain_text() {
        assert_eq!(
            extract_sid_value("TXT sid=2e49d8ca-d43e-4efc-ad9d-1264f71e2d56 dnm=bespin").as_deref(),
            Some("2E49D8CA-D43E-4EFC-AD9D-1264F71E2D56")
        );
    }

    #[test]
    fn rejects_non_uuid_sid() {
        assert_eq!(extract_sid_value("sid=not-a-uuid"), None);
        assert!(!looks_like_uuid("not-a-uuid"));
    }

    #[test]
    fn extracts_service_identifier_from_endpoint_dictionary() {
        let line = r#"result.endpoint.dictionary=<dictionary: 0x123> { count = 3, transaction: 0, voucher = 0x0, contents = "service_identifier" => 3042C1AE-A65D-4F4C-82C6-C3A1BBC70393 "application_service_name" => "com.apple.universalcontrol" }"#;
        assert_eq!(
            extract_service_identifier_value(line).as_deref(),
            Some("3042C1AE-A65D-4F4C-82C6-C3A1BBC70393")
        );
    }
}
