use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const DEFAULT_COOLDOWN_SECONDS: u64 = 24 * 60 * 60;
pub const DEFAULT_COOLDOWN_STATE: &str = "/run/tiny54/email-cooldown";

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const IO_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsMode {
    None,
    StartTls,
    Implicit,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub tls: TlsMode,
    pub username: Option<String>,
    pub password: Option<String>,
    pub from: String,
    pub from_name: Option<String>,
    pub to: Vec<String>,
    pub cooldown_seconds: u64,
    pub cooldown_state: PathBuf,
}

#[derive(Debug, Eq, PartialEq)]
pub enum NotifyStatus {
    Sent,
    Suppressed { remaining_seconds: u64 },
}

pub fn notify_with_cooldown(
    cfg: &Config,
    key: &str,
    subject: &str,
    html_body: &str,
) -> Result<NotifyStatus, String> {
    let now = now_secs();
    if cfg.cooldown_seconds > 0 {
        let state = read_state(&cfg.cooldown_state)?;
        if let Some(last_sent) = state.iter().find(|(k, _)| k == key).map(|(_, t)| *t) {
            let elapsed = now.saturating_sub(last_sent);
            if elapsed < cfg.cooldown_seconds {
                return Ok(NotifyStatus::Suppressed {
                    remaining_seconds: cfg.cooldown_seconds - elapsed,
                });
            }
        }
    }

    send(cfg, subject, html_body)?;

    if cfg.cooldown_seconds > 0 {
        let mut state = read_state(&cfg.cooldown_state)?;
        if let Some((_, timestamp)) = state.iter_mut().find(|(k, _)| k == key) {
            *timestamp = now;
        } else {
            state.push((key.to_string(), now));
        }
        write_state(&cfg.cooldown_state, &state)?;
    }

    Ok(NotifyStatus::Sent)
}

pub fn send(cfg: &Config, subject: &str, html_body: &str) -> Result<(), String> {
    if cfg.username.is_some() != cfg.password.is_some() {
        return Err("SMTP username and password must be configured together".into());
    }
    if cfg.tls == TlsMode::None && cfg.username.is_some() {
        return Err("refusing to send SMTP credentials without TLS".into());
    }
    validate_smtp_path("from", &cfg.from)?;
    if let Some(from_name) = &cfg.from_name {
        validate_display_name("from_name", from_name)?;
    }
    for to in &cfg.to {
        validate_smtp_path("to", to)?;
    }

    match cfg.tls {
        TlsMode::Implicit => {
            let tcp = connect_tcp(&cfg.smtp_host, cfg.smtp_port)?;
            let connector = native_tls::TlsConnector::new()
                .map_err(|e| format!("building TLS connector: {e}"))?;
            let tls = connector
                .connect(&cfg.smtp_host, tcp)
                .map_err(|e| {
                    implicit_tls_connect_error(&cfg.smtp_host, cfg.smtp_port, &e.to_string())
                })?;
            let mut session = SmtpSession::new(tls);
            session.expect_greeting()?;
            send_message(&mut session, cfg, subject, html_body)
        }
        TlsMode::StartTls => {
            let tcp = connect_tcp(&cfg.smtp_host, cfg.smtp_port)?;
            let mut session = SmtpSession::new(tcp);
            session.expect_greeting()?;
            session.ehlo()?;
            session.command_expect("STARTTLS", &[220])?;
            let mut session = session.start_tls(&cfg.smtp_host)?;
            session.ehlo()?;
            send_message(&mut session, cfg, subject, html_body)
        }
        TlsMode::None => {
            let tcp = connect_tcp(&cfg.smtp_host, cfg.smtp_port)?;
            let mut session = SmtpSession::new(tcp);
            session.expect_greeting()?;
            session.ehlo()?;
            send_message(&mut session, cfg, subject, html_body)
        }
    }
}

pub fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

fn connect_tcp(host: &str, port: u16) -> Result<TcpStream, String> {
    let mut last_err = None;
    for addr in (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("resolving {host}:{port}: {e}"))?
    {
        match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
            Ok(stream) => {
                stream
                    .set_read_timeout(Some(IO_TIMEOUT))
                    .map_err(|e| format!("setting read timeout: {e}"))?;
                stream
                    .set_write_timeout(Some(IO_TIMEOUT))
                    .map_err(|e| format!("setting write timeout: {e}"))?;
                return Ok(stream);
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(format!(
        "connecting to {host}:{port}: {}",
        last_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "no socket addresses".into())
    ))
}

fn implicit_tls_connect_error(host: &str, port: u16, error: &str) -> String {
    let base = format!("TLS connect: {error}");
    if port == 465 {
        base
    } else {
        format!(
            "{base}; implicit TLS was selected for {host}:{port}, but this port often expects STARTTLS. Use <tls>starttls</tls> for STARTTLS or <tls>implicit</tls> for SMTPS."
        )
    }
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

struct SmtpSession<S: ReadWrite> {
    reader: BufReader<S>,
}

impl<S: ReadWrite> SmtpSession<S> {
    fn new(stream: S) -> Self {
        Self {
            reader: BufReader::new(stream),
        }
    }

    fn expect_greeting(&mut self) -> Result<(), String> {
        self.expect_response("SMTP greeting", &[220]).map(|_| ())
    }

    fn ehlo(&mut self) -> Result<(), String> {
        self.command_expect("EHLO tiny54", &[250]).map(|_| ())
    }

    fn command_expect(&mut self, command: &str, expected: &[u16]) -> Result<String, String> {
        self.write_line(command)?;
        self.expect_response(command, expected)
    }

    fn expect_response(&mut self, context: &str, expected: &[u16]) -> Result<String, String> {
        let (code, text) = self.read_response()?;
        if expected.contains(&code) {
            Ok(text)
        } else {
            Err(format!(
                "{context}: unexpected SMTP status {code}, expected {:?}: {text}",
                expected
            ))
        }
    }

    fn read_response(&mut self) -> Result<(u16, String), String> {
        let mut text = String::new();
        let mut code = None;

        loop {
            let mut line = String::new();
            let n = self
                .reader
                .read_line(&mut line)
                .map_err(|e| format!("reading SMTP response: {e}"))?;
            if n == 0 {
                return Err("SMTP connection closed while reading response".into());
            }
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if trimmed.len() < 3 {
                return Err(format!("malformed SMTP response line: {trimmed:?}"));
            }
            let parsed_code: u16 = trimmed[..3]
                .parse()
                .map_err(|e| format!("malformed SMTP status in {trimmed:?}: {e}"))?;
            if let Some(prev) = code {
                if prev != parsed_code {
                    return Err(format!(
                        "SMTP response status changed from {prev} to {parsed_code}"
                    ));
                }
            } else {
                code = Some(parsed_code);
            }
            if !text.is_empty() {
                text.push('\n');
            }
            text.push_str(trimmed);

            if trimmed.as_bytes().get(3).copied() != Some(b'-') {
                return Ok((parsed_code, text));
            }
        }
    }

    fn write_line(&mut self, line: &str) -> Result<(), String> {
        self.reader
            .get_mut()
            .write_all(line.as_bytes())
            .map_err(|e| format!("writing SMTP command: {e}"))?;
        self.reader
            .get_mut()
            .write_all(b"\r\n")
            .map_err(|e| format!("writing SMTP command terminator: {e}"))?;
        self.reader
            .get_mut()
            .flush()
            .map_err(|e| format!("flushing SMTP command: {e}"))
    }

    fn write_data(&mut self, data: &str) -> Result<(), String> {
        for line in data.split('\n') {
            let line = line.strip_suffix('\r').unwrap_or(line);
            if line.starts_with('.') {
                self.reader
                    .get_mut()
                    .write_all(b".")
                    .map_err(|e| format!("dot-stuffing SMTP body: {e}"))?;
            }
            self.reader
                .get_mut()
                .write_all(line.as_bytes())
                .map_err(|e| format!("writing SMTP body: {e}"))?;
            self.reader
                .get_mut()
                .write_all(b"\r\n")
                .map_err(|e| format!("writing SMTP body newline: {e}"))?;
        }
        self.reader
            .get_mut()
            .write_all(b".\r\n")
            .map_err(|e| format!("writing SMTP body terminator: {e}"))?;
        self.reader
            .get_mut()
            .flush()
            .map_err(|e| format!("flushing SMTP body: {e}"))
    }
}

impl SmtpSession<TcpStream> {
    fn start_tls(self, host: &str) -> Result<SmtpSession<native_tls::TlsStream<TcpStream>>, String> {
        let stream = self.reader.into_inner();
        let connector = native_tls::TlsConnector::new()
            .map_err(|e| format!("building TLS connector: {e}"))?;
        let tls = connector
            .connect(host, stream)
            .map_err(|e| format!("STARTTLS handshake: {e}"))?;
        Ok(SmtpSession::new(tls))
    }
}

fn send_message<S: ReadWrite>(
    session: &mut SmtpSession<S>,
    cfg: &Config,
    subject: &str,
    html_body: &str,
) -> Result<(), String> {
    if let (Some(username), Some(password)) = (&cfg.username, &cfg.password) {
        let mut auth = Vec::with_capacity(username.len() + password.len() + 2);
        auth.push(0);
        auth.extend_from_slice(username.as_bytes());
        auth.push(0);
        auth.extend_from_slice(password.as_bytes());
        session.command_expect(&format!("AUTH PLAIN {}", base64_encode(&auth)), &[235])?;
    }

    session.command_expect(&format!("MAIL FROM:<{}>", cfg.from), &[250])?;
    for to in &cfg.to {
        session.command_expect(&format!("RCPT TO:<{to}>"), &[250, 251])?;
    }
    session.command_expect("DATA", &[354])?;
    let message = build_message(cfg, subject, html_body);
    session.write_data(&message)?;
    session.expect_response("DATA body", &[250])?;
    let _ = session.command_expect("QUIT", &[221]);
    Ok(())
}

fn build_message(cfg: &Config, subject: &str, html_body: &str) -> String {
    let to = cfg
        .to
        .iter()
        .map(|s| sanitize_header(s))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "From: {}\r\nTo: {}\r\nSubject: {}\r\nAuto-Submitted: auto-generated\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n{}",
        format_from_header(cfg),
        to,
        sanitize_header(subject),
        html_body
    )
}

fn format_from_header(cfg: &Config) -> String {
    let addr = sanitize_header(&cfg.from);
    match cfg.from_name.as_deref().filter(|s| !s.is_empty()) {
        Some(name) => format!("{} <{addr}>", encode_display_name(name)),
        None => addr,
    }
}

fn encode_display_name(name: &str) -> String {
    if name.is_ascii() {
        let mut out = String::with_capacity(name.len() + 2);
        out.push('"');
        for ch in name.chars() {
            if ch == '"' || ch == '\\' {
                out.push('\\');
            }
            out.push(ch);
        }
        out.push('"');
        out
    } else {
        format!("=?UTF-8?B?{}?=", base64_encode(name.as_bytes()))
    }
}

fn sanitize_header(s: &str) -> String {
    s.chars().filter(|&c| c != '\r' && c != '\n').collect()
}

fn validate_display_name(label: &str, s: &str) -> Result<(), String> {
    if s.is_empty() || s.chars().any(char::is_control) {
        return Err(format!(
            "SMTP {label} must be non-empty and must not contain control characters"
        ));
    }
    Ok(())
}

fn validate_smtp_path(label: &str, s: &str) -> Result<(), String> {
    if s.is_empty() || s.contains(['\r', '\n', '<', '>']) {
        return Err(format!(
            "SMTP {label} address must be a bare address without CR, LF, '<', or '>'"
        ));
    }
    Ok(())
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn read_state(path: &Path) -> Result<Vec<(String, u64)>, String> {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("reading cooldown state {}: {e}", path.display())),
    };
    let mut out = Vec::new();
    for line in raw.lines() {
        let mut parts = line.splitn(2, ' ');
        let Some(key) = parts.next() else {
            continue;
        };
        let Some(timestamp) = parts.next() else {
            continue;
        };
        let Ok(timestamp) = timestamp.parse() else {
            continue;
        };
        out.push((key.to_string(), timestamp));
    }
    Ok(out)
}

fn write_state(path: &Path, state: &[(String, u64)]) -> Result<(), String> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("creating cooldown state dir {}: {e}", parent.display()))?;
    }

    let mut body = String::new();
    for (key, timestamp) in state {
        body.push_str(key);
        body.push(' ');
        body.push_str(&timestamp.to_string());
        body.push('\n');
    }

    let mut tmp = path.to_path_buf();
    tmp.set_extension(format!("tmp.{}", std::process::id()));
    std::fs::write(&tmp, body)
        .map_err(|e| format!("writing cooldown state {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!(
            "replacing cooldown state {} with {}: {e}",
            path.display(),
            tmp.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_escape_escapes_markup() {
        assert_eq!(
            escape_html("<tag attr=\"a&b\">'x'</tag>"),
            "&lt;tag attr=&quot;a&amp;b&quot;&gt;&#39;x&#39;&lt;/tag&gt;"
        );
    }

    #[test]
    fn base64_encoder_matches_auth_plain_vector() {
        assert_eq!(base64_encode(b"\0user\0pass"), "AHVzZXIAcGFzcw==");
    }

    #[test]
    fn sanitize_header_removes_newlines() {
        assert_eq!(sanitize_header("a\r\nBcc: x"), "aBcc: x");
    }

    #[test]
    fn from_header_uses_optional_display_name() {
        let cfg = Config {
            smtp_host: "smtp.example.com".into(),
            smtp_port: 587,
            tls: TlsMode::StartTls,
            username: None,
            password: None,
            from: "tiny54@example.com".into(),
            from_name: Some("tiny54 DDNS".into()),
            to: vec!["admin@example.com".into()],
            cooldown_seconds: DEFAULT_COOLDOWN_SECONDS,
            cooldown_state: PathBuf::from(DEFAULT_COOLDOWN_STATE),
        };

        let message = build_message(&cfg, "subject", "<p>body</p>");
        assert!(message.starts_with("From: \"tiny54 DDNS\" <tiny54@example.com>\r\n"));
    }

    #[test]
    fn display_name_quotes_ascii_and_encodes_utf8() {
        assert_eq!(encode_display_name("tiny54 \"DDNS\""), "\"tiny54 \\\"DDNS\\\"\"");
        assert_eq!(encode_display_name("tiny54 Δ"), "=?UTF-8?B?dGlueTU0IM6U?=");
    }

    #[test]
    fn smtp_path_rejects_command_metacharacters() {
        assert!(validate_smtp_path("from", "tiny54@example.com").is_ok());
        assert!(validate_smtp_path("from", "Tiny54 <tiny54@example.com>").is_err());
        assert!(validate_smtp_path("to", "a@example.com\r\nRCPT TO:<b@example.com>").is_err());
    }

    #[test]
    fn display_name_rejects_header_injection() {
        assert!(validate_display_name("from_name", "tiny54 DDNS").is_ok());
        assert!(validate_display_name("from_name", "tiny54\r\nBcc: x@example.com").is_err());
    }

    #[test]
    fn implicit_tls_error_on_non_465_port_mentions_starttls() {
        let msg = implicit_tls_connect_error(
            "smtp.example.com",
            587,
            "error:0A00010B:SSL routines:tls_validate_record_header:wrong version number",
        );
        assert!(msg.contains("implicit TLS was selected"));
        assert!(msg.contains("<tls>starttls</tls>"));
    }

    #[test]
    fn cooldown_state_round_trip() {
        let path = std::env::temp_dir().join(format!(
            "tiny54-email-state-{}-{}.txt",
            std::process::id(),
            now_secs()
        ));
        let state = vec![("ip-quorum".to_string(), 123), ("route53".to_string(), 456)];
        write_state(&path, &state).unwrap();
        assert_eq!(read_state(&path).unwrap(), state);
        let _ = std::fs::remove_file(path);
    }
}
