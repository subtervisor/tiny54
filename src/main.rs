mod detect;
mod email;
mod route53;

use std::env;
use std::ffi::{CStr, CString};
use std::net::Ipv6Addr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static SHUTDOWN: AtomicBool = AtomicBool::new(false);
static VERBOSE: AtomicBool = AtomicBool::new(false);
static USE_SYSLOG: AtomicBool = AtomicBool::new(false);

// In daemon mode, force a full Route53 re-check this often even when our local
// cache says nothing has changed — catches drift if the record is edited out of band.
const FULL_RECHECK_SECONDS: u64 = 24 * 60 * 60;

const SAMPLE_CONFIG: &str = r#"<tiny54>
  <aws>
    <aws_access_key_id>AKIA...</aws_access_key_id>
    <aws_secret_access_key>...</aws_secret_access_key>
  </aws>
  <ddns>
    <zone_id>Z123ABC</zone_id>
    <name>host.example.com.</name>
    <ttl>300</ttl>
    <interval>300</interval>
  </ddns>
  <!-- Optional error notifications:
  <email>
    <smtp_host>smtp.example.com</smtp_host>
    <smtp_port>587</smtp_port>
    <tls>starttls</tls>
    <username>tiny54@example.com</username>
    <password>...</password>
    <from>tiny54@example.com</from>
    <from_name>tiny54 DDNS</from_name>
    <to>admin@example.com</to>
    <cooldown_seconds>86400</cooldown_seconds>
    <cooldown_state>/tmp/tiny54-email-cooldown</cooldown_state>
  </email>
  -->
</tiny54>
"#;

struct Args {
    config: PathBuf,
    zone_id: Option<String>,
    name: Option<String>,
    ttl: Option<u32>,
    interval: Option<u64>,
    verbose: bool,
    syslog: bool,
}

struct Config {
    akid: String,
    secret: String,
    zone_id: String,
    name: String,
    ttl: u32,
    interval: Option<u64>,
    email: Option<email::Config>,
}

enum RunError {
    IpQuorum(String),
    Route53(route53::Error),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::IpQuorum(e) => f.write_str(e),
            RunError::Route53(e) => write!(f, "{e}"),
        }
    }
}

fn main() -> ExitCode {
    let args = match parse_args(env::args()) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("argument error: {e}\n");
            print_usage();
            return ExitCode::from(2);
        }
    };

    if args.verbose {
        VERBOSE.store(true, Ordering::SeqCst);
    }
    if args.syslog {
        enable_syslog();
    }

    let cfg = match load_config(&args.config, &args) {
        Ok(c) => c,
        Err(e) => {
            log_error(&format!("config: {e}"));
            return ExitCode::from(1);
        }
    };

    let agent = build_agent();
    let client = route53::Client::new(agent.clone(), cfg.akid.clone(), cfg.secret.clone());

    match cfg.interval {
        None => match run_once(&client, &agent, &cfg, None) {
            Ok(_) => ExitCode::SUCCESS,
            Err(e) => {
                log_error(&e.to_string());
                notify_error(&cfg, &e);
                ExitCode::FAILURE
            }
        },
        Some(interval) => run_daemon(&client, &agent, &cfg, interval),
    }
}

fn run_daemon(
    client: &route53::Client,
    agent: &ureq::Agent,
    cfg: &Config,
    interval: u64,
) -> ExitCode {
    install_signal_handler();
    log_info(&format!("entering daemon mode: interval={interval}s"));

    let mut last_set: Option<Ipv6Addr> = None;
    let mut last_full_check = SystemTime::now();

    while !SHUTDOWN.load(Ordering::SeqCst) {
        let now = SystemTime::now();
        if now
            .duration_since(last_full_check)
            .map(|d| d.as_secs() >= FULL_RECHECK_SECONDS)
            .unwrap_or(false)
        {
            log_debug("forcing periodic full re-check");
            last_set = None;
            last_full_check = now;
        }

        match run_once(client, agent, cfg, last_set) {
            Ok(addr) => last_set = Some(addr),
            Err(e) => {
                log_error(&format!("cycle failed: {e}"));
                notify_error(cfg, &e);
                last_set = None;
            }
        }

        if SHUTDOWN.load(Ordering::SeqCst) {
            break;
        }
        interruptible_sleep(interval);
    }

    log_info("exited cleanly");
    ExitCode::SUCCESS
}

fn run_once(
    client: &route53::Client,
    agent: &ureq::Agent,
    cfg: &Config,
    last_set: Option<Ipv6Addr>,
) -> Result<Ipv6Addr, RunError> {
    let addr = detect::get_public_ipv6(agent).map_err(RunError::IpQuorum)?;

    // Optimization: if the detected address matches the one we last
    // successfully wrote, skip the Route53 read. The 24h forced re-check
    // (above) bounds how stale this view can be when records are edited
    // out of band.
    if last_set == Some(addr) {
        log_debug(&format!("no change since last cycle: {addr}"));
        return Ok(addr);
    }

    let current = client
        .list_aaaa(&cfg.zone_id, &cfg.name)
        .map_err(RunError::Route53)?;
    if current == Some(addr) {
        log_debug(&format!("no change: {} already points at {addr}", cfg.name));
        return Ok(addr);
    }

    let prev = match current {
        Some(a) => a.to_string(),
        None => "(unset)".into(),
    };
    log_info(&format!(
        "updating {} AAAA: {prev} -> {addr} (ttl={})",
        cfg.name, cfg.ttl
    ));
    let change_id = client
        .upsert_aaaa(&cfg.zone_id, &cfg.name, cfg.ttl, addr)
        .map_err(RunError::Route53)?;
    log_info(&format!("submitted change {change_id}"));
    Ok(addr)
}

fn notify_error(cfg: &Config, err: &RunError) {
    let Some(email_cfg) = &cfg.email else {
        return;
    };

    let (key, subject, html) = match err {
        RunError::IpQuorum(e) => (
            "ip-quorum",
            "tiny54: IPv6 detection quorum not reached".to_string(),
            error_email_html(
                "IPv6 detection quorum not reached",
                &format!(
                    "tiny54 could not determine a public IPv6 address for {}.",
                    cfg.name
                ),
                e,
                None,
            ),
        ),
        RunError::Route53(e) => (
            "route53",
            "tiny54: Route53 update failed".to_string(),
            error_email_html(
                "Route53 update failed",
                &format!(
                    "tiny54 could not update {} in hosted zone {}.",
                    cfg.name, cfg.zone_id
                ),
                &e.to_string(),
                e.unparsed_response_body(),
            ),
        ),
    };

    match email::notify_with_cooldown(email_cfg, key, &subject, &html) {
        Ok(email::NotifyStatus::Sent) => log_info(&format!("sent error notification: {subject}")),
        Ok(email::NotifyStatus::Suppressed { remaining_seconds }) => log_debug(&format!(
            "suppressed error notification for {key}; cooldown has {remaining_seconds}s remaining"
        )),
        Err(e) => log_error(&format!("email notification failed: {e}")),
    }
}

fn error_email_html(
    title: &str,
    summary: &str,
    details: &str,
    unparsed_response: Option<&str>,
) -> String {
    let mut html = format!(
        "<!doctype html><html><body><h1>{}</h1><p>{}</p><h2>Details</h2><pre>{}</pre>",
        email::escape_html(title),
        email::escape_html(summary),
        email::escape_html(details)
    );
    if let Some(body) = unparsed_response {
        html.push_str("<h2>Unparsed Route53 Response</h2><pre>");
        html.push_str(&email::escape_html(body));
        html.push_str("</pre>");
    }
    html.push_str("</body></html>");
    html
}

// ============ args ============

fn parse_args(argv: env::Args) -> Result<Args, String> {
    let mut config: Option<PathBuf> = None;
    let mut zone_id: Option<String> = None;
    let mut name: Option<String> = None;
    let mut ttl: Option<u32> = None;
    let mut interval: Option<u64> = None;
    let mut verbose = false;
    let mut syslog = false;

    let mut it = argv.skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--config" => {
                config = Some(PathBuf::from(
                    it.next().ok_or("--config requires a value")?,
                ));
            }
            "--zone-id" => zone_id = Some(it.next().ok_or("--zone-id requires a value")?),
            "--name" => name = Some(it.next().ok_or("--name requires a value")?),
            "--ttl" => {
                let v = it.next().ok_or("--ttl requires a value")?;
                ttl = Some(v.parse().map_err(|e| format!("--ttl: {e}"))?);
            }
            "--interval" => {
                let v = it.next().ok_or("--interval requires a value")?;
                interval = Some(v.parse().map_err(|e| format!("--interval: {e}"))?);
            }
            "-v" | "--verbose" => verbose = true,
            "--syslog" => syslog = true,
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }
    let config = config.ok_or("--config is required")?;
    Ok(Args {
        config,
        zone_id,
        name,
        ttl,
        interval,
        verbose,
        syslog,
    })
}

fn print_usage() {
    eprintln!(
        "Update a Route53 AAAA record with this host's public IPv6.

USAGE: tiny54 --config PATH [OPTIONS]

OPTIONS:
  --config PATH       Path to XML config file (required)
  --zone-id ID        Override <ddns><zone_id>
  --name NAME         Override <ddns><name>
  --ttl SECONDS       Override <ddns><ttl>
  --interval SECONDS  Run forever, re-checking every N seconds
                      (overrides <ddns><interval>; if unset, runs once and exits)
  --syslog            Log to syslog (facility=daemon) instead of stderr
  -v, --verbose       Verbose logging (DEBUG lines on stderr; ignored under --syslog,
                      where the syslog daemon's priority filter is authoritative)
  -h, --help          Show this help

Sample config (XML):

{SAMPLE_CONFIG}"
    );
}

// ============ config ============

fn load_config(path: &Path, args: &Args) -> Result<Config, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("reading {}: {e}", path.display()))?;
    let doc = roxmltree::Document::parse(&raw).map_err(|e| format!("parsing XML: {e}"))?;
    let root = doc.root_element();
    let config = if root.tag_name().name() == "tiny54" {
        root
    } else {
        find_child(root, "tiny54").ok_or("missing <tiny54> root element")?
    };

    let aws = find_child(config, "aws").ok_or("missing <aws> section")?;
    let ddns = find_child(config, "ddns").ok_or("missing <ddns> section")?;

    if child_text(aws, "region").is_some() {
        return Err(
            "<aws><region>: Route53 is global; remove this field (it has no effect)".into(),
        );
    }

    let akid = required_child_text(aws, "aws_access_key_id", "<aws><aws_access_key_id>")?
        .to_string();
    let secret = required_child_text(aws, "aws_secret_access_key", "<aws><aws_secret_access_key>")?
        .to_string();

    let zone_id = args
        .zone_id
        .clone()
        .or_else(|| {
            required_child_text(ddns, "zone_id", "<ddns><zone_id>")
                .ok()
                .map(String::from)
        })
        .ok_or("<ddns><zone_id> required (or --zone-id)")?;

    let mut name = args
        .name
        .clone()
        .or_else(|| {
            required_child_text(ddns, "name", "<ddns><name>")
                .ok()
                .map(String::from)
        })
        .ok_or("<ddns><name> required (or --name)")?;
    if !name.ends_with('.') {
        name.push('.');
    }

    let ttl = args
        .ttl
        .map(Ok)
        .or_else(|| child_text(ddns, "ttl").map(parse_u32))
        .ok_or("<ddns><ttl> required and must be a non-negative integer (or --ttl)")??;

    let interval = args
        .interval
        .map(Ok)
        .or_else(|| child_text(ddns, "interval").map(parse_u64))
        .transpose()?;
    if let Some(i) = interval
        && i < 1
    {
        return Err("interval must be >= 1 second".into());
    }

    let email = find_child(config, "email")
        .map(parse_email_config)
        .transpose()?;

    Ok(Config {
        akid,
        secret,
        zone_id,
        name,
        ttl,
        interval,
        email,
    })
}

fn parse_email_config(node: roxmltree::Node<'_, '_>) -> Result<email::Config, String> {
    let smtp_host = required_child_text(node, "smtp_host", "<email><smtp_host>")?.to_string();
    let tls = match child_text(node, "tls")
        .unwrap_or("starttls")
        .to_ascii_lowercase()
        .as_str()
    {
        "starttls" => email::TlsMode::StartTls,
        "implicit" | "smtps" => email::TlsMode::Implicit,
        "none" | "plain" => email::TlsMode::None,
        "tls" => {
            return Err(
                "<email><tls> value \"tls\" is ambiguous; use \"starttls\" for SMTP STARTTLS or \"implicit\"/\"smtps\" for SMTPS".into(),
            );
        }
        other => {
            return Err(format!(
                "<email><tls> must be starttls, implicit/smtps, or none; got {other:?}"
            ));
        }
    };
    let smtp_port = child_text(node, "smtp_port")
        .map(parse_u16)
        .transpose()?
        .unwrap_or(match tls {
            email::TlsMode::Implicit => 465,
            email::TlsMode::StartTls | email::TlsMode::None => 587,
        });
    let username = child_text(node, "username")
        .filter(|s| !s.is_empty())
        .map(String::from);
    let password = child_text(node, "password")
        .filter(|s| !s.is_empty())
        .map(String::from);
    if username.is_some() != password.is_some() {
        return Err("<email><username> and <email><password> must be configured together".into());
    }
    let from = required_child_text(node, "from", "<email><from>")?.to_string();
    let from_name = child_text(node, "from_name")
        .filter(|s| !s.is_empty())
        .map(String::from);
    let to = children_text(node, "to")
        .into_iter()
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect::<Vec<_>>();
    if to.is_empty() {
        return Err("<email><to> required".into());
    }
    let cooldown_seconds = child_text(node, "cooldown_seconds")
        .map(parse_u64)
        .transpose()?
        .unwrap_or(email::DEFAULT_COOLDOWN_SECONDS);
    let cooldown_state = child_text(node, "cooldown_state")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(email::DEFAULT_COOLDOWN_STATE));

    Ok(email::Config {
        smtp_host,
        smtp_port,
        tls,
        username,
        password,
        from,
        from_name,
        to,
        cooldown_seconds,
        cooldown_state,
    })
}

fn find_child<'a, 'b>(
    node: roxmltree::Node<'a, 'b>,
    tag: &str,
) -> Option<roxmltree::Node<'a, 'b>> {
    node.children()
        .find(|n| n.is_element() && n.tag_name().name() == tag)
}

fn child_text<'a, 'b>(node: roxmltree::Node<'a, 'b>, tag: &str) -> Option<&'a str> {
    find_child(node, tag).and_then(|n| n.text()).map(str::trim)
}

fn children_text<'a, 'b>(node: roxmltree::Node<'a, 'b>, tag: &str) -> Vec<&'a str> {
    node.children()
        .filter(|n| n.is_element() && n.tag_name().name() == tag)
        .filter_map(|n| n.text())
        .map(str::trim)
        .collect()
}

fn required_child_text<'a, 'b>(
    node: roxmltree::Node<'a, 'b>,
    tag: &str,
    label: &str,
) -> Result<&'a str, String> {
    child_text(node, tag)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("{label} required"))
}

fn parse_u32(s: &str) -> Result<u32, String> {
    s.parse()
        .map_err(|e| format!("invalid non-negative integer {s:?}: {e}"))
}

fn parse_u16(s: &str) -> Result<u16, String> {
    s.parse()
        .map_err(|e| format!("invalid non-negative integer {s:?}: {e}"))
}

fn parse_u64(s: &str) -> Result<u64, String> {
    s.parse()
        .map_err(|e| format!("invalid non-negative integer {s:?}: {e}"))
}

// ============ ureq agent ============

fn build_agent() -> ureq::Agent {
    let tls = ureq::tls::TlsConfig::builder()
        .provider(ureq::tls::TlsProvider::NativeTls)
        .root_certs(ureq::tls::RootCerts::PlatformVerifier)
        .build();
    let config = ureq::Agent::config_builder()
        .tls_config(tls)
        .timeout_global(Some(Duration::from_secs(15)))
        .timeout_connect(Some(Duration::from_secs(10)))
        .http_status_as_error(false)
        .user_agent("tiny54/0.1")
        .build();
    config.into()
}

// ============ signals ============

extern "C" fn handle_signal(_sig: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

fn install_signal_handler() {
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handle_signal as *const () as libc::sighandler_t;
        libc::sigemptyset(&mut action.sa_mask);
        // SA_RESTART not set → blocking syscalls (nanosleep) return EINTR
        // when a signal is delivered, so the daemon loop wakes promptly.
        action.sa_flags = 0;
        libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut());
        libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut());
    }
}

fn interruptible_sleep(secs: u64) {
    let clamped = secs.min(i64::MAX as u64);
    let req = libc::timespec {
        tv_sec: clamped as libc::time_t,
        tv_nsec: 0,
    };
    // SAFETY: req points to valid memory; null remainder pointer is allowed.
    // Signal during sleep → returns -1/EINTR, which we ignore: the next
    // SHUTDOWN check in the loop will catch it.
    unsafe {
        libc::nanosleep(&req, std::ptr::null_mut());
    }
}

// ============ logging ============

pub fn log_info(msg: &str) {
    if USE_SYSLOG.load(Ordering::Relaxed) {
        syslog_emit(libc::LOG_INFO, msg);
    } else {
        eprintln!("{} INFO  {msg}", timestamp());
    }
}

pub fn log_debug(msg: &str) {
    if USE_SYSLOG.load(Ordering::Relaxed) {
        // Under syslog the daemon decides what gets stored based on priority;
        // we always send DEBUG events and let the user's syslog config filter.
        syslog_emit(libc::LOG_DEBUG, msg);
    } else if VERBOSE.load(Ordering::Relaxed) {
        eprintln!("{} DEBUG {msg}", timestamp());
    }
}

pub fn log_error(msg: &str) {
    if USE_SYSLOG.load(Ordering::Relaxed) {
        syslog_emit(libc::LOG_ERR, msg);
    } else {
        eprintln!("{} ERROR {msg}", timestamp());
    }
}

fn enable_syslog() {
    // openlog stores the ident pointer; the man page is explicit that the
    // pointed-to string must remain valid for the lifetime of subsequent
    // syslog() calls, hence the 'static literal.
    static IDENT: &CStr = c"tiny54";
    // SAFETY: IDENT outlives the program. LOG_NDELAY opens the /dev/log
    // socket immediately so subsequent syslog() calls can't fail on first use.
    unsafe {
        libc::openlog(
            IDENT.as_ptr(),
            libc::LOG_PID | libc::LOG_NDELAY,
            libc::LOG_DAEMON,
        );
    }
    USE_SYSLOG.store(true, Ordering::SeqCst);
}

fn syslog_emit(priority: libc::c_int, msg: &str) {
    // Use "%s" as the format and pass the message as a separate argument so
    // any '%' characters in user data aren't interpreted as format directives.
    static FMT: &CStr = c"%s";
    // CString::new rejects interior NULs; strip them defensively (logs aren't
    // expected to contain them, but error messages might include arbitrary
    // bytes from response snippets).
    let cleaned: Vec<u8> = msg.bytes().filter(|&b| b != 0).collect();
    let Ok(c) = CString::new(cleaned) else {
        return;
    };
    // SAFETY: FMT and c are valid CStr/CString for the duration of the call.
    // libc::syslog is variadic and matches "%s" → const char*.
    unsafe {
        libc::syslog(priority, FMT.as_ptr(), c.as_ptr());
    }
}

fn timestamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (y, m, d, hh, mm, ss) = route53::unix_to_utc(secs);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_args(path: PathBuf) -> Args {
        Args {
            config: path,
            zone_id: None,
            name: None,
            ttl: None,
            interval: None,
            verbose: false,
            syslog: false,
        }
    }

    #[test]
    fn load_xml_config() {
        let path = std::env::temp_dir().join(format!(
            "tiny54-config-{}-{}.xml",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(
            &path,
            r#"<tiny54>
  <aws>
    <aws_access_key_id>AKID</aws_access_key_id>
    <aws_secret_access_key>secret</aws_secret_access_key>
  </aws>
  <ddns>
    <zone_id>Z123</zone_id>
    <name>host.example.com</name>
    <ttl>300</ttl>
    <interval>60</interval>
  </ddns>
</tiny54>"#,
        )
        .unwrap();

        let cfg = load_config(&path, &default_args(path.clone())).unwrap();
        assert_eq!(cfg.akid, "AKID");
        assert_eq!(cfg.secret, "secret");
        assert_eq!(cfg.zone_id, "Z123");
        assert_eq!(cfg.name, "host.example.com.");
        assert_eq!(cfg.ttl, 300);
        assert_eq!(cfg.interval, Some(60));
        assert!(cfg.email.is_none());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_xml_config_cli_overrides_ddns() {
        let path = std::env::temp_dir().join(format!(
            "tiny54-config-override-{}-{}.xml",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(
            &path,
            r#"<tiny54>
  <aws>
    <aws_access_key_id>AKID</aws_access_key_id>
    <aws_secret_access_key>secret</aws_secret_access_key>
  </aws>
  <ddns>
    <zone_id>Z123</zone_id>
    <name>host.example.com.</name>
    <ttl>300</ttl>
  </ddns>
</tiny54>"#,
        )
        .unwrap();

        let mut args = default_args(path.clone());
        args.zone_id = Some("Z999".into());
        args.name = Some("override.example.com".into());
        args.ttl = Some(120);
        args.interval = Some(30);

        let cfg = load_config(&path, &args).unwrap();
        assert_eq!(cfg.zone_id, "Z999");
        assert_eq!(cfg.name, "override.example.com.");
        assert_eq!(cfg.ttl, 120);
        assert_eq!(cfg.interval, Some(30));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_xml_email_config() {
        let path = std::env::temp_dir().join(format!(
            "tiny54-config-email-{}-{}.xml",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(
            &path,
            r#"<tiny54>
  <aws>
    <aws_access_key_id>AKID</aws_access_key_id>
    <aws_secret_access_key>secret</aws_secret_access_key>
  </aws>
  <ddns>
    <zone_id>Z123</zone_id>
    <name>host.example.com.</name>
    <ttl>300</ttl>
  </ddns>
  <email>
    <smtp_host>smtp.example.com</smtp_host>
    <smtp_port>465</smtp_port>
    <tls>implicit</tls>
    <username>user</username>
    <password>pass</password>
    <from>tiny54@example.com</from>
    <from_name>tiny54 DDNS</from_name>
    <to>admin1@example.com</to>
    <to>admin2@example.com</to>
    <cooldown_seconds>120</cooldown_seconds>
    <cooldown_state>/tmp/tiny54-test-email-state</cooldown_state>
  </email>
</tiny54>"#,
        )
        .unwrap();

        let cfg = load_config(&path, &default_args(path.clone())).unwrap();
        let email_cfg = cfg.email.unwrap();
        assert_eq!(email_cfg.smtp_host, "smtp.example.com");
        assert_eq!(email_cfg.smtp_port, 465);
        assert_eq!(email_cfg.tls, email::TlsMode::Implicit);
        assert_eq!(email_cfg.username.as_deref(), Some("user"));
        assert_eq!(email_cfg.password.as_deref(), Some("pass"));
        assert_eq!(email_cfg.from, "tiny54@example.com");
        assert_eq!(email_cfg.from_name.as_deref(), Some("tiny54 DDNS"));
        assert_eq!(
            email_cfg.to,
            vec![
                "admin1@example.com".to_string(),
                "admin2@example.com".to_string()
            ]
        );
        assert_eq!(email_cfg.cooldown_seconds, 120);
        assert_eq!(
            email_cfg.cooldown_state,
            PathBuf::from("/tmp/tiny54-test-email-state")
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_xml_email_rejects_ambiguous_tls_value() {
        let path = std::env::temp_dir().join(format!(
            "tiny54-config-email-tls-{}-{}.xml",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(
            &path,
            r#"<tiny54>
  <aws>
    <aws_access_key_id>AKID</aws_access_key_id>
    <aws_secret_access_key>secret</aws_secret_access_key>
  </aws>
  <ddns>
    <zone_id>Z123</zone_id>
    <name>host.example.com.</name>
    <ttl>300</ttl>
  </ddns>
  <email>
    <smtp_host>smtp.example.com</smtp_host>
    <smtp_port>587</smtp_port>
    <tls>tls</tls>
    <from>tiny54@example.com</from>
    <to>admin@example.com</to>
  </email>
</tiny54>"#,
        )
        .unwrap();

        let err = match load_config(&path, &default_args(path.clone())) {
            Ok(_) => panic!("ambiguous <tls> value should be rejected"),
            Err(e) => e,
        };
        assert!(err.contains("ambiguous"));
        assert!(err.contains("starttls"));

        let _ = std::fs::remove_file(path);
    }
}
