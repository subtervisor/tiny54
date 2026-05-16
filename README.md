# tiny54

A small Dynamic DNS client that keeps an AWS Route53 `AAAA` record pointed at the host's current public IPv6 address.

Written in Rust with a deliberately tiny dependency footprint: no AWS SDK, no async runtime, no JSON parser. Just `ureq`, `roxmltree`, `sha2`/`hmac` for SigV4, and `native-tls` for the network bits.

## Features

- **IPv6-only AAAA updates** to Route53, suitable for hosts with rotating prefixes.
- **Two-stage IP detection.** First tries the kernel routing table via a connected UDP socket; falls back to a quorum vote across 11 public IPv6 echo services if that fails. Only globally routable addresses are accepted — loopback, ULA, link-local, Teredo, 6to4, NAT64, documentation, etc. are filtered out.
- **One-shot or daemon mode.** Run it from cron, run it once, or run it forever with `--interval`. Daemon mode handles `SIGTERM`/`SIGINT` cleanly.
- **Cached state.** Skips Route53 calls when the detected IP matches the last value written; re-checks Route53 every 24 hours anyway to catch out-of-band edits.
- **Hand-rolled AWS SigV4** signing — no `aws-sdk-*` crates.
- **Optional SMTP error notifications** with per-error-class cooldown so a long outage doesn't generate a flood of mail. Supports STARTTLS, implicit TLS, or plaintext (loopback only).
- **Logs to stderr or syslog** (`daemon` facility).
- **Small release binary.** `lto = true`, `codegen-units = 1`, `opt-level = "z"`, `strip = true`.

## Build

Requires a recent Rust toolchain with edition 2024 support.

```
cargo build --release
```

The binary lands at `target/release/tiny54`.

## Configure

tiny54 reads an XML config file. Minimum required fields are AWS credentials, the hosted zone ID, the record name, and a TTL:

```xml
<tiny54>
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
```

The IAM principal whose keys you supply needs `route53:ListResourceRecordSets` and `route53:ChangeResourceRecordSets` on the target hosted zone — nothing more.

`.gitignore` excludes `*.xml` at the repo root so live configs don't get committed by accident.

### `<email>` notes

- `<tls>` is one of `starttls`, `implicit`, or `none`. `none` is rejected unless both `smtp_host` resolves to a loopback address and credentials are absent.
- `<cooldown_seconds>` defaults to 86400. Two cooldown keys exist: `ip-quorum` (IP detection failures) and `route53` (API failures).
- `<cooldown_state>` defaults to `/run/tiny54/email-cooldown`. The parent directory must exist and be writable; state is updated atomically via rename.

## Run

```
tiny54 --config /etc/tiny54.xml
```

That's the one-shot form: detect IP, compare to Route53, upsert if different, exit.

For daemon mode, supply `--interval` (or set `<ddns><interval>` in the config):

```
tiny54 --config /etc/tiny54.xml --interval 300 --syslog
```

### Options

| Flag | Description |
| --- | --- |
| `--config PATH` | Path to XML config file (required). |
| `--zone-id ID` | Override `<ddns><zone_id>`. |
| `--name NAME` | Override `<ddns><name>`. |
| `--ttl SECONDS` | Override `<ddns><ttl>`. |
| `--interval SECONDS` | Run forever, re-checking every N seconds. Overrides `<ddns><interval>`; if unset entirely, runs once and exits. |
| `--syslog` | Log to syslog (facility `daemon`) instead of stderr. |
| `-v`, `--verbose` | Verbose `DEBUG` logging on stderr. Ignored under `--syslog`; the syslog daemon's priority filter is authoritative there. |
| `-h`, `--help` | Print help, including the sample config. |

### Exit codes

- `0` — success (one-shot mode) or clean shutdown on signal (daemon mode).
- `1` — runtime failure (config error, IP detection failed, Route53 error).
- `2` — argument parsing error.

## systemd

A minimal unit looks like:

```ini
[Unit]
Description=tiny54 Route53 AAAA updater
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/tiny54 --config /etc/tiny54.xml --interval 300 --syslog
Restart=on-failure
RestartSec=10
DynamicUser=yes
RuntimeDirectory=tiny54

[Install]
WantedBy=multi-user.target
```

`RuntimeDirectory=tiny54` gives you `/run/tiny54/`, which matches the default `<cooldown_state>` path.

## Tests

```
cargo test
```

Covers SigV4 signing against AWS's published test vectors, IPv6 address classification, SMTP path/header validation, cooldown state serialization, and config parsing.

## License

MIT — see [LICENSE](LICENSE).
