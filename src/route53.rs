use std::net::Ipv6Addr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

const HOST: &str = "route53.amazonaws.com";
const REGION: &str = "us-east-1";
const SERVICE: &str = "route53";
const API_VERSION: &str = "2013-04-01";
const XMLNS: &str = "https://route53.amazonaws.com/doc/2013-04-01/";
const ROUTE53_BODY_LIMIT: u64 = 64 * 1024;

pub struct Client {
    agent: ureq::Agent,
    akid: String,
    secret: String,
}

#[derive(Debug)]
pub struct Error {
    message: String,
    unparsed_response_body: Option<String>,
}

impl Error {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            unparsed_response_body: None,
        }
    }

    fn with_unparsed_response(message: impl Into<String>, body: &str) -> Self {
        Self {
            message: message.into(),
            unparsed_response_body: Some(body.to_string()),
        }
    }

    fn prefixed(mut self, prefix: impl AsRef<str>) -> Self {
        self.message = format!("{}: {}", prefix.as_ref(), self.message);
        self
    }

    pub fn unparsed_response_body(&self) -> Option<&str> {
        self.unparsed_response_body.as_deref()
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl Client {
    pub fn new(agent: ureq::Agent, akid: String, secret: String) -> Self {
        Self { agent, akid, secret }
    }

    pub fn list_aaaa(&self, zone: &str, name: &str) -> Result<Option<Ipv6Addr>, Error> {
        let path = format!("/{API_VERSION}/hostedzone/{zone}/rrset");
        // SigV4: canonical query string must be sorted by ASCII order on the
        // encoded parameter name. AWS rebuilds the canonical form from the
        // received URL, so we send the already-sorted form here.
        let query = canonical_query(&[
            ("maxitems", "1"),
            ("name", name),
            ("type", "AAAA"),
        ]);
        let url = format!("https://{HOST}{path}?{query}");

        retry("list_aaaa", || {
            let now = SystemTime::now();
            let signed = sign_v4("GET", &path, &query, b"", &self.akid, &self.secret, now);
            crate::log_debug(&format!(
                "SigV4 canonical request:\n{}",
                signed.canonical_request
            ));
            let mut req = self.agent.get(&url);
            for (k, v) in &signed.headers {
                req = req.header(k.as_str(), v.as_str());
            }
            let resp = match req.call() {
                Ok(r) => r,
                Err(e) => return classify_ureq_error(e),
            };
            let status = resp.status().as_u16();
            let body = match resp
                .into_body()
                .into_with_config()
                .limit(ROUTE53_BODY_LIMIT)
                .read_to_string()
            {
                Ok(b) => b,
                Err(e) => {
                    return Retry::Transient(Error::new(format!(
                        "reading body (limit {ROUTE53_BODY_LIMIT} bytes): {e}"
                    )));
                }
            };
            if status >= 500 || status == 429 {
                return Retry::Transient(http_error_message(
                    status,
                    &body,
                    &signed.canonical_request,
                ));
            }
            if status >= 400 {
                return Retry::Permanent(http_error_message(
                    status,
                    &body,
                    &signed.canonical_request,
                ));
            }
            match parse_list_response(&body, name) {
                Ok(addr) => Retry::Ok(addr),
                Err(e) => Retry::Permanent(Error::with_unparsed_response(
                    format!(
                        "parsing list response: {e}\n--- response body ---\n{}\n---",
                        snippet(&body, 800)
                    ),
                    &body,
                )),
            }
        })
    }

    pub fn upsert_aaaa(
        &self,
        zone: &str,
        name: &str,
        ttl: u32,
        addr: Ipv6Addr,
    ) -> Result<String, Error> {
        let path = format!("/{API_VERSION}/hostedzone/{zone}/rrset");
        let url = format!("https://{HOST}{path}");
        let body = build_change_xml(name, ttl, addr);

        retry("upsert_aaaa", || {
            let now = SystemTime::now();
            let signed =
                sign_v4("POST", &path, "", body.as_bytes(), &self.akid, &self.secret, now);
            crate::log_debug(&format!(
                "SigV4 canonical request:\n{}",
                signed.canonical_request
            ));
            let mut req = self
                .agent
                .post(&url)
                .header("content-type", "application/xml");
            for (k, v) in &signed.headers {
                req = req.header(k.as_str(), v.as_str());
            }
            let resp = match req.send(body.as_bytes()) {
                Ok(r) => r,
                Err(e) => return classify_ureq_error(e),
            };
            let status = resp.status().as_u16();
            let resp_body = match resp
                .into_body()
                .into_with_config()
                .limit(ROUTE53_BODY_LIMIT)
                .read_to_string()
            {
                Ok(b) => b,
                Err(e) => {
                    return Retry::Transient(Error::new(format!(
                        "reading body (limit {ROUTE53_BODY_LIMIT} bytes): {e}"
                    )));
                }
            };
            if status >= 500 || status == 429 {
                return Retry::Transient(http_error_message(
                    status,
                    &resp_body,
                    &signed.canonical_request,
                ));
            }
            if status >= 400 {
                return Retry::Permanent(http_error_message(
                    status,
                    &resp_body,
                    &signed.canonical_request,
                ));
            }
            match parse_change_response(&resp_body) {
                Ok(id) => Retry::Ok(id),
                Err(e) => Retry::Permanent(Error::with_unparsed_response(
                    format!(
                        "parsing change response: {e}\n--- response body ---\n{}\n---",
                        snippet(&resp_body, 800)
                    ),
                    &resp_body,
                )),
            }
        })
    }
}

fn http_error_message(status: u16, body: &str, canonical_request: &str) -> Error {
    let summary = match parse_error_summary(body) {
        Ok(summary) => summary,
        Err(e) => {
            return Error::with_unparsed_response(
                format!("HTTP {status}: could not parse Route53 error response: {e}"),
                body,
            );
        }
    };
    // SignatureDoesNotMatch can't be diagnosed without seeing OUR canonical
    // request — Route53 doesn't echo back its computed canonical form like
    // some other AWS services do. Include it inline so the failure is
    // actionable from a single log line.
    if summary.contains("SignatureDoesNotMatch") {
        Error::new(format!(
            "HTTP {status}: {summary}\n--- our canonical request ---\n{canonical_request}\n--- end ---"
        ))
    } else {
        Error::new(format!("HTTP {status}: {summary}"))
    }
}

// ============ retry ============

enum Retry<T> {
    Ok(T),
    Transient(Error),
    Permanent(Error),
}

const RETRY_ATTEMPTS: u32 = 3;
const RETRY_DELAYS_SECS: [u64; 2] = [1, 3];

fn retry<T, F>(label: &str, mut f: F) -> Result<T, Error>
where
    F: FnMut() -> Retry<T>,
{
    let mut last_err: Option<Error> = None;
    for attempt in 0..RETRY_ATTEMPTS {
        if attempt > 0 {
            let delay = RETRY_DELAYS_SECS[(attempt as usize) - 1];
            let err = last_err
                .as_ref()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "unknown error".into());
            crate::log_debug(&format!(
                "{label}: attempt {attempt} failed ({err}); retrying in {delay}s"
            ));
            std::thread::sleep(Duration::from_secs(delay));
        }
        match f() {
            Retry::Ok(v) => return Ok(v),
            Retry::Transient(e) => last_err = Some(e),
            Retry::Permanent(e) => return Err(e.prefixed(label)),
        }
    }
    Err(last_err
        .unwrap_or_else(|| Error::new("unknown error"))
        .prefixed(format!("{label}: failed after {RETRY_ATTEMPTS} attempts")))
}

fn classify_ureq_error<T>(e: ureq::Error) -> Retry<T> {
    // With http_status_as_error(false) we don't get StatusCode errors here;
    // all remaining ureq errors are transport-related (TCP, TLS, DNS, timeout).
    // Treat them all as transient — worst case a truly-permanent error wastes
    // ~4 seconds retrying before bubbling up, which we'll happily eat for the
    // safety of retrying every transient failure.
    Retry::Transient(Error::new(format!("transport: {e}")))
}

// ============ XML ============

fn build_change_xml(name: &str, ttl: u32, addr: Ipv6Addr) -> String {
    // All interpolated values are tightly controlled (DNS-name chars, digits,
    // canonical IPv6) and contain no XML metacharacters, so no escaping needed.
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<ChangeResourceRecordSetsRequest xmlns="{XMLNS}"><ChangeBatch><Comment>tiny54 update</Comment><Changes><Change><Action>UPSERT</Action><ResourceRecordSet><Name>{name}</Name><Type>AAAA</Type><TTL>{ttl}</TTL><ResourceRecords><ResourceRecord><Value>{addr}</Value></ResourceRecord></ResourceRecords></ResourceRecordSet></Change></Changes></ChangeBatch></ChangeResourceRecordSetsRequest>"#
    )
}

fn parse_list_response(xml: &str, want_name: &str) -> Result<Option<Ipv6Addr>, String> {
    let doc = roxmltree::Document::parse(xml).map_err(|e| format!("XML parse: {e}"))?;
    let root = doc.root_element();

    let Some(sets) = find_child(root, "ResourceRecordSets") else {
        return Ok(None);
    };
    let Some(rec) = find_child(sets, "ResourceRecordSet") else {
        return Ok(None);
    };

    let name = child_text(rec, "Name").unwrap_or("");
    let typ = child_text(rec, "Type").unwrap_or("");
    if !name.eq_ignore_ascii_case(want_name) || typ != "AAAA" {
        return Ok(None);
    }

    let Some(rrs) = find_child(rec, "ResourceRecords") else {
        return Ok(None);
    };
    let Some(rr) = find_child(rrs, "ResourceRecord") else {
        return Ok(None);
    };
    let Some(value) = child_text(rr, "Value") else {
        return Ok(None);
    };
    let addr: Ipv6Addr = value
        .trim()
        .parse()
        .map_err(|e| format!("Value '{value}' is not a valid IPv6 address: {e}"))?;
    Ok(Some(addr))
}

fn parse_change_response(xml: &str) -> Result<String, String> {
    let doc = roxmltree::Document::parse(xml).map_err(|e| format!("XML parse: {e}"))?;
    let root = doc.root_element();
    let info = find_descendant(root, "ChangeInfo")
        .ok_or("response missing <ChangeInfo>")?;
    let id = child_text(info, "Id")
        .ok_or("response <ChangeInfo> missing <Id>")?;
    Ok(id.to_string())
}

fn parse_error_summary(xml: &str) -> Result<String, String> {
    let doc = roxmltree::Document::parse(xml).map_err(|e| format!("XML parse: {e}"))?;
    let root = doc.root_element();
    let Some(err) = find_descendant(root, "Error") else {
        return Err("missing <Error> element".into());
    };
    let code = child_text(err, "Code").unwrap_or("?");
    let message = child_text(err, "Message").unwrap_or("?");
    let req_id = find_descendant(root, "RequestId")
        .and_then(|n| n.text())
        .map(|s| format!(" [RequestId: {s}]"))
        .unwrap_or_default();
    Ok(format!("{code}: {message}{req_id}"))
}

fn find_child<'a, 'b>(
    node: roxmltree::Node<'a, 'b>,
    tag: &str,
) -> Option<roxmltree::Node<'a, 'b>> {
    node.children()
        .find(|n| n.is_element() && n.tag_name().name() == tag)
}

fn find_descendant<'a, 'b>(
    node: roxmltree::Node<'a, 'b>,
    tag: &str,
) -> Option<roxmltree::Node<'a, 'b>> {
    node.descendants()
        .find(|n| n.is_element() && n.tag_name().name() == tag)
}

fn child_text<'a, 'b>(node: roxmltree::Node<'a, 'b>, tag: &str) -> Option<&'a str> {
    find_child(node, tag).and_then(|n| n.text())
}

fn snippet(s: &str, max: usize) -> String {
    let trimmed = s.trim();
    if trimmed.len() <= max {
        trimmed.to_string()
    } else {
        let mut end = max;
        while end > 0 && !trimmed.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &trimmed[..end])
    }
}

// ============ SigV4 ============

type HmacSha256 = Hmac<Sha256>;

struct SigV4 {
    headers: Vec<(String, String)>,
    canonical_request: String,
}

fn sign_v4(
    method: &str,
    path: &str,
    query: &str,
    body: &[u8],
    akid: &str,
    secret: &str,
    now: SystemTime,
) -> SigV4 {
    let (amz_date, date) = format_amz_date(now);
    let payload_hash = sha256_hex(body);

    let canonical_headers = format!(
        "host:{HOST}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n"
    );
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";

    let canonical_request =
        format!("{method}\n{path}\n{query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}");

    let scope = format!("{date}/{REGION}/{SERVICE}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );

    let k_secret = format!("AWS4{secret}");
    let k_date = hmac_sha256(k_secret.as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, REGION.as_bytes());
    let k_service = hmac_sha256(&k_region, SERVICE.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let signature = hex_lower(&hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={akid}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
    );

    SigV4 {
        headers: vec![
            ("host".into(), HOST.to_string()),
            ("x-amz-content-sha256".into(), payload_hash),
            ("x-amz-date".into(), amz_date),
            ("authorization".into(), auth),
        ],
        canonical_request,
    }
}

fn canonical_query(params: &[(&str, &str)]) -> String {
    let mut encoded: Vec<(String, String)> = params
        .iter()
        .map(|(k, v)| (uri_encode(k, true), uri_encode(v, true)))
        .collect();
    encoded.sort();
    encoded
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    let out = mac.finalize().into_bytes();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out);
    buf
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex_lower(&h.finalize())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(*b >> 4) as usize] as char);
        out.push(HEX[(*b & 0xf) as usize] as char);
    }
    out
}

fn uri_encode(s: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b'/' if !encode_slash => out.push('/'),
            _ => {
                out.push('%');
                out.push(hex_upper_nibble(b >> 4));
                out.push(hex_upper_nibble(b & 0xf));
            }
        }
    }
    out
}

fn hex_upper_nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'A' + (n - 10)) as char,
        _ => unreachable!(),
    }
}

fn format_amz_date(now: SystemTime) -> (String, String) {
    let secs = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let (y, m, d, hh, mm, ss) = unix_to_utc(secs);
    (
        format!("{y:04}{m:02}{d:02}T{hh:02}{mm:02}{ss:02}Z"),
        format!("{y:04}{m:02}{d:02}"),
    )
}

// Convert unix seconds → (year, month, day, hour, minute, second) UTC.
// Howard Hinnant's civil_from_days algorithm.
pub fn unix_to_utc(secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    let days = (secs / 86400) as i64;
    let s = secs % 86400;
    let hh = (s / 3600) as u32;
    let mm = ((s % 3600) / 60) as u32;
    let ss = (s % 60) as u32;

    let z = days + 719_468;
    let era = if z >= 0 {
        z / 146097
    } else {
        (z - 146096) / 146097
    };
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y_base = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = (y_base + if m <= 2 { 1 } else { 0 }) as u32;
    (y, m, d, hh, mm, ss)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_epoch() {
        assert_eq!(unix_to_utc(0), (1970, 1, 1, 0, 0, 0));
    }

    #[test]
    fn fixed_date() {
        // 2024-01-15 12:34:56 UTC = 1705322096
        assert_eq!(unix_to_utc(1_705_322_096), (2024, 1, 15, 12, 34, 56));
    }

    #[test]
    fn leap_day() {
        // 2024-02-29 00:00:00 UTC = 1709164800
        assert_eq!(unix_to_utc(1_709_164_800), (2024, 2, 29, 0, 0, 0));
    }

    #[test]
    fn aws_example_sigv4() {
        // From AWS SigV4 test vectors (get-vanilla):
        // AccessKey: AKIDEXAMPLE, Secret: wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY
        // expected signing key for 20150830 us-east-1 iam:
        let date = "20150830";
        let region = "us-east-1";
        let service = "iam";
        let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

        let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes());
        let k_region = hmac_sha256(&k_date, region.as_bytes());
        let k_service = hmac_sha256(&k_region, service.as_bytes());
        let k_signing = hmac_sha256(&k_service, b"aws4_request");
        assert_eq!(
            hex_lower(&k_signing),
            "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
        );
    }

    #[test]
    fn uri_encoding() {
        assert_eq!(uri_encode("host.example.com.", true), "host.example.com.");
        assert_eq!(uri_encode("a/b c", false), "a/b%20c");
        assert_eq!(uri_encode("a/b c", true), "a%2Fb%20c");
    }

    #[test]
    fn canonical_query_sorts_by_key() {
        // Unsorted input → sorted output, per SigV4 spec.
        let q = canonical_query(&[("type", "AAAA"), ("name", "h.ex.com."), ("maxitems", "1")]);
        assert_eq!(q, "maxitems=1&name=h.ex.com.&type=AAAA");
    }

    #[test]
    fn canonical_query_url_encodes_values() {
        let q = canonical_query(&[("k", "a b"), ("k2", "a/b")]);
        assert_eq!(q, "k=a%20b&k2=a%2Fb");
    }

    #[test]
    fn list_aaaa_canonical_request_shape() {
        // Regression test for the SigV4 query-sort bug. Reconstructs the exact
        // canonical request list_aaaa would sign for a fixed time and inputs,
        // and asserts each line position is right (incl. sorted query at line 2).
        use std::time::{Duration, UNIX_EPOCH};
        let now = UNIX_EPOCH + Duration::from_secs(1_640_995_200); // 2022-01-01T00:00:00Z
        let path = format!("/{}/hostedzone/Z123ABC/rrset", super::API_VERSION);
        let query =
            canonical_query(&[("maxitems", "1"), ("name", "host.example.com."), ("type", "AAAA")]);
        let signed = sign_v4("GET", &path, &query, b"", "AKID", "secret", now);
        let cr: Vec<&str> = signed.canonical_request.split('\n').collect();
        assert_eq!(cr[0], "GET");
        assert_eq!(cr[1], "/2013-04-01/hostedzone/Z123ABC/rrset");
        assert_eq!(cr[2], "maxitems=1&name=host.example.com.&type=AAAA");
        assert_eq!(cr[3], "host:route53.amazonaws.com");
        assert_eq!(
            cr[4],
            "x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(cr[5], "x-amz-date:20220101T000000Z");
        assert_eq!(cr[6], "");
        assert_eq!(cr[7], "host;x-amz-content-sha256;x-amz-date");
        assert_eq!(
            cr[8],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn parse_change_response_basic() {
        let xml = r#"<?xml version="1.0"?>
<ChangeResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <ChangeInfo>
    <Id>/change/C123ABC</Id>
    <Status>PENDING</Status>
  </ChangeInfo>
</ChangeResourceRecordSetsResponse>"#;
        assert_eq!(parse_change_response(xml).unwrap(), "/change/C123ABC");
    }

    #[test]
    fn parse_list_response_matches() {
        let xml = r#"<?xml version="1.0"?>
<ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <ResourceRecordSets>
    <ResourceRecordSet>
      <Name>host.example.com.</Name>
      <Type>AAAA</Type>
      <TTL>300</TTL>
      <ResourceRecords>
        <ResourceRecord><Value>2001:db8::1</Value></ResourceRecord>
      </ResourceRecords>
    </ResourceRecordSet>
  </ResourceRecordSets>
</ListResourceRecordSetsResponse>"#;
        let got = parse_list_response(xml, "host.example.com.").unwrap();
        assert_eq!(got, Some("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn parse_list_response_name_mismatch() {
        let xml = r#"<?xml version="1.0"?>
<ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <ResourceRecordSets>
    <ResourceRecordSet>
      <Name>other.example.com.</Name>
      <Type>AAAA</Type>
      <ResourceRecords><ResourceRecord><Value>2001:db8::2</Value></ResourceRecord></ResourceRecords>
    </ResourceRecordSet>
  </ResourceRecordSets>
</ListResourceRecordSetsResponse>"#;
        let got = parse_list_response(xml, "host.example.com.").unwrap();
        assert_eq!(got, None);
    }

    #[test]
    fn parse_error_summary_basic() {
        let xml = r#"<?xml version="1.0"?>
<ErrorResponse>
  <Error>
    <Type>Sender</Type>
    <Code>NoSuchHostedZone</Code>
    <Message>No hosted zone found with ID: Z123</Message>
  </Error>
  <RequestId>abc-123</RequestId>
</ErrorResponse>"#;
        let s = parse_error_summary(xml).unwrap();
        assert!(s.contains("NoSuchHostedZone"));
        assert!(s.contains("No hosted zone found"));
        assert!(s.contains("abc-123"));
    }

    #[test]
    fn http_error_keeps_unparsed_response_body() {
        let err = http_error_message(502, "<html>bad gateway</html>", "GET\n/...");
        assert!(err.to_string().contains("could not parse Route53 error"));
        assert_eq!(
            err.unparsed_response_body(),
            Some("<html>bad gateway</html>")
        );
    }
}
