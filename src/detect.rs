use std::net::{IpAddr, Ipv6Addr, UdpSocket};
use std::time::{SystemTime, UNIX_EPOCH};

const HTTP_DETECT_BODY_LIMIT: u64 = 512;
const HTTP_DETECT_MAX_RESULTS: usize = 5;

const HTTP_IPV6_SERVICES_BARE: &[&str] = &[
    "https://ipv6.whatismyip.akamai.com",
    "https://api6.ipify.org",
    "https://ipv6.icanhazip.com",
    "https://v6.ident.me",
    "https://v6.tnedi.me",
    "https://ipv6.seeip.org",
    "https://ipv6.wtfismyip.com/text",
    "https://ifconfig.co/ip",
    "https://ifconfig.me/ip",
    "https://ip.sb",
    "https://ipecho.net/plain",
];

pub fn get_public_ipv6(agent: &ureq::Agent) -> Result<Ipv6Addr, String> {
    if let Some(addr) = detect_local_ipv6() {
        crate::log_debug(&format!("detected IPv6 (local): {addr}"));
        return Ok(addr);
    }
    let addr = detect_http_ipv6(agent)?;
    crate::log_debug(&format!("detected IPv6 (http): {addr}"));
    Ok(addr)
}

fn detect_local_ipv6() -> Option<Ipv6Addr> {
    // UDP "connect" doesn't send any packet — it just resolves routing so
    // local_addr() returns the source the kernel would pick for outbound v6.
    let sock = match UdpSocket::bind("[::]:0") {
        Ok(s) => s,
        Err(e) => {
            crate::log_debug(&format!("local probe: bind failed: {e}"));
            return None;
        }
    };
    if let Err(e) = sock.connect("[2001:4860:4860::8888]:80") {
        crate::log_debug(&format!("local probe: connect failed: {e}"));
        return None;
    }
    let local = match sock.local_addr() {
        Ok(a) => a,
        Err(e) => {
            crate::log_debug(&format!("local probe: local_addr failed: {e}"));
            return None;
        }
    };
    let IpAddr::V6(addr) = local.ip() else {
        return None;
    };
    if !is_global_v6(&addr) {
        crate::log_debug(&format!("local probe: {addr} is not globally routable"));
        return None;
    }
    Some(addr)
}

fn is_global_v6(addr: &Ipv6Addr) -> bool {
    if addr.is_unspecified() || addr.is_loopback() || addr.is_multicast() {
        return false;
    }
    let segs = addr.segments();
    // For this DDNS client, accept only normal global unicast addresses.
    if segs[0] & 0xe000 != 0x2000 {
        return false;
    }
    // fe80::/10 link-local
    if segs[0] & 0xffc0 == 0xfe80 {
        return false;
    }
    // fc00::/7 unique-local
    if segs[0] & 0xfe00 == 0xfc00 {
        return false;
    }
    // 2001::/23 IETF protocol assignments, including Teredo and other
    // protocol/anycast assignments rather than normal host space.
    if segs[0] == 0x2001 && segs[1] & 0xfe00 == 0 {
        return false;
    }
    // 2001:db8::/32 documentation.
    if segs[0] == 0x2001 && segs[1] == 0x0db8 {
        return false;
    }
    // 2002::/16 6to4.
    if segs[0] == 0x2002 {
        return false;
    }
    // 3ffe::/16 old 6bone and 3fff::/20 documentation.
    if segs[0] == 0x3ffe || (segs[0] == 0x3fff && segs[1] & 0xf000 == 0) {
        return false;
    }
    true
}

fn detect_http_ipv6(agent: &ureq::Agent) -> Result<Ipv6Addr, String> {
    let mut errors = Vec::new();
    let mut results = Vec::new();

    for url in shuffled_services() {
        crate::log_debug(&format!("trying HTTP IPv6 detection (bare): {url}"));
        match query(agent, url) {
            Ok(addr) => {
                crate::log_debug(&format!("  {url}: {addr}"));
                results.push((url, addr));
                if results.len() >= HTTP_DETECT_MAX_RESULTS {
                    break;
                }
            }
            Err(e) => {
                crate::log_debug(&format!("  {url}: {e}"));
                errors.push(format!("{url}: {e}"));
            }
        }
    }
    find_quorum(&results).ok_or_else(|| quorum_error(&results, &errors))
}

fn shuffled_services() -> Vec<&'static str> {
    let mut services = HTTP_IPV6_SERVICES_BARE.to_vec();
    let mut seed = random_seed();

    for i in (1..services.len()).rev() {
        let j = (splitmix64(&mut seed) as usize) % (i + 1);
        services.swap(i, j);
    }

    services
}

fn random_seed() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let mut seed = now.as_secs() ^ u64::from(now.subsec_nanos()).rotate_left(32);
    seed ^= u64::from(std::process::id()).rotate_left(17);
    seed
}

fn splitmix64(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *seed;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn find_quorum(results: &[(&str, Ipv6Addr)]) -> Option<Ipv6Addr> {
    if results.len() < 2 {
        return None;
    }

    let required = (results.len() / 2) + 1;
    for (_, candidate) in results {
        let count = results
            .iter()
            .filter(|(_, addr)| addr == candidate)
            .count();
        if count >= required {
            return Some(*candidate);
        }
    }

    None
}

fn quorum_error(results: &[(&str, Ipv6Addr)], errors: &[String]) -> String {
    if results.is_empty() {
        return format!(
            "all HTTP IPv6 services failed:\n  {}",
            errors.join("\n  ")
        );
    }

    let mut msg = format!(
        "HTTP IPv6 detection could not reach quorum from {} successful response(s):",
        results.len()
    );
    for (url, addr) in results {
        msg.push_str(&format!("\n  {url}: {addr}"));
    }
    if !errors.is_empty() {
        msg.push_str("\nfailed services:");
        for e in errors {
            msg.push_str(&format!("\n  {e}"));
        }
    }
    msg
}

fn query(agent: &ureq::Agent, url: &str) -> Result<Ipv6Addr, String> {
    let resp = agent
        .get(url)
        .header("accept", "text/plain")
        .call()
        .map_err(|e| format!("request: {e}"))?;
    let status = resp.status().as_u16();
    if status >= 400 {
        return Err(format!("HTTP {status}"));
    }
    let body = resp
        .into_body()
        .into_with_config()
        .limit(HTTP_DETECT_BODY_LIMIT)
        .read_to_string()
        .map_err(|e| format!("read body (limit {HTTP_DETECT_BODY_LIMIT} bytes): {e}"))?;
    let trimmed = body.trim();
    let addr = trimmed
        .parse::<Ipv6Addr>()
        .map_err(|e| format!("parse {trimmed:?}: {e}"))?;
    if !is_global_v6(&addr) {
        return Err(format!("{addr} is not globally routable"));
    }
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_v6() {
        assert!(is_global_v6(&"2001:4860:4860::8888".parse().unwrap()));
        assert!(is_global_v6(&"2606:4700::1".parse().unwrap()));
    }

    #[test]
    fn non_global_v6() {
        assert!(!is_global_v6(&"::1".parse().unwrap()));
        assert!(!is_global_v6(&"::".parse().unwrap()));
        assert!(!is_global_v6(&"fe80::1".parse().unwrap()));
        // fc00::/7 ULA
        assert!(!is_global_v6(&"fc00::1".parse().unwrap()));
        assert!(!is_global_v6(&"fd00::1".parse().unwrap()));
        // multicast
        assert!(!is_global_v6(&"ff02::1".parse().unwrap()));
        // IPv4-mapped and NAT64 prefixes
        assert!(!is_global_v6(&"::ffff:192.0.2.1".parse().unwrap()));
        assert!(!is_global_v6(&"64:ff9b::192.0.2.1".parse().unwrap()));
        assert!(!is_global_v6(&"64:ff9b:1::1".parse().unwrap()));
        // Special-use global-unicast-looking ranges
        assert!(!is_global_v6(&"100::1".parse().unwrap()));
        assert!(!is_global_v6(&"100:0:0:1::1".parse().unwrap()));
        assert!(!is_global_v6(&"2001::1".parse().unwrap()));
        assert!(!is_global_v6(&"2001:2::1".parse().unwrap()));
        assert!(!is_global_v6(&"2001:db8::1".parse().unwrap()));
        assert!(!is_global_v6(&"2002::1".parse().unwrap()));
        assert!(!is_global_v6(&"3ffe::1".parse().unwrap()));
        assert!(!is_global_v6(&"3fff::1".parse().unwrap()));
        assert!(!is_global_v6(&"5f00::1".parse().unwrap()));
    }

    #[test]
    fn quorum_requires_at_least_two_successes() {
        let a = "2001:4860:4860::8888".parse().unwrap();
        assert_eq!(find_quorum(&[]), None);
        assert_eq!(find_quorum(&[("one", a)]), None);
    }

    #[test]
    fn quorum_accepts_two_matching_successes() {
        let a = "2001:4860:4860::8888".parse().unwrap();
        assert_eq!(find_quorum(&[("one", a), ("two", a)]), Some(a));
    }

    #[test]
    fn quorum_accepts_majority_successes() {
        let a = "2001:4860:4860::8888".parse().unwrap();
        let b = "2606:4700::1".parse().unwrap();
        let results = [
            ("one", a),
            ("two", b),
            ("three", a),
            ("four", a),
            ("five", b),
        ];
        assert_eq!(find_quorum(&results), Some(a));
    }

    #[test]
    fn quorum_rejects_split_successes() {
        let a = "2001:4860:4860::8888".parse().unwrap();
        let b = "2606:4700::1".parse().unwrap();
        let results = [("one", a), ("two", a), ("three", b), ("four", b)];
        assert_eq!(find_quorum(&results), None);
    }
}
