use super::*;

#[derive(serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GoHostPort {
    proto: String,
    port: i64,
    note: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Golden {
    name: String,
    input: Input,
    #[serde(rename = "NFT")]
    nft: String,
    #[serde(rename = "PFNat")]
    pf_nat: String,
    #[serde(rename = "PFRdr")]
    pf_rdr: String,
    #[serde(rename = "PFFilter")]
    pf_filter: String,
    #[serde(deserialize_with = "crate::gojson::nullable")]
    iptables: Vec<Vec<String>>,
    #[serde(deserialize_with = "crate::gojson::nullable")]
    host_open: Vec<GoHostPort>,
    #[serde(deserialize_with = "crate::gojson::nullable")]
    warnings: Vec<String>,
}

/// Every case the Go build rendered must come out byte for byte the same.
#[test]
fn matches_go_golden() {
    let b = include_str!("../../testdata/fw.json");
    let cases: Vec<Golden> = serde_json::from_str(b).unwrap();
    assert!(cases.len() > 20);
    for c in cases {
        let mut p = build(&c.input);
        for (k, l) in p.lans.iter_mut().enumerate() {
            l.iface = format!("lan{k}");
        }
        let (n, r, f) = render_pf(&p);
        assert_eq!(render_nft(&p), c.nft, "nft differs: {}", c.name);
        assert_eq!(n, c.pf_nat, "pf nat differs: {}", c.name);
        assert_eq!(r, c.pf_rdr, "pf rdr differs: {}", c.name);
        assert_eq!(f, c.pf_filter, "pf filter differs: {}", c.name);
        assert_eq!(p.iptables_rules(), c.iptables, "iptables differ: {}", c.name);
        let ho: Vec<(String, i64, String)> = c.host_open.into_iter().map(|h| (h.proto, h.port, h.note)).collect();
        let got: Vec<(String, i64, String)> = p.host_open.into_iter().map(|h| (h.proto, h.port, h.note)).collect();
        assert_eq!(got, ho, "host ports differ: {}", c.name);
        assert_eq!(p.warnings, c.warnings, "warnings differ: {}", c.name);
    }
}

#[test]
fn is_tunnel_names() {
    for (name, p2p, want) in [
        ("wg0", false, true),
        ("tun_wg0", false, true),
        ("ovpns1", false, true),
        ("tailscale0", false, true),
        ("myvpn", true, true),
        ("eth0", false, false),
        ("igb1.20", false, false),
        ("br0", false, false),
    ] {
        assert_eq!(is_tunnel(name, p2p), want, "{name}");
    }
}

#[test]
fn monitor_validate() {
    let m = |node: &str, proto: &str, ip: &str, ports: &str| model::Monitor {
        node: node.into(),
        proto: proto.into(),
        ip: ip.into(),
        ports: ports.into(),
        ..Default::default()
    };
    for bad in [
        m("vps", "tcp", "", ""),
        m("vps", "any", "", "80"),
        m("vps", "tcp", "nas.local", ""),
        m("vps", "tcp", "", "70000"),
        m("", "tcp", "", "80"),
        m("vps", "icmp", "192.168.1.1", ""),
    ] {
        assert!(bad.validate().is_err(), "{bad:?}");
    }
}

/// The rendered script must be valid nft (checked in an unprivileged
/// namespace when the host allows it).
#[test]
fn nft_syntax() {
    if !crate::util::look_path("nft") || !crate::util::look_path("unshare") {
        return;
    }
    let cases: Vec<Golden> = serde_json::from_str(include_str!("../../testdata/fw.json")).unwrap();
    let dir = tempfile::tempdir().unwrap();
    for c in cases.iter().take(6) {
        let s = render_nft(&build(&c.input));
        let body = &s[s.find("table inet meshgate {").unwrap()..];
        let f = dir.path().join("x.nft");
        std::fs::write(&f, body).unwrap();
        let o = crate::util::run("unshare", &["-rn", "nft", "-c", "-f", f.to_str().unwrap()], None);
        if !o.ok && (o.out.contains("Operation not permitted") || o.out.contains("unshare failed")) {
            return;
        }
        assert!(o.ok, "nft -c {}: {}\n{body}", c.name, o.out);
    }
}
