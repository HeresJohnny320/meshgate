//! The web UI over HTTPS without setup (Go: internal/webtls): a certificate
//! for the addresses the web UI answers on, signed by the server's own small
//! name-constrained CA, renewed before expiry or when an address is missing.
//! The files are shared with the Go build: a CA the Go build made (and that
//! devices may have installed) keeps signing; its issuer name and key ID are
//! copied byte for byte into new certificates.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

use crate::netx::Prefix;

const VALIDITY: i64 = 397 * 86400;
const CA_VALIDITY: i64 = 10 * 365 * 86400;
const RENEW_AT: i64 = 30 * 86400;
const MAX_HOSTS: usize = 64;

/// Where the web UI serves its CA certificate for download.
pub const CA_PATH: &str = "/meshgate-ca.crt";

#[derive(Default)]
struct State {
    cert: Option<Arc<CertifiedKey>>,
    fp: String,
    ca_der: Vec<u8>,
    ca_pkcs8: Vec<u8>,
    ca_pem: String,
    ca_fp: String,
    skipped: Vec<String>,
}

pub struct Cert {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub ca_cert_path: PathBuf,
    pub ca_key_path: PathBuf,
    pub name: String,
    pub hosts: Vec<String>,
    pub mesh: Option<Prefix>,
    st: Mutex<State>,
}

/// Uppercase colon-separated SHA-256, as browsers show it.
pub fn fingerprint(der: &[u8]) -> String {
    Sha256::digest(der).iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

impl Cert {
    pub fn new(
        cert_path: PathBuf,
        key_path: PathBuf,
        ca_cert_path: PathBuf,
        ca_key_path: PathBuf,
        name: &str,
        hosts: Vec<String>,
        mesh: Option<Prefix>,
    ) -> Arc<Cert> {
        Arc::new(Cert { cert_path, key_path, ca_cert_path, ca_key_path, name: name.into(), hosts, mesh, st: Mutex::new(State::default()) })
    }

    /// Loads the certificate, creating a new one when there is none, it
    /// expires within 30 days or it does not cover every host. A new one
    /// keeps the old one's addresses too.
    pub fn refresh(&self, now: i64) -> Result<(), String> {
        let mut st = self.st.lock().unwrap();
        let new_ca = self.load_ca(&mut st, now)?;
        let (mut hosts, skipped) = permitted(&st.ca_der, &self.hosts);
        st.skipped = skipped;
        if !new_ca
            && let Ok((chain, key)) = load_pair(&self.cert_path, &self.key_path)
            && let Ok((_, leaf)) = parse_x509_certificate(&chain[0])
        {
            let ca = parse_x509_certificate(&st.ca_der).map(|c| c.1).ok();
            if ca.is_some_and(|ca| leaf.verify_signature(Some(ca.public_key())).is_ok()) {
                if now + RENEW_AT < leaf.validity().not_after.timestamp() && covers(&leaf, &hosts) {
                    set(&mut st, chain, key)?;
                    return Ok(());
                }
                hosts = permitted(&st.ca_der, &union(&hosts, &leaf)).0;
            }
        }
        let (chain, key) = self.create(&st, &hosts, now)?;
        set(&mut st, chain, key)
    }

    /// Loads the CA, creating it when there is none or it expires within 30
    /// days; reports whether it made a new one.
    fn load_ca(&self, st: &mut State, now: i64) -> Result<bool, String> {
        if !st.ca_der.is_empty()
            && let Ok((_, ca)) = parse_x509_certificate(&st.ca_der)
            && now + RENEW_AT < ca.validity().not_after.timestamp()
        {
            return Ok(false);
        }
        if let (Ok(chain), Ok(key)) = (read_certs(&self.ca_cert_path), std::fs::read(&self.ca_key_path))
            && let (Some(der), Some(pkcs8)) = (chain.first(), key_pkcs8(&key))
            && let Ok((_, ca)) = parse_x509_certificate(der)
            && ca.is_ca()
            && now + RENEW_AT < ca.validity().not_after.timestamp()
            && key_matches(&pkcs8, ca.public_key().raw)
        {
            set_ca(st, der.to_vec(), pkcs8);
            return Ok(false);
        }
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;
        let mut p = rcgen::CertificateParams::default();
        p.serial_number = Some(crate::tlsx::serial(62));
        p.distinguished_name = rcgen::DistinguishedName::new();
        p.distinguished_name.push(rcgen::DnType::OrganizationName, "meshgate");
        p.distinguished_name.push(rcgen::DnType::CommonName, format!("meshgate web UI CA {}", self.name).trim());
        p.not_before = crate::tlsx::date(now - 3600);
        p.not_after = crate::tlsx::date(now + CA_VALIDITY);
        p.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign, rcgen::KeyUsagePurpose::CrlSign];
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        p.key_identifier_method = rcgen::KeyIdMethod::Sha256;
        let (names, ranges) = constraints(&self.hosts, self.mesh);
        let mut permitted = vec![];
        for n in names {
            permitted.push(rcgen::GeneralSubtree::DnsName(n));
        }
        for r in ranges {
            permitted.push(rcgen::GeneralSubtree::IpAddress(rcgen::CidrSubnet::from_addr_prefix(r.addr, r.bits)));
        }
        p.name_constraints = Some(rcgen::NameConstraints { permitted_subtrees: permitted, excluded_subtrees: vec![] });
        let c = p.self_signed(&kp).map_err(|e| e.to_string())?;
        let pkcs8 = kp.serialize_der();
        write_file(&self.ca_key_path, kp.serialize_pem().as_bytes(), 0o600)?;
        write_file(&self.ca_cert_path, c.pem().as_bytes(), 0o644)?;
        set_ca(st, c.der().to_vec(), pkcs8);
        Ok(true)
    }

    fn create(&self, st: &State, hosts: &[String], now: i64) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;
        let leaf = sign_leaf(&st.ca_der, &st.ca_pkcs8, &kp.public_key_der(), hosts, now)?;
        let mut cert_pem = pem("CERTIFICATE", &leaf);
        cert_pem.push_str(&st.ca_pem); // the chain, so browsers that trust the CA can build it
        write_file(&self.key_path, kp.serialize_pem().as_bytes(), 0o600)?;
        write_file(&self.cert_path, cert_pem.as_bytes(), 0o644)?;
        load_pair(&self.cert_path, &self.key_path)
    }

    pub fn fingerprint(&self) -> String {
        self.st.lock().unwrap().fp.clone()
    }

    pub fn ca_fingerprint(&self) -> String {
        self.st.lock().unwrap().ca_fp.clone()
    }

    /// Hosts left out because the CA may not sign for them.
    pub fn skipped(&self) -> Vec<String> {
        self.st.lock().unwrap().skipped.clone()
    }

    pub fn ca_pem(&self) -> String {
        self.st.lock().unwrap().ca_pem.clone()
    }

    /// Serves the current certificate (renewals apply without a restart).
    pub fn tls_config(self: &Arc<Self>) -> Arc<rustls::ServerConfig> {
        let mut c = rustls::ServerConfig::builder_with_provider(crate::tlsx::provider())
            .with_safe_default_protocol_versions()
            .expect("tls versions")
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Resolver(self.clone())));
        c.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(c)
    }
}

#[derive(Debug)]
struct Resolver(Arc<Cert>);

impl std::fmt::Debug for Cert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("webtls::Cert")
    }
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.0.st.lock().unwrap().cert.clone()
    }
}

fn set(st: &mut State, chain: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> Result<(), String> {
    st.fp = fingerprint(&chain[0]);
    let signing = crate::tlsx::provider().key_provider.load_private_key(key).map_err(|e| e.to_string())?;
    st.cert = Some(Arc::new(CertifiedKey::new(chain, signing)));
    Ok(())
}

fn set_ca(st: &mut State, der: Vec<u8>, pkcs8: Vec<u8>) {
    st.ca_pem = pem("CERTIFICATE", &der);
    st.ca_fp = fingerprint(&der);
    st.ca_der = der;
    st.ca_pkcs8 = pkcs8;
}

fn pem(label: &str, der: &[u8]) -> String {
    use base64::Engine;
    let b = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

fn read_certs(p: &std::path::Path) -> Result<Vec<CertificateDer<'static>>, String> {
    CertificateDer::pem_file_iter(p).map_err(|e| e.to_string())?.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
}

fn load_pair(cert: &std::path::Path, key: &std::path::Path) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
    let kp = crate::tlsx::KeyPair::load(cert, key)?;
    Ok((kp.chain, kp.key))
}

/// A PEM private key as PKCS#8 DER (SEC1 "EC PRIVATE KEY" from Go is
/// wrapped).
fn key_pkcs8(pem_bytes: &[u8]) -> Option<Vec<u8>> {
    match PrivateKeyDer::from_pem_slice(pem_bytes).ok()? {
        PrivateKeyDer::Pkcs8(k) => Some(k.secret_pkcs8_der().to_vec()),
        PrivateKeyDer::Sec1(k) => Some(sec1_to_pkcs8(k.secret_sec1_der())),
        _ => None,
    }
}

/// PrivateKeyInfo { 0, { id-ecPublicKey, prime256v1 }, OCTET STRING sec1 }.
fn sec1_to_pkcs8(sec1: &[u8]) -> Vec<u8> {
    let alg = der::seq(&[der::oid(&[1, 2, 840, 10045, 2, 1]), der::oid(&[1, 2, 840, 10045, 3, 1, 7])]);
    der::seq(&[der::int(&[0]), alg, der::tlv(0x04, sec1)])
}

fn signer(pkcs8: &[u8]) -> Result<ring::signature::EcdsaKeyPair, String> {
    let rng = ring::rand::SystemRandom::new();
    ring::signature::EcdsaKeyPair::from_pkcs8(&ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8, &rng)
        .map_err(|e| format!("CA key: {e}"))
}

fn key_matches(pkcs8: &[u8], spki_raw: &[u8]) -> bool {
    use ring::signature::KeyPair;
    signer(pkcs8).is_ok_and(|k| spki_raw.ends_with(k.public_key().as_ref()))
}

/// Builds and signs a server certificate with the CA (Go's template:
/// digitalSignature, serverAuth, not a CA, SANs for every host).
fn sign_leaf(ca_der: &[u8], ca_pkcs8: &[u8], spki: &[u8], hosts: &[String], now: i64) -> Result<Vec<u8>, String> {
    let (_, ca) = parse_x509_certificate(ca_der).map_err(|e| e.to_string())?;
    let issuer = ca.tbs_certificate.subject.as_raw().to_vec();
    let ski = ca.extensions().iter().find_map(|e| match e.parsed_extension() {
        ParsedExtension::SubjectKeyIdentifier(k) => Some(k.0.to_vec()),
        _ => None,
    });
    let ecdsa_sha256 = der::seq(&[der::oid(&[1, 2, 840, 10045, 4, 3, 2])]);
    let name = |cn: &str| {
        der::seq(&[
            der::tlv(0x31, &der::seq(&[der::oid(&[2, 5, 4, 10]), der::tlv(0x13, b"meshgate")])),
            der::tlv(0x31, &der::seq(&[der::oid(&[2, 5, 4, 3]), der::tlv(0x13, cn.as_bytes())])),
        ])
    };
    let mut sans = vec![];
    for h in hosts {
        match h.parse::<IpAddr>() {
            Ok(IpAddr::V4(a)) => sans.push(der::tlv(0x87, &a.octets())),
            Ok(IpAddr::V6(a)) => sans.push(der::tlv(0x87, &a.octets())),
            Err(_) if !h.is_empty() => sans.push(der::tlv(0x82, h.as_bytes())),
            _ => {}
        }
    }
    let ext = |oid: &[u64], critical: bool, value: Vec<u8>| {
        let mut parts = vec![der::oid(oid)];
        if critical {
            parts.push(vec![0x01, 0x01, 0xff]);
        }
        parts.push(der::tlv(0x04, &value));
        der::seq(&parts)
    };
    let mut exts = vec![
        ext(&[2, 5, 29, 15], true, vec![0x03, 0x02, 0x07, 0x80]),
        ext(&[2, 5, 29, 37], false, der::seq(&[der::oid(&[1, 3, 6, 1, 5, 5, 7, 3, 1])])),
        ext(&[2, 5, 29, 19], true, der::seq(&[])),
    ];
    if let Some(k) = ski {
        exts.push(ext(&[2, 5, 29, 35], false, der::seq(&[der::tlv(0x80, &k)])));
    }
    if !sans.is_empty() {
        exts.push(ext(&[2, 5, 29, 17], false, der::seq(&sans)));
    }
    let mut serial = crate::util::random_bytes::<8>().to_vec();
    serial[0] &= 0x3f;
    let tbs = der::seq(&[
        der::tlv(0xa0, &der::int(&[2])),
        der::int(&serial),
        ecdsa_sha256.clone(),
        issuer,
        der::seq(&[der::time(now - 3600), der::time(now + VALIDITY)]),
        name("meshgate web UI"),
        spki.to_vec(),
        der::tlv(0xa3, &der::seq(&exts)),
    ]);
    let rng = ring::rand::SystemRandom::new();
    let sig = signer(ca_pkcs8)?.sign(&rng, &tbs).map_err(|e| e.to_string())?;
    let mut bits = vec![0u8];
    bits.extend_from_slice(sig.as_ref());
    Ok(der::seq(&[tbs, ecdsa_sha256, der::tlv(0x03, &bits)]))
}

/// What the CA may sign for: names among hosts, loopback, the mesh range
/// and each other listen address exactly.
fn constraints(hosts: &[String], mesh: Option<Prefix>) -> (Vec<String>, Vec<Prefix>) {
    let mut names = vec!["localhost".to_string()];
    let mut ranges = vec![crate::netx::parse_prefix("127.0.0.0/8").unwrap(), crate::netx::parse_prefix("::1/128").unwrap()];
    if let Some(m) = mesh {
        ranges.push(m.masked());
    }
    for h in hosts {
        if let Ok(ip) = h.parse::<IpAddr>() {
            let ip = match ip {
                IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
                v4 => v4,
            };
            if !ranges.iter().any(|r| r.contains(ip)) {
                ranges.push(Prefix::new(ip, if ip.is_ipv4() { 32 } else { 128 }));
            }
        } else if !h.is_empty() && !names.contains(h) {
            names.push(h.clone());
        }
    }
    (names, ranges)
}

/// Splits hosts into those the CA may sign for and the rest.
fn permitted(ca_der: &[u8], hosts: &[String]) -> (Vec<String>, Vec<String>) {
    let (mut dns, mut ips): (Vec<String>, Vec<Prefix>) = (vec![], vec![]);
    if let Ok((_, ca)) = parse_x509_certificate(ca_der) {
        for e in ca.extensions() {
            if let ParsedExtension::NameConstraints(nc) = e.parsed_extension() {
                for s in nc.permitted_subtrees.iter().flatten() {
                    match &s.base {
                        GeneralName::DNSName(d) => dns.push(d.to_string()),
                        GeneralName::IPAddress(b) => {
                            let (a, m) = b.split_at(b.len() / 2);
                            let bits: u32 = m.iter().map(|x| x.count_ones()).sum();
                            let ip = if a.len() == 4 {
                                IpAddr::V4(std::net::Ipv4Addr::new(a[0], a[1], a[2], a[3]))
                            } else if let Ok(o) = <[u8; 16]>::try_from(a) {
                                IpAddr::V6(o.into())
                            } else {
                                continue;
                            };
                            ips.push(Prefix::new(ip, bits as u8));
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    let (mut ok, mut skipped) = (vec![], vec![]);
    for h in hosts {
        let allowed = match h.parse::<IpAddr>() {
            Ok(ip) => {
                let ip4 = match ip {
                    IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
                    v4 => v4,
                };
                ips.iter().any(|r| r.contains(ip4) || r.contains(ip))
            }
            Err(_) => {
                let l = h.to_lowercase();
                dns.iter().any(|d| l == d.to_lowercase() || l.ends_with(&format!(".{}", d.to_lowercase())))
            }
        };
        if allowed { ok.push(h.clone()) } else { skipped.push(h.clone()) }
    }
    (ok, skipped)
}

fn sans(leaf: &X509Certificate) -> (Vec<String>, Vec<IpAddr>) {
    let (mut dns, mut ips) = (vec![], vec![]);
    if let Ok(Some(s)) = leaf.subject_alternative_name() {
        for n in &s.value.general_names {
            match n {
                GeneralName::DNSName(d) => dns.push(d.to_string()),
                GeneralName::IPAddress(b) if b.len() == 4 => ips.push(IpAddr::V4(std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]))),
                GeneralName::IPAddress(b) if b.len() == 16 => {
                    if let Ok(o) = <[u8; 16]>::try_from(*b) {
                        ips.push(IpAddr::V6(o.into()))
                    }
                }
                _ => {}
            }
        }
    }
    (dns, ips)
}

fn covers(leaf: &X509Certificate, hosts: &[String]) -> bool {
    let (dns, ips) = sans(leaf);
    hosts.iter().all(|h| match h.parse::<IpAddr>() {
        Ok(ip) => ips.contains(&ip),
        Err(_) => dns.contains(h),
    })
}

fn union(hosts: &[String], leaf: &X509Certificate) -> Vec<String> {
    let mut out = hosts.to_vec();
    let (dns, ips) = sans(leaf);
    for h in ips.iter().map(|i| i.to_string()).chain(dns) {
        if out.len() < MAX_HOSTS && !out.contains(&h) {
            out.push(h);
        }
    }
    out
}

fn write_file(path: &std::path::Path, b: &[u8], mode: u32) -> Result<(), String> {
    let tmp = crate::config::tmp_path(path);
    crate::config::write_mode(&tmp, b, mode).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}

/// What the certificate covers for the listen addresses: their IPs (every
/// interface's for 0.0.0.0 / ::), localhost and the machine's name.
pub fn hosts(listen: &[String], extra: &[&str]) -> Vec<String> {
    let mut set: std::collections::BTreeSet<String> = ["127.0.0.1", "::1", "localhost"].iter().map(|s| s.to_string()).collect();
    if let Some(h) = hostname() {
        set.insert(h.to_lowercase());
    }
    for e in extra.iter().filter(|e| !e.is_empty()) {
        set.insert(e.to_string());
    }
    for addr in listen {
        let Ok((host, _)) = crate::netx::split_host_port(addr) else { continue };
        let unspecified = host.is_empty() || host.parse::<IpAddr>().is_ok_and(|i| i.is_unspecified());
        if unspecified {
            for i in crate::ifaces::list() {
                for (a, _) in i.addrs {
                    let link_local = match a {
                        IpAddr::V4(v) => v.is_link_local(),
                        IpAddr::V6(v) => (v.segments()[0] & 0xffc0) == 0xfe80,
                    };
                    if !link_local {
                        set.insert(a.to_string());
                    }
                }
            }
        } else {
            set.insert(host);
        }
    }
    set.into_iter().collect()
}

/// os.Hostname.
pub fn hostname() -> Option<String> {
    #[cfg(unix)]
    {
        let mut b = [0u8; 256];
        // SAFETY: gethostname writes at most b.len() bytes.
        if unsafe { libc::gethostname(b.as_mut_ptr() as *mut libc::c_char, b.len()) } == 0 {
            let n = b.iter().position(|c| *c == 0).unwrap_or(b.len());
            return Some(String::from_utf8_lossy(&b[..n]).into_owned()).filter(|s| !s.is_empty());
        }
        None
    }
    #[cfg(not(unix))]
    {
        std::env::var("COMPUTERNAME").ok()
    }
}

/// A minimal DER writer.
mod der {
    pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let n = content.len();
        if n < 128 {
            out.push(n as u8);
        } else {
            let b = (n as u64).to_be_bytes();
            let first = b.iter().position(|x| *x != 0).unwrap_or(7);
            out.push(0x80 | (8 - first) as u8);
            out.extend_from_slice(&b[first..]);
        }
        out.extend_from_slice(content);
        out
    }

    pub fn seq(items: &[Vec<u8>]) -> Vec<u8> {
        tlv(0x30, &items.concat())
    }

    /// A non-negative INTEGER from big-endian bytes.
    pub fn int(b: &[u8]) -> Vec<u8> {
        let first = b.iter().position(|x| *x != 0).unwrap_or(b.len().saturating_sub(1));
        let mut v = b[first..].to_vec();
        if v.is_empty() {
            v.push(0);
        }
        if v[0] & 0x80 != 0 {
            v.insert(0, 0);
        }
        tlv(0x02, &v)
    }

    pub fn oid(arcs: &[u64]) -> Vec<u8> {
        let mut b = vec![(arcs[0] * 40 + arcs[1]) as u8];
        for &a in &arcs[2..] {
            let mut tmp = vec![(a & 0x7f) as u8];
            let mut v = a >> 7;
            while v > 0 {
                tmp.push(0x80 | (v & 0x7f) as u8);
                v >>= 7;
            }
            tmp.reverse();
            b.extend(tmp);
        }
        tlv(0x06, &b)
    }

    /// UTCTime before 2050, GeneralizedTime after (RFC 5280).
    pub fn time(unix: i64) -> Vec<u8> {
        let (y, mo, d, h, mi, s, _) = crate::logx::utc(unix);
        if (1950..2050).contains(&y) {
            tlv(0x17, format!("{:02}{mo:02}{d:02}{h:02}{mi:02}{s:02}Z", y % 100).as_bytes())
        } else {
            tlv(0x18, format!("{y:04}{mo:02}{d:02}{h:02}{mi:02}{s:02}Z").as_bytes())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(d: &std::path::Path) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
        (d.join("webui.crt"), d.join("webui.key"), d.join("webui-ca.crt"), d.join("webui-ca.key"))
    }

    fn cert(d: &std::path::Path, hosts: &[&str]) -> Arc<Cert> {
        let (c, k, cc, ck) = paths(d);
        Cert::new(c, k, cc, ck, "vps", hosts.iter().map(|s| s.to_string()).collect(), crate::netx::parse_prefix("100.88.0.0/16"))
    }

    /// The CA the Go build made keeps signing: same CA fingerprint, and the
    /// new leaf verifies against it.
    #[test]
    fn keeps_go_ca() {
        let dir = tempfile::tempdir().unwrap();
        for f in ["webui.crt", "webui.key", "webui-ca.crt", "webui-ca.key"] {
            std::fs::copy(format!("testdata/webtls/{f}"), dir.path().join(f)).unwrap();
        }
        let fps = std::fs::read_to_string("testdata/webtls/fp").unwrap();
        let mut lines = fps.lines();
        let (go_fp, go_ca_fp) = (lines.next().unwrap().to_string(), lines.next().unwrap().to_string());
        let now = crate::util::now_unix();
        let c = cert(dir.path(), &["127.0.0.1", "::1", "localhost", "vps", "100.88.0.1", "203.0.113.7"]);
        c.refresh(now).unwrap();
        assert_eq!(c.ca_fingerprint(), go_ca_fp);
        assert_eq!(c.fingerprint(), go_fp, "a still-valid Go certificate is kept");

        // A new address inside the mesh: new leaf, same CA, chain verifies.
        let c2 = cert(dir.path(), &["127.0.0.1", "vps", "100.88.0.1", "100.88.7.7", "evil.example"]);
        c2.refresh(now).unwrap();
        assert_eq!(c2.ca_fingerprint(), go_ca_fp);
        assert_ne!(c2.fingerprint(), go_fp);
        assert_eq!(c2.skipped(), vec!["evil.example".to_string()]);
        let chain = read_certs(&dir.path().join("webui.crt")).unwrap();
        assert_eq!(chain.len(), 2);
        let (_, leaf) = parse_x509_certificate(&chain[0]).unwrap();
        let (_, ca) = parse_x509_certificate(&chain[1]).unwrap();
        leaf.verify_signature(Some(ca.public_key())).unwrap();
        assert_eq!(leaf.issuer().as_raw(), ca.subject().as_raw());
        let (dns, ips) = sans(&leaf);
        assert!(
            dns.contains(&"vps".to_string())
                && ips.contains(&"100.88.7.7".parse().unwrap())
                && ips.contains(&"203.0.113.7".parse().unwrap())
        );
        // Verified by a real TLS client that trusts only the Go CA.
        verify_with_webpki(&chain, &chain[1], "vps", now);
    }

    fn verify_with_webpki(chain: &[CertificateDer<'static>], ca: &CertificateDer<'static>, name: &str, now: i64) {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.clone()).unwrap();
        let v = rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), crate::tlsx::provider()).build().unwrap();
        use rustls::client::danger::ServerCertVerifier;
        let sn = rustls_pki_types::ServerName::try_from(name.to_string()).unwrap();
        v.verify_server_cert(
            &chain[0],
            &chain[1..],
            &sn,
            &[],
            rustls_pki_types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(now as u64)),
        )
        .expect("certificate verifies against the CA");
    }

    #[test]
    fn new_ca_and_renewal() {
        let dir = tempfile::tempdir().unwrap();
        let now = crate::util::now_unix();
        let c = cert(dir.path(), &["127.0.0.1", "vps", "100.88.0.1"]);
        c.refresh(now).unwrap();
        let (fp, ca_fp) = (c.fingerprint(), c.ca_fingerprint());
        assert_eq!(fp.len(), 95);
        let chain = read_certs(&dir.path().join("webui.crt")).unwrap();
        verify_with_webpki(&chain, &chain[1], "vps", now);
        // Reload: same certificate.
        let again = cert(dir.path(), &["127.0.0.1", "vps", "100.88.0.1"]);
        again.refresh(now).unwrap();
        assert_eq!((again.fingerprint(), again.ca_fingerprint()), (fp.clone(), ca_fp.clone()));
        // Close to expiry: renewed, same CA.
        let later = cert(dir.path(), &["127.0.0.1", "vps", "100.88.0.1"]);
        later.refresh(now + VALIDITY - 86400).unwrap();
        assert_ne!(later.fingerprint(), fp);
        assert_eq!(later.ca_fingerprint(), ca_fp);
    }
}
