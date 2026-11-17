//! TLS helpers: certificate files compatible with Go's crypto/tls, pinned
//! fingerprints, and the public CA roots for GitHub / Let's Encrypt.

use std::path::Path;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::{DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};

pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Hex SHA-256 of a DER certificate (the fingerprint shown everywhere).
pub fn fingerprint(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der))
}

/// A certificate chain and key loaded from PEM files (tls.LoadX509KeyPair).
pub struct KeyPair {
    pub chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

impl KeyPair {
    pub fn load(cert: &Path, key: &Path) -> Result<KeyPair, String> {
        let chain: Vec<_> = CertificateDer::pem_file_iter(cert)
            .map_err(|e| format!("{}: {e}", cert.display()))?
            .collect::<Result<_, _>>()
            .map_err(|e| format!("{}: {e}", cert.display()))?;
        if chain.is_empty() {
            return Err(format!("{}: no certificate", cert.display()));
        }
        let key = PrivateKeyDer::from_pem_file(key).map_err(|e| format!("{}: {e}", key.display()))?;
        // Like LoadX509KeyPair: the key must match the certificate.
        let signing = provider().key_provider.load_private_key(key.clone_key()).map_err(|e| e.to_string())?;
        let ck = rustls::sign::CertifiedKey::new(chain.clone(), signing);
        ck.keys_match().map_err(|e| format!("private key does not match public key: {e}"))?;
        Ok(KeyPair { chain, key })
    }

    pub fn fingerprint(&self) -> String {
        fingerprint(&self.chain[0])
    }

    pub fn server_config(&self, alpn: &[&[u8]]) -> Result<Arc<rustls::ServerConfig>, String> {
        let mut c = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_no_client_auth()
            .with_single_cert(self.chain.clone(), self.key.clone_key())
            .map_err(|e| e.to_string())?;
        c.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        Ok(Arc::new(c))
    }
}

/// Trusts exactly the certificate with fingerprint `fp` (TLS 1.3 only).
pub fn pinned(fp: &str) -> Arc<rustls::ClientConfig> {
    let v = Arc::new(Pinned { fp: fp.to_lowercase(), provider: provider() });
    let c = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("tls13")
        .dangerous()
        .with_custom_certificate_verifier(v)
        .with_no_client_auth();
    Arc::new(c)
}

/// Verifies against the public web PKI (GitHub, Let's Encrypt).
pub fn public() -> Arc<rustls::ClientConfig> {
    let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    let c = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("tls versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(c)
}

/// Accepts any certificate (backends of HTTPS routes with self-signed certs,
/// like Go's InsecureSkipVerify).
pub fn insecure() -> Arc<rustls::ClientConfig> {
    let v = Arc::new(Pinned { fp: String::new(), provider: provider() });
    let c = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("tls versions")
        .dangerous()
        .with_custom_certificate_verifier(v)
        .with_no_client_auth();
    Arc::new(c)
}

#[derive(Debug)]
struct Pinned {
    fp: String, // empty: accept any
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if !self.fp.is_empty() && fingerprint(end_entity) != self.fp {
            return Err(rustls::Error::General("join server certificate does not match token".into()));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// A random positive certificate serial below 2^bits.
pub fn serial(bits: u32) -> rcgen::SerialNumber {
    let v = u64::from_be_bytes(crate::util::random_bytes::<8>()) >> (64 - bits);
    let b = v.to_be_bytes();
    let first = b.iter().position(|x| *x != 0).unwrap_or(7);
    let mut s = b[first..].to_vec();
    if s[0] & 0x80 != 0 {
        s.insert(0, 0);
    }
    rcgen::SerialNumber::from_slice(&s)
}

/// Unix time `secs` as a certificate date.
pub fn date(secs: i64) -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(secs).unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
}
