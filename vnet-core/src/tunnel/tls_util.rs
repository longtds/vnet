//! TLS/QUIC 证书辅助: rcgen 自签证书 + 跳过服务端证书校验

use crate::common::error::{Error, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;

/// 生成自签证书 (CN/SAN = "vnet")
pub fn self_signed_cert() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let certified = rcgen::generate_simple_self_signed(vec!["vnet".to_string()])
        .map_err(|e| Error::Tunnel(format!("generate cert: {e}")))?;
    let cert_der = CertificateDer::from(certified.cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(certified.signing_key.serialize_der().to_vec())
        .map_err(|e| Error::Tunnel(format!("private key der: {e:?}")))?;
    Ok((vec![cert_der], key_der))
}

/// 显式 ring provider (避免 aws-lc-rs/ring 共存时无法自动选择)
pub fn ring_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// 跳过服务端证书校验的客户端配置 (自签证书场景)
pub fn insecure_client_config() -> Result<rustls::ClientConfig> {
    Ok(rustls::ClientConfig::builder_with_provider(ring_provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Tunnel(format!("rustls versions: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth())
}

/// 使用自定义 CA 的严格校验客户端配置 (wss 对接真实/私有 CA 证书时使用)
pub fn ca_client_config(ca_pem: &[u8]) -> Result<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    let mut added = 0usize;
    for cert in rustls_pemfile::certs(&mut &ca_pem[..]).filter_map(|r| r.ok()) {
        roots
            .add(cert)
            .map_err(|e| Error::Config(format!("add ca cert: {e}")))?;
        added += 1;
    }
    if added == 0 {
        return Err(Error::Config("no CA certificate found in pem".into()));
    }
    Ok(rustls::ClientConfig::builder_with_provider(ring_provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Tunnel(format!("rustls versions: {e}")))?
        .with_root_certificates(roots)
        .with_no_client_auth())
}

/// 自签证书的服务端配置 (WSS 用)
pub fn self_signed_server_config() -> Result<Arc<rustls::ServerConfig>> {
    let (certs, key) = self_signed_cert()?;
    let cfg = rustls::ServerConfig::builder_with_provider(ring_provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Tunnel(format!("rustls versions: {e}")))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| Error::Tunnel(format!("rustls: {e}")))?;
    Ok(Arc::new(cfg))
}

/// 跳过证书校验的 verifier (自签证书场景)
#[derive(Debug)]
pub struct SkipServerVerification;

impl SkipServerVerification {
    pub fn new() -> Arc<Self> {
        Arc::new(SkipServerVerification)
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme::*;
        vec![
            RSA_PKCS1_SHA256,
            ECDSA_NISTP256_SHA256,
            RSA_PKCS1_SHA384,
            ECDSA_NISTP384_SHA384,
            RSA_PKCS1_SHA512,
            ECDSA_NISTP521_SHA512,
            RSA_PSS_SHA256,
            RSA_PSS_SHA384,
            RSA_PSS_SHA512,
            ED25519,
        ]
    }
}
