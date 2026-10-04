use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, Error, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
};
use std::sync::Arc;
use tundra_common::hash::{Hash32, sha256};

#[inline]
fn schemes(provider: &CryptoProvider) -> Vec<SignatureScheme> {
    provider
        .signature_verification_algorithms
        .supported_schemes()
}

fn tls12(
    provider: &CryptoProvider,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, Error> {
    rustls::crypto::verify_tls12_signature(
        message,
        cert,
        dss,
        &provider.signature_verification_algorithms,
    )
}

fn tls13(
    provider: &CryptoProvider,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, Error> {
    rustls::crypto::verify_tls13_signature(
        message,
        cert,
        dss,
        &provider.signature_verification_algorithms,
    )
}

pub trait CertPins: std::fmt::Debug + Send + Sync {
    fn node_for(&self, hash: &Hash32) -> Option<uuid::Uuid>;
    fn pin_of(&self, node: &uuid::Uuid) -> Option<Hash32>;
    #[inline]
    fn refresh(&self) {}
}

#[derive(Debug)]
pub struct PinnedCert {
    pin: Hash32,
    provider: Arc<CryptoProvider>,
}

impl PinnedCert {
    #[inline]
    pub fn new(pin: Hash32, provider: Arc<CryptoProvider>) -> Self {
        Self { pin, provider }
    }
}

impl ServerCertVerifier for PinnedCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if sha256(end_entity) == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        tls12(&self.provider, message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        tls13(&self.provider, message, cert, dss)
    }

    #[inline]
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        schemes(&self.provider)
    }
}

#[derive(Debug)]
pub struct PeerServerVerifier {
    expected: uuid::Uuid,
    pins: Arc<dyn CertPins>,
    provider: Arc<CryptoProvider>,
}

impl PeerServerVerifier {
    #[inline]
    pub fn new(
        expected: uuid::Uuid,
        pins: Arc<dyn CertPins>,
        provider: Arc<CryptoProvider>,
    ) -> Self {
        Self {
            expected,
            pins,
            provider,
        }
    }
}

impl ServerCertVerifier for PeerServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        match self.pins.pin_of(&self.expected) {
            Some(pin) if pin == sha256(end_entity) => Ok(ServerCertVerified::assertion()),
            Some(_) => Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            )),
            None => Err(Error::InvalidCertificate(CertificateError::UnknownIssuer)),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        tls12(&self.provider, message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        tls13(&self.provider, message, cert, dss)
    }

    #[inline]
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        schemes(&self.provider)
    }
}

#[derive(Debug)]
pub struct PeerClientVerifier {
    pins: Arc<dyn CertPins>,
    provider: Arc<CryptoProvider>,
    empty: Vec<DistinguishedName>,
}

impl PeerClientVerifier {
    #[inline]
    pub fn new(pins: Arc<dyn CertPins>, provider: Arc<CryptoProvider>) -> Self {
        Self {
            pins,
            provider,
            empty: Vec::new(),
        }
    }
}

impl ClientCertVerifier for PeerClientVerifier {
    #[inline]
    fn offer_client_auth(&self) -> bool {
        true
    }

    #[inline]
    fn client_auth_mandatory(&self) -> bool {
        true
    }

    #[inline]
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.empty
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        let hash = sha256(end_entity);
        if self.pins.node_for(&hash).is_some() {
            return Ok(ClientCertVerified::assertion());
        }

        self.pins.refresh();

        Err(Error::InvalidCertificate(CertificateError::UnknownIssuer))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        tls12(&self.provider, message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        tls13(&self.provider, message, cert, dss)
    }

    #[inline]
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        schemes(&self.provider)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::HashMap,
        sync::atomic::{AtomicUsize, Ordering},
    };

    #[derive(Debug, Default)]
    struct FakePins {
        map: parking_lot::Mutex<HashMap<Hash32, uuid::Uuid>>,
        pending: parking_lot::Mutex<Vec<(Hash32, uuid::Uuid)>>,
        refreshes: AtomicUsize,
    }

    impl CertPins for FakePins {
        fn node_for(&self, hash: &Hash32) -> Option<uuid::Uuid> {
            self.map.lock().get(hash).copied()
        }

        fn pin_of(&self, node: &uuid::Uuid) -> Option<Hash32> {
            self.map
                .lock()
                .iter()
                .find(|(_, n)| *n == node)
                .map(|(h, _)| *h)
        }

        fn refresh(&self) {
            self.refreshes.fetch_add(1, Ordering::Relaxed);
            let pending: Vec<_> = self.pending.lock().drain(..).collect();
            self.map.lock().extend(pending);
        }
    }

    fn provider() -> Arc<CryptoProvider> {
        Arc::new(rustls::crypto::aws_lc_rs::default_provider())
    }

    fn cert(body: &[u8]) -> CertificateDer<'static> {
        CertificateDer::from(body.to_vec())
    }

    fn now() -> UnixTime {
        UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_700_000_000))
    }

    fn name() -> ServerName<'static> {
        ServerName::try_from("n1.nodes.calagopus.internal").unwrap()
    }

    // PinnedCert

    #[test]
    fn pinned_cert_accepts_only_the_configured_digest() {
        let good = cert(b"panel cert");
        let v = PinnedCert::new(sha256(&good), provider());

        assert!(
            v.verify_server_cert(&good, &[], &name(), &[], now())
                .is_ok()
        );
        assert!(
            v.verify_server_cert(&cert(b"other"), &[], &name(), &[], now())
                .is_err()
        );
    }

    // PeerServerVerifier

    #[test]
    fn peer_server_verifier_requires_the_intended_nodes_own_digest() {
        let target = uuid::Uuid::from_u128(1);
        let other = uuid::Uuid::from_u128(2);
        let target_cert = cert(b"target cert");
        let other_cert = cert(b"other node cert");

        let pins = Arc::new(FakePins::default());
        pins.map.lock().insert(sha256(&target_cert), target);
        pins.map.lock().insert(sha256(&other_cert), other);

        let v = PeerServerVerifier::new(target, pins.clone(), provider());
        assert!(
            v.verify_server_cert(&target_cert, &[], &name(), &[], now())
                .is_ok()
        );

        assert!(
            v.verify_server_cert(&other_cert, &[], &name(), &[], now())
                .is_err()
        );
        assert!(
            v.verify_server_cert(&cert(b"nobody"), &[], &name(), &[], now())
                .is_err()
        );
    }

    #[test]
    fn peer_server_verifier_fails_closed_with_no_pin_on_file() {
        let pins = Arc::new(FakePins::default());
        let v = PeerServerVerifier::new(uuid::Uuid::from_u128(1), pins, provider());
        assert!(
            v.verify_server_cert(&cert(b"anything"), &[], &name(), &[], now())
                .is_err()
        );
    }

    // PeerClientVerifier

    #[test]
    fn peer_client_verifier_maps_the_digest_to_a_known_node() {
        let known = cert(b"peer cert");
        let pins = Arc::new(FakePins::default());
        pins.map
            .lock()
            .insert(sha256(&known), uuid::Uuid::from_u128(1));

        let v = PeerClientVerifier::new(pins.clone(), provider());
        assert!(v.client_auth_mandatory());
        assert!(v.verify_client_cert(&known, &[], now()).is_ok());
        assert_eq!(pins.refreshes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn peer_client_verifier_nudges_a_refetch_and_accepts_the_redial() {
        let rotated = cert(b"just re-issued");
        let pins = Arc::new(FakePins::default());
        pins.pending
            .lock()
            .push((sha256(&rotated), uuid::Uuid::from_u128(7)));

        let v = PeerClientVerifier::new(pins.clone(), provider());
        assert!(v.verify_client_cert(&rotated, &[], now()).is_err());
        assert_eq!(pins.refreshes.load(Ordering::Relaxed), 1);

        assert!(v.verify_client_cert(&rotated, &[], now()).is_ok());
        assert_eq!(pins.refreshes.load(Ordering::Relaxed), 1);
    }
}
