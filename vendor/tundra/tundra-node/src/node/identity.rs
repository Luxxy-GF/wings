use crate::remote::RemoteClient;
use anyhow::Context;
use rcgen::{
    CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{fs, path::Path};
use tundra_common::hash::{Hash32, sha256};

fn load_or_create_key(dir: &Path) -> Result<KeyPair, anyhow::Error> {
    use std::io::Write;

    let path = dir.join("node.key.pem");
    if path.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }

        return KeyPair::from_pkcs8_pem_and_sign_algo(
            &fs::read_to_string(&path)?,
            &PKCS_ECDSA_P256_SHA256,
        )
        .context("failed to load the node key");
    }

    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(&path)
        .context(format!("failed to create {}", path.display()))?
        .write_all(key.serialize_pem().as_bytes())?;

    tracing::info!("generated a new node keypair");

    Ok(key)
}

fn build_csr(key: &KeyPair, uuid: &uuid::Uuid) -> Result<String, anyhow::Error> {
    let dns = format!("n{}.nodes.calagopus.internal", uuid.simple());
    let mut params = CertificateParams::new(Vec::<String>::new())?;

    params.distinguished_name.push(DnType::CommonName, dns);
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ClientAuth,
        ExtendedKeyUsagePurpose::ServerAuth,
    ];

    Ok(params.serialize_request(key)?.pem()?)
}

fn pem_to_der(pem: &str) -> Result<Vec<u8>, anyhow::Error> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    let mut body = String::new();
    for line in pem.lines() {
        if line.starts_with("-----") {
            continue;
        }

        for c in line.chars() {
            if !c.is_whitespace() {
                body.push(c);
            }
        }
    }

    STANDARD
        .decode(body)
        .context("failed to decode the PEM body")
}

pub struct Identity {
    pub uuid: uuid::Uuid,
    pub cert_der: Vec<u8>,
    pub cert_sha256: Hash32,
    key_der: Vec<u8>,
}

impl Identity {
    #[inline]
    pub fn chain(&self) -> Vec<CertificateDer<'static>> {
        vec![CertificateDer::from(self.cert_der.clone())]
    }

    #[inline]
    pub fn key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_der.clone()))
    }

    /// Only used as the TLS server name on a dial: validation is by certificate digest,
    /// not by name.
    #[inline]
    pub fn dns_name_of(uuid: &uuid::Uuid) -> String {
        format!("n{}.nodes.calagopus.internal", uuid.simple())
    }

    pub async fn bootstrap(dir: &Path, remote: &RemoteClient) -> Result<Self, anyhow::Error> {
        fs::create_dir_all(dir).context(format!("failed to create {}", dir.display()))?;

        let key = load_or_create_key(dir)?;
        let assigned = remote
            .identity()
            .await
            .context("failed to ask the control plane who we are")?;

        let cert_path = dir.join("node.crt.pem");
        let local = fs::read_to_string(&cert_path).ok().and_then(|pem| {
            let der = pem_to_der(&pem).ok()?;
            Some((pem, der))
        });

        let cert_der = match local {
            Some((pem, der))
                if assigned.cert_sha256 == Some(sha256(&der)) && !pem.trim().is_empty() =>
            {
                tracing::info!(
                    node = %assigned.uuid,
                    fingerprint = %sha256(&der),
                    "reusing the stored node certificate"
                );
                der
            }
            _ => {
                tracing::info!(
                    node = %assigned.uuid,
                    "requesting a node certificate from the control plane"
                );
                let csr = build_csr(&key, &assigned.uuid)?;
                let pem = remote
                    .submit_csr(&csr)
                    .await
                    .context("failed to submit the CSR")?;
                let der = pem_to_der(&pem)?;
                fs::write(&cert_path, &pem)?;
                tracing::info!(
                    fingerprint = %sha256(&der),
                    "node certificate issued"
                );

                der
            }
        };

        Ok(Self {
            uuid: assigned.uuid,
            cert_sha256: sha256(&cert_der),
            cert_der,
            key_der: key.serialize_der(),
        })
    }

    pub fn from_disk(dir: &Path, uuid: uuid::Uuid) -> Result<Self, anyhow::Error> {
        let key = KeyPair::from_pkcs8_pem_and_sign_algo(
            &fs::read_to_string(dir.join("node.key.pem")).context("failed to read the node key")?,
            &PKCS_ECDSA_P256_SHA256,
        )
        .context("failed to load the node key")?;

        let pem = fs::read_to_string(dir.join("node.crt.pem"))
            .context("failed to read the node certificate")?;
        let cert_der = pem_to_der(&pem)?;
        if cert_der.is_empty() {
            return Err(anyhow::anyhow!("the stored node certificate is empty"));
        }

        Ok(Self {
            uuid,
            cert_sha256: sha256(&cert_der),
            cert_der,
            key_der: key.serialize_der(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // build_csr

    #[test]
    fn build_csr_is_self_signed_and_carries_a_p256_key() {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let uuid = uuid::Uuid::new_v4();
        let pem = build_csr(&key, &uuid).unwrap();

        assert!(pem.contains("BEGIN CERTIFICATE REQUEST"));

        // parsing verifies the CSR self-signature, which is what the panel relies on
        let parsed = rcgen::CertificateSigningRequestParams::from_pem(&pem).unwrap();
        assert_eq!(parsed.public_key.algorithm(), &PKCS_ECDSA_P256_SHA256);
    }

    // load_or_create_key

    #[test]
    fn load_or_create_key_generates_once_and_then_reloads() {
        let dir = std::env::temp_dir().join(format!("tundra-id-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let a = load_or_create_key(&dir).unwrap();
        let b = load_or_create_key(&dir).unwrap();
        assert_eq!(a.serialize_der(), b.serialize_der());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_or_create_key_keeps_the_key_private() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("tundra-id-mode-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("node.key.pem");

        load_or_create_key(&dir).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        load_or_create_key(&dir).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        fs::remove_dir_all(&dir).ok();
    }

    // pem_to_der

    #[test]
    fn pem_to_der_ignores_armour_and_line_breaks() {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(vec!["x.test".to_owned()]).unwrap();
        params.distinguished_name.push(DnType::CommonName, "x.test");
        let cert = params.self_signed(&key).unwrap();

        assert_eq!(pem_to_der(&cert.pem()).unwrap(), cert.der().to_vec());
        assert!(pem_to_der("not base64 !!!").is_err());
    }
}
