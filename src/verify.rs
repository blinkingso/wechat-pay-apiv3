use crate::prelude::*;
use std::collections::HashMap;

pub trait Verifier {
    /// A function to verify signature
    fn verify(
        &self,
        serial_number: impl AsRef<str>,
        message: impl AsRef<[u8]>,
        signature: impl AsRef<str>,
    ) -> Result<(), String>;

    /// A function to get x509 certificate bytes in `[u8]`
    fn get_valid_certificate(&self) -> &[u8];
}

/// Verify with certificates.
pub struct CertificatesVerifier(HashMap<BigUint, Vec<u8>>);

impl CertificatesVerifier {
    pub fn new() -> Self {
        CertificatesVerifier(HashMap::new())
    }

    pub fn update_certificates(&mut self, certificates: HashMap<BigUint, Vec<u8>>) {
        self.0.clear();
        self.0.extend(certificates.into_iter());
    }

    fn __verify(certificate: &[u8], message: &[u8], signature: &str) -> Result<(), String> {
        verify_with_x509_pem(certificate, message, signature)
    }
}

impl Verifier for CertificatesVerifier {
    fn verify(
        &self,
        serial_number: impl AsRef<str>,
        message: impl AsRef<[u8]>,
        signature: impl AsRef<str>,
    ) -> Result<(), String> {
        let val = BigUint::parse_bytes(serial_number.as_ref().as_bytes(), 16).unwrap();
        let cert = self.0.get(&val);
        if cert.is_none() {
            error!(
                "Can't found certificate with serial number: {}",
                serial_number.as_ref()
            );
            return Err("certificate not found".to_string());
        }
        Self::__verify(cert.as_ref().unwrap(), message.as_ref(), signature.as_ref())
    }

    fn get_valid_certificate(&self) -> &[u8] {
        todo!()
    }
}

/// A function to verify signature with x509 certificate in [PEM] format
///
/// # Params
///
/// * cert: A `x509` certificate in `PEM` format
/// * text_bytes: Origin text in bytes
/// * signature: A signed text represent signature
///
/// # Returns
///
/// logging error detail msg and return an empty `()` if verification equals `true`
///
pub fn verify_with_x509_pem(
    cert: impl AsRef<[u8]>,
    text_bytes: impl AsRef<[u8]>,
    signature: impl AsRef<str>,
) -> Result<(), String> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::{hash::Hash, PaddingScheme, PublicKey, RsaPublicKey};
    use sha2::{Digest, Sha256};
    use x509_parser::pem::parse_x509_pem;
    match parse_x509_pem(cert.as_ref()) {
        Ok((_, cert)) => match cert.parse_x509() {
            Ok(cert) => {
                let pub_key = cert.public_key();
                match RsaPublicKey::from_pkcs1_der(pub_key.raw) {
                    Ok(pub_key) => {
                        let mut digest = Sha256::new();
                        digest.update(text_bytes.as_ref());
                        let hashed = digest.finalize();
                        let sig = base64::decode(signature.as_ref()).unwrap();
                        pub_key
                            .verify(
                                PaddingScheme::PKCS1v15Sign {
                                    hash: Some(Hash::SHA2_256),
                                },
                                &hashed[..],
                                sig.as_slice(),
                            )
                            .map_err(|e| {
                                error!("Failed to verify for: {}", e);
                                "verify error".to_string()
                            })?
                    }
                    Err(e) => {
                        error!("Failed to load pkcs1 public key in der for: {}", e);
                        return Err("invalid public key".into());
                    }
                }
            }
            Err(e) => {
                error!("Failed to parse certificate for: {:?}", e);
                return Err("cert parse error".into());
            }
        },
        Err(e) => {
            error!(
                "Failed to load certificate, please check if your cert is in PEM format: {}",
                e
            );
            return Err("cert load error".into());
        }
    }
    Ok(())
}
