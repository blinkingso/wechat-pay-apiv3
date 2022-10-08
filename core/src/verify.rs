use num_bigint_dig::BigUint;
use security::prelude::*;
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
        // verify_with_x509_pem(certificate, message, signature)
        todo!()
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
