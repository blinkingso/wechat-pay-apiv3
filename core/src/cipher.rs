#[derive(Debug, Clone)]
pub struct SignatureResult {
    pub signature: String,
    pub certificate_serial_number: String,
}

impl SignatureResult {
    #[must_use]
    pub fn new(signature: String, certificate_serial_number: String) -> Self {
        Self {
            signature,
            certificate_serial_number,
        }
    }

    pub fn get_sign(&self) -> &str {
        self.signature.as_str()
    }

    pub fn get_serial_number(&self) -> &str {
        self.certificate_serial_number.as_str()
    }
}

impl std::fmt::Display for SignatureResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{signature: {}, serial_number: {}}}",
            self.get_sign(),
            self.get_serial_number()
        )
    }
}
pub trait Signer {
    /// Generate sign result str
    fn sign(&self, message: impl AsRef<str>) -> Result<SignatureResult, String>;

    /// Get signature algorithm
    fn get_algorithm(&self) -> &str;
}

/// `#PKCS8` private key
pub struct RsaSigner(Vec<u8>);
impl RsaSigner {
    const ALGORITHM: &str = "SHA256-RSA2048";
}
impl Signer for RsaSigner {
    fn get_algorithm(&self) -> &str {
        Self::ALGORITHM
    }

    fn sign(&self, message: impl AsRef<str>) -> Result<SignatureResult, String> {
        todo!()
    }
}
