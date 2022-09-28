//! Http request and response validator module.

use std::io::Bytes;
use std::time::{Duration, SystemTime};

use crate::constant::headers::*;
use crate::http::HttpHeaders;
use crate::prelude::*;
use crate::verify::Verifier;

pub mod signer {

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
}
pub trait Signer {
    /// Generate sign result str
    fn sign(&self, message: impl AsRef<str>);

    /// Get signature algorithm
    fn get_algorithm(&self) -> &str;
}

pub struct RsaSigner(Bytes<u8>);
impl RsaSigner {
    const ALGORITHM: &str = "SHA256-RSA2048";
}
impl Signer for RsaSigner {
    fn get_algorithm(&self) -> &str {
        Self::ALGORITHM
    }

    fn sign(&self, message: impl AsRef<str>) {
        todo!()
    }
}

pub trait Credential {
    /// Get auth type
    fn get_schema(&self) -> &str;

    /// Get merchant id
    fn get_merchant_id(&self) -> &str;

    /// Get authorization information
    fn get_authorization(
        &self,
        uri: impl AsRef<str>,
        method: impl AsRef<str>,
        sign: impl AsRef<str>,
    ) -> String;
}

pub trait Validator {
    type Response;
    type Error;

    /// To validate whether response headers are valid or not.
    fn validate(
        &self,
        body: impl AsRef<str>,
        headers: HttpHeaders,
        verifier: impl Verifier,
    ) -> Result<(), Self::Error>;
}
use std::time::UNIX_EPOCH;

pub struct WxPayValidator;
pub struct WxPayCredential;
const RESPONSE_EXPIRED_SECONDS: u64 = 5 * 60;
impl Validator for WxPayValidator {
    type Response = ();
    type Error = String;

    fn validate(
        &self,
        body: impl AsRef<str>,
        headers: HttpHeaders,
        verifier: impl Verifier,
    ) -> Result<(), Self::Error> {
        // CHECK TIMESTAMP
        let timestamp = headers
            .get(WECHAT_PAY_TIMESTAMP)
            .ok_or(format!("missing http header {}", WECHAT_PAY_TIMESTAMP))?;
        let now = SystemTime::now();
        let now = now.duration_since(UNIX_EPOCH).unwrap();
        let timestamp = timestamp
            .parse::<u64>()
            .map_err(|_| "timestamp parse error".to_string())?;
        let timestamp_d = Duration::from_secs(timestamp);
        let elapsed = now - timestamp_d;
        if elapsed.as_secs() > RESPONSE_EXPIRED_SECONDS {
            return Err("response is expired".into());
        }
        // CHECK nonce
        let nonce = headers.get(WECHAT_PAY_NONCE).ok_or(format!(
            "missing http header {} not exists",
            WECHAT_PAY_NONCE
        ))?;

        let message = format!("{}\n{}\n{}\n", timestamp, nonce, body.as_ref());
        debug!("Message for verifying signatures is {}", message);
        // CHECK serial number
        let serial_number = headers
            .get(WECHAT_PAY_SERIAL)
            .ok_or(format!("missing http header {}", WECHAT_PAY_SERIAL))?;
        // CHECK signature
        let signature = headers
            .get(WECHAT_PAY_SIGNATURE)
            .ok_or(format!("missing http header {}", WECHAT_PAY_SIGNATURE))?;
        verifier.verify(serial_number, message, signature)
    }
}

const NONCE_LENGTH: i32 = 32;
const SCHEMA_PREFIX: &str = "WECHATPAY2-";

impl Credential for WxPayCredential {
    fn get_schema(&self) -> &str {
        todo!()
    }

    fn get_merchant_id(&self) -> &str {
        todo!()
    }

    fn get_authorization(
        &self,
        uri: impl AsRef<str>,
        method: impl AsRef<str>,
        sign: impl AsRef<str>,
    ) -> String {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;
    #[test]
    fn test_timestamp() {
        let now = SystemTime::now();
        println!("{}", now.elapsed().unwrap().as_secs());
        let now_timestamp = now.duration_since(UNIX_EPOCH).unwrap();
        let time = Duration::from_secs(1663754624);
        let duration = now_timestamp - time;
        println!("{}", duration.as_secs());
    }
}
