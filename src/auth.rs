//! Http request and response validator module.

use std::io::Bytes;
use std::time::{Duration, SystemTime};

use reqwest::Url;
use security::util::random_string;

use crate::constant::headers::*;
use crate::http::HttpHeaders;
use crate::prelude::*;
use crate::verify::{Verifier, CertificatesVerifier};

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

pub trait Credential {
    /// Get auth type
    fn get_schema(&self) -> String;

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
    ) -> Result<(), Self::Error>;
}
use std::time::UNIX_EPOCH;

use self::signer::SignatureResult;

pub struct WxPay2Validator(CertificatesVerifier);
pub type MerchantId = String;
pub struct WxPay2Credential(MerchantId, RsaSigner);
const RESPONSE_EXPIRED_SECONDS: u64 = 5 * 60;
impl Validator for WxPay2Validator {
    type Response = ();
    type Error = String;

    fn validate(
        &self,
        body: impl AsRef<str>,
        headers: HttpHeaders,
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
        self.0.verify(serial_number, message, signature)
    }
}

const NONCE_LENGTH: usize = 32;
const SCHEMA_PREFIX: &str = "WECHATPAY2-";
impl WxPay2Credential {
    fn get_token(&self, uri: &str, http_method: &str, sign_body: &str) -> String {
        let nonce_str = random_string(NONCE_LENGTH);
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let url = uri.parse::<Url>().unwrap();
        let mut canonical_url = url.path().to_string();
        if let Some(query) = url.query() {
            canonical_url.push('?');
            canonical_url.push_str(query);
        }
        let message = format!(
            "{}\n{}\n{}\n{}\n{}\n",
            http_method, canonical_url, timestamp, nonce_str, sign_body
        );
        debug!("authorization message[{}]", message);
        let signature_result = self.1.sign(message).unwrap();
        let token = format!(
            "mchid=\"{}\",nonce_str=\"{}\",timestamp=\"{}\",searial_no=\"{}\",signature=\"{}\"",
            self.get_merchant_id(),
            nonce_str,
            timestamp,
            signature_result.get_serial_number(),
            signature_result.get_sign()
        );
        debug!("The generated request signature information is[{}]", token);

        token
    }
}
impl Credential for WxPay2Credential {
    fn get_schema(&self) -> String {
        format!("{}{}", SCHEMA_PREFIX, self.1.get_algorithm())
    }

    fn get_merchant_id(&self) -> &str {
        self.0.as_str()
    }

    fn get_authorization(
        &self,
        uri: impl AsRef<str>,
        method: impl AsRef<str>,
        sign: impl AsRef<str>,
    ) -> String {
        format!(
            "{} {}",
            self.get_schema(),
            self.get_token(uri.as_ref(), method.as_ref(), sign.as_ref())
        )
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
