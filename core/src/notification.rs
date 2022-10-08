use crate::{
    prelude::*,
    verify::{CertificatesVerifier, Verifier},
};

pub trait Request {
    /// A function to get http header `Wechatpay-Serial`
    fn get_serial_number(&self) -> &str;

    /// A function to get bytes to be verified.
    fn get_message(&self) -> &[u8];

    /// A function to get http header `Wechatpay-Signature`
    fn get_signature(&self) -> &str;

    /// A function to get payload.
    fn get_body(&self) -> &str;
}

pub trait Builder {
    type Target;
    fn build(self) -> Self::Target;
}

pub struct NotificationRequestBuilder<'a> {
    serial_number: &'a str,
    timestamp: &'a str,
    nonce: &'a str,
    signature: &'a str,
    body: &'a str,
}

impl<'a> NotificationRequestBuilder<'a> {
    pub fn with_serial_number(&'a mut self, serial_number: impl AsRef<&'a str>) -> &'a mut Self {
        self.serial_number = serial_number.as_ref();
        self
    }

    pub fn with_timestamp(mut self, timestamp: impl AsRef<&'a str>) -> Self {
        self.timestamp = timestamp.as_ref();
        self
    }

    pub fn width_nonce(mut self, nonce: impl AsRef<&'a str>) -> Self {
        self.nonce = nonce.as_ref();
        self
    }

    pub fn with_signature(mut self, signature: impl AsRef<&'a str>) -> Self {
        self.signature = signature.as_ref();
        self
    }

    pub fn with_body(mut self, payload: impl AsRef<&'a str>) -> Self {
        self.body = payload.as_ref();
        self
    }
}

impl Builder for NotificationRequestBuilder<'_> {
    type Target = NotificationRequest;
    fn build(self) -> Self::Target {
        let verify_message = format!("{}\n{}\n{}\n", self.timestamp, self.nonce, self.body);
        let message = verify_message.as_bytes().to_vec();
        NotificationRequest {
            serial_number: self.serial_number.to_string(),
            signature: self.signature.to_string(),
            message,
            body: self.body.to_string(),
        }
    }
}

pub struct NotificationRequest {
    pub serial_number: String,
    pub signature: String,
    pub message: Vec<u8>,
    pub body: String,
}

impl std::fmt::Debug for NotificationRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = String::from_utf8_lossy(self.message.as_slice());
        writeln!(
            f,
            "NotificationRequest={{serial_number={}, signature={}, message={}, body={}}}",
            self.serial_number, self.signature, msg, self.body
        )
    }
}

impl std::fmt::Display for NotificationRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = String::from_utf8_lossy(self.message.as_slice());
        writeln!(
            f,
            "NotificationRequest={{serial_number={}, signature={}, message={}, body={}}}",
            self.serial_number, self.signature, msg, self.body
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Notification {
    pub id: String,
    pub create_time: String,
    pub event_type: String,
    pub resource_type: String,
    pub summary: String,
    pub resource: Resource,
    pub decrypt_data: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Resource {
    pub algorithm: String,
    #[serde(alias = "ciphertext")]
    pub cipher_text: String,
    pub associated_data: Option<String>,
    pub nonce: String,
    pub original_type: String,
}

pub struct NotificationHandler {
    api_v3_key: Vec<u8>,
    verifier: CertificatesVerifier,
}

impl NotificationHandler {
    pub fn new(api_v3_key: impl AsRef<[u8]>, verifier: CertificatesVerifier) -> Self {
        Self {
            api_v3_key: api_v3_key.as_ref().to_vec(),
            verifier,
        }
    }
}

impl NotificationHandler {
    fn set_decrypt_data(&self, notification: &mut Notification) -> Result<(), String> {
        let resource = &notification.resource;
        let associated_data = resource
            .associated_data
            .as_ref()
            .map(|s| s.as_bytes())
            .unwrap_or(b"");
        let nonce = resource.nonce.as_bytes();
        let cipher_text = resource.cipher_text.as_bytes();
        let decrypt_data = decrypt(
            self.api_v3_key.as_slice(),
            associated_data,
            nonce,
            cipher_text,
        )?;
        notification.decrypt_data = Some(decrypt_data);
        Ok(())
    }
    fn is_empty_and_return(value: &str, tag: &str) -> Result<(), String> {
        if value.is_empty() {
            Err(format!("{} is empty", tag))
        } else {
            Ok(())
        }
    }
    fn validate_notification(notification: &Notification) -> Result<(), String> {
        Self::is_empty_and_return(&notification.id, "id")?;
        Self::is_empty_and_return(&notification.create_time, "create_time")?;
        Self::is_empty_and_return(&notification.event_type, "event_type")?;
        Self::is_empty_and_return(&notification.summary, "summary")?;
        Self::is_empty_and_return(&notification.resource_type, "resource_type")?;
        Self::is_empty_and_return(&notification.resource.algorithm, "resource.algorithm")?;
        Self::is_empty_and_return(
            &notification.resource.original_type,
            "resource.original_type",
        )?;
        Self::is_empty_and_return(&notification.resource.cipher_text, "resource.cipher_text")?;
        Self::is_empty_and_return(&notification.resource.nonce, "resource.nonce")?;
        Ok(())
    }
    fn parse_body(&self, payload: &str) -> Result<Notification, String> {
        match serde_json::from_str::<Notification>(payload) {
            Ok(mut notification) => {
                // check notification.
                Self::validate_notification(&notification)?;
                // set decrypt data.
                self.set_decrypt_data(&mut notification)?;
                Ok(notification)
            }
            Err(e) => {
                error!("Failed to parse json to `Notification` for : {:?}", e);
                Err("failed to parse json".to_string())
            }
        }
    }
    pub fn parse(&self, request: impl Request) -> Result<Notification, String> {
        if request.get_serial_number().is_empty() {
            return Err("serial_number is empty".to_string());
        }

        if request.get_message().is_empty() {
            return Err("message is empty".to_string());
        }

        if request.get_signature().is_empty() {
            return Err("signature is empty".to_string());
        }

        self.verifier.verify(
            request.get_serial_number(),
            request.get_message(),
            request.get_signature(),
        )?;

        // parse body
        self.parse_body(request.get_body())
    }
}
