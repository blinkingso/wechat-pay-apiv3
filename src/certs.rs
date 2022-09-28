//! WeiXin Platform Certificates operations.

/// Auto updating platform certificates in schedule (default value [UPDATE_INTERNAL_MINUTE])
/// [certs-manager] feature must be enabled to start the schedule.
// #[cfg(feature = "certs-manager")]
mod certs_manager {

    use lazy_static::lazy_static;
    use num_bigint_dig::BigUint;
    use std::{
        collections::HashMap,
        str::FromStr,
        sync::{Arc, RwLock},
    };
    use x509_parser::prelude::X509Certificate;

    use crate::{prelude::*, verify::Verifier};

    /// Certificate download url
    const CERT_DOWNLOAD_PATH: &str = "https://api.mch.weixin.qq.com/v3/certificates";

    lazy_static! {
        // cached certificates
        static ref certificates: Arc<RwLock<HashMap<String, HashMap<BigUint, X509Certificate<'static>>>>> =
            Arc::new(RwLock::new(HashMap::new()));
        // cached api-v3-keys
        static ref api_v3_keys: Arc<RwLock<HashMap<String, Vec<u8>>>> = Arc::new(RwLock::new(HashMap::new()));
    }

    struct DefaultVerifier {
        merchant_id: String,
    }

    impl DefaultVerifier {
        pub fn new(merchant_id: impl AsRef<str>) -> Self {
            Self {
                merchant_id: merchant_id.as_ref().to_string(),
            }
        }
    }

    impl Verifier for DefaultVerifier {
        fn verify(
            &self,
            serial_number: impl AsRef<str>,
            message: impl AsRef<[u8]>,
            signature: impl AsRef<str>,
        ) -> Result<(), String> {
            todo!()
        }

        fn get_valid_certificate(&self) -> &[u8] {
            todo!()
        }
    }

    pub(crate) struct CertificateManager;
    impl CertificateManager {
        /// Add a merchant to [CertificateManager] which should auto update certificates
        pub fn push_merchant(
            &mut self,
            merchant_id: impl AsRef<str>,
            api_v3_key: &[u8],
        ) -> Result<(), String> {
            if merchant_id.as_ref().is_empty() {
                return Err("merchant_id is empty".into());
            }
            if certificates
                .read()
                .unwrap()
                .get(merchant_id.as_ref())
                .is_none()
            {
                certificates
                    .write()
                    .unwrap()
                    .insert(merchant_id.as_ref().to_string(), HashMap::new());
            }

            // init_certificate
            init_certificates(merchant_id.as_ref(), api_v3_key);
            todo!()
        }

        /// Get the latest X.509  certificate from [CertificateManager].
        pub fn get_latest_certificate(
            &self,
            merchant_id: &str,
        ) -> Result<X509Certificate<'static>, String> {
            if merchant_id.is_empty() {
                return Err("merchant_id is empty".into());
            }

            let certs = certificates.read().unwrap();
            if let Some(cert_map) = certs.get(merchant_id) {
                if cert_map.is_empty() {
                    return Err(format!(
                        "no certificate found, merchant_id: {}",
                        merchant_id
                    ));
                }
                let mut latest_certificate: Option<&X509Certificate> = None;
                for cert in cert_map.values() {
                    if latest_certificate.is_none()
                        || latest_certificate
                            .as_ref()
                            .unwrap()
                            .validity()
                            .not_before
                            .cmp(&cert.validity().not_before)
                            .is_lt()
                    {
                        latest_certificate = Some(cert);
                    }
                }

                // if certificate date is not valid or expired, should return an error.
                if latest_certificate.unwrap().validity().is_valid() {
                    Ok(latest_certificate.unwrap().clone())
                } else {
                    Err(format!(
                        "certificate is invalid or expired: {}",
                        merchant_id
                    ))
                }
            } else {
                return Err(format!(
                    "no certificate found, merchant_id: {}",
                    merchant_id
                ));
            }
        }
    }

    /// A function to check and init X.509 certificate
    fn init_certificates(merchant_id: impl AsRef<str>, api_v3_key: &[u8]) {}

    fn download_certificate() {
        use reqwest::blocking::{Client, ClientBuilder};
        use reqwest::{
            header::{ACCEPT, USER_AGENT},
            Method,
        };
        // ClientBuilder::default().proxy(proxy)
        let client = Client::new();
        let request = client
            .get(CERT_DOWNLOAD_PATH)
            .header(ACCEPT, "application/json")
            .header(USER_AGENT, "rust/sdk")
            .build();
    }
}
