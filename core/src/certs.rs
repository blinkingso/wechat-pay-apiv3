use crate::prelude::X509Certificate;

use num_bigint_dig::BigUint;
use std::{
    cmp::Ordering,
    collections::HashMap,
    str::FromStr,
    sync::{Arc, RwLock},
};

use lazy_static::lazy_static;

/// WxPay platform certificate provider
pub trait CertificateProvider {
    fn get_certificate(&self, serial_number: &str) -> Option<X509Certificate>;

    fn get_available_certificate(&self) -> Option<&X509Certificate>;
}

lazy_static! {

    /// Certificates in memory
    pub(crate) static ref IN_MEMOERY_CERTIFICATES: Arc<RwLock<HashMap<BigUint, X509Certificate<'static>>>> =
        Arc::new(RwLock::new(HashMap::new()));
}

/// A simple certificates provider, all certificates stored in memory with a `HashMap`
pub struct InMemoryCertificateProvider<'a>(Option<X509Certificate<'a>>);

impl<'a> InMemoryCertificateProvider<'a> {
    pub fn init(certificates: Vec<X509Certificate<'static>>) -> Self {
        let mut lock = IN_MEMOERY_CERTIFICATES.write().unwrap();

        // get an avaliable certificate.
        let mut longest: Option<X509Certificate> = None;
        for cert in certificates {
            let serial_number = &cert.serial;
            let serial_number = BigUint::from_bytes_be(serial_number.to_bytes_be().as_slice());

            if longest.is_none()
                || longest
                    .as_ref()
                    .unwrap()
                    .validity()
                    .not_after
                    .cmp(&cert.validity().not_after)
                    == Ordering::Less
            {
                longest = Some(cert.clone());
            }

            lock.insert(serial_number, cert);
        }

        Self(longest)
    }
}

impl CertificateProvider for InMemoryCertificateProvider<'_> {
    fn get_certificate(&self, serial_number: &str) -> Option<X509Certificate> {
        let serial_number = BigUint::from_str(serial_number).unwrap();
        match IN_MEMOERY_CERTIFICATES.read().unwrap().get(&serial_number) {
            None => None,
            Some(certificate) => Some(certificate.clone()),
        }
    }

    fn get_available_certificate(&self) -> Option<&X509Certificate> {
        self.0.as_ref()
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_serial_number() {
        use num_bigint_dig::BigUint;
        use std::str::FromStr;
        let serial_number = "458609";
        let serial_number = BigUint::from_str(serial_number).unwrap();
        assert_eq!(BigUint::new(vec![458609]), serial_number);
    }
}
