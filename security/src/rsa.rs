//! Rsa Sign/Verify and Encryption/Decryption Methods
use ::rsa::RsaPrivateKey;
use anyhow::Error;
use log::*;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePublicKey, LineEnding};
use rsa::{hash::Hash, PaddingScheme, PublicKey, RsaPublicKey};
use x509_parser::pem::parse_x509_pem;

use crate::hash::{Hash as HashAlg, HashDigest};

/// A trait to abstract `encryption` and `decryption`
pub trait Cipher {
    type Error;

    /// Encrypt with rsa private key
    fn encrypt_with_private_key(
        &self,
        private_key: impl AsRef<[u8]>,
    ) -> Result<Vec<u8>, Self::Error>;

    /// Encrypt with rsa public key
    fn encrypt_with_public_key(
        &self,
        private_key: impl AsRef<[u8]>,
    ) -> Result<Vec<u8>, Self::Error>;

    /// Decrypt with rsa private key
    fn decrypt_with_private_key(
        &self,
        private_key: impl AsRef<[u8]>,
    ) -> Result<Vec<u8>, Self::Error>;

    /// Decrypt with rsa public key.
    fn decrypt_with_public_key(
        &self,
        private_key: impl AsRef<[u8]>,
    ) -> Result<Vec<u8>, Self::Error>;
}

/// Hash and rsa algorithm compositions definition.
/// `Warning`: only `#pkcs8` is supported
pub enum RsaAlgorithm {
    Sha256withRsa,
    Sha512withRsa,
}

impl RsaAlgorithm {
    /// Calculate signature
    pub fn sign(
        &self,
        src: impl AsRef<[u8]>,
        private_key: impl AsRef<str>,
    ) -> Result<String, Error> {
        let pri_key = RsaPrivateKey::from_pkcs8_pem(private_key.as_ref()).map_err(|e| {
            error!("Failed to parse rsa pkcs8 pem for: {:?}", e);
            Error::msg("private key error")
        })?;
        let (hashed, hash) = match self {
            RsaAlgorithm::Sha256withRsa => (HashAlg::Sha256.hash(src), Hash::SHA2_256),
            RsaAlgorithm::Sha512withRsa => (HashAlg::Sha512.hash(src), Hash::SHA2_512),
        };
        let signed = pri_key
            .sign(
                PaddingScheme::PKCS1v15Sign { hash: Some(hash) },
                hashed.as_slice(),
            )
            .map_err(|e| {
                error!("Failed to sign for: {:?}", e);
                Error::msg("sign error")
            })?;
        Ok(base64::encode(signed))
    }

    /// Verify signature
    pub fn verify(
        &self,
        text: impl AsRef<[u8]>,
        signature: impl AsRef<str>,
        public_key_pem: impl AsRef<str>,
    ) -> Result<(), Error> {
        let pb_key = RsaPublicKey::from_public_key_pem(public_key_pem.as_ref()).map_err(|e| {
            error!("Failed to parse RsaPublicKey for: {:?}", e);
            Error::msg("public key parse error")
        })?;
        let (hashed, hash) = match self {
            RsaAlgorithm::Sha256withRsa => (HashAlg::Sha256.hash(text.as_ref()), Hash::SHA2_256),
            RsaAlgorithm::Sha512withRsa => (HashAlg::Sha512.hash(text.as_ref()), Hash::SHA2_512),
        };
        let signature = base64::decode(signature.as_ref()).map_err(|e| {
            error!("Invalid base64 string: {:?}", e);
            Error::msg("invalid base64 str")
        })?;
        pb_key
            .verify(
                PaddingScheme::PKCS1v15Sign { hash: Some(hash) },
                hashed.as_slice(),
                signature.as_slice(),
            )
            .map_err(|e| {
                error!("Failed to verify for: {:?}", e);
                Error::msg("verify error")
            })
    }

    pub fn verify_with_x509(
        &self,
        text: impl AsRef<[u8]>,
        signature: impl AsRef<str>,
        cert: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        // 1. parse certificate
        let (_, pem) = parse_x509_pem(cert.as_ref()).map_err(|e| {
            error!("Failed to parse certificate in pem for: {:?}", e);
            Error::msg("pem parse error")
        })?;
        let x509 = pem.parse_x509().map_err(|e| {
            error!("Failed to parse x.509 for: {:?}", e);
            Error::msg("x509 parse error")
        })?;
        let public_key = x509.public_key().raw;
        // 2. verify pkcs1 pem public key
        // convert pkcs1 pem key to pkcs8
        let pub_key = RsaPublicKey::from_public_key_der(public_key).map_err(|e| {
            error!("Failed to parse public key from x.509 for: {:?}", e);
            Error::msg("public key invalid")
        })?;
        let pub_key_pkcs8 = pub_key.to_public_key_pem(LineEnding::CRLF).map_err(|e| {
            error!("Unable to encode public key to pkcs8: {:?}", e);
            Error::msg("unable to transform pub key")
        })?;
        debug!("public key is: {}", pub_key_pkcs8);
        self.verify(text, signature, pub_key_pkcs8.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs8::EncodePublicKey;
    use rsa::pkcs8::LineEnding;
    use rsa::BigUint;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use x509_parser::public_key::PublicKey;

    const PRIVATE_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAsGZkPZWTiVVioUmwwuY31yJUmYVqnWp/LxQBpfPGygCazbuH
2f0ivCr3dKn67EYWVKvQIDDohz24pgmVd4pbTa99MRNdhXOBSWYIvnnnBt5fzmYW
W72oI0i3poz7qbTwDW2R4/ZXw/p5IKH6k0imyiTYnkNxW1jj1XU+MgjZ2aqGiyp8
xnQ6fx9urbwWYeXiiJkSRp8P69Wo1Q0qxdoyJbfsnSe2Isi+6ELCPO2PYKkp409T
SZM2Nfu/7LmizmyhDSZIzix2IIVhueVBmSOQbdM+kXlLIafo0ef2a3UisMQmsRMr
5xHe86Wv6q0oNCxx60lCpZYU7PxHRQL7ziasHQIDAQABAoIBAGl6kG4SxsnT+Mog
2kVwi+tkZ9n04S+Hws1P1Tx6bF/VxLtIa495wg9qUdW83oHx1uCCbE0TcbeMvKDs
EigM31Own9d8kOt/ictt68SZ9/8vcXJlsPDik2uly8sXelScEP62igoZ/5j8aPmO
Yds4EiPFrJHWGi5ZFMNK/AnHKRzx0CDMqMFI3/aSvtWaz4GmSAP4o2i+Z8MeRV4e
JE9vaOd9L4vhxaHBqcnaPCEcfxjJPFbVqJs9JmvJJQPV0fFsl8IYJUdkVYrq0Z2D
h10SfV4iuJXLOuh6uZEV2yN2VG+kp0oax03HHfi5FibjRGKuJm5f35tzJTV2Klp0
28GkuwECgYEA4o1Wdnkjuq9C7eOeTBWcQQ67Q8JrSkdBh2gwM59R13sZIJbxjUuG
dZoa97z86uSKZ22gxx2lBG5ydwf2MKP4+0uVQvzVmlWY5kn95Y+5taTla3tTpN2g
7hRUcKBwlko78FBgoFUMdAvV33hibkbhvIvjv1jJru2CrMnrFixHSw0CgYEAx1Q1
2MvT0p9551lnrgxIUDjFbljrGZcOUDjrRODYNOOY3yUQIT1u/57fSs32IOjfdt0l
NaXX+QSbIGlAoBT7ad+rXcadglpgp5hssoz+jAy8p8j1fImMulSJHwoc+yeTo22e
VlAaty5sIkmE5bwmZ/HXt1SD2yMEOgd/VT7IYVECgYA0bTy7AeGQzAoS/v+c38tf
CsevMIifkcnKSgQNjirkUKpJ7mRLrFSbVmQzPFrTCLw2nxn7uhJ76gs3HHKOYwO1
M5KBA/1yT6iocir9OrthG52zt8BtgJRDRBUeUyJ6xQcF37PcppHRMQP3SOaOWnzW
oxC7MRLLFk+NKNTsNqbw6QKBgH4qlTK2QUtN2hFPi8qkx5jPdlgUPCska9DnVjNw
xikj7n0/rmf7xKhT3S4yE5pdDCTmcUj1wjBCdBYdyOQKo+AtzQA8WTJLFma+mf6i
M/Rdk4P4NTowrjy6iVh2REXMlSyak+A6L87GuXcyZcYsQ3sDnvDRs+wey+wXFsfU
R20hAoGAG3TW1M4lNpB1M454dAr+Aq3FDuH0Zpizp2CHfl51BQ/pflj5sQUXa637
fyaXwl+ZevxC8/dTzrlnV0EHgN91l7Hd7ajjOAMoMYiV4P01XQSsqi5avCkzG4e2
n1rq3kDJx6hBxFXqUFzHRzBuEVgfvz/Q9NUZTb/2i9FGzDWiTjc=
-----END RSA PRIVATE KEY-----";
    const _PUBLIC_KEY: &str = "-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAsGZkPZWTiVVioUmwwuY31yJUmYVqnWp/LxQBpfPGygCazbuH2f0i
vCr3dKn67EYWVKvQIDDohz24pgmVd4pbTa99MRNdhXOBSWYIvnnnBt5fzmYWW72o
I0i3poz7qbTwDW2R4/ZXw/p5IKH6k0imyiTYnkNxW1jj1XU+MgjZ2aqGiyp8xnQ6
fx9urbwWYeXiiJkSRp8P69Wo1Q0qxdoyJbfsnSe2Isi+6ELCPO2PYKkp409TSZM2
Nfu/7LmizmyhDSZIzix2IIVhueVBmSOQbdM+kXlLIafo0ef2a3UisMQmsRMr5xHe
86Wv6q0oNCxx60lCpZYU7PxHRQL7ziasHQIDAQAB
-----END RSA PUBLIC KEY-----";

    static CERT_PRIVATE_KEY: &str = include_str!("/Users/andrew/Downloads/shitu/apiclient_key.pem");
    static CERT_DER: &[u8] = include_bytes!("/Users/andrew/Downloads/shitu/apiclient_cert.pem");

    #[test]
    fn test_sign_verify() {
        pretty_env_logger::init();

        let pem = pem::parse(PRIVATE_KEY).unwrap();
        let contents = base64::encode(&pem.contents);
        println!("{}\n{}", pem.tag, contents);

        let pri_key = RsaPrivateKey::from_pkcs1_der(pem.contents.as_slice()).unwrap();
        let _pub_key = pri_key.to_public_key();
        let (_, pem) = x509_parser::pem::parse_x509_pem(CERT_DER).expect("failed to parse pem");
        let x509 = pem.parse_x509().unwrap();
        let pb_key = x509.public_key().parsed().unwrap();
        println!("{}", pb_key.key_size());
        if let PublicKey::RSA(key) = &pb_key {
            let m = key.modulus;
            let e = key.exponent;
            let m = BigUint::from_bytes_be(m);
            let e = BigUint::from_bytes_be(e);
            let pb_key = RsaPublicKey::new(m, e).unwrap();
            let pb_key_pkcs8_pem = pb_key.to_public_key_pem(LineEnding::CRLF).unwrap();
            println!("{}", pb_key_pkcs8_pem);
        }

        let origin = b"hello world";
        let sign = RsaAlgorithm::Sha256withRsa
            .sign(origin, CERT_PRIVATE_KEY)
            .unwrap();
        println!("sign: {}", sign);
        let verify = RsaAlgorithm::Sha256withRsa.verify_with_x509(origin, sign.as_str(), CERT_DER);
        if verify.is_ok() {
            info!("verify ok");
        } else {
            error!("verify failed");
        }
    }
}
