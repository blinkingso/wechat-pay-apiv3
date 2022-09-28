//! Module to define `Encryption` and `Decryption` tools.
use aes_gcm::{aead::heapless::Vec, AeadInPlace, Aes256Gcm, KeyInit, Nonce};
use log::*;

pub trait Cipher {
    type Error;

    /// encrypt
    fn encrypt(
        &self,
        key: impl AsRef<[u8]>,
        nonce: impl AsRef<[u8]>,
        text: impl AsRef<[u8]>,
    ) -> Result<String, Self::Error>;
}

/// A function to execute aes-256 gcm alg
pub(crate) fn decrypt(
    key: impl AsRef<[u8]>,
    associated_data: impl AsRef<[u8]>,
    nonce: impl AsRef<[u8]>,
    cipher_text: impl AsRef<[u8]>,
) -> Result<String, String> {
    let cipher = match Aes256Gcm::new_from_slice(key.as_ref()) {
        Ok(key) => key,
        Err(_) => {
            error!("Invalid length for key size: {}", key.as_ref().len());
            return Err("invalid key len".to_string());
        }
    };

    let mut buffer: Vec<u8, 128> = Vec::new();
    buffer
        .extend_from_slice(cipher_text.as_ref())
        .map_err(|e| {
            error!("Failed to extend buffer for: {:?}", e);
            "extend buffer error".to_string()
        })?;
    let nonce = Nonce::from_slice(nonce.as_ref());
    cipher
        .decrypt_in_place(nonce, associated_data.as_ref(), &mut buffer)
        .map_err(|e| {
            error!("Failed to decrypt cipher text for: {:?}", e);
            "decrypt error".to_string()
        })?;
    let buffer = buffer.to_vec();
    let buffer = unsafe { String::from_utf8_unchecked(buffer) };
    Ok(buffer)
}
