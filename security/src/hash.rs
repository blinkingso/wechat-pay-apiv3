#[cfg(feature = "__sha1")]
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};

use crate::hash_alg;

pub trait HashDigest {
    /// A hash function
    fn hash(&self, src: impl AsRef<[u8]>) -> Vec<u8>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hash {
    #[cfg(feature = "__md5")]
    Md5,
    #[cfg(feature = "__sha1")]
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl std::fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "__md5")]
            Hash::Md5 => "md5".fmt(f),
            #[cfg(feature = "__sha1")]
            Hash::Sha1 => "sha1".fmt(f),
            Hash::Sha224 => "sha224".fmt(f),
            Hash::Sha256 => "sha256".fmt(f),
            Hash::Sha384 => "sha384".fmt(f),
            Hash::Sha512 => "sha512".fmt(f),
        }
    }
}

impl HashDigest for Hash {
    fn hash(&self, src: impl AsRef<[u8]>) -> Vec<u8> {
        match self {
            #[cfg(feature = "__md5")]
            Hash::Md5 => md5::compute(src).0.to_vec(),
            #[cfg(feature = "__sha1")]
            Hash::Sha1 => hash_alg!(Sha1, src),
            Hash::Sha224 => hash_alg!(Sha224, src),
            Hash::Sha256 => hash_alg!(Sha256, src),
            Hash::Sha384 => hash_alg!(Sha384, src),
            Hash::Sha512 => hash_alg!(Sha512, src),
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_hash() {
        use super::{Hash, HashDigest};
        let src = b"Hello World";
        #[cfg(feature = "__md5")]
        {
            let hash = Hash::Md5.hash(src);
            println!("Md5: {}", base64::encode(hash));
        }
        #[cfg(feature = "__sha1")]
        {
            let hash = Hash::Sha1.hash(src);
            println!("Sha1: {}", base64::encode(hash));
        }
        let hash = Hash::Sha224.hash(src);
        println!("Sha224: {}", base64::encode(hash));
        let hash = Hash::Sha256.hash(src);
        println!("Sha256: {}", base64::encode(hash));
        let hash = Hash::Sha384.hash(src);
        println!("Sha384: {}", base64::encode(hash));
        let hash = Hash::Sha512.hash(src);
        println!("Sha512: {}", base64::encode(hash));
    }
}
