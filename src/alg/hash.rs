use sha2::{digest::core_api::CoreWrapper, Digest, Sha224, Sha256, Sha384, Sha512};

macro_rules! hash_to_string {
    ($hash:ty) => {{
        let name = stringify!($hash);
        let iter = name.split("::");
        iter.last().unwrap().to_lowercase()
    }};
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hash {
    MD5,
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
}

/// Hash algorithm together
pub fn hash(alg: Hash, origin_message: impl AsRef<[u8]>) -> Result<Vec<u8>, String> {
    match alg {
        Hash::SHA256 => {
            let mut digest = Sha256::new();
            digest.update(origin_message);
        }
        _ => return Err(format!("not implemented hash alg: {:?}", alg)),
    };
    Ok(vec![])
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_hash() {
        assert_eq!(hash_to_string!(Hash::SHA1), "sha1");
    }
}

// 农业银行	103100000026 3077493986 6228481453687792218 张胜男
// 工商银行	102100099996 6222032008009832337 陈景生  13138319991
// 工商银行	102100099996 张严军  18206515799    6212261605009751186
// 工商银行	102100099996 6212262010035433447 卢劲强 13680000057
// 工商银行	102100099996 6212264200005533361 狄志宏  17833335553
// 中国银行	104100000004 18777361533 秦丽荣   6217852600003407962
