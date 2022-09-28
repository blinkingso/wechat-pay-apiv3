#[macro_export]
macro_rules! hash_alg {
    (
        $hash:ident, $src:expr
    ) => {{
        let mut digest = $hash::new();
        digest.update($src);
        digest.finalize().to_vec()
    }};
}
