#[macro_export]
macro_rules! unwrap_or {
    ($expr:expr, $or:expr) => {
        match $expr {
            Some(value) => value,
            None => {
                $or;
            }
        }
    };
}
