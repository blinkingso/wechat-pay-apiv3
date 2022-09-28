use std::boxed::Box;

/// Error result definition
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
