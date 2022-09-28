pub(crate) mod aes;
mod alg;
pub(crate) mod auth;
pub(crate) mod certs;
pub(crate) mod constant;
pub(crate) mod http;
pub(crate) mod macros;
pub(crate) mod verify;

pub mod client;
pub mod notification;
pub mod error;

pub mod prelude {
    // crate use
    pub(crate) use crate::aes::decrypt;
    pub(crate) use crate::constant::*;

    // expose to public
    pub use crate::client::*;
    pub use log::{debug, error, info, warn};
    pub use num_bigint_dig::BigUint;
    pub use serde::{Deserialize, Serialize};
}
