use std::any::type_name;

use crate::auth::{WxPay2Credential, WxPay2Validator};

pub(crate) mod headers {
    pub const REQUEST_ID: &str = "Request-ID";
    pub const WECHAT_PAY_SERIAL: &str = "Wechatpay-Serial";
    pub const WECHAT_PAY_SIGNATURE: &str = "Wechatpay-Signature";
    pub const WECHAT_PAY_TIMESTAMP: &str = "Wechatpay-Timestamp";
    pub const WECHAT_PAY_NONCE: &str = "Wechatpay-Nonce";
    pub const USER_AGENT: &str = "User-Agent";
    pub const ACCEPT: &str = "Accept";
    pub const CONTENT_TYPE: &str = "Content-Type";
    pub const AUTHORIZATION: &str = "Authorization";
}

pub fn get_user_agent() -> String {
    let version = env!("CARGO_PKG_VERSION");
    let os_info = os_info::get();
    let os_type = os_info.os_type();
    let os_version = os_info.version();
    format!(
        "WechatPay-Rust/{} ({}/{}.{:?}) Rust/{} Credential/{:?} Validator/{:?} with reqwest",
        version,
        os_type,
        os_version,
        os_info.bitness(),
        "1.66",
        type_name::<WxPay2Credential>().split("::").last().unwrap(),
        type_name::<WxPay2Validator>().split("::").last().unwrap()
    )
}

/// WeiXin Pay host name suffix
pub const WECHAT_PAY_HOST_NAME_SUFFIX: &str = ".mch.weixin.qq.com";

#[cfg(test)]
mod tests {

    #[test]
    fn test_user_agent() {
        println!("{}", super::get_user_agent());
        println!("{}", env!("CARGO_PKG_VERSION"));
        println!("{}", env!("CARGO_PKG_NAME"));
    }
}
