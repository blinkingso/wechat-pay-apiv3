pub(crate) mod headers {
    pub const REQUEST_ID: &str = "Request-ID";
    pub const WECHAT_PAY_SERIAL: &str = "Wechatpay-Serial";
    pub const WECHAT_PAY_SIGNATURE: &str = "Wechatpay-Signature";
    pub const WECHAT_PAY_TIMESTAMP: &str = "Wechatpay-Timestamp";
    pub const WECHAT_PAY_NONCE: &str = "Wechatpay-Nonce";
}

/// WeiXin Pay host name suffix
pub const WECHAT_PAY_HOST_NAME_SUFFIX: &str = ".mch.weixin.qq.com";
