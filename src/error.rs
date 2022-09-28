#[derive(Debug, Clone)]
pub enum SdkError {
    DecryptErr(String),
    HttpErr(u16, String),
    MalformedMsgErr,
    ServiceErr,
    ValidationErr,
    WechatPayErr,
}