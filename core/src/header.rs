use crate::prelude::*;
use std::collections::HashMap;

/// A struct to represent Http-Headers
#[derive(Debug, Default, Clone)]
pub struct HttpHeaders(HashMap<String, String>);

impl HttpHeaders {
    /// Create a HttpHeaders instant with headers.
    pub fn new(headers: HashMap<String, String>) -> Self {
        HttpHeaders(headers)
    }

    /// Add a http header
    pub fn insert(&mut self, name: impl AsRef<str>, value: impl AsRef<str>) {
        self.0.insert(name.as_ref().into(), value.as_ref().into());
    }

    /// Try to get an exist http header or return None if not exist
    pub fn get(&self, name: impl AsRef<str>) -> Option<&String> {
        self.0.get(name.as_ref())
    }

    /// Get all http headers
    pub fn get_headers(&self) -> HashMap<String, String> {
        self.0.clone()
    }

    /// Get all http headers
    pub fn get_headers_ref(&self) -> &HashMap<String, String> {
        &self.0
    }
}

impl std::fmt::Display for HttpHeaders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.is_empty() {
            return Ok(());
        }
        let kvs = self
            .0
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<String>>();
        let display = kvs.join(",");
        write!(f, "{}", display)
    }
}

impl From<&HeaderMap> for HttpHeaders {
    fn from(hm: &HeaderMap) -> Self {
        let hh = hm
            .iter()
            .flat_map(|(k, v)| {
                if let Ok(v) = v.to_str() {
                    Some((k.as_str().to_string(), v.to_string()))
                } else {
                    None
                }
            })
            .collect::<HashMap<String, String>>();
        HttpHeaders(hh)
    }
}

impl From<HeaderMap> for HttpHeaders {
    fn from(map: HeaderMap) -> Self {
        HttpHeaders::from(&map)
    }
}

/// wx-pay domains
#[derive(Debug)]
pub struct HostName(&'static str);
impl HostName {
    pub const API: HostName = HostName("api.mch.weixin.qq.com");
    pub const API_HK: HostName = HostName("apihk.mch.weixin.qq.com");

    pub fn get_value(&self) -> &str {
        self.0
    }

    pub fn equals(&self, string: impl AsRef<str>) -> bool {
        string.as_ref().starts_with(self.0)
    }
}

impl std::fmt::Display for HostName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HostName({})", self.0)
    }
}
