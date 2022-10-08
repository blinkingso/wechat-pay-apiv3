use std::collections::HashMap;
use std::time::Duration;

use reqwest::{header::HeaderMap, ClientBuilder};
use serde::{Deserialize, Serialize};

use crate::cons::get_user_agent;

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

/// Build a http client to execute http request.
pub fn build_http_client(connect_timeout: u64, timeout: u64) -> reqwest::Client {
    ClientBuilder::default()
        .connect_timeout(Duration::from_millis(connect_timeout))
        .timeout(Duration::from_millis(timeout))
        .https_only(true)
        .user_agent(get_user_agent())
        .build()
        .unwrap()
}

pub struct HttpClient;

#[cfg(feature = "blocking")]
pub mod blocking {
    use reqwest::blocking::{Client, ClientBuilder};
    impl HttpClient {
        pub fn post<T, R>(url: &str, body: &T) -> Result<R, Box<dyn std::error::Error>> {}
    }
}

pub async fn post<T, R>(url: &str)
where
    T: Serialize,
    R: Deserialize<'static>,
{
}

pub async fn get(url: &str) {}
