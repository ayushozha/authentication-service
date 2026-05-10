use anyhow::{anyhow, Result};
use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::{json, Value};

pub mod jwt;
#[cfg(feature = "axum")]
pub mod axum;
#[cfg(feature = "actix")]
pub mod actix;

#[derive(Clone)]
pub struct AuthServiceClient {
    base_url: String,
    api_key: Option<String>,
    admin_key: Option<String>,
    http: reqwest::Client,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
}

impl AuthServiceClient {
    pub fn new(base_url: impl Into<String>, api_key: Option<String>, admin_key: Option<String>) -> Self {
        Self { base_url: base_url.into().trim_end_matches('/').to_string(), api_key, admin_key, http: reqwest::Client::new(), access_token: None, refresh_token: None }
    }

    pub async fn request(&self, method: reqwest::Method, path: &str, body: Option<Value>, admin: bool, auth: bool) -> Result<Value> {
        let mut headers = HeaderMap::new();
        if admin {
            if let Some(key) = &self.admin_key { headers.insert("X-Admin-Key", HeaderValue::from_str(key)?); }
        } else if let Some(key) = &self.api_key {
            headers.insert("X-API-Key", HeaderValue::from_str(key)?);
        }
        if auth {
            if let Some(token) = &self.access_token { headers.insert("Authorization", HeaderValue::from_str(&format!("Bearer {}", token))?); }
        }
        let mut req = self.http.request(method, format!("{}{}", self.base_url, path)).headers(headers);
        if let Some(body) = body { req = req.json(&body); }
        let res = req.send().await?;
        let status = res.status();
        let text = res.text().await?;
        if !status.is_success() { return Err(anyhow!("AuthService {}: {}", status, text)); }
        Ok(if text.is_empty() { json!({}) } else { serde_json::from_str(&text)? })
    }

    pub async fn login(&mut self, email: &str, password: &str) -> Result<Value> {
        let out = self.request(reqwest::Method::POST, "/api/auth/login", Some(json!({"email": email, "password": password, "session_mode": "token"})), false, false).await?;
        self.access_token = out.get("access_token").and_then(|v| v.as_str()).map(str::to_string);
        self.refresh_token = out.get("refresh_token").and_then(|v| v.as_str()).map(str::to_string);
        Ok(out)
    }

    pub async fn me(&self) -> Result<Value> { self.request(reqwest::Method::GET, "/api/auth/me", None, false, true).await }
    pub async fn create_client(&self, body: Value) -> Result<Value> { self.request(reqwest::Method::POST, "/api/admin/clients", Some(body), true, false).await }
    pub async fn create_service_account(&self, client_id: &str, body: Value) -> Result<Value> { self.request(reqwest::Method::POST, &format!("/api/admin/clients/{}/service-accounts", client_id), Some(body), true, false).await }
}
