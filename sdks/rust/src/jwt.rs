use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde_json::Value;
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct JwtVerifier {
    jwks_url: String,
    client_id: Option<String>,
    token_use: Option<String>,
    required_scopes: Vec<String>,
    required_org_permissions: Vec<String>,
}

impl JwtVerifier {
    pub fn new(jwks_url: impl Into<String>) -> Self {
        Self { jwks_url: jwks_url.into(), client_id: None, token_use: None, required_scopes: vec![], required_org_permissions: vec![] }
    }

    pub fn client_id(mut self, value: impl Into<String>) -> Self { self.client_id = Some(value.into()); self }
    pub fn token_use(mut self, value: impl Into<String>) -> Self { self.token_use = Some(value.into()); self }
    pub fn required_scopes(mut self, value: Vec<String>) -> Self { self.required_scopes = value; self }
    pub fn required_org_permissions(mut self, value: Vec<String>) -> Self { self.required_org_permissions = value; self }

    pub async fn verify(&self, token: &str) -> Result<Value> {
        let header = decode_header(token)?;
        let kid = header.kid.ok_or_else(|| anyhow!("missing kid"))?;
        let jwks: Value = reqwest::get(&self.jwks_url).await?.json().await?;
        let key = jwks["keys"].as_array().and_then(|keys| keys.iter().find(|k| k["kid"] == kid)).ok_or_else(|| anyhow!("signing key not found"))?;
        let decoding = DecodingKey::from_rsa_components(key["n"].as_str().unwrap_or(""), key["e"].as_str().unwrap_or(""))?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_aud = false;
        let data = decode::<Value>(token, &decoding, &validation)?;
        let claims = data.claims;
        if let Some(client_id) = &self.client_id { if claims["client_id"] != *client_id { return Err(anyhow!("token client mismatch")); } }
        if let Some(token_use) = &self.token_use { if claims["token_use"] != *token_use { return Err(anyhow!("token_use mismatch")); } }
        for scope in &self.required_scopes { if !has_scope(&claims, scope) { return Err(anyhow!("missing scope {}", scope)); } }
        for permission in &self.required_org_permissions { if !has_org_permission(&claims, permission) { return Err(anyhow!("missing organization permission {}", permission)); } }
        Ok(claims)
    }
}

pub fn has_scope(claims: &Value, scope: &str) -> bool {
    claims["scopes"].as_array().map(|v| v.iter().any(|x| x == scope)).unwrap_or(false)
        || claims["scope"].as_str().map(|s| s.split_whitespace().any(|x| x == scope)).unwrap_or(false)
}

pub fn has_org_permission(claims: &Value, permission: &str) -> bool {
    claims["org_role"] == "owner" || claims["org_permissions"].as_array().map(|v| v.iter().any(|x| x == permission)).unwrap_or(false)
}

pub fn verify_webhook_signature(secret: &str, timestamp: &str, signature: &str, body: &[u8], tolerance_seconds: u64) -> bool {
    let ts: u64 = match timestamp.parse() { Ok(v) => v, Err(_) => return false };
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    if now.abs_diff(ts) > tolerance_seconds { return false; }
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac accepts any key");
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body);
    let expected = format!("v1={}", hex::encode(mac.finalize().into_bytes()));
    expected.as_bytes() == signature.as_bytes()
}
