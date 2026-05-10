use actix_web::{dev::ServiceRequest, Error};
use crate::jwt::JwtVerifier;

pub async fn verify_actix_request(req: &mut ServiceRequest, verifier: &JwtVerifier) -> Result<(), Error> {
    let header = req.headers().get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
    let token = header.strip_prefix("Bearer ").unwrap_or("");
    let claims = verifier.verify(token).await.map_err(actix_web::error::ErrorUnauthorized)?;
    req.extensions_mut().insert(claims);
    Ok(())
}
