use axum::{extract::State, http::Request, middleware::Next, response::Response};
use crate::jwt::JwtVerifier;

pub async fn authservice_middleware<B>(State(verifier): State<JwtVerifier>, mut request: Request<B>, next: Next<B>) -> Result<Response, axum::http::StatusCode> {
    let header = request.headers().get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
    let token = header.strip_prefix("Bearer ").unwrap_or("");
    let claims = verifier.verify(token).await.map_err(|_| axum::http::StatusCode::UNAUTHORIZED)?;
    request.extensions_mut().insert(claims);
    Ok(next.run(request).await)
}
