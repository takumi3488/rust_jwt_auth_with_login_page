use std::env;

use axum::{routing::get, Router};
use tower_http::services::ServeFile;

use crate::{
    handler::{accept_form, check_token, show_form},
    state::Config,
};

pub async fn init_router() -> Router {
    // Load environment variables for JWT authentication
    let hashed_password = env::var("HASHED_PASSWORD").ok();
    let jwt_secret = env::var("JWT_SECRET").ok();
    if hashed_password.as_ref().is_none_or(|p| p.is_empty())
        && jwt_secret.as_ref().is_some_and(|s| !s.is_empty())
    {
        panic!("HASHED_PASSWORD must be set if JWT_SECRET is set");
    } else if jwt_secret.as_ref().is_none_or(|s| s.is_empty())
        && !hashed_password.as_ref().is_some_and(|p| !p.is_empty())
    {
        panic!("JWT_SECRET must be set if HASHED_PASSWORD is set");
    }
    let exp: i64 = env::var("JWT_EXP")
        .unwrap_or("3600".to_string())
        .parse()
        .expect("JWT_EXP must be a number in seconds");
    let cookie_domain = match env::var("COOKIE_DOMAIN") {
        Ok(domain) => Some(domain),
        Err(_) => None,
    };

    // Load environment variables for Bearer token authentication
    let hashed_bearer_token = env::var("HASHED_BEARER_TOKEN").ok();

    let config = Config {
        hashed_password,
        jwt_secret,
        exp,
        cookie_domain,
        hashed_bearer_token,
    };
    Router::new()
        .route("/", get(show_form).post(accept_form))
        .route("/check", get(check_token))
        .route_service("/style.css", ServeFile::new("style.css"))
        .with_state(config)
}
