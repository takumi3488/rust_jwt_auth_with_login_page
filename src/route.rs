use std::env;

use axum::{routing::get, Router};
use tower_http::services::ServeFile;

use crate::{
    handler::{accept_form, check_token, show_form},
    state::Config,
};

pub async fn init_router() -> Router {
    let hashed_password = env::var("HASHED_PASSWORD").expect("HASHED_PASSWORD must be set");
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    if hashed_password.is_empty() || jwt_secret.is_empty() {
        panic!("HASHED_PASSWORD and JWT_SECRET must be set");
    }
    let exp: i64 = env::var("JWT_EXP")
        .unwrap_or("3600".to_string())
        .parse()
        .expect("JWT_EXP must be a number in seconds");
    let cookie_domain = match env::var("COOKIE_DOMAIN") {
        Ok(domain) => Some(domain),
        Err(_) => None,
    };
    let config = Config {
        hashed_password,
        jwt_secret,
        exp,
        cookie_domain,
    };
    Router::new()
        .route("/", get(show_form).post(accept_form))
        .route("/check", get(check_token))
        .route_service("/style.css", ServeFile::new("style.css"))
        .with_state(config)
}
