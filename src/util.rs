use std::env;

use axum::http::HeaderMap;
use jsonwebtoken::DecodingKey;
use serde_json::Value;
use tracing::{debug, trace};

use crate::state::Config;

#[tracing::instrument]
pub fn login_html(redirect_to: Option<&str>) -> String {
    debug!("CALLED LOGIN HTML");
    trace!("redirect_to: {:?}", redirect_to);
    format!(
        "
    <!doctype html>
    <html lang=\"en\">
        <head>
            <meta charset=\"utf-8\">
            <title>Login</title>
            <link rel=\"stylesheet\" href=\"/style.css\">
        </head>
        <body>
            <form action=\"/\" method=\"post\">
                <label>
                    <input type=\"password\" name=\"password\" placeholder=\"Password\">
                </label>
                {}
                <input type=\"submit\" value=\"Login\">
            </form>
        </body>
    </html>
    ",
        redirect_to
            .map(|url| format!(
                "<input type=\"hidden\" name=\"redirect_to\" value=\"{}\">",
                url
            ))
            .unwrap_or_default()
    )
}

#[tracing::instrument]
pub fn is_logged_in(headers: &HeaderMap, config: &Config) -> bool {
    debug!("CALLED IS LOGGED IN");
    trace!("headers: {:?}", headers);
    trace!("config: {:?}", config);
    get_token_from_headers(headers)
        .map(|token| {
            let key = DecodingKey::from_secret(config.jwt_secret.as_ref());
            jsonwebtoken::decode::<Value>(&token, &key, &jsonwebtoken::Validation::default())
                .ok()
                .map(|data| data.claims)
        })
        .map(|claims| {
            let now = chrono::Utc::now().timestamp();
            claims.map(|c| c["exp"].as_i64().map(|exp| exp > now).unwrap_or(false))
        })
        .unwrap_or(None)
        .unwrap_or(false)
}

fn get_token_from_headers(headers: &HeaderMap) -> Option<String> {
    // Check for token in cookie
    let token_key = env::var("TOKEN_KEY").unwrap_or("token".to_string());
    let token_value = headers.get("cookie").and_then(|cookie| {
        cookie
            .to_str()
            .unwrap()
            .split(';')
            .map(|c| c.trim())
            .find(|&c| c.starts_with(&format!("{}=", token_key)))
            .map(|c| c.to_string())
    });

    // Check for token in authorization header
    let api_key_value = headers.get("authorization").and_then(|auth| {
        auth.to_str()
            .ok()
            .and_then(|auth| auth.strip_prefix("Bearer "))
            .map(|auth| auth.to_string())
    });

    token_value
        .map(|t| t.trim().split('=').nth(1).unwrap().to_string())
        .or(api_key_value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_token_from_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            "some_key=some_value; token=some_token;".parse().unwrap(),
        );
        assert_eq!(
            get_token_from_headers(&headers).unwrap(),
            "some_token".to_string()
        );
    }

    #[test]
    fn test_get_api_key_from_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer some_token".parse().unwrap());
        assert_eq!(
            get_token_from_headers(&headers).unwrap(),
            "some_token".to_string()
        );
    }
}
