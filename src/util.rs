use axum::http::HeaderMap;
use jsonwebtoken::DecodingKey;
use serde_json::Value;
use tracing::debug;

use crate::state::Config;

pub fn login_html(redirect_to: Option<&str>) -> String {
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

pub fn is_logged_in(headers: &HeaderMap, config: &Config) -> bool {
    debug!("CALLED IS LOGGED IN");
    headers
        .get("cookie")
        .and_then(|cookie| {
            let cookie = cookie.to_str().unwrap();
            let token = cookie.split(';').find(|c| c.starts_with("token="));
            token
                .map(|t| t.split('=').nth(1).unwrap().to_string())
                .map(|t| {
                    let key = DecodingKey::from_secret(config.jwt_secret.as_ref());
                    jsonwebtoken::decode::<Value>(&t, &key, &jsonwebtoken::Validation::default())
                        .ok()
                        .map(|data| data.claims)
                })
        })
        .map(|claims| {
            let now = chrono::Utc::now().timestamp();
            claims.map(|c| c["exp"].as_i64().map(|exp| exp > now).unwrap_or(false))
        })
        .unwrap_or(None)
        .unwrap_or(false)
}