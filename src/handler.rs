use axum::{
    extract::{Query, State},
    http::{
        header::{LOCATION, SET_COOKIE},
        HeaderMap, StatusCode,
    },
    response::{AppendHeaders, Html, IntoResponse},
    Form,
};
use jsonwebtoken::{DecodingKey, EncodingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::state::Config;

fn login_html(redirect_to: Option<&str>) -> String {
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

#[derive(Deserialize, Debug)]
pub struct FormQuery {
    redirect_to: Option<String>,
}

pub async fn show_form(query: Query<FormQuery>) -> Html<String> {
    Html(login_html(query.redirect_to.as_deref()))
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
pub struct Input {
    password: Option<String>,
    redirect_to: Option<String>,
}
#[derive(Serialize, Debug)]
pub struct Claims {
    pub exp: i64,
}

fn is_logged_in(headers: &HeaderMap, config: &Config) -> bool {
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

pub async fn check_token(State(config): State<Config>, headers: HeaderMap) -> impl IntoResponse {
    if is_logged_in(&headers, &config) {
        StatusCode::OK
    } else {
        StatusCode::UNAUTHORIZED
    }
    .into_response()
}

pub async fn accept_form(
    State(config): State<Config>,
    headers: HeaderMap,
    Form(input): Form<Input>,
) -> impl IntoResponse {
    // Redirect if the user is already logged in
    if is_logged_in(&headers, &config) {
        return (
            StatusCode::SEE_OTHER,
            AppendHeaders([(
                LOCATION,
                input.redirect_to.unwrap_or_else(|| "/".to_string()),
            )]),
        )
            .into_response();
    }

    // Error if no password is provided
    if input.password.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            AppendHeaders([(
                LOCATION,
                format!(
                    "/{}",
                    input
                        .redirect_to
                        .map(|r| format!("?redirect_to={}", r))
                        .unwrap_or_default()
                ),
            )]),
        )
            .into_response();
    }

    let hashed_input_password = format!("{:x}", Sha256::digest(input.password.clone().unwrap()));
    if hashed_input_password == config.hashed_password {
        let key = EncodingKey::from_secret(config.jwt_secret.as_ref());
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        let claims = Claims {
            exp: chrono::Utc::now().timestamp() + config.exp,
        };
        let token = jsonwebtoken::encode(&header, &claims, &key).unwrap();
        (
            StatusCode::SEE_OTHER,
            AppendHeaders([
                (
                    SET_COOKIE,
                    format!(
                        "token={};Domain={};Max-Age={};Path=/;Secure;HttpOnly;SameSite=None",
                        token,
                        config
                            .cookie_domain
                            .as_deref()
                            .unwrap_or(headers.get("host").unwrap().to_str().unwrap()),
                        config.exp,
                    ),
                ),
                (LOCATION, input.redirect_to.unwrap_or("/".to_string())),
            ]),
        )
            .into_response()
    } else {
        (
            StatusCode::SEE_OTHER,
            AppendHeaders([(
                LOCATION,
                format!(
                    "/{}",
                    input
                        .redirect_to
                        .map(|r| format!("?redirect_to={}", r))
                        .unwrap_or_default()
                ),
            )]),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderMap;

    use crate::state::Config;

    use super::*;

    #[test]
    fn test_is_logged_in() {
        let mut headers = HeaderMap::new();
        let config = Config {
            hashed_password: "hashed_password".to_string(),
            jwt_secret: "secret".to_string(),
            exp: 3600,
            cookie_domain: None,
        };

        // No cookie
        assert!(!is_logged_in(&headers, &config));

        // Invalid token
        headers.insert("cookie", "token=invalid".parse().unwrap());
        assert!(!is_logged_in(&headers, &config));

        // Expired token
        let jwt_header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        let claims = Claims {
            exp: chrono::Utc::now().timestamp() - 1,
        };
        let key = jsonwebtoken::EncodingKey::from_secret(config.jwt_secret.as_ref());
        let token = jsonwebtoken::encode(&jwt_header, &claims, &key).unwrap();
        headers.insert("cookie", format!("token={}", token).parse().unwrap());
        assert!(!is_logged_in(&headers, &config));

        // Valid token
        let claims = Claims {
            exp: chrono::Utc::now().timestamp() + 3600,
        };
        let token = jsonwebtoken::encode(&jwt_header, &claims, &key).unwrap();
        headers.insert("cookie", format!("token={}", token).parse().unwrap());
        assert!(is_logged_in(&headers, &config));
    }
}
