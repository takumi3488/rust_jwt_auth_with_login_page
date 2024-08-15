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

pub async fn accept_form(
    State(config): State<Config>,
    headers: HeaderMap,
    Form(input): Form<Input>,
) -> impl IntoResponse {
    // Redirect if the user is already logged in
    let payload = headers.get("cookie").and_then(|cookie| {
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
    });
    if payload.is_some() {
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
