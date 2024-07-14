use std::env;

use axum::{
    extract::{Form, Query, State},
    http::{
        header::{LOCATION, SET_COOKIE},
        HeaderMap, StatusCode,
    },
    response::{AppendHeaders, Html, IntoResponse, Redirect},
    routing::get,
    Router,
};
use jsonwebtoken::EncodingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

fn login_html(redirect_to: Option<&str>) -> String {
    format!(
        "
    <!doctype html>
    <html lang=\"en\">
        <head></head>
        <body>
            <form action=\"/\" method=\"post\">
                <label>
                    Enter your password:
                    <input type=\"password\" name=\"password\">
                </label>
                {}
                <input type=\"submit\" value=\"Subscribe!\">
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

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "example_form=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // build our application with some routes
    let app = init_router().await;

    // run it
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

#[derive(Clone)]
struct Config {
    hashed_password: String,
    jwt_secret: String,
    exp: i64,
    cookie_domain: Option<String>,
}

async fn init_router() -> Router {
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
        .with_state(config)
}

#[derive(Deserialize, Debug)]
struct FormQuery {
    redirect_to: Option<String>,
}

async fn show_form(query: Query<FormQuery>) -> Html<String> {
    Html(login_html(query.redirect_to.as_deref()))
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct Input {
    password: String,
    redirect_to: Option<String>,
}
#[derive(Serialize, Debug)]
struct Claims {
    exp: i64,
}

async fn accept_form(
    State(config): State<Config>,
    headers: HeaderMap,
    Form(input): Form<Input>,
) -> impl IntoResponse {
    let hashed_input_password = format!("{:x}", Sha256::digest(input.password));
    if hashed_input_password == config.hashed_password {
        let key = EncodingKey::from_secret(config.jwt_secret.as_ref());
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        let claims = Claims {
            exp: chrono::Utc::now().timestamp() + config.exp,
        };
        let token = jsonwebtoken::encode(&header, &claims, &key).unwrap();
        (
            StatusCode::TEMPORARY_REDIRECT,
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
        Redirect::temporary(&format!(
            "/{}",
            input
                .redirect_to
                .map(|r| format!("?redirect_to={}", r))
                .unwrap_or_default()
        ))
        .into_response()
    }
}

#[cfg(test)]
mod tests {
    use std::{env, str::from_utf8};

    use axum::{
        body::{to_bytes, Body},
        http::{Method, Request, StatusCode},
    };
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;

    use super::init_router;

    #[tokio::test]
    async fn test_show_form() {
        env::set_var("HASHED_PASSWORD", format!("{:x}", Sha256::digest("1234")));
        env::set_var("JWT_SECRET", "secret");
        let router = init_router().await;
        let response = router
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/?redirect_to=http://example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let text = from_utf8(&body).unwrap();
        assert!(
            text.contains(r#"<input type="hidden" name="redirect_to" value="http://example.com">"#)
        );
    }

    #[tokio::test]
    async fn test_accept_form_with_correct_password() {
        env::set_var(
            "HASHED_PASSWORD",
            format!("{:x}", Sha256::digest("password")),
        );
        env::set_var("JWT_SECRET", "secret");
        let router = init_router().await;
        let response = router
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("host", "localhost")
                    .body(Body::from(
                        "password=password&redirect_to=http://example.com",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        let headers = response.headers();
        assert!(headers.contains_key("set-cookie"));
        assert!(headers
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("token="));
        assert!(headers.contains_key("location"));
        assert_eq!(
            headers.get("location").unwrap().to_str().unwrap(),
            "http://example.com"
        );
    }

    #[tokio::test]
    async fn test_accept_form_with_incorrect_password() {
        env::set_var("HASHED_PASSWORD", format!("{:x}", Sha256::digest("1234")));
        env::set_var("JWT_SECRET", "secret");
        let router = init_router().await;
        let response = router
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("host", "localhost")
                    .body(Body::from("password=2345"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert!(!response.headers().contains_key("set-cookie"));
    }
}
