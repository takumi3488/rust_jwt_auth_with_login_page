mod handler;
mod route;
mod state;
mod util;

use route::init_router;

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "rust_jwt_auth_with_login_page=debug,tower_http=debug,axum::rejection=trace".into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // build our application with some routes
    let app = init_router().await;

    // run it
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

#[cfg(test)]
#[serial_test::serial]
mod tests {
    use std::{env, str::from_utf8};

    use axum::{
        body::{to_bytes, Body},
        http::{Method, Request, StatusCode},
    };
    use jsonwebtoken::EncodingKey;
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;

    use crate::handler::Claims;

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
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
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
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert!(!response.headers().contains_key("set-cookie"));
    }

    #[tokio::test]
    async fn test_accept_form_with_no_password() {
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
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_accept_form_with_cookie() {
        env::set_var("HASHED_PASSWORD", format!("{:x}", Sha256::digest("1234")));
        env::set_var("JWT_SECRET", "secret");
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        let claims = Claims {
            exp: chrono::Utc::now().timestamp() + 3600i64,
        };
        let key = EncodingKey::from_secret("secret".as_ref());
        let router = init_router().await;
        let response = router
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("host", "localhost")
                    .header(
                        "cookie",
                        &format!(
                            "token={}",
                            jsonwebtoken::encode(&header, &claims, &key).unwrap()
                        ),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert!(response.headers().contains_key("location"));
    }

    #[tokio::test]
    async fn test_get_style() {
        env::set_var("HASHED_PASSWORD", format!("{:x}", Sha256::digest("1234")));
        env::set_var("JWT_SECRET", "secret");
        let router = init_router().await;
        let response = router
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/style.css")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let text = from_utf8(&body).unwrap();
        assert!(text.contains("body"));
    }
}
