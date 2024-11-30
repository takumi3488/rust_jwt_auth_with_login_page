#[derive(Clone, Debug)]
pub struct Config {
    pub hashed_password: Option<String>,
    pub jwt_secret: Option<String>,
    pub exp: i64,
    pub cookie_domain: Option<String>,
    pub hashed_bearer_token: Option<String>,
}
