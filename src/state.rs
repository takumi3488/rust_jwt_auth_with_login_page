#[derive(Clone)]
pub struct Config {
    pub hashed_password: String,
    pub jwt_secret: String,
    pub exp: i64,
    pub cookie_domain: Option<String>,
}
