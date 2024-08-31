# rust_jwt_auth_with_login_page

Login page for Nginx `auth_request`. See e2e.conf for example.

## Environment variables

`HASHED_PASSWORD`: password hashed with sha256

`JWT_SECRET`: The private key used to encrypt JWT.

`JWT_EXP`: JWT lifetime in seconds (default: 3600).

`COOKIE_DOMAIN`: domain attribute of the jwt cookie (default: host of the URL specified in redirect_to)
