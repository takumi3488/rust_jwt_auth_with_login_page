FROM rust:1.79.0-slim-bookworm AS builder

WORKDIR /work

RUN --mount=type=cache,target=/var/cache/apt \
    apt-get update && apt-get install -y musl-tools
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    rustup target add "$(uname -m)"-unknown-linux-musl

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo build --release --target "$(uname -m)"-unknown-linux-musl
RUN strip /work/target/"$(uname -m)"-unknown-linux-musl/release/rust_jwt_auth_with_login_page -o /rust_jwt_auth_with_login_page


FROM gcr.io/distroless/static-debian12

WORKDIR /work
COPY --from=builder /rust_jwt_auth_with_login_page /work/rust_jwt_auth_with_login_page
COPY styles.css /work/styles.css

CMD ["/rust_jwt_auth_with_login_page"]
