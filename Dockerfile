FROM rust:1.79.0-slim-bookworm AS builder

RUN apt-get update && apt-get install -y musl-tools
RUN rustup target add "$(uname -m)"-unknown-linux-musl
WORKDIR /work
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/work/target \
    cargo build --release --target "$(uname -m)"-unknown-linux-musl
RUN strip /work/target/"$(uname -m)"-unknown-linux-musl/release/rust_jwt_auth_with_login_page -o /rust_jwt_auth_with_login_page


FROM gcr.io/distroless/static-debian12

COPY --from=builder /rust_jwt_auth_with_login_page /rust_jwt_auth_with_login_page

CMD ["/rust_jwt_auth_with_login_page"]
