FROM rust:1-bookworm AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release

FROM smallstep/step-cli:0.30.2 AS step-cli

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 portal \
    && useradd --system --uid 10001 --gid portal --home-dir /nonexistent --shell /usr/sbin/nologin portal

COPY --from=builder /build/target/release/eap-tls-cert-portal /usr/local/bin/eap-tls-cert-portal
COPY --from=step-cli /usr/local/bin/step /usr/local/bin/step
COPY --chown=portal:portal static /app/static

USER 10001:10001
WORKDIR /app
ENV HOME=/tmp \
    STEPPATH=/tmp/step
EXPOSE 3000

ENTRYPOINT ["/usr/local/bin/eap-tls-cert-portal"]
