FROM rust:1.88-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY core core
COPY api api
RUN cargo build --release -p veyra-api

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /var/lib/veyra --shell /usr/sbin/nologin veyra \
 && install -d -o veyra -g veyra -m 700 /var/lib/veyra
COPY --from=build /src/target/release/veyra-api /usr/local/bin/veyra-api
USER veyra
ENV VEYRA_DATA_DIR=/var/lib/veyra
EXPOSE 4000
HEALTHCHECK --interval=15s --timeout=3s --retries=5 CMD curl -fsS http://127.0.0.1:4000/health || exit 1
ENTRYPOINT ["/usr/local/bin/veyra-api"]
