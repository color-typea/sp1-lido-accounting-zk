FROM rust:1.85 AS builder
WORKDIR /usr/src/sp1-lido-zk
# copying this file separately to avoid busting cache and rerunning bootstrap on every file change
COPY docker/docker_build_bootstrap.sh ./docker_build_bootstrap.sh
RUN ./docker_build_bootstrap.sh
# See .dockerignore for list of copied files
COPY . .
ENV PATH="$PATH:/root/.sp1/bin:/root/.foundry/bin"
RUN cargo build --release --locked

# Cannot use alpine because we need glibc, and alpine uses musl. Between compiling for musl
# (only for docker), and using slightly larger base image, the latter seems a lesser evil
FROM debian:stable-slim AS lido_sp1_oracle
RUN apt-get update && apt install -y openssl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/src/sp1-lido-zk/target/release/service /usr/local/bin/service
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["service"]
HEALTHCHECK --interval=30s --timeout=20s --start-period=5s --retries=3 CMD curl -f http://localhost:8080/health || exit 1