FROM rust:1.79 AS builder
WORKDIR /usr/src/sp1-lido-zk
# copying this file separately to avoid busting cache and rerunning bootstrap on every file change
COPY ./docker_build_bootstrap.sh ./docker_build_bootstrap.sh
RUN ./docker_build_bootstrap.sh
COPY . .
ENV PATH="$PATH:/root/.sp1/bin:/root/.foundry/bin"
RUN cargo build --release

FROM debian:bookworm-slim AS lido_sp1_oracle
RUN apt-get update && apt install -y openssl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/src/sp1-lido-zk/target/release/submit /usr/local/bin/submit
CMD ["submit"]