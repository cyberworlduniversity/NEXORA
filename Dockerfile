# Build the NEXORA CLI as a small, non-root runtime image.
# This image packages the local CLI; it is not a network service.
FROM rust:1.86-slim-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release -p nexora-cli

FROM debian:bookworm-slim AS runtime
RUN useradd --system --uid 10001 --create-home nexora \
    && mkdir -p /workspace \
    && chown nexora:nexora /workspace
COPY --from=builder /src/target/release/nexora /usr/local/bin/nexora
USER 10001:10001
WORKDIR /workspace
VOLUME ["/workspace"]
ENTRYPOINT ["/usr/local/bin/nexora"]
