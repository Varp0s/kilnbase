FROM rust:1.99.1-slim-trixie AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked --bin kilnbase-core && mkdir -p /data

FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=build /src/target/release/kilnbase-core /usr/local/bin/kilnbase-core
# A fresh named volume copies this directory, so it starts out writable by nonroot.
COPY --from=build --chown=65532:65532 /data /data
EXPOSE 8000
USER nonroot
ENTRYPOINT ["/usr/local/bin/kilnbase-core"]
