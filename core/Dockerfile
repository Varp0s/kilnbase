FROM rust:1.99.1-slim-trixie AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked --bin kilnbase-core

FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=build /src/target/release/kilnbase-core /usr/local/bin/kilnbase-core
EXPOSE 8000
USER nonroot
ENTRYPOINT ["/usr/local/bin/kilnbase-core"]
