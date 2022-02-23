FROM --platform=linux/x86-64 rust:latest as build-env
WORKDIR /app
COPY . /app
RUN cargo build --release

FROM --platform=linux/x86-64 gcr.io/distroless/cc
COPY --from=build-env /app/target/release/mirrord-agent /

CMD ["./mirrord-agent"]