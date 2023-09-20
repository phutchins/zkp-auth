FROM rust:1.67.0 as builder
RUN apt update
RUN apt install protobuf-compiler -y
WORKDIR /app
COPY . .
RUN cargo install --path .

FROM debian:bullseye-slim
RUN apt-get update & apt-get install -y extra-runtime-dependencies & rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/server /usr/local/bin/server
COPY --from=builder /usr/local/cargo/bin/client /usr/local/bin/client
CMD ["server"]