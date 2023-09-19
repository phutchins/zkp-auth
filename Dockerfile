FROM rust:1.67

WORKDIR /usr/src/zkp-auth
#COPY ./target/release/server /usr/local/bin/server
#COPY ./target/release/client /usr/local/bin/client

CMD ["server"]