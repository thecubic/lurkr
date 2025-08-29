FROM rust:latest AS builder

LABEL org.opencontainers.image.source=https://github.com/thecubic/lurkr
LABEL org.opencontainers.image.authors="thecubic@thecubic.net"

WORKDIR /usr/src/lurkr
COPY . .
RUN ls -l .
RUN cargo install --path .

# can't use alpine lol
FROM rust:latest as runner
COPY --from=builder /usr/local/cargo/bin/lurkr /usr/local/bin/lurkr

# this means one must mount the config as /lurkr.toml

ENTRYPOINT ["/usr/local/bin/lurkr"]

#CMD ["--conf", "lurkr.toml"]
CMD ["--debug", "--conf", "lurkr.toml"]

