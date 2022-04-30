FROM rust:latest as builder

WORKDIR /usr/src/lurkr
COPY . .
RUN ls -l .
RUN cargo install --path .

# can't use alpine lol
FROM rust:latest as runner
COPY --from=builder /usr/local/cargo/bin/lurkr /usr/local/bin/lurkr

# this means one must mount the config as /lurkr.toml
CMD ["lurkr", "--conf", "lurkr.toml"]

