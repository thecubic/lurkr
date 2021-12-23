# lurkr
an SNI reverse router / proxy

## Usage

`cargo run -- --conf sample.toml --debug`
`cargo build -r && target/release/lurkr --conf sample.toml --debug`

with the sample config it will listen on `localhost:9337`

you can then test connection with the `openssl s_client`:

`openssl s_client -servername blah.google.com -connect localhost:9337`