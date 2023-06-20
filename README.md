# lurkr
an SNI reverse router / proxy

## Usage

`cargo run -- --conf sample.toml --debug`

or

`cargo build -r && target/release/lurkr --conf sample.toml --debug`

with the sample config it will listen on `localhost:9337`

you can then test connection with the `openssl s_client`:

`openssl s_client -servername blah.google.com -connect localhost:9337`

It will proxy to the selected downstream, and you should expect a server response with a PEM certificate, which you can read with `| openssl x509 -text -noout`

You can test specific hostnames with curl easily
`curl --resolve tlyestotls:9337:127.0.0.1 -k https://tlyestotls:9337/ -v`