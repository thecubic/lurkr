use std::sync::Arc;

use crate::dispatcher::Dispatcher;

use rustls::server::Acceptor;
use tokio::net::TcpStream;

use crate::matcher::Matcher;

const PEEK_SIZE: usize = 10240;

pub async fn handle_connection(socket: TcpStream, mymatchlist: Arc<Vec<Matcher>>) {
    let mut peekbuf = [0; PEEK_SIZE];
    // "peek" into the socket to retrieve TLS
    // ClientHello and SNI
    let rsz = socket
        .peek(&mut peekbuf)
        .await
        .expect("couldn't peek from socket");
    // EOF case
    if rsz == 0 {
        return;
    }

    // handle the confused-case where they plaintext HTTP'ed at us
    if peekbuf
        .windows(4)
        .any(move |subslice| subslice == "HTTP".as_bytes())
    {
        log::debug!("HTTP connection detected, this only supports TLS");
        return;
    }

    let mut tls_ponder = Acceptor::default();
    tls_ponder
        .read_tls(&mut &peekbuf[..])
        .expect("couldn't read data from connection");
    match tls_ponder.accept() {
        Ok(None) => {
            // TODO: refactor so it peeks a few times
            log::debug!("haven't consumed a ClientHello");
            return;
        }
        Ok(Some(accepted)) => {
            let ch = accepted.client_hello();
            match ch.server_name() {
                None => {
                    // Didn't get SNI, send to first universal match
                    log::debug!("no name indicated");
                    if let Some(dispatcher) = Dispatcher::from_matching("", mymatchlist) {
                        dispatcher.do_dispatch(socket).await
                    } else {
                        log::warn!("no dispatcher for zero-string: elvis left the building");
                        panic!("zero-string dispatcher missing");
                    }
                }
                Some(sn) => {
                    log::debug!("indicated: {:?}", sn);
                    if let Some(dispatcher) = Dispatcher::from_matching(sn, mymatchlist) {
                        dispatcher.do_dispatch(socket).await
                    } else {
                        // should be unreachable
                        panic!("no dispatcher for indicated");
                    }
                }
            }
        }
        Err((e, alert)) => {
            log::debug!("err: {:?} alert: {:?}", e, alert);
            return;
        }
    }
}
