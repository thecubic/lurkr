use std::sync::Arc;

use crate::dispatcher::Dispatcher;
use crate::tls;

use rustls::internal::msgs::{
    codec::Reader,
    message::{Message, OpaqueMessage},
};
use tokio::net::TcpStream;

use crate::matcher::Matcher;

pub async fn handle_connection(socket: TcpStream, mymatchlist: Arc<Vec<Matcher>>) {
    let mut peekbuf = [0; 10240];
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

    // TODO: refactor so it peeks a few times

    if peekbuf
        .windows(4)
        .any(move |subslice| subslice == "HTTP".as_bytes())
    {
        log::debug!("HTTP connection detected, this only supports TLS");
        return;
    }

    // Deserialize the TLS ClientHello
    let omsg = OpaqueMessage::read(&mut Reader::init(&peekbuf))
        .expect("couldn't read TLS message")
        .into_plain_message();
    let msg = Message::try_from(omsg).expect("Couldn't decipher message");

    // Extract the SNI payload and determine indicated name
    let session_sni = tls::extract_sni(&msg.payload).await;

    // Core rule-matching; find an appropriate matcher
    // or do the no-mapping procedure
    if let Some(hn) = session_sni {
        let indicated: &str = std::str::from_utf8(&hn.0 .0).unwrap();
        log::debug!("indicated: {:?}", indicated);
        if let Some(dispatcher) = Dispatcher::from_matching(indicated, mymatchlist) {
            dispatcher.do_dispatch(socket).await
        } else {
            // should be unreachable
            panic!("no dispatcher for indicated");
        }
    } else {
        // Didn't get SNI, send to first universal match
        log::debug!("no name indicated");
        if let Some(dispatcher) = Dispatcher::from_matching("", mymatchlist) {
            dispatcher.do_dispatch(socket).await
        } else {
            log::warn!("no dispatcher for zero-string: elvis left the building");
            panic!("zero-string dispatcher missing");
        }
    }
}
