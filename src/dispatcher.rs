use std::sync::Arc;

use log::debug;
use rand::prelude::SliceRandom;
use rustls::internal::msgs::{
    enums::{AlertDescription, AlertLevel},
    message::{Message, PlainMessage},
};
use tokio::{
    io::{self, AsyncWriteExt},
    net::TcpStream,
};

use crate::{conf::{MappingEntry, TLSKeyCertificateEntry}, matcher::Matcher};

#[derive(Debug, Clone)]
pub enum Dispatcher {
    // represent raw TCP
    TCPDownstreamDispatcher {
        downstreams: Vec<String>,
    },
    // represent a plaintext HTTP connection
    TLSWrappedDownstreamDispatcher {
        downstreams: Vec<String>,
        tls: TLSKeyCertificateEntry,
        // reference to a tls config for upstream term
    },
    // https://github.com/rustls/rustls/blob/5bda754ac18f37eb39132f89fb5522494b6202eb/rustls-mio/examples/tlsserver.rs

    // sends the client one 404 or whatever
    // "help me I can't program" is the best hiding strat
    // TODO: Apache test page?
    HTTPSStaticDispatcher {
        response_code: u8,
        response_body: String,
    },
    HTTPSRedirectDispatcher {
        //
    },
    // you don't want no part of this shit
    // so send them a TLS "PC LOAD LETTER"
    TLSAlertDispatcher {
        alert_level: AlertLevel,
        alert_description: AlertDescription,
        // payload: AlertMessagePayload,
        // alert_level: u8,
        // alert_description: u8,
    },
    // effectively does nothing
    // when the socket goes out of scope, RST
    NothingDispatcher,
}

impl Dispatcher {
    pub async fn do_dispatch(&self, mut clientsock: TcpStream) {
        match self {
            Dispatcher::TCPDownstreamDispatcher { downstreams } => {
                let chosen = downstreams
                    .choose(&mut rand::thread_rng())
                    .expect("no downstreams in dispatcher");
                log::debug!("connect ye to {}", chosen);
                tcp_proxy(clientsock, chosen)
                    .await
                    .expect("couldn't TCP-proxy")
            }
            Dispatcher::TLSAlertDispatcher {
                alert_level,
                alert_description,
            } => {
                clientsock
                    .write(
                        &PlainMessage::try_from(Message::build_alert(
                            *alert_level,
                            *alert_description,
                        ))
                        .expect("couldn't convert alert to PlainMessage")
                        .into_unencrypted_opaque()
                        .encode(),
                    )
                    .await
                    .expect("Error sending TLS alert");
            }
            _ => {}
        }
    }
    // Dispatchers determine how to execute
    pub fn from_mappingentry(me: &MappingEntry) -> Option<Dispatcher> {
        if let Some(downstreams) = &me.downstreams {
            return Some(Dispatcher::TCPDownstreamDispatcher {
                downstreams: downstreams.clone(),
            });
        }
        None
    }
    pub fn from_matching(indicated: &str, matchers: Arc<Vec<Matcher>>) -> Option<Dispatcher> {
        for matcher in matchers.iter() {
            match matcher {
                Matcher::ExactMatcher {
                    rulename,
                    exact,
                    dispatcher,
                } => {
                    if exact.as_str() == indicated {
                        debug!("rule {} matched exact: {}", rulename, indicated);
                        Some(dispatcher)
                    } else {
                        None
                    }
                }
                Matcher::RegexMatcher {
                    rulename,
                    regex,
                    dispatcher,
                } => {
                    if regex.is_match(indicated) {
                        debug!("rule {} regexed: {}", rulename, indicated);
                        Some(dispatcher)
                    } else {
                        None
                    }
                }
                Matcher::UniversalMatcher {
                    rulename,
                    dispatcher,
                } => {
                    debug!("rule {} universal match", rulename);
                    Some(dispatcher)
                }
            };
        }
        None
    }
}

async fn tcp_proxy(mut incoming: TcpStream, addr: &String) -> io::Result<()> {
    let mut outgoing = TcpStream::connect(addr).await?;

    let (mut ri, mut wi) = incoming.split();
    let (mut ro, mut wo) = outgoing.split();

    let left = async {
        tokio::io::copy(&mut ri, &mut wo).await?;
        let sr = wo.shutdown().await;
        if sr.is_err() {
            // eat the socket close error
            Ok(())
        } else {
            sr
        }
    };
    let right = async {
        tokio::io::copy(&mut ro, &mut wi).await?;
        let sr = wi.shutdown().await;
        if sr.is_err() {
            // eat the socket close error
            Ok(())
        } else {
            sr
        }
    };

    tokio::try_join!(left, right)?;
    Ok(())
}

