use config::Map;
use rand::prelude::SliceRandom;
use rustls::{
    internal::msgs::{
        enums::{AlertDescription, AlertLevel},
        message::{Message, PlainMessage},
    },
    server::Acceptor,
    ServerConfig,
};
use std::{
    collections::HashMap,
    fmt::{Error, Formatter},
    sync::Arc,
};
use tokio::{
    io::{self, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{server::TlsStream, TlsAcceptor};

use crate::{
    conf::{MappingEntry, TLSKeyCertificateEntry},
    matcher::Matcher,
};

impl std::fmt::Debug for Dispatcher {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dispatcher").finish()
    }
}

// impl std::fmt::Debug for tokio_rustls::TlsAcceptor {
//     fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
//         f.debug_struct("Dispatcher").finish()
//     }
// }

// -Debug because TlsAcceptor
#[derive(Clone)]
pub enum Dispatcher {
    // represent raw TCP
    TCPDownstreamDispatcher {
        downstreams: Vec<String>,
    },
    // represent a plaintext connection, like stunnel
    TLSWrappedDownstreamDispatcher {
        downstreams: Vec<String>,
        // reference to a tls acceptor for upstream term
        acceptor: Arc<TlsAcceptor>,
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
                tcp_proxy_addr(clientsock, chosen)
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
            Dispatcher::TLSWrappedDownstreamDispatcher {
                downstreams,
                acceptor,
            } => {
                let chosen = downstreams
                    .choose(&mut rand::thread_rng())
                    .expect("no downstreams in dispatcher");
                log::debug!("TLS-term and connect to {}", chosen);
                tls_proxy_addr(clientsock, chosen, acceptor.clone())
                    .await
                    .expect("couldn't TLS-proxy");
            }
            _ => {}
        }
    }
    // Dispatchers determine how to execute
    pub fn from_mappingentry(me: &MappingEntry) -> Option<Dispatcher> {
        // if me.tls.is_some() && me.downstreams.is_some() {
        // }
        if let Some(downstreams) = &me.downstreams {
            return Some(Dispatcher::TCPDownstreamDispatcher {
                downstreams: downstreams.clone(),
            });
        }
        None
    }

    pub fn from_mappingentry_tlses(
        me: &MappingEntry,
        tlses: Arc<HashMap<String, Arc<TlsAcceptor>>>,
    ) -> Option<Dispatcher> {
        if let Some(downstreams) = &me.downstreams {
            if let Some(tlsname) = &me.tls_config {
                log::debug!("TLSWrappedDownstreamDispatcher");
                if let Some(acceptor) = tlses.get(tlsname) {
                    log::debug!("found tls acceptor");
                    return Some(Dispatcher::TLSWrappedDownstreamDispatcher {
                        downstreams: downstreams.clone(),
                        acceptor: acceptor.clone(),
                    });
                } else {
                    log::debug!("not found tls acceptor");
                    return None;
                }
            } else {
                log::debug!("TCPDownstreamDispatcher");
                return Some(Dispatcher::TCPDownstreamDispatcher {
                    downstreams: downstreams.clone(),
                });
            }
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
                        log::debug!("rule {} matched exact: {}", rulename, indicated);
                        return Some(dispatcher.clone());
                    }
                }
                Matcher::RegexMatcher {
                    rulename,
                    regex,
                    dispatcher,
                } => {
                    if regex.is_match(indicated) {
                        log::debug!("rule {} regexed: {}", rulename, indicated);
                        return Some(dispatcher.clone());
                    }
                }
                Matcher::UniversalMatcher {
                    rulename,
                    dispatcher,
                } => {
                    log::debug!("rule {} universal match", rulename);
                    return Some(dispatcher.clone());
                }
            }
        }
        None
    }
}

async fn tcp_proxy_addr(mut incoming: TcpStream, addr: &String) -> io::Result<()> {
    let mut outgoing = TcpStream::connect(addr).await?;
    tcp_proxy_stream(incoming, outgoing).await
}

async fn tcp_proxy_stream(mut incoming: TcpStream, mut outgoing: TcpStream) -> io::Result<()> {
    let (mut ri, mut wi) = incoming.split();
    let (mut ro, mut wo) = outgoing.split();

    let left = async move {
        tokio::io::copy(&mut ri, &mut wo).await?;
        let sr = wo.shutdown().await;
        if sr.is_err() {
            // eat the socket close error
            Ok(())
        } else {
            sr
        }
    };
    let right = async move {
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

async fn tls_proxy_stream(
    mut incoming: TlsStream<TcpStream>,
    mut outgoing: TcpStream,
) -> io::Result<()> {
    let (mut ri, mut wi) = tokio::io::split(incoming);
    let (mut ro, mut wo) = tokio::io::split(outgoing);

    let left = async move {
        tokio::io::copy(&mut ri, &mut wo).await?;
        let sr = wo.shutdown().await;
        if sr.is_err() {
            // eat the socket close error
            Ok(())
        } else {
            sr
        }
    };
    let right = async move {
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

async fn tls_proxy_addr(
    mut incoming: TcpStream,
    addr: &String,
    acceptor: Arc<TlsAcceptor>,
) -> io::Result<()> {
    let mut outgoing = TcpStream::connect(addr).await?;
    let mut plaintext_stream = acceptor.accept(incoming).await?;
    tls_proxy_stream(plaintext_stream, outgoing).await
}
