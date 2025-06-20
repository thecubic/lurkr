use rand::seq::IndexedRandom;
use rustls::internal::msgs::{
    enums::{AlertDescription, AlertLevel},
    message::{Message, PlainMessage},
};
use std::{collections::HashMap, fmt::Formatter, sync::Arc};
use tokio::{
    io::{self, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{server::TlsStream, TlsAcceptor};

use crate::{conf::MappingEntry, https::https_answer_request, matcher::Matcher};

impl std::fmt::Debug for Dispatcher {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // TODO: make this not shit
        f.debug_struct("Dispatcher").finish()
    }
}

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

    // sends the client one 404 or whatever
    // "help me I can't program" is the best hiding strat
    // can't put body because String on heap and not Copy
    // gotta fix that
    HTTPSStaticDispatcher {
        response_code: u16,
        acceptor: Arc<TlsAcceptor>,
    },

    // NOT IMPLEMENTED
    // HTTPSRedirectDispatcher {
    //     //
    // },

    // you don't want no part of this shit
    // so send them a TLS "PC LOAD LETTER"
    TLSAlertDispatcher {
        alert_level: AlertLevel,
        alert_description: AlertDescription,
    },
    // effectively does nothing
    // when the socket goes out of scope, RST
    // not even in use lmao
    // NothingDispatcher,
}

impl Dispatcher {
    pub async fn do_dispatch(&self, mut clientsock: TcpStream) {
        match self {
            Dispatcher::TCPDownstreamDispatcher { downstreams } => {
                let chosen = downstreams
                    .choose(&mut rand::rng())
                    .expect("no downstreams in dispatcher");
                log::debug!("connect ye to {}", chosen);
                match tcp_proxy_addr(clientsock, chosen).await {
                    io::Result::Ok(_) => {
                        log::debug!("normal termination");
                    }
                    io::Result::Err(err) => match err.kind() {
                        std::io::ErrorKind::UnexpectedEof => {
                            log::debug!("ignoring EOF");
                        }
                        std::io::ErrorKind::InvalidData => {
                            log::debug!("tls abort");
                        }
                        _ => {
                            log::debug!("unhandled kind");
                            log::debug!("error termination: {:?}", err);
                        }
                    },
                };
                // .expect("couldn't TCP-proxy")
            }
            Dispatcher::TLSAlertDispatcher {
                alert_level,
                alert_description,
            } => {
                log::debug!("sending TLS alert & closing stream");
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
                // FIN here, otherwise the socket will RST
                let _ = clientsock.shutdown().await;
            }
            Dispatcher::TLSWrappedDownstreamDispatcher {
                downstreams,
                acceptor,
            } => {
                let chosen = downstreams
                    .choose(&mut rand::rng())
                    .expect("no downstreams in dispatcher");
                log::debug!("TLS-term and connect to {}", chosen);
                match tls_proxy_addr(clientsock, chosen, acceptor.clone()).await {
                    io::Result::Ok(_) => {
                        log::debug!("normal termination");
                    }
                    io::Result::Err(err) => match err.kind() {
                        std::io::ErrorKind::UnexpectedEof => {
                            log::debug!("ignoring EOF");
                        }
                        std::io::ErrorKind::InvalidData => {
                            log::debug!("tls abort");
                        }
                        _ => {
                            log::debug!("unhandled kind");
                            log::debug!("error termination: {:?}", err);
                        }
                    },
                }
            }
            Dispatcher::HTTPSStaticDispatcher {
                response_code,
                acceptor,
            } => {
                log::debug!("to https_answer_request");
                match https_answer_request(clientsock, *response_code, acceptor.clone()).await {
                    io::Result::Ok(_) => {
                        log::debug!("normal termination");
                    }
                    io::Result::Err(err) => match err.kind() {
                        std::io::ErrorKind::UnexpectedEof => {
                            log::debug!("ignoring EOF");
                        }
                        std::io::ErrorKind::InvalidData => {
                            log::debug!("tls abort");
                        }
                        _ => {
                            log::debug!("unhandled kind");
                            log::debug!("error termination: {:?}", err);
                        }
                    },
                };
            }
        }
    }
    // Dispatchers determine how to execute
    pub fn from_mappingentry_tlses(
        me: &MappingEntry,
        tlses: Arc<HashMap<String, Arc<TlsAcceptor>>>,
    ) -> Option<Dispatcher> {
        if let Some(tlsname) = &me.tls {
            if let Some(acceptor) = tlses.get(tlsname) {
                if let Some(downstreams) = &me.downstreams {
                    log::debug!("TLSWrappedDownstreamDispatcher");
                    return Some(Dispatcher::TLSWrappedDownstreamDispatcher {
                        downstreams: downstreams.clone(),
                        acceptor: acceptor.clone(),
                    });
                }
                if let Some(response_code) = me.response_code {
                    log::debug!("HTTPSStaticDispatcher");
                    return Some(Dispatcher::HTTPSStaticDispatcher {
                        response_code: response_code,
                        acceptor: acceptor.clone(),
                    });
                }
            } else {
                log::debug!("not found tls acceptor");
                panic!("named tls config not found");
            }
        } else {
            if let Some(downstreams) = &me.downstreams {
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
                    } else {
                        log::debug!("rule {} no matched exact: {}", rulename, indicated);
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
                    } else {
                        log::debug!("rule {} no matched regex: {}", rulename, indicated);
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

async fn tcp_proxy_addr(incoming: TcpStream, addr: &String) -> io::Result<()> {
    let outgoing = TcpStream::connect(addr).await?;
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

async fn tls_proxy_stream(incoming: TlsStream<TcpStream>, outgoing: TcpStream) -> io::Result<()> {
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
    incoming: TcpStream,
    addr: &String,
    acceptor: Arc<TlsAcceptor>,
) -> io::Result<()> {
    let outgoing = TcpStream::connect(addr).await?;
    let plaintext_stream = acceptor.accept(incoming).await?;
    tls_proxy_stream(plaintext_stream, outgoing).await
}
