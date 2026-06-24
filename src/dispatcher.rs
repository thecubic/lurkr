use rand::seq::IndexedRandom;
use rustls::AlertDescription;
use rustls::internal::msgs::{
    enums::AlertLevel,
    message::{Message, PlainMessage},
};
use std::{fmt::Formatter, sync::Arc};
use tokio::{
    io::{self, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::TlsAcceptor;

use crate::https::WebService;
use crate::{conf::MappingEntry, matcher::Matcher};

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
    HTTPSStaticDispatcher {
        webservice: WebService,
        acceptor: Arc<TlsAcceptor>,
    },

    // NOT IMPLEMENTED
    // should be HTTP 308 with Location: <place>
    // content-length 0
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
                tracing::debug!("connect ye to {}", chosen);
                match crate::proxy::tcp_proxy_addr(clientsock, chosen).await {
                    io::Result::Ok(_) => {
                        tracing::debug!("normal termination");
                    }
                    io::Result::Err(err) => match err.kind() {
                        std::io::ErrorKind::UnexpectedEof => {
                            tracing::debug!("ignoring EOF");
                        }
                        std::io::ErrorKind::InvalidData => {
                            tracing::debug!("tls abort");
                        }
                        _ => {
                            tracing::debug!("unhandled kind");
                            tracing::debug!("error termination: {:?}", err);
                        }
                    },
                };
                // .expect("couldn't TCP-proxy")
            }
            Dispatcher::TLSAlertDispatcher {
                alert_level,
                alert_description,
            } => {
                tracing::debug!("sending TLS alert & closing stream");
                // TODO: has to be a better modern way to alert
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
                tracing::debug!("TLS-term and connect to {}", chosen);
                match crate::proxy::tls_proxy_addr(clientsock, chosen, acceptor.clone()).await {
                    io::Result::Ok(_) => {
                        tracing::debug!("normal termination");
                    }
                    io::Result::Err(err) => match err.kind() {
                        std::io::ErrorKind::UnexpectedEof => {
                            tracing::debug!("ignoring EOF");
                        }
                        std::io::ErrorKind::InvalidData => {
                            tracing::debug!("tls abort");
                        }
                        _ => {
                            tracing::debug!("unhandled kind");
                            tracing::debug!("error termination: {:?}", err);
                        }
                    },
                }
            }
            Dispatcher::HTTPSStaticDispatcher {
                webservice,
                acceptor,
            } => {
                tracing::debug!("to https_serve_conn");
                match webservice
                    .https_serve_conn(clientsock, acceptor.clone())
                    .await
                {
                    io::Result::Ok(_) => {
                        tracing::debug!("normal termination");
                    }
                    io::Result::Err(err) => match err.kind() {
                        std::io::ErrorKind::UnexpectedEof => {
                            tracing::debug!("ignoring EOF");
                        }
                        std::io::ErrorKind::InvalidData => {
                            tracing::debug!("tls abort");
                        }
                        _ => {
                            tracing::debug!("unhandled kind");
                            tracing::debug!("error termination: {:?}", err);
                        }
                    },
                };
            }
        }
    }
    // Dispatchers determine how to execute
    pub fn from_mappingentry(me: &MappingEntry) -> Option<Dispatcher> {
        if let Some(tlsname) = &me.tls {
            if let Some(acceptor) = crate::TLSMAP.get(tlsname) {
                if let Some(downstreams) = &me.downstreams {
                    tracing::debug!("TLSWrappedDownstreamDispatcher");
                    return Some(Dispatcher::TLSWrappedDownstreamDispatcher {
                        downstreams: downstreams.clone(),
                        acceptor: acceptor.clone(),
                    });
                }
                if let Some(response_code) = me.response_code {
                    tracing::debug!("HTTPSStaticDispatcher");
                    if let Some(response_body) = &me.response_body {
                        return Some(Dispatcher::HTTPSStaticDispatcher {
                            webservice: WebService::new(response_code, response_body.clone()),
                            acceptor: acceptor.clone(),
                        });
                    }
                }
            } else {
                tracing::debug!("not found tls acceptor");
                panic!("named tls config not found");
            }
        } else {
            if let Some(downstreams) = &me.downstreams {
                tracing::debug!("TCPDownstreamDispatcher");
                return Some(Dispatcher::TCPDownstreamDispatcher {
                    downstreams: downstreams.clone(),
                });
            }
        }
        None
    }
    pub fn from_indicated(indicated: &str) -> Option<Dispatcher> {
        for matcher in crate::MATCHLIST.iter() {
            match matcher {
                Matcher::ExactMatcher {
                    rulename,
                    exact,
                    dispatcher,
                } => {
                    if exact.as_str() == indicated {
                        tracing::debug!("rule {} matched exact: {}", rulename, indicated);
                        return Some(dispatcher.clone());
                    } else {
                        tracing::debug!("rule {} no matched exact: {}", rulename, indicated);
                    }
                }
                Matcher::RegexMatcher {
                    rulename,
                    regex,
                    dispatcher,
                } => {
                    if regex.is_match(indicated) {
                        tracing::debug!("rule {} regexed: {}", rulename, indicated);
                        return Some(dispatcher.clone());
                    } else {
                        tracing::debug!("rule {} no matched regex: {}", rulename, indicated);
                    }
                }
                Matcher::UniversalMatcher {
                    rulename,
                    dispatcher,
                } => {
                    tracing::debug!("rule {} universal match", rulename);
                    return Some(dispatcher.clone());
                }
            }
        }
        None
    }
}
