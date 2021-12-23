#![warn(rust_2018_idioms)]

#[macro_use]
extern crate serde_derive;

use log::{debug, info};
use rand::seq::SliceRandom;
use regex::Regex;
use rustls::internal::msgs::codec::Reader;
use rustls::internal::msgs::enums::{AlertDescription, AlertLevel};
use rustls::internal::msgs::handshake::HandshakePayload::ClientHello;
use rustls::internal::msgs::handshake::ServerNamePayload;
use rustls::internal::msgs::message::Message;
use rustls::internal::msgs::message::MessagePayload::Handshake;
use rustls::internal::msgs::message::OpaqueMessage;
use rustls::internal::msgs::message::PlainMessage;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use structopt::StructOpt;
use tokio::io::{self, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug, Deserialize)]
struct Listener {
    addr: String,
    port: u16,
    no_mapping: Option<String>,
    mappings: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct MappingEntry {
    exact: Option<String>,
    matcher: Option<String>,
    downstreams: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Configuration {
    listener: Listener,
    mapping: HashMap<String, MappingEntry>,
}

#[derive(Debug)]
enum Matcher {
    ExactMatcher {
        rulename: String,
        exact: String,
        downstreams: Vec<String>,
    },
    RegexMatcher {
        rulename: String,
        regex: Regex,
        downstreams: Vec<String>,
    },
    UniversalMatcher {
        rulename: String,
        downstreams: Vec<String>,
    },
}

fn create_matchers(cfg_obj: &Configuration) -> Vec<Matcher> {
    let mut matchers = Vec::<Matcher>::new();
    // TODO: preserve order feature in config-rs
    for mapping in &cfg_obj.listener.mappings {
        let me: &MappingEntry = &cfg_obj.mapping[mapping];
        if me.exact.is_some() && me.matcher.is_some() {
            panic!(
                "mapping entry {} cannot have both exact and regex matching",
                mapping
            );
        } else if me.exact.is_none() && me.matcher.is_none() {
            matchers.push(Matcher::UniversalMatcher {
                rulename: mapping.clone(),
                downstreams: me.downstreams.clone(),
            });
        } else if let Some(direct) = &me.exact {
            matchers.push(Matcher::ExactMatcher {
                rulename: mapping.clone(),
                exact: direct.clone(),
                downstreams: me.downstreams.clone(),
            });
        } else if let Some(regex) = &me.matcher {
            matchers.push(Matcher::RegexMatcher {
                rulename: mapping.clone(),
                regex: Regex::new(regex.as_str())
                    .expect(format!("faulty regex {} in mapping {}", regex, mapping).as_str()),
                downstreams: me.downstreams.clone(),
            })
        }
    }
    matchers
}

#[derive(Debug, StructOpt)]
struct CliOptions {
    #[structopt(short, long)]
    debug: bool,

    #[structopt(short, long, parse(from_os_str))]
    conf: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli_opt = CliOptions::from_args();
    if cli_opt.debug {
        env_logger::Builder::new()
            .filter_level(log::LevelFilter::Debug)
            .init();
    } else {
        env_logger::Builder::new()
            .filter_level(log::LevelFilter::Info)
            .init();
    }
    let mut cfg = config::Config::default();
    cfg.merge(config::File::with_name(
        cli_opt.conf.to_str().expect("invalid pathname"),
    ))?;

    let fullcfg: Configuration = cfg.try_into().expect("could not deserialize configuration");

    let _no_mapping = if let Some(chose_no_mapping) = &fullcfg.listener.no_mapping {
        chose_no_mapping.clone()
    } else {
        "unrecognized_name".to_string()
    };

    let matchlist: Arc<Vec<Matcher>> = Arc::new(create_matchers(&fullcfg));
    let final_addr = format!("{}:{}", fullcfg.listener.addr, fullcfg.listener.port);
    let lsnr = TcpListener::bind(&final_addr).await?;
    info!("listening on {}", final_addr);

    // TODO: can't get this to work as a function ptr match
    // so we'll let the proxy code eval every time
    // and just let this be a sanity check
    let no_mapping_fn = match _no_mapping.as_str() {
        "unrecognized_name" => _no_mapping,
        "do_nothing" => _no_mapping,
        _ => {
            panic!("unrecognized no_mapping behavior: {}", _no_mapping);
        }
    };

    loop {
        let (mut socket, _) = lsnr.accept().await?;
        let mymatchlist = Arc::clone(&matchlist);
        // clone it, wishing we could use fn ptrs
        let my_no_mapping_fn = no_mapping_fn.clone();
        tokio::spawn(async move {
            let mut peekbuf = [0; 512];
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

            // Deserialize the TLS ClientHello
            let msg = Message::try_from(
                OpaqueMessage::read(&mut Reader::init(&peekbuf))
                    .expect("couldn't read TLS message")
                    .into_plain_message(),
            )
            .expect("Couldn't decipher message");

            // Extract the SNI payload and determine indicated name
            let hostname = if let Handshake(shake) = msg.payload {
                if let ClientHello(ohhai) = shake.payload {
                    let sni = ohhai.get_sni_extension();
                    if sni.is_none() {
                        // No SNI extension
                        None
                    } else {
                        let sni_f = sni.unwrap().first();
                        if sni_f.is_none() {
                            // No name indicated
                            None
                        } else {
                            if let ServerNamePayload::HostName(hostname) = &sni_f.unwrap().payload {
                                Some(hostname.clone())
                            } else {
                                None
                            }
                        }
                    }
                } else {
                    None
                }
            } else {
                None
            };

            // Core rule-matching; find an appropriate matcher
            // or do the no-mapping procedure
            if let Some(hn) = hostname {
                let indicated: &str = std::str::from_utf8(&hn.0 .0).unwrap();
                let mut downstream: Option<String> = None;
                'matching: for matcher in mymatchlist.iter() {
                    let endpoint = match matcher {
                        Matcher::ExactMatcher {
                            rulename,
                            exact,
                            downstreams,
                        } => {
                            if exact.as_str() == indicated {
                                debug!("rule {} matched exact: {}", rulename, indicated);
                                downstreams.choose(&mut rand::thread_rng())
                            } else {
                                None
                            }
                        }
                        Matcher::RegexMatcher {
                            rulename,
                            regex,
                            downstreams,
                        } => {
                            if regex.is_match(indicated) {
                                debug!("rule {} regexed: {}", rulename, indicated);
                                downstreams.choose(&mut rand::thread_rng())
                            } else {
                                None
                            }
                        }
                        Matcher::UniversalMatcher {
                            rulename,
                            downstreams,
                        } => {
                            debug!("rule {} universal match", rulename);
                            downstreams.choose(&mut rand::thread_rng())
                        }
                    };
                    if let Some(ep) = endpoint {
                        downstream = Some(ep.clone());
                        break 'matching;
                    }
                }
                // match rules complete, let's see if we should proxy
                if let Some(endpoint) = downstream {
                    debug!("connect ye to {}", endpoint);
                    // do proxying here
                    tcp_proxy(socket, endpoint)
                        .await
                        .expect("couldn't TCP-proxy");
                } else {
                    // No match for this name; handle no-mapping case
                    debug!("name {} matched no rules", indicated);
                    if handle_no_mapping(&mut socket, my_no_mapping_fn)
                        .await
                        .expect("couldn't handle no-mapping")
                        > 0
                    {
                        // because this used the socket, we now need shutdown
                        socket.shutdown().await.expect("could not shutdown");
                    }
                }
            } else {
                // TODO: maybe different no-sni?
                // Didn't get SNI, handle no-mapping case
                debug!("no name indicated");
                if handle_no_mapping(&mut socket, my_no_mapping_fn)
                    .await
                    .expect("couldn't handle no-mapping")
                    > 0
                {
                    // because this used the socket, we now need shutdown
                    socket.shutdown().await.expect("could not shutdown");
                }
            }
        });
    }
}

async fn tcp_proxy(mut incoming: TcpStream, addr: String) -> io::Result<()> {
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

async fn handle_no_mapping(socket: &mut TcpStream, my_no_mapping_fn: String) -> io::Result<usize> {
    match my_no_mapping_fn.as_str() {
        "unrecognized_name" => send_unrecognized_name(socket).await,
        "do_nothing" => do_nothing(socket).await,
        _ => {
            panic!("unrecognized no_mapping (this should be unreachable)")
        }
    }
}

async fn send_unrecognized_name(socket: &mut TcpStream) -> io::Result<usize> {
    Ok(socket
        .write(
            &PlainMessage::try_from(Message::build_alert(
                AlertLevel::Fatal,
                // it's a "z" in the standard #gotem
                AlertDescription::UnrecognisedName,
            ))
            .expect("couldn't convert built-alert to PlainMessage")
            .into_unencrypted_opaque()
            .encode(),
        )
        .await
        .expect("Error sending TLS alert"))
}

async fn do_nothing(_socket: &mut TcpStream) -> io::Result<usize> {
    Ok(0)
}
