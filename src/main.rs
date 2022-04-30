#![warn(rust_2018_idioms)]

#[macro_use]
extern crate serde_derive;

mod conf;
mod conn;
mod dispatcher;
mod matcher;
mod runtime;
mod tls;

use conf::Configuration;
use log::{debug, info};
use matcher::Matcher;
use rand::seq::SliceRandom;
use rand::Rng;
use regex::Regex;
use rustls::internal::msgs::alert::AlertMessagePayload;
use rustls::internal::msgs::base::PayloadU16;
use rustls::internal::msgs::codec::Reader;
use rustls::internal::msgs::enums::{AlertDescription, AlertLevel};
use rustls::internal::msgs::handshake::HandshakePayload::ClientHello;
use rustls::internal::msgs::handshake::ServerNamePayload;
use rustls::internal::msgs::message::MessagePayload::Handshake;
use rustls::internal::msgs::message::OpaqueMessage;
use rustls::internal::msgs::message::PlainMessage;
use rustls::internal::msgs::message::{Message, MessagePayload};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use structopt::StructOpt;
use tokio::io::{self, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::MappedMutexGuard;
use webpki::DnsName;

use crate::conf::MappingEntry;
use crate::dispatcher::Dispatcher;

// Matchers define the SNI-to-execution mapping
fn create_matchers(cfg_obj: &Configuration) -> Vec<Matcher> {
    let mut matchers = Vec::<Matcher>::new();
    // TODO: preserve order feature in config-rs
    for mapping in &cfg_obj.listener.mappings {
        let me: &MappingEntry = &cfg_obj.mapping[mapping];
        if let Some(dispatcher) = Dispatcher::from_mappingentry(me) {
            if me.exact.is_some() && me.matcher.is_some() {
                panic!(
                    "mapping entry {} cannot have both exact and regex matching",
                    mapping
                );
            } else if me.exact.is_none() && me.matcher.is_none() {
                matchers.push(Matcher::UniversalMatcher {
                    rulename: mapping.clone(),
                    dispatcher: dispatcher,
                });
            } else if let Some(direct) = &me.exact {
                matchers.push(Matcher::ExactMatcher {
                    rulename: mapping.clone(),
                    exact: direct.clone(),
                    dispatcher: dispatcher,
                });
            } else if let Some(regex) = &me.matcher {
                matchers.push(Matcher::RegexMatcher {
                    rulename: mapping.clone(),
                    regex: Regex::new(regex.as_str())
                        .expect(format!("faulty regex {} in mapping {}", regex, mapping).as_str()),
                    dispatcher: dispatcher,
                })
            }
        } else {
            panic!("mapping entry {} is not dispatchable", mapping);
        }
    }
    // the no_mapping handler is just a UniversalMatcher at the end
    matchers.push(match &cfg_obj.listener.no_mapping.as_deref() {
        Some("ignore") => Matcher::UniversalMatcher {
            rulename: "__default".to_string(),
            dispatcher: Dispatcher::NothingDispatcher,
        },
        _ => Matcher::UniversalMatcher {
            rulename: "__default".to_string(),
            dispatcher: Dispatcher::TLSAlertDispatcher {
                alert_level: AlertLevel::Fatal,
                // it's a "z" in the standard #gotem
                alert_description: AlertDescription::UnrecognisedName,
            },
        },
    });
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
    let mut cfg = ::config::Config::default();
    cfg.merge(::config::File::with_name(
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

    loop {
        let (socket, _) = lsnr.accept().await?;
        let mymatchlist = Arc::clone(&matchlist);
        let _ = tokio::spawn(conn::handle_connection(socket, mymatchlist));
    }
}


