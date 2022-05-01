#![warn(rust_2018_idioms)]

#[macro_use]
extern crate serde_derive;

mod conf;
mod conn;
mod dispatcher;
mod matcher;
mod runtime;
mod tls;

use config::Config;

use conf::Configuration;
use log::info;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use structopt::StructOpt;
use tokio::net::TcpListener;

use crate::matcher::Matcher;

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

    let settings = Config::builder()
        .add_source(config::File::with_name(
            cli_opt.conf.to_str().expect("invalid pathname"),
        ))
        // Add in settings from the environment (with a prefix of APP)
        // Eg.. `APP_DEBUG=1 ./target/app` would set the `debug` key
        .add_source(config::Environment::with_prefix("LURKR"))
        .build()
        .unwrap();

    let fullcfg: Configuration = settings
        .try_deserialize()
        .expect("could not deserialize configuration");

    let _no_mapping = if let Some(chose_no_mapping) = &fullcfg.listener.no_mapping {
        chose_no_mapping.clone()
    } else {
        "unrecognized_name".to_string()
    };

    // let tlsmap: HashMap<String, Arc<TlsAcceptor>>;
    let tlsmap = Arc::new(tls::acceptors_from_configuration(&fullcfg)?);
    let matchlist: Arc<Vec<Matcher>> =
        Arc::new(Matcher::from_configuration_tlses(&fullcfg, tlsmap));
    let final_addr = format!("{}:{}", fullcfg.listener.addr, fullcfg.listener.port);
    let lsnr = TcpListener::bind(&final_addr).await?;
    info!("listening on {}", final_addr);

    loop {
        let (socket, _) = lsnr.accept().await?;
        let mymatchlist = Arc::clone(&matchlist);
        let _ = tokio::spawn(conn::handle_connection(socket, mymatchlist));
    }
}
