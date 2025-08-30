#![warn(rust_2018_idioms)]

use config::Config;

use log::info;

use std::sync::Arc;
use std::{panic, path::PathBuf};
use structopt::StructOpt;
use tokio::{
    io,
    net::TcpListener,
    select,
    signal::unix::{SignalKind, signal},
    sync::watch,
    task::JoinSet,
};

use lurkr::conf::Configuration;
use lurkr::matcher::Matcher;

#[derive(Debug, StructOpt)]
struct CliOptions {
    #[structopt(short, long)]
    debug: bool,

    #[structopt(short, long, parse(from_os_str))]
    conf: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (stop_tx, mut stop_rx) = watch::channel(());

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

    tokio::spawn(async move {
        let mut sigterm = signal(SignalKind::terminate()).unwrap();
        let mut sigint = signal(SignalKind::interrupt()).unwrap();
        loop {
            select! {
                _ = sigterm.recv() => {log::debug!("SIGTERM receive")},
                _ = sigint.recv() => {log::debug!("SIGINT receive")},
            };
            stop_tx.send(()).unwrap();
        }
    });

    let settings = Config::builder()
        .add_source(config::File::with_name(
            cli_opt.conf.to_str().expect("invalid pathname"),
        ))
        .add_source(config::Environment::with_prefix("LURKR"))
        .build()
        .unwrap();

    let fullcfg: Configuration = settings
        .try_deserialize()
        .expect("could not deserialize configuration");

    let tlsmap = Arc::new(lurkr::tls::acceptors_from_configuration(&fullcfg)?);
    let matchlist: Arc<Vec<Matcher>> =
        Arc::new(Matcher::from_configuration_tlses(&fullcfg, tlsmap));
    let final_addr = format!("{}:{}", fullcfg.listener.addr, fullcfg.listener.port);
    let lsnr = TcpListener::bind(&final_addr).await?;
    info!("listening on {}", final_addr);

    let mut conns = JoinSet::new();

    select! {
        biased;
        _ = stop_rx.changed() => {log::debug!("bailing due to signal received");},
        _ = async {
            loop {
                let (socket, _) = lsnr.accept().await?;
                conns.spawn(lurkr::conn::handle_connection(socket, matchlist.clone()));
            }
            #[allow(unreachable_code)]
            Ok::<_, io::Error>(())
        } => {},
    }
    log::info!("vended {} connections", conns.len());
    // panic now? no, panic later!
    while let Some(res) = conns.join_next().await {
        match res {
            Ok(()) => {}
            Err(err) if err.is_panic() => panic::resume_unwind(err.into_panic()),
            Err(err) => panic!("{err}"),
        }
    }
    Ok(())
}
