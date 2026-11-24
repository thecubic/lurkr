use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicBool, AtomicU32},
    },
    time::Duration,
};

use config::Config;
use structopt::StructOpt;
use tokio::{
    sync::{
        Mutex,
        watch::{self, Receiver, Sender},
    },
    task::JoinSet,
};
use tokio_rustls::TlsAcceptor;

use crate::{conf::Configuration, matcher::Matcher};

pub mod conf;
pub mod conn;
pub mod dispatcher;
pub mod https;
pub mod matcher;
pub mod proxy;
pub mod tasks;
pub mod tls;

pub static CONNS_VENDED: AtomicU32 = AtomicU32::new(0);
pub static CONNS_OKAY: AtomicU32 = AtomicU32::new(0);
pub static CONNS_PANICED: AtomicU32 = AtomicU32::new(0);
pub static CONNS_ENDED: AtomicBool = AtomicBool::new(false);
pub static SCONNS: LazyLock<Mutex<JoinSet<()>>> = LazyLock::new(|| Mutex::new(JoinSet::new()));
pub static FULLCFG: LazyLock<Configuration> = LazyLock::new(|| {
    Config::builder()
        .add_source(config::File::with_name(
            CliOptions::from_args()
                .conf
                .to_str()
                .expect("invalid pathname"),
        ))
        .add_source(config::Environment::with_prefix("LURKR"))
        .build()
        .unwrap()
        .try_deserialize()
        .expect("could not deserialize configuration")
});

pub static TLSMAP: LazyLock<HashMap<String, Arc<TlsAcceptor>>> = LazyLock::new(|| {
    crate::tls::acceptors_from_configuration().expect("couldn't create TLS acceptors")
});
pub static MATCHLIST: LazyLock<Vec<Matcher>> = LazyLock::new(Matcher::from_configuration);

#[derive(Debug, StructOpt)]
pub struct CliOptions {
    /// Enable debug-level logging
    #[structopt(short, long)]
    pub debug: bool,

    /// Path to listener configuration TOML
    #[structopt(short, long, parse(from_os_str))]
    pub conf: PathBuf,

    /// Grace period seconds before soft termination and then hard
    /// [default: 1, or `global.grace_period` from the configuration]
    #[structopt(short, long)]
    pub grace_period: Option<u64>,
}

pub const DEFAULT_GRACE_PERIOD_SECS: u64 = 1;

pub static CLI_OPTIONS: LazyLock<CliOptions> = LazyLock::new(CliOptions::from_args);

/// Effective debug setting: `--debug` forces it on, otherwise
/// `global.debug` from the configuration, otherwise off.
pub static DEBUG: LazyLock<bool> = LazyLock::new(|| {
    CLI_OPTIONS.debug
        || FULLCFG
            .global
            .as_ref()
            .and_then(|g| g.debug)
            .unwrap_or(false)
});

/// Effective grace period: explicit `--grace-period`, otherwise
/// `global.grace_period` from the configuration, otherwise the default.
pub static GRACE_PERIOD: LazyLock<Duration> = LazyLock::new(|| {
    Duration::from_secs(
        CLI_OPTIONS
            .grace_period
            .or_else(|| FULLCFG.global.as_ref().and_then(|g| g.grace_period))
            .unwrap_or(DEFAULT_GRACE_PERIOD_SECS),
    )
});

pub static LISTENER_STOP: LazyLock<(Sender<()>, Receiver<()>)> =
    LazyLock::new(|| watch::channel(()));
pub static CONNECTION_STOP: LazyLock<(Sender<()>, Receiver<()>)> =
    LazyLock::new(|| watch::channel(()));
