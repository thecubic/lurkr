use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicU32},
    },
    time::Duration,
};

use anyhow::Context;
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

// Infallible process state: initialized on first use.
// (structopt exits the process itself on bad arguments; it does not panic.)
static CLI_OPTIONS: OnceLock<CliOptions> = OnceLock::new();
static SCONNS: OnceLock<Mutex<JoinSet<()>>> = OnceLock::new();
static LISTENER_STOP: OnceLock<(Sender<()>, Receiver<()>)> = OnceLock::new();
static CONNECTION_STOP: OnceLock<(Sender<()>, Receiver<()>)> = OnceLock::new();

// Configuration-derived state: set exactly once by init_config() and
// init_dispatch(), which report errors instead of panicking.
static FULLCFG: OnceLock<Configuration> = OnceLock::new();
static DEBUG: OnceLock<bool> = OnceLock::new();
static GRACE_PERIOD: OnceLock<Duration> = OnceLock::new();
static TLSMAP: OnceLock<HashMap<String, Arc<TlsAcceptor>>> = OnceLock::new();
static MATCHLIST: OnceLock<Vec<Matcher>> = OnceLock::new();

const UNINIT: &str = "lurkr::init_config() / init_dispatch() must run first";

pub fn cli_options() -> &'static CliOptions {
    CLI_OPTIONS.get_or_init(CliOptions::from_args)
}

pub fn connections() -> &'static Mutex<JoinSet<()>> {
    SCONNS.get_or_init(|| Mutex::new(JoinSet::new()))
}

pub fn listener_stop() -> &'static (Sender<()>, Receiver<()>) {
    LISTENER_STOP.get_or_init(|| watch::channel(()))
}

pub fn connection_stop() -> &'static (Sender<()>, Receiver<()>) {
    CONNECTION_STOP.get_or_init(|| watch::channel(()))
}

pub fn config() -> &'static Configuration {
    FULLCFG.get().expect(UNINIT)
}

/// Effective debug setting: `--debug` forces it on, otherwise
/// `global.debug` from the configuration, otherwise off.
pub fn debug() -> bool {
    *DEBUG.get().expect(UNINIT)
}

/// Effective grace period: explicit `--grace-period`, otherwise
/// `global.grace_period` from the configuration, otherwise the default.
pub fn grace_period() -> Duration {
    *GRACE_PERIOD.get().expect(UNINIT)
}

pub fn tls_acceptors() -> &'static HashMap<String, Arc<TlsAcceptor>> {
    TLSMAP.get().expect(UNINIT)
}

pub fn matchers() -> &'static [Matcher] {
    MATCHLIST.get().expect(UNINIT)
}

fn set_once<T>(cell: &OnceLock<T>, value: T, what: &str) -> anyhow::Result<()> {
    cell.set(value)
        .map_err(|_| anyhow::anyhow!("{} already initialized", what))
}

/// Load the configuration file and resolve settings needed before logging.
pub fn init_config() -> anyhow::Result<()> {
    let cli = cli_options();
    let path = cli
        .conf
        .to_str()
        .with_context(|| format!("invalid pathname {:?}", cli.conf))?;
    let cfg: Configuration = Config::builder()
        .add_source(config::File::with_name(path))
        .add_source(config::Environment::with_prefix("LURKR"))
        .build()
        .with_context(|| format!("could not load configuration {}", path))?
        .try_deserialize()
        .context("could not deserialize configuration")?;

    let global = cfg.global.as_ref();
    let debug = cli.debug || global.and_then(|g| g.debug).unwrap_or(false);
    let grace_period = Duration::from_secs(
        cli.grace_period
            .or_else(|| global.and_then(|g| g.grace_period))
            .unwrap_or(DEFAULT_GRACE_PERIOD_SECS),
    );

    set_once(&FULLCFG, cfg, "configuration")?;
    set_once(&DEBUG, debug, "debug setting")?;
    set_once(&GRACE_PERIOD, grace_period, "grace period")?;
    Ok(())
}

/// Build TLS acceptors and SNI matchers from the loaded configuration.
pub fn init_dispatch() -> anyhow::Result<()> {
    let tlsmap =
        tls::acceptors_from_configuration(config()).context("couldn't create TLS acceptors")?;
    set_once(&TLSMAP, tlsmap, "TLS acceptors")?;
    let matchers = Matcher::from_configuration(config(), tls_acceptors())?;
    set_once(&MATCHLIST, matchers, "matchers")?;
    Ok(())
}
