#![warn(rust_2018_idioms)]

use std::panic;
use std::sync::atomic::Ordering;
use tokio::select;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    if lurkr::CLI_OPTIONS.debug {
        // env_logger::Builder::new()
        //     .filter_level(log::LevelFilter::Debug)
        //     .init();
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .try_init()?;
    } else {
        // env_logger::Builder::new()
        //     .filter_level(log::LevelFilter::Info)
        //     .init();
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .try_init()?;
    }

    #[cfg(unix)]
    tokio::spawn(async move {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = signal(SignalKind::terminate()).unwrap();
        let mut sigint = signal(SignalKind::interrupt()).unwrap();
        loop {
            select! {
                _ = sigterm.recv() => {tracing::debug!("SIGTERM received")},
                _ = sigint.recv() => {tracing::debug!("SIGINT received")},
            };
            lurkr::LISTENER_STOP.0.send(()).unwrap();
        }
    });

    #[cfg(windows)]
    tokio::spawn(async move {
        use tokio::signal::windows;

        let mut ctrl_break = windows::ctrl_break().unwrap();
        let mut ctrl_c = windows::ctrl_c().unwrap();
        let mut ctrl_close = windows::ctrl_close().unwrap();
        let mut ctrl_logoff = windows::ctrl_logoff().unwrap();
        let mut ctrl_shutdown = windows::ctrl_shutdown().unwrap();

        loop {
            select! {
                _ = ctrl_break.recv() => {tracing::debug!("CTRL-BREAK receive")},
                _ = ctrl_c.recv() => {tracing::debug!("CTRL-C receive")},
                _ = ctrl_close.recv() => {tracing::debug!("CTRL-CLOSE receive")},
                _ = ctrl_logoff.recv() => {tracing::debug!("CTRL-LOGOFF receive")},
                _ = ctrl_shutdown.recv() => {tracing::debug!("CTRL-SHUTDOWN receive")},
            };
            lurkr::LISTENER_STOP.0.send(()).unwrap();
        }
    });

    let collector_jh = tokio::spawn(lurkr::tasks::connection_collector());
    lurkr::tasks::listener().await?;
    collector_jh.await?;

    tracing::info!(
        "VENDED: {}, OKAY: {}, PANICED: {}",
        lurkr::CONNS_VENDED.load(Ordering::Relaxed),
        lurkr::CONNS_OKAY.load(Ordering::Relaxed),
        lurkr::CONNS_PANICED.load(Ordering::Relaxed),
    );
    Ok(())
}
