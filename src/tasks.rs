use std::{
    panic,
    sync::atomic::Ordering,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{io, net::TcpListener, select, task::JoinHandle};

pub async fn listener() -> Result<(), anyhow::Error> {
    let final_addr = format!(
        "{}:{}",
        crate::FULLCFG.listener.addr,
        crate::FULLCFG.listener.port
    );
    let lsnr = TcpListener::bind(&final_addr).await?;
    tracing::info!("listening on {}", final_addr);

    let mut stopper = crate::LISTENER_STOP.1.clone();
    select! {
        biased;
        _ = stopper.changed() => {tracing::debug!("bailing due to signal received");},
        _ = async {
            loop {
                let (socket, _) = lsnr.accept().await?;
                crate::SCONNS.lock().await.spawn(crate::conn::handle_connection(socket));
            }
            #[allow(unreachable_code)]
            Ok::<_, io::Error>(())
        } => {},
    }
    drop(lsnr);
    tracing::info!("vended {} connections", crate::SCONNS.lock().await.len());
    crate::CONNS_ENDED.store(true, Ordering::Relaxed);
    Ok(())
}

pub async fn connection_terminator() {
    tracing::debug!("terminating connections");
    if !crate::SCONNS.lock().await.is_empty() {
        tracing::debug!("pending connections exist, entering grace period");
        tokio::time::sleep(Duration::from_secs(crate::CLI_OPTIONS.grace_period)).await;
        tracing::debug!("signalling all connections to die");
        crate::CONNECTION_STOP.0.send(()).ok();
        tokio::time::sleep(Duration::from_secs(crate::CLI_OPTIONS.grace_period)).await;
    }
    tracing::debug!("finally killing all connection tasks");
    crate::SCONNS.lock().await.shutdown().await;
}

pub async fn connection_collector() {
    let a = futures::task::noop_waker();
    let mut terminated = false;
    let mut terminator_jh: Option<JoinHandle<()>> = None;
    'mtconnsate: loop {
        let conns_ended = crate::CONNS_ENDED.load(Ordering::Relaxed);
        let mut relax = false;
        match crate::SCONNS
            .lock()
            .await
            .poll_join_next_with_id(&mut Context::from_waker(&a))
        {
            Poll::Ready(None) => {
                // I really miss coinflip or LOG_EVERY_N logs
                // don't take that as I miss glog tho
                // tracing::debug!("empty connections");
                if conns_ended {
                    // empty and we're done accepting connections
                    if terminated {
                        break 'mtconnsate;
                    } else {
                        tracing::debug!("issuing termination");
                        terminator_jh = Some(tokio::spawn(connection_terminator()));
                        terminated = true;
                    }
                }
                relax = true;
            }
            Poll::Ready(Some(Ok((id, _)))) => {
                tracing::debug!("successful connection, id: {}", id);
                crate::CONNS_OKAY.fetch_add(1, Ordering::Relaxed);
                crate::CONNS_VENDED.fetch_add(1, Ordering::Relaxed);
            }
            // TODO: we need some way to emotionally process these
            // without dying ourselves
            // but one way to force it!
            Poll::Ready(Some(Err(err))) if err.is_panic() => {
                tracing::debug!("panicked: {}", err);
                crate::CONNS_PANICED.fetch_add(1, Ordering::Relaxed);
                crate::CONNS_VENDED.fetch_add(1, Ordering::Relaxed);
            }
            Poll::Ready(Some(Err(err))) => {
                tracing::debug!("cancelled: {}", err);
                crate::CONNS_PANICED.fetch_add(1, Ordering::Relaxed);
                crate::CONNS_VENDED.fetch_add(1, Ordering::Relaxed);
            }
            Poll::Pending => {
                relax = true;
                tracing::debug!("no connections to collect");
                if conns_ended {
                    // still live connections but we're done accepting them
                    if !terminated {
                        terminator_jh = Some(tokio::spawn(connection_terminator()));
                        terminated = true;
                    }
                }
            }
        }
        if relax {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    if let Some(jh) = terminator_jh {
        tracing::debug!("joining terminator");
        jh.await.ok();
    }
}
