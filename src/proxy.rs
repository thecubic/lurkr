use std::sync::Arc;

use tokio::{
    io::{self, AsyncWriteExt as _},
    net::TcpStream,
    select,
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

pub(crate) async fn tcp_proxy_addr(incoming: TcpStream, addr: &String) -> io::Result<()> {
    let outgoing = TcpStream::connect(addr).await?;
    tcp_proxy_stream(incoming, outgoing).await
}

pub(crate) async fn tcp_proxy_stream(
    mut incoming: TcpStream,
    mut outgoing: TcpStream,
) -> io::Result<()> {
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

    // tokio::try_join!(left, right)?;
    let mut stopper = crate::CONNECTION_STOP.1.clone();
    select! {
        biased;
        _ = stopper.changed() => {log::debug!("stopping connection"); },
        _ = left => {},
        _ = right => {},
    }
    Ok(())
}

pub(crate) async fn tls_proxy_stream(
    incoming: TlsStream<TcpStream>,
    outgoing: TcpStream,
) -> io::Result<()> {
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
    // 'vayacondios: loop {
    let mut stopper = crate::CONNECTION_STOP.1.clone();
    select! {
        biased;
        _ = stopper.changed() => {log::debug!("stopping connection"); },
        _ = left => {},
        _ = right => {},
    }
    // }
    // tokio::try_join!(left, right)?;
    Ok(())
}

pub(crate) async fn tls_proxy_addr(
    incoming: TcpStream,
    addr: &String,
    acceptor: Arc<TlsAcceptor>,
) -> io::Result<()> {
    let outgoing = TcpStream::connect(addr).await?;
    let plaintext_stream = acceptor.accept(incoming).await?;
    tls_proxy_stream(plaintext_stream, outgoing).await
}
