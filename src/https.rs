use std::{convert::Infallible, sync::Arc};

use hyper::{service::service_fn, Body, Request, Response, StatusCode};
use tokio::{io, net::TcpStream};
use tokio_rustls::TlsAcceptor;

pub async fn https_answer_request(
    incoming: TcpStream,
    response_code: u16,
    acceptor: Arc<TlsAcceptor>,
) -> io::Result<()> {
    let nonstatic_svc = service_fn(|_: Request<Body>| async move {
        Ok::<_, Infallible>(
            Response::builder()
                .status(StatusCode::from_u16(response_code).expect("invalid HTTP response code"))
                .body(Body::default())
                .expect("couldn't craft HTTP response object"),
        )
    });

    // do the thing

    let result = hyper::server::conn::Http::new()
        .serve_connection(acceptor.accept(incoming).await?, nonstatic_svc)
        .await;
    if result.is_ok() {
        return Ok(());
    }
    // pretty much ignore all errors
    // because happens:

    // hyper::Error(Shutdown, Os {
    // code: 107,
    // kind: NotConnected,
    // message: "Transport endpoint is not connected" }

    if let Err(err) = result {
        if err.is_closed() {
            log::debug!("meh closed");
        }
        if err.is_body_write_aborted() {
            log::debug!("meh body write aborted");
        }
        if err.is_canceled() {
            log::debug!("meh cancelled");
        }
        if err.is_user() {
            log::debug!("meh some user cause");
        }
        log::debug!("message: {}", err.message());
    }
    Ok(())
}
