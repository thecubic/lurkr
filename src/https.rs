use std::sync::Arc;

use http_body_util::Full;
use hyper::{
    Request, Response, StatusCode,
    body::{Bytes, Incoming},
    server::conn::http1,
    service::Service,
};
use hyper_util::rt::TokioIo;
use std::pin::Pin;
use tokio::{io, net::TcpStream};
use tokio_rustls::TlsAcceptor;

#[derive(Debug, Clone)]
pub struct WebService {
    response_code: u16,
    response_body: Full<Bytes>,
}

impl WebService {
    pub fn new(response_code: u16, response_body: String) -> Self {
        Self {
            response_code: response_code,
            response_body: Full::new(Bytes::from(response_body)),
        }
    }
    pub async fn https_serve_conn(
        &self,
        incoming: TcpStream,
        acceptor: Arc<TlsAcceptor>,
    ) -> io::Result<()> {
        let result = http1::Builder::new()
            .serve_connection(TokioIo::new(acceptor.accept(incoming).await?), self)
            .await;
        if result.is_ok() {
            return Ok(());
        }

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
            log::debug!("message: {:?}", err);
        }
        Ok(())
    }
}

impl Service<Request<Incoming>> for WebService {
    type Response = Response<Full<Bytes>>;
    type Error = hyper::http::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, _req: Request<Incoming>) -> Self::Future {
        let res = Response::builder()
            .status(StatusCode::from_u16(self.response_code).unwrap())
            .body(self.response_body.clone())
            .unwrap();

        Box::pin(async { Ok(res) })
    }
}
