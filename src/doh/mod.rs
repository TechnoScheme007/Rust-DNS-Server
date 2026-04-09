use crate::dns::DnsMessage;
use crate::resolver::Resolver;
use crate::dns::header::ResponseCode;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::convert::Infallible;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

const DNS_MESSAGE_TYPE: &str = "application/dns-message";

pub struct DohServer {
    resolver: Arc<Resolver>,
    listen_addr: String,
    tls_cert_path: Option<String>,
    tls_key_path: Option<String>,
}

impl DohServer {
    pub fn new(
        resolver: Arc<Resolver>,
        listen_addr: String,
        tls_cert_path: Option<String>,
        tls_key_path: Option<String>,
    ) -> Self {
        DohServer {
            resolver,
            listen_addr,
            tls_cert_path,
            tls_key_path,
        }
    }

    pub async fn run(self: Arc<Self>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(&self.listen_addr).await?;
        info!("DoH server listening on {}", self.listen_addr);

        // Check if TLS is configured
        let tls_acceptor = if let (Some(cert_path), Some(key_path)) =
            (&self.tls_cert_path, &self.tls_key_path)
        {
            match self.create_tls_acceptor(cert_path, key_path) {
                Ok(acceptor) => {
                    info!("DoH TLS enabled");
                    Some(acceptor)
                }
                Err(e) => {
                    error!("Failed to initialize TLS: {}. Running without TLS.", e);
                    None
                }
            }
        } else {
            info!("DoH running without TLS (HTTP mode for development/testing)");
            None
        };

        loop {
            let (stream, addr) = listener.accept().await?;
            let server = self.clone();

            if let Some(ref acceptor) = tls_acceptor {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            let io = TokioIo::new(tls_stream);
                            let service = service_fn(move |req| {
                                let server = server.clone();
                                async move { server.handle_request(req).await }
                            });
                            if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                                TokioExecutor::new(),
                            )
                            .serve_connection(io, service)
                            .await
                            {
                                warn!("DoH TLS connection error from {}: {}", addr, e);
                            }
                        }
                        Err(e) => {
                            warn!("TLS handshake failed from {}: {}", addr, e);
                        }
                    }
                });
            } else {
                let io = TokioIo::new(stream);
                tokio::spawn(async move {
                    let service = service_fn(move |req| {
                        let server = server.clone();
                        async move { server.handle_request(req).await }
                    });
                    if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                        TokioExecutor::new(),
                    )
                    .serve_connection(io, service)
                    .await
                    {
                        warn!("DoH connection error from {}: {}", addr, e);
                    }
                });
            }
        }
    }

    fn create_tls_acceptor(
        &self,
        cert_path: &str,
        key_path: &str,
    ) -> Result<tokio_rustls::TlsAcceptor, Box<dyn std::error::Error + Send + Sync>> {
        use rustls::ServerConfig;
        use std::io::BufReader;
        use tokio_rustls::TlsAcceptor;

        let cert_file = std::fs::File::open(cert_path)?;
        let key_file = std::fs::File::open(key_path)?;

        let certs: Vec<_> = rustls_pemfile::certs(&mut BufReader::new(cert_file))
            .filter_map(|r| r.ok())
            .collect();

        let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))?
            .ok_or("No private key found")?;

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;

        Ok(TlsAcceptor::from(Arc::new(config)))
    }

    async fn handle_request(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let response = match (req.method(), req.uri().path()) {
            (&Method::GET, "/dns-query") => self.handle_get(req).await,
            (&Method::POST, "/dns-query") => self.handle_post(req).await,
            (&Method::GET, "/health") => Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(Bytes::from("OK")))
                .unwrap()),
            _ => Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from("Not Found")))
                .unwrap()),
        };

        match response {
            Ok(resp) => Ok(resp),
            Err(e) => {
                error!("DoH request error: {}", e);
                Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Full::new(Bytes::from("Internal Server Error")))
                    .unwrap())
            }
        }
    }

    async fn handle_get(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync>> {
        let query_string = req.uri().query().unwrap_or("");
        let dns_param = query_string
            .split('&')
            .find_map(|pair| {
                let mut parts = pair.splitn(2, '=');
                let key = parts.next()?;
                let value = parts.next()?;
                if key == "dns" {
                    Some(value.to_string())
                } else {
                    None
                }
            })
            .ok_or("Missing 'dns' query parameter")?;

        let dns_bytes = URL_SAFE_NO_PAD.decode(&dns_param)?;
        self.process_dns_query(&dns_bytes).await
    }

    async fn handle_post(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync>> {
        // Check content type
        let content_type = req
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if content_type != DNS_MESSAGE_TYPE {
            return Ok(Response::builder()
                .status(StatusCode::UNSUPPORTED_MEDIA_TYPE)
                .body(Full::new(Bytes::from("Expected application/dns-message")))
                .unwrap());
        }

        let body = req.collect().await?.to_bytes();
        self.process_dns_query(&body).await
    }

    async fn process_dns_query(
        &self,
        query_bytes: &[u8],
    ) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync>> {
        let query = DnsMessage::parse(query_bytes)?;

        if query.questions.is_empty() {
            let error_response = query.make_error_response(ResponseCode::FormatError);
            let response_bytes = error_response.serialize();
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", DNS_MESSAGE_TYPE)
                .body(Full::new(Bytes::from(response_bytes)))
                .unwrap());
        }

        let question = &query.questions[0];
        let mut response = query.make_response();

        match self
            .resolver
            .resolve(&question.name, question.record_type)
            .await
        {
            Ok(records) => {
                response.answers = records;
                response.header.response_code = ResponseCode::NoError;
            }
            Err(code) => {
                response.header.response_code = code;
            }
        }

        let response_bytes = response.serialize();
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", DNS_MESSAGE_TYPE)
            .header("cache-control", "max-age=300")
            .body(Full::new(Bytes::from(response_bytes)))
            .unwrap())
    }
}
