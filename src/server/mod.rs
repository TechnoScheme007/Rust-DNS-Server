use crate::dns::header::ResponseCode;
use crate::dns::DnsMessage;
use crate::resolver::Resolver;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, error, info, warn};

pub struct DnsServer {
    resolver: Arc<Resolver>,
    udp_addr: String,
    tcp_addr: String,
}

impl DnsServer {
    pub fn new(resolver: Arc<Resolver>, listen_addr: String) -> Self {
        DnsServer {
            resolver,
            udp_addr: listen_addr.clone(),
            tcp_addr: listen_addr,
        }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let udp_socket = UdpSocket::bind(&self.udp_addr).await?;
        info!("DNS UDP server listening on {}", self.udp_addr);

        let tcp_listener = TcpListener::bind(&self.tcp_addr).await?;
        info!("DNS TCP server listening on {}", self.tcp_addr);

        let resolver_udp = self.resolver.clone();
        let resolver_tcp = self.resolver.clone();

        tokio::select! {
            result = Self::run_udp(udp_socket, resolver_udp) => {
                if let Err(e) = result {
                    error!("UDP server error: {}", e);
                }
            }
            result = Self::run_tcp(tcp_listener, resolver_tcp) => {
                if let Err(e) = result {
                    error!("TCP server error: {}", e);
                }
            }
        }

        Ok(())
    }

    async fn run_udp(
        socket: UdpSocket,
        resolver: Arc<Resolver>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let socket = Arc::new(socket);
        let mut buf = vec![0u8; 4096];

        loop {
            let (len, addr) = socket.recv_from(&mut buf).await?;
            let data = buf[..len].to_vec();
            let socket = socket.clone();
            let resolver = resolver.clone();

            tokio::spawn(async move {
                match Self::handle_query(&resolver, &data).await {
                    Ok(response_bytes) => {
                        // Check if response exceeds UDP limit
                        if response_bytes.len() > 512 {
                            // Set TC bit and truncate
                            let mut response = match DnsMessage::parse(&response_bytes) {
                                Ok(r) => r,
                                Err(_) => return,
                            };
                            response.header.truncated = true;
                            response.answers.truncate(0);
                            response.authorities.truncate(0);
                            response.additional.truncate(0);
                            let truncated = response.serialize();
                            if let Err(e) = socket.send_to(&truncated, addr).await {
                                warn!("Failed to send truncated UDP response to {}: {}", addr, e);
                            }
                        } else if let Err(e) = socket.send_to(&response_bytes, addr).await {
                            warn!("Failed to send UDP response to {}: {}", addr, e);
                        }
                    }
                    Err(e) => {
                        debug!("Failed to handle query from {}: {}", addr, e);
                    }
                }
            });
        }
    }

    async fn run_tcp(
        listener: TcpListener,
        resolver: Arc<Resolver>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        loop {
            let (mut stream, addr) = listener.accept().await?;
            let resolver = resolver.clone();

            tokio::spawn(async move {
                // TCP DNS: read 2-byte length prefix, then message
                let mut len_buf = [0u8; 2];
                if let Err(e) = stream.read_exact(&mut len_buf).await {
                    debug!("TCP read error from {}: {}", addr, e);
                    return;
                }

                let msg_len = u16::from_be_bytes(len_buf) as usize;
                if msg_len > 65535 {
                    warn!("TCP message too large from {}", addr);
                    return;
                }

                let mut msg_buf = vec![0u8; msg_len];
                if let Err(e) = stream.read_exact(&mut msg_buf).await {
                    debug!("TCP read error from {}: {}", addr, e);
                    return;
                }

                match Self::handle_query(&resolver, &msg_buf).await {
                    Ok(response_bytes) => {
                        let len = response_bytes.len() as u16;
                        if let Err(e) = stream.write_all(&len.to_be_bytes()).await {
                            warn!("TCP write error to {}: {}", addr, e);
                            return;
                        }
                        if let Err(e) = stream.write_all(&response_bytes).await {
                            warn!("TCP write error to {}: {}", addr, e);
                        }
                    }
                    Err(e) => {
                        debug!("Failed to handle TCP query from {}: {}", addr, e);
                    }
                }
            });
        }
    }

    async fn handle_query(
        resolver: &Resolver,
        data: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let query = DnsMessage::parse(data)?;

        if query.questions.is_empty() {
            let error_response = query.make_error_response(ResponseCode::FormatError);
            return Ok(error_response.serialize());
        }

        let question = &query.questions[0];
        debug!(
            "Query: {} {} from id={}",
            question.name, question.record_type, query.header.id
        );

        let mut response = query.make_response();

        match resolver
            .resolve(&question.name, question.record_type)
            .await
        {
            Ok(records) => {
                if records.is_empty() {
                    response.header.response_code = ResponseCode::NoError;
                } else {
                    response.header.response_code = ResponseCode::NoError;
                    response.answers = records;
                }
            }
            Err(code) => {
                response.header.response_code = code;
            }
        }

        Ok(response.serialize())
    }
}
