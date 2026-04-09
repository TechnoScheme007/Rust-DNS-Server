use crate::cache::DnsCache;
use crate::dns::header::ResponseCode;
use crate::dns::rdata::RecordType;
use crate::dns::{DnsMessage, DnsName, DnsRecord, RData};
use crate::dnssec::{DnssecValidator, ValidationResult};
use crate::zone::ZoneStore;
use parking_lot::RwLock;
use rand::Rng;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};
use tracing::{debug, warn};

/// Root DNS servers (IANA root hints)
const ROOT_SERVERS: &[(&str, &str)] = &[
    ("a.root-servers.net", "198.41.0.4"),
    ("b.root-servers.net", "170.247.170.2"),
    ("c.root-servers.net", "192.33.4.12"),
    ("d.root-servers.net", "199.7.91.13"),
    ("e.root-servers.net", "192.203.230.10"),
    ("f.root-servers.net", "192.5.5.241"),
    ("g.root-servers.net", "192.112.36.4"),
    ("h.root-servers.net", "198.97.190.53"),
    ("i.root-servers.net", "192.36.148.17"),
    ("j.root-servers.net", "192.58.128.30"),
    ("k.root-servers.net", "193.0.14.129"),
    ("l.root-servers.net", "199.7.83.42"),
    ("m.root-servers.net", "202.12.27.33"),
];

const MAX_RECURSION_DEPTH: usize = 32;
const MAX_CNAME_CHAIN: usize = 16;
const QUERY_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_RETRIES: usize = 3;

pub struct Resolver {
    cache: Arc<DnsCache>,
    zone_store: Arc<RwLock<ZoneStore>>,
    dnssec_validator: DnssecValidator,
    enable_dnssec: bool,
}

impl Resolver {
    pub fn new(cache: Arc<DnsCache>, zone_store: Arc<RwLock<ZoneStore>>, enable_dnssec: bool) -> Self {
        Resolver {
            cache,
            zone_store,
            dnssec_validator: DnssecValidator::new(),
            enable_dnssec,
        }
    }

    pub async fn resolve(
        &self,
        name: &DnsName,
        record_type: RecordType,
    ) -> Result<Vec<DnsRecord>, ResponseCode> {
        // 1. Check authoritative zones first
        enum ZoneResult {
            Found(Vec<DnsRecord>),
            FollowCname(Vec<DnsRecord>),
            NoData,
            NotFound,
        }

        let zone_result = {
            let zones = self.zone_store.read();
            if let Some(records) = zones.lookup(name, record_type) {
                debug!("Zone hit for {} {}", name, record_type);
                ZoneResult::Found(records)
            } else if let Some(zone) = zones.find_zone(name) {
                if zone.has_name(name) && record_type != RecordType::CNAME {
                    if let Some(cnames) = zone.lookup(name, RecordType::CNAME) {
                        ZoneResult::FollowCname(cnames)
                    } else {
                        ZoneResult::NoData
                    }
                } else {
                    ZoneResult::NotFound
                }
            } else {
                ZoneResult::NotFound
            }
        }; // guard dropped here

        match zone_result {
            ZoneResult::Found(records) => return Ok(records),
            ZoneResult::FollowCname(cnames) => {
                return self.follow_cname_chain(&cnames, record_type, 0).await;
            }
            ZoneResult::NoData => return Ok(vec![]),
            ZoneResult::NotFound => {}
        }

        // 2. Check cache
        if let Some(records) = self.cache.lookup(name, record_type) {
            debug!("Cache hit for {} {}", name, record_type);
            return Ok(records);
        }

        // Also check cache for CNAME
        if record_type != RecordType::CNAME {
            if let Some(cnames) = self.cache.lookup(name, RecordType::CNAME) {
                return self.follow_cname_chain(&cnames, record_type, 0).await;
            }
        }

        // 3. Recursive resolution from root
        debug!("Recursively resolving {} {}", name, record_type);
        self.resolve_recursive(name, record_type, 0).await
    }

    fn resolve_recursive<'a>(
        &'a self,
        name: &'a DnsName,
        record_type: RecordType,
        depth: usize,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<DnsRecord>, ResponseCode>> + Send + 'a>> {
        Box::pin(async move {
        if depth > MAX_RECURSION_DEPTH {
            warn!("Max recursion depth exceeded for {} {}", name, record_type);
            return Err(ResponseCode::ServerFailure);
        }

        // Start with root servers
        let mut nameservers: Vec<SocketAddr> = ROOT_SERVERS
            .iter()
            .map(|(_, ip)| {
                let addr: std::net::Ipv4Addr = ip.parse().unwrap();
                SocketAddr::new(addr.into(), 53)
            })
            .collect();

        let mut last_ns_names: Vec<DnsName> = Vec::new();

        loop {
            let response = self.query_nameservers(name, record_type, &nameservers).await?;

            // Check for answers
            if response.header.response_code == ResponseCode::NameError {
                return Err(ResponseCode::NameError);
            }

            // If we got answers, process them
            if !response.answers.is_empty() {
                let mut result = Vec::new();
                let mut cnames = Vec::new();

                for record in &response.answers {
                    if record.record_type == record_type {
                        result.push(record.clone());
                    } else if record.record_type == RecordType::CNAME {
                        cnames.push(record.clone());
                    }
                }

                // DNSSEC validation
                if self.enable_dnssec && !response.answers.is_empty() {
                    let all_records: Vec<DnsRecord> = response
                        .answers
                        .iter()
                        .chain(response.authorities.iter())
                        .chain(response.additional.iter())
                        .cloned()
                        .collect();

                    let validation = self.dnssec_validator.validate_response(
                        &all_records,
                        name,
                        record_type,
                    );

                    match validation {
                        ValidationResult::Bogus => {
                            warn!("DNSSEC validation failed (BOGUS) for {} {}", name, record_type);
                            return Err(ResponseCode::ServerFailure);
                        }
                        ValidationResult::Secure => {
                            debug!("DNSSEC validation: SECURE for {} {}", name, record_type);
                        }
                        _ => {
                            debug!("DNSSEC validation: {:?} for {} {}", validation, name, record_type);
                        }
                    }
                }

                if !result.is_empty() {
                    // Cache the result
                    self.cache.insert(name, record_type, result.clone());
                    return Ok(result);
                }

                // Follow CNAME chain
                if !cnames.is_empty() {
                    self.cache.insert(name, RecordType::CNAME, cnames.clone());
                    return self.follow_cname_chain(&cnames, record_type, depth).await;
                }

                // Got answers but not the type we want
                return Ok(vec![]);
            }

            // Check for NS referrals in authority section
            let mut new_ns_names: Vec<DnsName> = Vec::new();
            let mut glue_addrs: Vec<SocketAddr> = Vec::new();

            for record in &response.authorities {
                if record.record_type == RecordType::NS {
                    if let RData::NS(ns_name) = &record.rdata {
                        new_ns_names.push(ns_name.clone());
                        // Cache NS records
                        self.cache.insert(
                            &record.name,
                            RecordType::NS,
                            vec![record.clone()],
                        );
                    }
                }
            }

            // Look for glue records in additional section
            for record in &response.additional {
                if record.record_type == RecordType::A {
                    if let RData::A(addr) = &record.rdata {
                        if new_ns_names.iter().any(|ns| ns == &record.name) {
                            glue_addrs.push(SocketAddr::new((*addr).into(), 53));
                            self.cache.insert(
                                &record.name,
                                RecordType::A,
                                vec![record.clone()],
                            );
                        }
                    }
                }
            }

            if new_ns_names.is_empty() {
                // No referral, check if authority has SOA (negative answer)
                let has_soa = response
                    .authorities
                    .iter()
                    .any(|r| r.record_type == RecordType::SOA);
                if has_soa {
                    return Ok(vec![]);
                }
                return Err(ResponseCode::ServerFailure);
            }

            // Prevent loops
            if new_ns_names == last_ns_names {
                return Err(ResponseCode::ServerFailure);
            }
            last_ns_names = new_ns_names.clone();

            if !glue_addrs.is_empty() {
                nameservers = glue_addrs;
            } else {
                // Need to resolve the nameserver addresses
                let mut resolved_addrs = Vec::new();
                for ns_name in &new_ns_names {
                    // Check cache first
                    if let Some(cached) = self.cache.lookup(ns_name, RecordType::A) {
                        for r in cached {
                            if let RData::A(addr) = r.rdata {
                                resolved_addrs.push(SocketAddr::new(addr.into(), 53));
                            }
                        }
                    } else {
                        // Recursively resolve nameserver
                        match self.resolve_recursive(ns_name, RecordType::A, depth + 1).await {
                            Ok(records) => {
                                for r in records {
                                    if let RData::A(addr) = r.rdata {
                                        resolved_addrs.push(SocketAddr::new(addr.into(), 53));
                                    }
                                }
                            }
                            Err(_) => continue,
                        }
                    }
                    if !resolved_addrs.is_empty() {
                        break;
                    }
                }

                if resolved_addrs.is_empty() {
                    return Err(ResponseCode::ServerFailure);
                }
                nameservers = resolved_addrs;
            }
        }
        }) // close Box::pin
    }

    fn follow_cname_chain<'a>(
        &'a self,
        cnames: &'a [DnsRecord],
        target_type: RecordType,
        depth: usize,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<DnsRecord>, ResponseCode>> + Send + 'a>> {
        Box::pin(async move {
            let mut chain = cnames.to_vec();
            let mut current_name = match cnames.last() {
                Some(r) => match &r.rdata {
                    RData::CNAME(name) => name.clone(),
                    _ => return Err(ResponseCode::ServerFailure),
                },
                None => return Err(ResponseCode::ServerFailure),
            };

            for _ in 0..MAX_CNAME_CHAIN {
                match self.resolve_recursive(&current_name, target_type, depth + 1).await {
                    Ok(records) if !records.is_empty() => {
                        chain.extend(records);
                        return Ok(chain);
                    }
                    Ok(_) => {
                        if let Ok(cname_records) =
                            self.resolve_recursive(&current_name, RecordType::CNAME, depth + 1).await
                        {
                            for r in &cname_records {
                                if let RData::CNAME(name) = &r.rdata {
                                    chain.push(r.clone());
                                    current_name = name.clone();
                                }
                            }
                        } else {
                            break;
                        }
                    }
                    Err(e) => return Err(e),
                }
            }

            Ok(chain)
        })
    }

    async fn query_nameservers(
        &self,
        name: &DnsName,
        record_type: RecordType,
        nameservers: &[SocketAddr],
    ) -> Result<DnsMessage, ResponseCode> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|_| ResponseCode::ServerFailure)?;

        // Build query message - scope rng so it doesn't live across await
        let (id, query_bytes, ns_offsets) = {
            let mut rng = rand::thread_rng();
            let id: u16 = rng.gen();
            let mut query = DnsMessage::new_query(id);
            query.header.recursion_desired = false;

            if self.enable_dnssec {
                query.header.authentic_data = true;
                let opt = DnsRecord {
                    name: DnsName::root(),
                    record_type: RecordType::OPT,
                    record_class: crate::dns::record::RecordClass::Unknown(4096),
                    ttl: 0x00008000, // DO bit set
                    rdata: RData::OPT(vec![]),
                };
                query.additional.push(opt);
            }

            query.questions.push(crate::dns::DnsQuestion::new(
                name.clone(),
                record_type,
            ));
            let bytes = query.serialize();
            let offsets: Vec<usize> = (0..MAX_RETRIES)
                .map(|i| (i + rng.gen::<usize>()) % nameservers.len())
                .collect();
            (id, bytes, offsets)
        };

        // Try multiple nameservers with retries
        for retry in 0..MAX_RETRIES {
            let ns_idx = ns_offsets[retry];
            let ns = nameservers[ns_idx];

            debug!("Querying {} {} @ {} (attempt {})", name, record_type, ns, retry + 1);

            if let Err(e) = socket.send_to(&query_bytes, ns).await {
                warn!("Failed to send to {}: {}", ns, e);
                continue;
            }

            let mut buf = vec![0u8; 4096];
            match timeout(QUERY_TIMEOUT, socket.recv_from(&mut buf)).await {
                Ok(Ok((len, _))) => {
                    match DnsMessage::parse(&buf[..len]) {
                        Ok(response) => {
                            if response.header.id == id {
                                if response.header.truncated {
                                    // Try TCP fallback
                                    if let Ok(tcp_response) =
                                        self.query_tcp(name, record_type, ns).await
                                    {
                                        return Ok(tcp_response);
                                    }
                                }
                                return Ok(response);
                            }
                        }
                        Err(e) => {
                            warn!("Failed to parse response from {}: {}", ns, e);
                        }
                    }
                }
                Ok(Err(e)) => {
                    warn!("Recv error from {}: {}", ns, e);
                }
                Err(_) => {
                    debug!("Timeout querying {}", ns);
                }
            }
        }

        Err(ResponseCode::ServerFailure)
    }

    async fn query_tcp(
        &self,
        name: &DnsName,
        record_type: RecordType,
        server: SocketAddr,
    ) -> Result<DnsMessage, ResponseCode> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let mut stream = timeout(QUERY_TIMEOUT, TcpStream::connect(server))
            .await
            .map_err(|_| ResponseCode::ServerFailure)?
            .map_err(|_| ResponseCode::ServerFailure)?;

        let query_bytes = {
            let mut rng = rand::thread_rng();
            let id: u16 = rng.gen();
            let mut query = DnsMessage::new_query(id);
            query.header.recursion_desired = false;
            query.questions.push(crate::dns::DnsQuestion::new(
                name.clone(),
                record_type,
            ));
            query.serialize()
        };

        // TCP DNS: 2-byte length prefix
        let len = query_bytes.len() as u16;
        stream
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|_| ResponseCode::ServerFailure)?;
        stream
            .write_all(&query_bytes)
            .await
            .map_err(|_| ResponseCode::ServerFailure)?;

        let mut len_buf = [0u8; 2];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|_| ResponseCode::ServerFailure)?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;

        let mut resp_buf = vec![0u8; resp_len];
        stream
            .read_exact(&mut resp_buf)
            .await
            .map_err(|_| ResponseCode::ServerFailure)?;

        DnsMessage::parse(&resp_buf).map_err(|_| ResponseCode::ServerFailure)
    }
}
