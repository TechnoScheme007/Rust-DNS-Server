use super::error::DnsError;
use super::name::DnsName;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordType {
    A,
    AAAA,
    CNAME,
    MX,
    TXT,
    NS,
    SOA,
    SRV,
    PTR,
    DS,
    DNSKEY,
    RRSIG,
    NSEC,
    OPT,
    Unknown(u16),
}

impl RecordType {
    pub fn from_u16(val: u16) -> Self {
        match val {
            1 => RecordType::A,
            28 => RecordType::AAAA,
            5 => RecordType::CNAME,
            15 => RecordType::MX,
            16 => RecordType::TXT,
            2 => RecordType::NS,
            6 => RecordType::SOA,
            33 => RecordType::SRV,
            12 => RecordType::PTR,
            43 => RecordType::DS,
            48 => RecordType::DNSKEY,
            46 => RecordType::RRSIG,
            47 => RecordType::NSEC,
            41 => RecordType::OPT,
            n => RecordType::Unknown(n),
        }
    }

    pub fn to_u16(self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::AAAA => 28,
            RecordType::CNAME => 5,
            RecordType::MX => 15,
            RecordType::TXT => 16,
            RecordType::NS => 2,
            RecordType::SOA => 6,
            RecordType::SRV => 33,
            RecordType::PTR => 12,
            RecordType::DS => 43,
            RecordType::DNSKEY => 48,
            RecordType::RRSIG => 46,
            RecordType::NSEC => 47,
            RecordType::OPT => 41,
            RecordType::Unknown(n) => n,
        }
    }

    pub fn from_str_type(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "A" => Some(RecordType::A),
            "AAAA" => Some(RecordType::AAAA),
            "CNAME" => Some(RecordType::CNAME),
            "MX" => Some(RecordType::MX),
            "TXT" => Some(RecordType::TXT),
            "NS" => Some(RecordType::NS),
            "SOA" => Some(RecordType::SOA),
            "SRV" => Some(RecordType::SRV),
            "PTR" => Some(RecordType::PTR),
            "DS" => Some(RecordType::DS),
            "DNSKEY" => Some(RecordType::DNSKEY),
            _ => None,
        }
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordType::A => write!(f, "A"),
            RecordType::AAAA => write!(f, "AAAA"),
            RecordType::CNAME => write!(f, "CNAME"),
            RecordType::MX => write!(f, "MX"),
            RecordType::TXT => write!(f, "TXT"),
            RecordType::NS => write!(f, "NS"),
            RecordType::SOA => write!(f, "SOA"),
            RecordType::SRV => write!(f, "SRV"),
            RecordType::PTR => write!(f, "PTR"),
            RecordType::DS => write!(f, "DS"),
            RecordType::DNSKEY => write!(f, "DNSKEY"),
            RecordType::RRSIG => write!(f, "RRSIG"),
            RecordType::NSEC => write!(f, "NSEC"),
            RecordType::OPT => write!(f, "OPT"),
            RecordType::Unknown(n) => write!(f, "TYPE{}", n),
        }
    }
}

#[derive(Debug, Clone)]
pub enum RData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CNAME(DnsName),
    MX { preference: u16, exchange: DnsName },
    TXT(Vec<String>),
    NS(DnsName),
    SOA {
        mname: DnsName,
        rname: DnsName,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: DnsName,
    },
    PTR(DnsName),
    DS {
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: Vec<u8>,
    },
    DNSKEY {
        flags: u16,
        protocol: u8,
        algorithm: u8,
        public_key: Vec<u8>,
    },
    RRSIG {
        type_covered: RecordType,
        algorithm: u8,
        labels: u8,
        original_ttl: u32,
        signature_expiration: u32,
        signature_inception: u32,
        key_tag: u16,
        signer_name: DnsName,
        signature: Vec<u8>,
    },
    NSEC {
        next_domain: DnsName,
        type_bitmaps: Vec<u8>,
    },
    OPT(Vec<u8>),
    Unknown(Vec<u8>),
}

impl RData {
    pub fn parse(
        record_type: RecordType,
        data: &[u8],
        offset: &mut usize,
        rdlength: u16,
    ) -> Result<Self, DnsError> {
        let end = *offset + rdlength as usize;
        if end > data.len() {
            return Err(DnsError::BufferTooShort);
        }

        let rdata = match record_type {
            RecordType::A => {
                if rdlength != 4 {
                    return Err(DnsError::ParseError("Invalid A record length".into()));
                }
                let addr = Ipv4Addr::new(
                    data[*offset],
                    data[*offset + 1],
                    data[*offset + 2],
                    data[*offset + 3],
                );
                *offset = end;
                RData::A(addr)
            }
            RecordType::AAAA => {
                if rdlength != 16 {
                    return Err(DnsError::ParseError("Invalid AAAA record length".into()));
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[*offset..*offset + 16]);
                let addr = Ipv6Addr::from(octets);
                *offset = end;
                RData::AAAA(addr)
            }
            RecordType::CNAME => {
                let name = DnsName::parse(data, offset)?;
                *offset = end;
                RData::CNAME(name)
            }
            RecordType::NS => {
                let name = DnsName::parse(data, offset)?;
                *offset = end;
                RData::NS(name)
            }
            RecordType::PTR => {
                let name = DnsName::parse(data, offset)?;
                *offset = end;
                RData::PTR(name)
            }
            RecordType::MX => {
                if rdlength < 3 {
                    return Err(DnsError::ParseError("Invalid MX record".into()));
                }
                let preference = u16::from_be_bytes([data[*offset], data[*offset + 1]]);
                *offset += 2;
                let exchange = DnsName::parse(data, offset)?;
                *offset = end;
                RData::MX {
                    preference,
                    exchange,
                }
            }
            RecordType::TXT => {
                let mut texts = Vec::new();
                let mut pos = *offset;
                while pos < end {
                    let txt_len = data[pos] as usize;
                    pos += 1;
                    if pos + txt_len > end {
                        return Err(DnsError::ParseError("TXT record overflow".into()));
                    }
                    texts.push(String::from_utf8_lossy(&data[pos..pos + txt_len]).to_string());
                    pos += txt_len;
                }
                *offset = end;
                RData::TXT(texts)
            }
            RecordType::SOA => {
                let mname = DnsName::parse(data, offset)?;
                let rname = DnsName::parse(data, offset)?;
                if *offset + 20 > end {
                    return Err(DnsError::ParseError("Invalid SOA record".into()));
                }
                let serial = u32::from_be_bytes([
                    data[*offset],
                    data[*offset + 1],
                    data[*offset + 2],
                    data[*offset + 3],
                ]);
                let refresh = u32::from_be_bytes([
                    data[*offset + 4],
                    data[*offset + 5],
                    data[*offset + 6],
                    data[*offset + 7],
                ]);
                let retry = u32::from_be_bytes([
                    data[*offset + 8],
                    data[*offset + 9],
                    data[*offset + 10],
                    data[*offset + 11],
                ]);
                let expire = u32::from_be_bytes([
                    data[*offset + 12],
                    data[*offset + 13],
                    data[*offset + 14],
                    data[*offset + 15],
                ]);
                let minimum = u32::from_be_bytes([
                    data[*offset + 16],
                    data[*offset + 17],
                    data[*offset + 18],
                    data[*offset + 19],
                ]);
                *offset = end;
                RData::SOA {
                    mname,
                    rname,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                }
            }
            RecordType::SRV => {
                if rdlength < 7 {
                    return Err(DnsError::ParseError("Invalid SRV record".into()));
                }
                let priority = u16::from_be_bytes([data[*offset], data[*offset + 1]]);
                let weight = u16::from_be_bytes([data[*offset + 2], data[*offset + 3]]);
                let port = u16::from_be_bytes([data[*offset + 4], data[*offset + 5]]);
                *offset += 6;
                let target = DnsName::parse(data, offset)?;
                *offset = end;
                RData::SRV {
                    priority,
                    weight,
                    port,
                    target,
                }
            }
            RecordType::DS => {
                if rdlength < 5 {
                    return Err(DnsError::ParseError("Invalid DS record".into()));
                }
                let key_tag = u16::from_be_bytes([data[*offset], data[*offset + 1]]);
                let algorithm = data[*offset + 2];
                let digest_type = data[*offset + 3];
                let digest = data[*offset + 4..end].to_vec();
                *offset = end;
                RData::DS {
                    key_tag,
                    algorithm,
                    digest_type,
                    digest,
                }
            }
            RecordType::DNSKEY => {
                if rdlength < 5 {
                    return Err(DnsError::ParseError("Invalid DNSKEY record".into()));
                }
                let flags = u16::from_be_bytes([data[*offset], data[*offset + 1]]);
                let protocol = data[*offset + 2];
                let algorithm = data[*offset + 3];
                let public_key = data[*offset + 4..end].to_vec();
                *offset = end;
                RData::DNSKEY {
                    flags,
                    protocol,
                    algorithm,
                    public_key,
                }
            }
            RecordType::RRSIG => {
                if rdlength < 19 {
                    return Err(DnsError::ParseError("Invalid RRSIG record".into()));
                }
                let type_covered =
                    RecordType::from_u16(u16::from_be_bytes([data[*offset], data[*offset + 1]]));
                let algorithm = data[*offset + 2];
                let labels = data[*offset + 3];
                let original_ttl = u32::from_be_bytes([
                    data[*offset + 4],
                    data[*offset + 5],
                    data[*offset + 6],
                    data[*offset + 7],
                ]);
                let signature_expiration = u32::from_be_bytes([
                    data[*offset + 8],
                    data[*offset + 9],
                    data[*offset + 10],
                    data[*offset + 11],
                ]);
                let signature_inception = u32::from_be_bytes([
                    data[*offset + 12],
                    data[*offset + 13],
                    data[*offset + 14],
                    data[*offset + 15],
                ]);
                let key_tag = u16::from_be_bytes([data[*offset + 16], data[*offset + 17]]);
                *offset += 18;
                let signer_name = DnsName::parse(data, offset)?;
                let signature = data[*offset..end].to_vec();
                *offset = end;
                RData::RRSIG {
                    type_covered,
                    algorithm,
                    labels,
                    original_ttl,
                    signature_expiration,
                    signature_inception,
                    key_tag,
                    signer_name,
                    signature,
                }
            }
            RecordType::NSEC => {
                let next_domain = DnsName::parse(data, offset)?;
                let type_bitmaps = data[*offset..end].to_vec();
                *offset = end;
                RData::NSEC {
                    next_domain,
                    type_bitmaps,
                }
            }
            RecordType::OPT => {
                let opt_data = data[*offset..end].to_vec();
                *offset = end;
                RData::OPT(opt_data)
            }
            _ => {
                let raw = data[*offset..end].to_vec();
                *offset = end;
                RData::Unknown(raw)
            }
        };

        Ok(rdata)
    }

    pub fn serialize(&self) -> Vec<u8> {
        match self {
            RData::A(addr) => addr.octets().to_vec(),
            RData::AAAA(addr) => addr.octets().to_vec(),
            RData::CNAME(name) | RData::NS(name) | RData::PTR(name) => name.to_wire(),
            RData::MX {
                preference,
                exchange,
            } => {
                let mut buf = Vec::new();
                buf.extend_from_slice(&preference.to_be_bytes());
                buf.extend_from_slice(&exchange.to_wire());
                buf
            }
            RData::TXT(texts) => {
                let mut buf = Vec::new();
                for text in texts {
                    let bytes = text.as_bytes();
                    // Split into 255-byte chunks
                    for chunk in bytes.chunks(255) {
                        buf.push(chunk.len() as u8);
                        buf.extend_from_slice(chunk);
                    }
                    if bytes.is_empty() {
                        buf.push(0);
                    }
                }
                buf
            }
            RData::SOA {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                let mut buf = Vec::new();
                buf.extend_from_slice(&mname.to_wire());
                buf.extend_from_slice(&rname.to_wire());
                buf.extend_from_slice(&serial.to_be_bytes());
                buf.extend_from_slice(&refresh.to_be_bytes());
                buf.extend_from_slice(&retry.to_be_bytes());
                buf.extend_from_slice(&expire.to_be_bytes());
                buf.extend_from_slice(&minimum.to_be_bytes());
                buf
            }
            RData::SRV {
                priority,
                weight,
                port,
                target,
            } => {
                let mut buf = Vec::new();
                buf.extend_from_slice(&priority.to_be_bytes());
                buf.extend_from_slice(&weight.to_be_bytes());
                buf.extend_from_slice(&port.to_be_bytes());
                buf.extend_from_slice(&target.to_wire());
                buf
            }
            RData::DS {
                key_tag,
                algorithm,
                digest_type,
                digest,
            } => {
                let mut buf = Vec::new();
                buf.extend_from_slice(&key_tag.to_be_bytes());
                buf.push(*algorithm);
                buf.push(*digest_type);
                buf.extend_from_slice(digest);
                buf
            }
            RData::DNSKEY {
                flags,
                protocol,
                algorithm,
                public_key,
            } => {
                let mut buf = Vec::new();
                buf.extend_from_slice(&flags.to_be_bytes());
                buf.push(*protocol);
                buf.push(*algorithm);
                buf.extend_from_slice(public_key);
                buf
            }
            RData::RRSIG {
                type_covered,
                algorithm,
                labels,
                original_ttl,
                signature_expiration,
                signature_inception,
                key_tag,
                signer_name,
                signature,
            } => {
                let mut buf = Vec::new();
                buf.extend_from_slice(&type_covered.to_u16().to_be_bytes());
                buf.push(*algorithm);
                buf.push(*labels);
                buf.extend_from_slice(&original_ttl.to_be_bytes());
                buf.extend_from_slice(&signature_expiration.to_be_bytes());
                buf.extend_from_slice(&signature_inception.to_be_bytes());
                buf.extend_from_slice(&key_tag.to_be_bytes());
                buf.extend_from_slice(&signer_name.to_wire());
                buf.extend_from_slice(signature);
                buf
            }
            RData::NSEC {
                next_domain,
                type_bitmaps,
            } => {
                let mut buf = Vec::new();
                buf.extend_from_slice(&next_domain.to_wire());
                buf.extend_from_slice(type_bitmaps);
                buf
            }
            RData::OPT(data) | RData::Unknown(data) => data.clone(),
        }
    }
}

impl fmt::Display for RData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RData::A(addr) => write!(f, "{}", addr),
            RData::AAAA(addr) => write!(f, "{}", addr),
            RData::CNAME(name) => write!(f, "{}", name),
            RData::NS(name) => write!(f, "{}", name),
            RData::PTR(name) => write!(f, "{}", name),
            RData::MX {
                preference,
                exchange,
            } => write!(f, "{} {}", preference, exchange),
            RData::TXT(texts) => write!(f, "\"{}\"", texts.join("\" \"")),
            RData::SOA {
                mname,
                rname,
                serial,
                ..
            } => write!(f, "{} {} {}", mname, rname, serial),
            RData::SRV {
                priority,
                weight,
                port,
                target,
            } => write!(f, "{} {} {} {}", priority, weight, port, target),
            RData::DS {
                key_tag, algorithm, ..
            } => write!(f, "{} {}", key_tag, algorithm),
            RData::DNSKEY {
                flags, algorithm, ..
            } => write!(f, "{} 3 {}", flags, algorithm),
            RData::RRSIG {
                type_covered,
                signer_name,
                ..
            } => write!(f, "{} {}", type_covered, signer_name),
            RData::NSEC { next_domain, .. } => write!(f, "{}", next_domain),
            RData::OPT(_) => write!(f, "<OPT>"),
            RData::Unknown(data) => write!(f, "<{} bytes>", data.len()),
        }
    }
}
