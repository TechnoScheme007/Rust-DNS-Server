use crate::dns::{DnsError, DnsName, DnsRecord, RData, RecordType};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Deserialize, Clone)]
pub struct ZoneConfig {
    pub zones: Vec<ZoneDefinition>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ZoneDefinition {
    pub name: String,
    pub soa: SoaConfig,
    pub records: Vec<RecordConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SoaConfig {
    pub mname: String,
    pub rname: String,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RecordConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub ttl: Option<u32>,
    pub value: String,
    pub priority: Option<u16>,
    pub weight: Option<u16>,
    pub port: Option<u16>,
}

#[derive(Debug)]
pub struct Zone {
    pub name: DnsName,
    pub soa: DnsRecord,
    records: HashMap<(DnsName, RecordType), Vec<DnsRecord>>,
    ns_records: Vec<DnsRecord>,
}

impl Zone {
    pub fn from_config(def: &ZoneDefinition) -> Result<Self, DnsError> {
        let zone_name = DnsName::new(&def.name).map_err(|e| DnsError::ParseError(format!("Invalid zone name: {}", e)))?;
        let default_ttl = def.soa.minimum;

        let soa = DnsRecord::new(
            zone_name.clone(),
            RecordType::SOA,
            default_ttl,
            RData::SOA {
                mname: DnsName::new(&def.soa.mname).map_err(|e| DnsError::ParseError(format!("{}", e)))?,
                rname: DnsName::new(&def.soa.rname).map_err(|e| DnsError::ParseError(format!("{}", e)))?,
                serial: def.soa.serial,
                refresh: def.soa.refresh,
                retry: def.soa.retry,
                expire: def.soa.expire,
                minimum: def.soa.minimum,
            },
        );

        let mut records: HashMap<(DnsName, RecordType), Vec<DnsRecord>> = HashMap::new();
        let mut ns_records = Vec::new();

        for rec in &def.records {
            let record_name = if rec.name == "@" {
                zone_name.clone()
            } else {
                DnsName::new(&format!("{}.{}", rec.name, def.name))
                    .map_err(|e| DnsError::ParseError(format!("{}", e)))?
            };

            let ttl = rec.ttl.unwrap_or(default_ttl);
            let rtype = RecordType::from_str_type(&rec.record_type)
                .ok_or_else(|| DnsError::ParseError(format!("Unknown record type: {}", rec.record_type)))?;

            let rdata = match rtype {
                RecordType::A => {
                    let addr: Ipv4Addr = rec.value.parse()
                        .map_err(|_| DnsError::ParseError(format!("Invalid IPv4: {}", rec.value)))?;
                    RData::A(addr)
                }
                RecordType::AAAA => {
                    let addr: Ipv6Addr = rec.value.parse()
                        .map_err(|_| DnsError::ParseError(format!("Invalid IPv6: {}", rec.value)))?;
                    RData::AAAA(addr)
                }
                RecordType::CNAME => {
                    RData::CNAME(DnsName::new(&rec.value).map_err(|e| DnsError::ParseError(format!("{}", e)))?)
                }
                RecordType::NS => {
                    RData::NS(DnsName::new(&rec.value).map_err(|e| DnsError::ParseError(format!("{}", e)))?)
                }
                RecordType::MX => {
                    let pref = rec.priority.unwrap_or(10);
                    RData::MX {
                        preference: pref,
                        exchange: DnsName::new(&rec.value).map_err(|e| DnsError::ParseError(format!("{}", e)))?,
                    }
                }
                RecordType::TXT => {
                    RData::TXT(vec![rec.value.clone()])
                }
                RecordType::SRV => {
                    let priority = rec.priority.unwrap_or(0);
                    let weight = rec.weight.unwrap_or(0);
                    let port = rec.port.unwrap_or(0);
                    RData::SRV {
                        priority,
                        weight,
                        port,
                        target: DnsName::new(&rec.value).map_err(|e| DnsError::ParseError(format!("{}", e)))?,
                    }
                }
                RecordType::PTR => {
                    RData::PTR(DnsName::new(&rec.value).map_err(|e| DnsError::ParseError(format!("{}", e)))?)
                }
                _ => return Err(DnsError::ParseError(format!("Unsupported zone record type: {}", rec.record_type))),
            };

            let record = DnsRecord::new(record_name.clone(), rtype, ttl, rdata);

            if rtype == RecordType::NS {
                ns_records.push(record.clone());
            }

            records
                .entry((record_name, rtype))
                .or_default()
                .push(record);
        }

        Ok(Zone {
            name: zone_name,
            soa,
            records,
            ns_records,
        })
    }

    pub fn lookup(&self, name: &DnsName, record_type: RecordType) -> Option<Vec<DnsRecord>> {
        // Check for SOA
        if record_type == RecordType::SOA && name == &self.name {
            return Some(vec![self.soa.clone()]);
        }

        // Check for NS at zone apex
        if record_type == RecordType::NS && name == &self.name && !self.ns_records.is_empty() {
            return Some(self.ns_records.clone());
        }

        let key = (name.clone(), record_type);
        self.records.get(&key).cloned()
    }

    pub fn contains(&self, name: &DnsName) -> bool {
        name.is_subdomain_of(&self.name) || name == &self.name
    }

    pub fn has_name(&self, name: &DnsName) -> bool {
        if name == &self.name {
            return true;
        }
        self.records.keys().any(|(n, _)| n == name)
    }
}

pub struct ZoneStore {
    zones: Vec<Zone>,
}

impl ZoneStore {
    pub fn new() -> Self {
        ZoneStore { zones: Vec::new() }
    }

    pub fn load_config(&mut self, config: &ZoneConfig) -> Result<(), DnsError> {
        for def in &config.zones {
            let zone = Zone::from_config(def)?;
            tracing::info!("Loaded zone: {}", zone.name);
            self.zones.push(zone);
        }
        Ok(())
    }

    pub fn find_zone(&self, name: &DnsName) -> Option<&Zone> {
        self.zones
            .iter()
            .filter(|z| z.contains(name))
            .max_by_key(|z| z.name.label_count())
    }

    pub fn lookup(&self, name: &DnsName, record_type: RecordType) -> Option<Vec<DnsRecord>> {
        let zone = self.find_zone(name)?;
        zone.lookup(name, record_type)
    }
}
