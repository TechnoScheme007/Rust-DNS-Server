use super::error::DnsError;
use super::name::DnsName;
use super::rdata::{RData, RecordType};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordClass {
    IN,
    CH,
    HS,
    ANY,
    Unknown(u16),
}

impl RecordClass {
    pub fn from_u16(val: u16) -> Self {
        match val {
            1 => RecordClass::IN,
            3 => RecordClass::CH,
            4 => RecordClass::HS,
            255 => RecordClass::ANY,
            n => RecordClass::Unknown(n),
        }
    }

    pub fn to_u16(self) -> u16 {
        match self {
            RecordClass::IN => 1,
            RecordClass::CH => 3,
            RecordClass::HS => 4,
            RecordClass::ANY => 255,
            RecordClass::Unknown(n) => n,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: DnsName,
    pub record_type: RecordType,
    pub record_class: RecordClass,
    pub ttl: u32,
    pub rdata: RData,
}

impl DnsRecord {
    pub fn new(name: DnsName, record_type: RecordType, ttl: u32, rdata: RData) -> Self {
        DnsRecord {
            name,
            record_type,
            record_class: RecordClass::IN,
            ttl,
            rdata,
        }
    }

    pub fn parse(data: &[u8], offset: &mut usize) -> Result<Self, DnsError> {
        let name = DnsName::parse(data, offset)?;

        if *offset + 10 > data.len() {
            return Err(DnsError::BufferTooShort);
        }

        let record_type = RecordType::from_u16(u16::from_be_bytes([data[*offset], data[*offset + 1]]));
        let record_class = RecordClass::from_u16(u16::from_be_bytes([data[*offset + 2], data[*offset + 3]]));
        let ttl = u32::from_be_bytes([
            data[*offset + 4],
            data[*offset + 5],
            data[*offset + 6],
            data[*offset + 7],
        ]);
        let rdlength = u16::from_be_bytes([data[*offset + 8], data[*offset + 9]]);
        *offset += 10;

        let rdata = RData::parse(record_type, data, offset, rdlength)?;

        Ok(DnsRecord {
            name,
            record_type,
            record_class,
            ttl,
            rdata,
        })
    }

    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.name.to_wire());
        buf.extend_from_slice(&self.record_type.to_u16().to_be_bytes());
        buf.extend_from_slice(&self.record_class.to_u16().to_be_bytes());
        buf.extend_from_slice(&self.ttl.to_be_bytes());

        let rdata = self.rdata.serialize();
        buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        buf.extend_from_slice(&rdata);
    }
}
