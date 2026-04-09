use super::error::DnsError;
use super::name::DnsName;
use super::rdata::RecordType;
use super::record::RecordClass;

#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: DnsName,
    pub record_type: RecordType,
    pub record_class: RecordClass,
}

impl DnsQuestion {
    pub fn new(name: DnsName, record_type: RecordType) -> Self {
        DnsQuestion {
            name,
            record_type,
            record_class: RecordClass::IN,
        }
    }

    pub fn parse(data: &[u8], offset: &mut usize) -> Result<Self, DnsError> {
        let name = DnsName::parse(data, offset)?;

        if *offset + 4 > data.len() {
            return Err(DnsError::BufferTooShort);
        }

        let record_type = RecordType::from_u16(u16::from_be_bytes([data[*offset], data[*offset + 1]]));
        let record_class = RecordClass::from_u16(u16::from_be_bytes([data[*offset + 2], data[*offset + 3]]));
        *offset += 4;

        Ok(DnsQuestion {
            name,
            record_type,
            record_class,
        })
    }

    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.name.to_wire());
        buf.extend_from_slice(&self.record_type.to_u16().to_be_bytes());
        buf.extend_from_slice(&self.record_class.to_u16().to_be_bytes());
    }
}
