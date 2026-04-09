use super::error::DnsError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpCode {
    Query,
    IQuery,
    Status,
    Unknown(u8),
}

impl OpCode {
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => OpCode::Query,
            1 => OpCode::IQuery,
            2 => OpCode::Status,
            n => OpCode::Unknown(n),
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            OpCode::Query => 0,
            OpCode::IQuery => 1,
            OpCode::Status => 2,
            OpCode::Unknown(n) => n,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseCode {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
    Unknown(u8),
}

impl ResponseCode {
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => ResponseCode::NoError,
            1 => ResponseCode::FormatError,
            2 => ResponseCode::ServerFailure,
            3 => ResponseCode::NameError,
            4 => ResponseCode::NotImplemented,
            5 => ResponseCode::Refused,
            n => ResponseCode::Unknown(n),
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            ResponseCode::NoError => 0,
            ResponseCode::FormatError => 1,
            ResponseCode::ServerFailure => 2,
            ResponseCode::NameError => 3,
            ResponseCode::NotImplemented => 4,
            ResponseCode::Refused => 5,
            ResponseCode::Unknown(n) => n,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DnsHeader {
    pub id: u16,
    pub is_response: bool,
    pub opcode: OpCode,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub authentic_data: bool,
    pub checking_disabled: bool,
    pub response_code: ResponseCode,
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
}

impl DnsHeader {
    pub fn new_query(id: u16) -> Self {
        DnsHeader {
            id,
            is_response: false,
            opcode: OpCode::Query,
            authoritative: false,
            truncated: false,
            recursion_desired: true,
            recursion_available: false,
            authentic_data: false,
            checking_disabled: false,
            response_code: ResponseCode::NoError,
            question_count: 0,
            answer_count: 0,
            authority_count: 0,
            additional_count: 0,
        }
    }

    pub fn parse(data: &[u8], offset: &mut usize) -> Result<Self, DnsError> {
        if *offset + 12 > data.len() {
            return Err(DnsError::BufferTooShort);
        }

        let id = u16::from_be_bytes([data[*offset], data[*offset + 1]]);
        let flags1 = data[*offset + 2];
        let flags2 = data[*offset + 3];

        let header = DnsHeader {
            id,
            is_response: (flags1 & 0x80) != 0,
            opcode: OpCode::from_u8((flags1 >> 3) & 0x0F),
            authoritative: (flags1 & 0x04) != 0,
            truncated: (flags1 & 0x02) != 0,
            recursion_desired: (flags1 & 0x01) != 0,
            recursion_available: (flags2 & 0x80) != 0,
            authentic_data: (flags2 & 0x20) != 0,
            checking_disabled: (flags2 & 0x10) != 0,
            response_code: ResponseCode::from_u8(flags2 & 0x0F),
            question_count: u16::from_be_bytes([data[*offset + 4], data[*offset + 5]]),
            answer_count: u16::from_be_bytes([data[*offset + 6], data[*offset + 7]]),
            authority_count: u16::from_be_bytes([data[*offset + 8], data[*offset + 9]]),
            additional_count: u16::from_be_bytes([data[*offset + 10], data[*offset + 11]]),
        };

        *offset += 12;
        Ok(header)
    }

    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.id.to_be_bytes());

        let mut flags1: u8 = 0;
        if self.is_response {
            flags1 |= 0x80;
        }
        flags1 |= (self.opcode.to_u8() & 0x0F) << 3;
        if self.authoritative {
            flags1 |= 0x04;
        }
        if self.truncated {
            flags1 |= 0x02;
        }
        if self.recursion_desired {
            flags1 |= 0x01;
        }
        buf.push(flags1);

        let mut flags2: u8 = 0;
        if self.recursion_available {
            flags2 |= 0x80;
        }
        if self.authentic_data {
            flags2 |= 0x20;
        }
        if self.checking_disabled {
            flags2 |= 0x10;
        }
        flags2 |= self.response_code.to_u8() & 0x0F;
        buf.push(flags2);

        buf.extend_from_slice(&self.question_count.to_be_bytes());
        buf.extend_from_slice(&self.answer_count.to_be_bytes());
        buf.extend_from_slice(&self.authority_count.to_be_bytes());
        buf.extend_from_slice(&self.additional_count.to_be_bytes());
    }
}
