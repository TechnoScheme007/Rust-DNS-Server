use std::fmt;

#[derive(Debug)]
pub enum DnsError {
    ParseError(String),
    SerializeError(String),
    NameTooLong,
    LabelTooLong,
    BufferTooShort,
    InvalidPointer,
    PointerLoop,
    UnknownRecordType(u16),
    IoError(std::io::Error),
    Truncated,
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            DnsError::SerializeError(msg) => write!(f, "Serialize error: {}", msg),
            DnsError::NameTooLong => write!(f, "Domain name exceeds 255 bytes"),
            DnsError::LabelTooLong => write!(f, "Label exceeds 63 bytes"),
            DnsError::BufferTooShort => write!(f, "Buffer too short"),
            DnsError::InvalidPointer => write!(f, "Invalid compression pointer"),
            DnsError::PointerLoop => write!(f, "Compression pointer loop detected"),
            DnsError::UnknownRecordType(t) => write!(f, "Unknown record type: {}", t),
            DnsError::IoError(e) => write!(f, "IO error: {}", e),
            DnsError::Truncated => write!(f, "Message truncated"),
        }
    }
}

impl std::error::Error for DnsError {}

impl From<std::io::Error> for DnsError {
    fn from(e: std::io::Error) -> Self {
        DnsError::IoError(e)
    }
}
