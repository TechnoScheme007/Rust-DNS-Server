use super::error::DnsError;
use std::fmt;

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DnsName {
    labels: Vec<String>,
}

impl DnsName {
    pub fn new(name: &str) -> Result<Self, DnsError> {
        if name.is_empty() || name == "." {
            return Ok(DnsName { labels: vec![] });
        }

        let name = name.strip_suffix('.').unwrap_or(name);
        let labels: Vec<String> = name.split('.').map(|l| l.to_lowercase()).collect();

        for label in &labels {
            if label.len() > 63 {
                return Err(DnsError::LabelTooLong);
            }
        }

        let total: usize = labels.iter().map(|l| l.len() + 1).sum::<usize>() + 1;
        if total > 255 {
            return Err(DnsError::NameTooLong);
        }

        Ok(DnsName { labels })
    }

    pub fn root() -> Self {
        DnsName { labels: vec![] }
    }

    pub fn is_root(&self) -> bool {
        self.labels.is_empty()
    }

    pub fn label_count(&self) -> usize {
        self.labels.len()
    }

    pub fn labels(&self) -> &[String] {
        &self.labels
    }

    pub fn parent(&self) -> Option<DnsName> {
        if self.labels.len() <= 1 {
            if self.labels.is_empty() {
                None
            } else {
                Some(DnsName::root())
            }
        } else {
            Some(DnsName {
                labels: self.labels[1..].to_vec(),
            })
        }
    }

    pub fn is_subdomain_of(&self, other: &DnsName) -> bool {
        if self.labels.len() < other.labels.len() {
            return false;
        }
        let offset = self.labels.len() - other.labels.len();
        self.labels[offset..] == other.labels[..]
    }

    pub fn to_wire(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for label in &self.labels {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0);
        buf
    }

    pub fn parse(data: &[u8], offset: &mut usize) -> Result<Self, DnsError> {
        let mut labels = Vec::new();
        let mut jumped = false;
        let mut current = *offset;
        let mut jumps = 0;
        const MAX_JUMPS: usize = 128;

        loop {
            if current >= data.len() {
                return Err(DnsError::BufferTooShort);
            }

            let len = data[current] as usize;

            if len == 0 {
                if !jumped {
                    *offset = current + 1;
                }
                break;
            }

            if (len & 0xC0) == 0xC0 {
                if current + 1 >= data.len() {
                    return Err(DnsError::BufferTooShort);
                }
                if !jumped {
                    *offset = current + 2;
                }
                let pointer = ((len & 0x3F) << 8) | (data[current + 1] as usize);
                if pointer >= data.len() {
                    return Err(DnsError::InvalidPointer);
                }
                current = pointer;
                jumped = true;
                jumps += 1;
                if jumps > MAX_JUMPS {
                    return Err(DnsError::PointerLoop);
                }
                continue;
            }

            current += 1;
            if current + len > data.len() {
                return Err(DnsError::BufferTooShort);
            }

            let label = String::from_utf8_lossy(&data[current..current + len]).to_lowercase();
            labels.push(label);
            current += len;
        }

        Ok(DnsName { labels })
    }

    pub fn to_dotted(&self) -> String {
        if self.labels.is_empty() {
            ".".to_string()
        } else {
            format!("{}.", self.labels.join("."))
        }
    }
}

impl fmt::Display for DnsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.labels.is_empty() {
            write!(f, ".")
        } else {
            write!(f, "{}", self.labels.join("."))
        }
    }
}

impl fmt::Debug for DnsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DnsName({})", self)
    }
}
