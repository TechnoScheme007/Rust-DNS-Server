use super::error::DnsError;
use super::header::DnsHeader;
use super::question::DnsQuestion;
use super::record::DnsRecord;

#[derive(Debug, Clone)]
pub struct DnsMessage {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additional: Vec<DnsRecord>,
}

impl DnsMessage {
    pub fn new_query(id: u16) -> Self {
        DnsMessage {
            header: DnsHeader::new_query(id),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additional: Vec::new(),
        }
    }

    pub fn parse(data: &[u8]) -> Result<Self, DnsError> {
        let mut offset = 0;
        let header = DnsHeader::parse(data, &mut offset)?;

        let mut questions = Vec::with_capacity(header.question_count as usize);
        for _ in 0..header.question_count {
            questions.push(DnsQuestion::parse(data, &mut offset)?);
        }

        let mut answers = Vec::with_capacity(header.answer_count as usize);
        for _ in 0..header.answer_count {
            match DnsRecord::parse(data, &mut offset) {
                Ok(record) => answers.push(record),
                Err(_) => break,
            }
        }

        let mut authorities = Vec::with_capacity(header.authority_count as usize);
        for _ in 0..header.authority_count {
            match DnsRecord::parse(data, &mut offset) {
                Ok(record) => authorities.push(record),
                Err(_) => break,
            }
        }

        let mut additional = Vec::new();
        for _ in 0..header.additional_count {
            match DnsRecord::parse(data, &mut offset) {
                Ok(record) => additional.push(record),
                Err(_) => break,
            }
        }

        Ok(DnsMessage {
            header,
            questions,
            answers,
            authorities,
            additional,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(512);

        let mut header = self.header.clone();
        header.question_count = self.questions.len() as u16;
        header.answer_count = self.answers.len() as u16;
        header.authority_count = self.authorities.len() as u16;
        header.additional_count = self.additional.len() as u16;
        header.serialize(&mut buf);

        for question in &self.questions {
            question.serialize(&mut buf);
        }
        for record in &self.answers {
            record.serialize(&mut buf);
        }
        for record in &self.authorities {
            record.serialize(&mut buf);
        }
        for record in &self.additional {
            record.serialize(&mut buf);
        }

        buf
    }

    pub fn make_response(&self) -> Self {
        let mut response = DnsMessage {
            header: self.header.clone(),
            questions: self.questions.clone(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additional: Vec::new(),
        };
        response.header.is_response = true;
        response.header.recursion_available = true;
        response
    }

    pub fn make_error_response(
        &self,
        code: super::header::ResponseCode,
    ) -> Self {
        let mut response = self.make_response();
        response.header.response_code = code;
        response
    }
}
