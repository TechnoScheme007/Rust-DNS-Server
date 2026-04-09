use crate::dns::{DnsName, DnsRecord, RData, RecordType};
use ring::signature;
use tracing::{debug, warn};

/// DNSSEC algorithm numbers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecAlgorithm {
    RsaSha1,         // 5
    RsaSha256,       // 8
    RsaSha512,       // 10
    EcdsaP256Sha256, // 13
    EcdsaP384Sha384, // 14
    Ed25519,         // 15
    Unknown(u8),
}

impl DnssecAlgorithm {
    pub fn from_u8(val: u8) -> Self {
        match val {
            5 => DnssecAlgorithm::RsaSha1,
            8 => DnssecAlgorithm::RsaSha256,
            10 => DnssecAlgorithm::RsaSha512,
            13 => DnssecAlgorithm::EcdsaP256Sha256,
            14 => DnssecAlgorithm::EcdsaP384Sha384,
            15 => DnssecAlgorithm::Ed25519,
            n => DnssecAlgorithm::Unknown(n),
        }
    }
}

/// Digest types for DS records
#[derive(Debug, Clone, Copy)]
pub enum DigestType {
    Sha1,   // 1
    Sha256, // 2
    Sha384, // 4
    Unknown(u8),
}

impl DigestType {
    pub fn from_u8(val: u8) -> Self {
        match val {
            1 => DigestType::Sha1,
            2 => DigestType::Sha256,
            4 => DigestType::Sha384,
            n => DigestType::Unknown(n),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationResult {
    Secure,
    Insecure,
    Bogus,
    Indeterminate,
}

pub struct DnssecValidator;

impl DnssecValidator {
    pub fn new() -> Self {
        DnssecValidator
    }

    /// Validate an RRSIG against a set of records using the provided DNSKEY
    pub fn verify_rrsig(
        &self,
        rrsig: &DnsRecord,
        records: &[DnsRecord],
        dnskey: &DnsRecord,
    ) -> ValidationResult {
        let (sig_algorithm, sig_labels, original_ttl, sig_expiration, sig_inception,
             signer_name, sig_signature, type_covered) = match &rrsig.rdata {
            RData::RRSIG {
                algorithm,
                labels,
                original_ttl,
                signature_expiration,
                signature_inception,
                signer_name,
                signature,
                type_covered,
                ..
            } => (
                *algorithm,
                *labels,
                *original_ttl,
                *signature_expiration,
                *signature_inception,
                signer_name,
                signature,
                type_covered,
            ),
            _ => return ValidationResult::Bogus,
        };

        let (key_algorithm, public_key) = match &dnskey.rdata {
            RData::DNSKEY {
                algorithm,
                public_key,
                ..
            } => (*algorithm, public_key),
            _ => return ValidationResult::Bogus,
        };

        if sig_algorithm != key_algorithm {
            debug!("Algorithm mismatch: RRSIG={} DNSKEY={}", sig_algorithm, key_algorithm);
            return ValidationResult::Bogus;
        }

        // Check signature time validity
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        if now < sig_inception || now > sig_expiration {
            debug!("RRSIG time invalid: now={} inception={} expiration={}", now, sig_inception, sig_expiration);
            return ValidationResult::Bogus;
        }

        // Build the data to verify: RRSIG_RDATA (without signature) + sorted RRset
        let mut signed_data = Vec::new();

        // RRSIG RDATA fields (without the signature)
        signed_data.extend_from_slice(&type_covered.to_u16().to_be_bytes());
        signed_data.push(sig_algorithm);
        signed_data.push(sig_labels);
        signed_data.extend_from_slice(&original_ttl.to_be_bytes());
        signed_data.extend_from_slice(&sig_expiration.to_be_bytes());
        signed_data.extend_from_slice(&sig_inception.to_be_bytes());

        // Key tag from the RRSIG
        if let RData::RRSIG { key_tag, .. } = &rrsig.rdata {
            signed_data.extend_from_slice(&key_tag.to_be_bytes());
        }
        signed_data.extend_from_slice(&signer_name.to_wire());

        // Sort RRset by canonical wire format
        let mut rr_wires: Vec<Vec<u8>> = records
            .iter()
            .filter(|r| r.record_type == *type_covered)
            .map(|r| {
                let mut wire = Vec::new();
                // Use lowercase canonical name
                wire.extend_from_slice(&r.name.to_wire());
                wire.extend_from_slice(&r.record_type.to_u16().to_be_bytes());
                wire.extend_from_slice(&r.record_class.to_u16().to_be_bytes());
                wire.extend_from_slice(&original_ttl.to_be_bytes());
                let rdata = r.rdata.serialize();
                wire.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
                wire.extend_from_slice(&rdata);
                wire
            })
            .collect();
        rr_wires.sort();

        for rr_wire in &rr_wires {
            signed_data.extend_from_slice(rr_wire);
        }

        // Verify the signature using the appropriate algorithm
        let algo = DnssecAlgorithm::from_u8(sig_algorithm);
        match self.verify_signature(algo, public_key, &signed_data, sig_signature) {
            Ok(true) => {
                debug!("DNSSEC signature verified for {}", signer_name);
                ValidationResult::Secure
            }
            Ok(false) => {
                warn!("DNSSEC signature verification FAILED for {}", signer_name);
                ValidationResult::Bogus
            }
            Err(e) => {
                debug!("DNSSEC verification error: {}", e);
                ValidationResult::Indeterminate
            }
        }
    }

    fn verify_signature(
        &self,
        algorithm: DnssecAlgorithm,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, String> {
        match algorithm {
            DnssecAlgorithm::RsaSha256 => {
                self.verify_rsa(&signature::RSA_PKCS1_2048_8192_SHA256, public_key, data, signature)
            }
            DnssecAlgorithm::RsaSha512 => {
                self.verify_rsa(&signature::RSA_PKCS1_2048_8192_SHA512, public_key, data, signature)
            }
            DnssecAlgorithm::RsaSha1 => {
                // SHA1 is deprecated but still seen in the wild
                self.verify_rsa(&signature::RSA_PKCS1_2048_8192_SHA256, public_key, data, signature)
            }
            DnssecAlgorithm::EcdsaP256Sha256 => {
                self.verify_ecdsa_p256(public_key, data, signature)
            }
            DnssecAlgorithm::EcdsaP384Sha384 => {
                self.verify_ecdsa_p384(public_key, data, signature)
            }
            DnssecAlgorithm::Ed25519 => {
                self.verify_ed25519(public_key, data, signature)
            }
            DnssecAlgorithm::Unknown(n) => {
                Err(format!("Unsupported DNSSEC algorithm: {}", n))
            }
        }
    }

    fn verify_rsa(
        &self,
        params: &signature::RsaParameters,
        public_key_data: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, String> {
        if public_key_data.is_empty() {
            return Err("Empty public key".into());
        }

        // DNS RSA public key format: exponent length (1 or 3 bytes) + exponent + modulus
        let (exp_len, offset) = if public_key_data[0] == 0 {
            if public_key_data.len() < 3 {
                return Err("RSA key too short".into());
            }
            let len = u16::from_be_bytes([public_key_data[1], public_key_data[2]]) as usize;
            (len, 3)
        } else {
            (public_key_data[0] as usize, 1)
        };

        if offset + exp_len >= public_key_data.len() {
            return Err("Invalid RSA key structure".into());
        }

        let exponent = &public_key_data[offset..offset + exp_len];
        let modulus = &public_key_data[offset + exp_len..];

        let public_key = signature::RsaPublicKeyComponents {
            n: modulus,
            e: exponent,
        };

        match public_key.verify(params, data, signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn verify_ecdsa_p256(
        &self,
        public_key_data: &[u8],
        data: &[u8],
        sig_data: &[u8],
    ) -> Result<bool, String> {
        if public_key_data.len() != 64 {
            return Err(format!("Invalid P-256 key length: {}", public_key_data.len()));
        }

        // DNS format is raw x||y, need to prepend 0x04 for uncompressed point
        let mut uncompressed = Vec::with_capacity(65);
        uncompressed.push(0x04);
        uncompressed.extend_from_slice(public_key_data);

        let public_key = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_FIXED,
            &uncompressed,
        );

        // DNS ECDSA signature is r||s (each 32 bytes for P-256)
        if sig_data.len() != 64 {
            return Err(format!("Invalid P-256 signature length: {}", sig_data.len()));
        }

        match public_key.verify(data, sig_data) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn verify_ecdsa_p384(
        &self,
        public_key_data: &[u8],
        data: &[u8],
        sig_data: &[u8],
    ) -> Result<bool, String> {
        if public_key_data.len() != 96 {
            return Err(format!("Invalid P-384 key length: {}", public_key_data.len()));
        }

        let mut uncompressed = Vec::with_capacity(97);
        uncompressed.push(0x04);
        uncompressed.extend_from_slice(public_key_data);

        let public_key = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P384_SHA384_FIXED,
            &uncompressed,
        );

        if sig_data.len() != 96 {
            return Err(format!("Invalid P-384 signature length: {}", sig_data.len()));
        }

        match public_key.verify(data, sig_data) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn verify_ed25519(
        &self,
        public_key_data: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, String> {
        if public_key_data.len() != 32 {
            return Err(format!("Invalid Ed25519 key length: {}", public_key_data.len()));
        }

        let public_key = signature::UnparsedPublicKey::new(
            &signature::ED25519,
            public_key_data,
        );

        match public_key.verify(data, signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Compute key tag for a DNSKEY record (RFC 4034 Appendix B)
    pub fn compute_key_tag(dnskey: &DnsRecord) -> u16 {
        let rdata = dnskey.rdata.serialize();
        let mut ac: u32 = 0;
        for (i, &byte) in rdata.iter().enumerate() {
            if i & 1 == 0 {
                ac += (byte as u32) << 8;
            } else {
                ac += byte as u32;
            }
        }
        ac += (ac >> 16) & 0xFFFF;
        (ac & 0xFFFF) as u16
    }

    /// Verify a DS record matches a DNSKEY
    pub fn verify_ds(&self, ds: &DnsRecord, dnskey: &DnsRecord) -> bool {
        let (ds_key_tag, ds_algorithm, ds_digest_type, ds_digest) = match &ds.rdata {
            RData::DS {
                key_tag,
                algorithm,
                digest_type,
                digest,
            } => (*key_tag, *algorithm, *digest_type, digest),
            _ => return false,
        };

        let (dk_algorithm, _) = match &dnskey.rdata {
            RData::DNSKEY { algorithm, .. } => (*algorithm, ()),
            _ => return false,
        };

        if ds_algorithm != dk_algorithm {
            return false;
        }

        let computed_tag = Self::compute_key_tag(dnskey);
        if ds_key_tag != computed_tag {
            return false;
        }

        // Compute digest: owner_name_wire || DNSKEY_RDATA
        let mut digest_input = Vec::new();
        digest_input.extend_from_slice(&dnskey.name.to_wire());
        digest_input.extend_from_slice(&dnskey.rdata.serialize());

        let digest_type = DigestType::from_u8(ds_digest_type);
        let computed_digest = match digest_type {
            DigestType::Sha1 => {
                use ring::digest;
                digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &digest_input)
                    .as_ref()
                    .to_vec()
            }
            DigestType::Sha256 => {
                use ring::digest;
                digest::digest(&digest::SHA256, &digest_input)
                    .as_ref()
                    .to_vec()
            }
            DigestType::Sha384 => {
                use ring::digest;
                digest::digest(&digest::SHA384, &digest_input)
                    .as_ref()
                    .to_vec()
            }
            DigestType::Unknown(n) => {
                warn!("Unknown DS digest type: {}", n);
                return false;
            }
        };

        computed_digest == *ds_digest
    }

    /// Validate a complete response with DNSSEC records
    pub fn validate_response(
        &self,
        answers: &[DnsRecord],
        _query_name: &DnsName,
        _query_type: RecordType,
    ) -> ValidationResult {
        // Find RRSIG records in the answer set
        let rrsigs: Vec<&DnsRecord> = answers
            .iter()
            .filter(|r| r.record_type == RecordType::RRSIG)
            .collect();

        if rrsigs.is_empty() {
            return ValidationResult::Insecure;
        }

        // Find DNSKEY records if present
        let dnskeys: Vec<&DnsRecord> = answers
            .iter()
            .filter(|r| r.record_type == RecordType::DNSKEY)
            .collect();

        // Try to verify each RRSIG with available DNSKEYs
        for rrsig in &rrsigs {
            let key_tag = match &rrsig.rdata {
                RData::RRSIG { key_tag, .. } => *key_tag,
                _ => continue,
            };

            for dnskey in &dnskeys {
                let computed_tag = Self::compute_key_tag(dnskey);
                if computed_tag == key_tag {
                    let result = self.verify_rrsig(rrsig, answers, dnskey);
                    if result == ValidationResult::Secure {
                        return ValidationResult::Secure;
                    }
                }
            }
        }

        ValidationResult::Indeterminate
    }
}
