use crate::dns::{DnsName, DnsRecord, RecordType};
use lru::LruCache;
use parking_lot::RwLock;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
struct CacheEntry {
    records: Vec<DnsRecord>,
    inserted_at: Instant,
    ttl: Duration,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        self.inserted_at.elapsed() >= self.ttl
    }

    fn remaining_ttl(&self) -> u32 {
        let elapsed = self.inserted_at.elapsed();
        if elapsed >= self.ttl {
            0
        } else {
            (self.ttl - elapsed).as_secs() as u32
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    name: DnsName,
    record_type: RecordType,
}

pub struct DnsCache {
    cache: RwLock<LruCache<CacheKey, CacheEntry>>,
}

impl DnsCache {
    pub fn new(max_entries: usize) -> Self {
        DnsCache {
            cache: RwLock::new(LruCache::new(
                NonZeroUsize::new(max_entries).unwrap_or(NonZeroUsize::new(10000).unwrap()),
            )),
        }
    }

    pub fn lookup(&self, name: &DnsName, record_type: RecordType) -> Option<Vec<DnsRecord>> {
        let key = CacheKey {
            name: name.clone(),
            record_type,
        };

        let mut cache = self.cache.write();
        if let Some(entry) = cache.get(&key) {
            if entry.is_expired() {
                cache.pop(&key);
                return None;
            }
            let remaining = entry.remaining_ttl();
            let records: Vec<DnsRecord> = entry
                .records
                .iter()
                .map(|r| {
                    let mut rec = r.clone();
                    rec.ttl = remaining;
                    rec
                })
                .collect();
            Some(records)
        } else {
            None
        }
    }

    pub fn insert(&self, name: &DnsName, record_type: RecordType, records: Vec<DnsRecord>) {
        if records.is_empty() {
            return;
        }

        let min_ttl = records.iter().map(|r| r.ttl).min().unwrap_or(0);
        if min_ttl == 0 {
            return;
        }

        // Cap TTL at 1 day
        let ttl = std::cmp::min(min_ttl, 86400);

        let key = CacheKey {
            name: name.clone(),
            record_type,
        };

        let entry = CacheEntry {
            records,
            inserted_at: Instant::now(),
            ttl: Duration::from_secs(ttl as u64),
        };

        self.cache.write().put(key, entry);
    }

    pub fn clear(&self) {
        self.cache.write().clear();
    }

    pub fn len(&self) -> usize {
        self.cache.read().len()
    }
}
