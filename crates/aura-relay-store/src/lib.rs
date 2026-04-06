//! Relay persistence layer.
//!
//! Abstracts storage for sender reputation, cross-conversation memory,
//! cached inference results, and feature store entries.
//!
//! The initial implementation uses in-memory stores with TTL eviction.
//! Production will plug in Postgres/Redis backends behind the same traits.

use std::collections::HashMap;

use aura_contracts::ThreatType;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderReputation {
    pub sender_id: String,
    pub cumulative_risk: f32,
    pub threat_counts: HashMap<String, u64>,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub total_requests: u64,
}

pub trait ReputationStore: Send + Sync {
    fn get(&self, sender_id: &str) -> Option<SenderReputation>;
    fn upsert(&mut self, reputation: SenderReputation);
}

pub struct InMemoryReputationStore {
    data: HashMap<String, SenderReputation>,
}

impl InMemoryReputationStore {
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }
}

impl Default for InMemoryReputationStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ReputationStore for InMemoryReputationStore {
    fn get(&self, sender_id: &str) -> Option<SenderReputation> {
        self.data.get(sender_id).cloned()
    }

    fn upsert(&mut self, reputation: SenderReputation) {
        self.data
            .insert(reputation.sender_id.clone(), reputation);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedInferenceEntry {
    pub text_hash: String,
    pub primary_threat: ThreatType,
    pub score: f32,
    pub created_ms: u64,
    pub ttl_ms: u64,
}

pub trait InferenceCache: Send + Sync {
    fn get(&self, text_hash: &str) -> Option<CachedInferenceEntry>;
    fn put(&mut self, entry: CachedInferenceEntry);
}

pub struct InMemoryInferenceCache {
    data: HashMap<String, CachedInferenceEntry>,
    capacity: usize,
}

impl InMemoryInferenceCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            data: HashMap::new(),
            capacity,
        }
    }
}

impl InferenceCache for InMemoryInferenceCache {
    fn get(&self, text_hash: &str) -> Option<CachedInferenceEntry> {
        self.data.get(text_hash).cloned()
    }

    fn put(&mut self, entry: CachedInferenceEntry) {
        if self.data.len() >= self.capacity {
            if let Some(oldest_key) = self
                .data
                .iter()
                .min_by_key(|(_, v)| v.created_ms)
                .map(|(k, _)| k.clone())
            {
                self.data.remove(&oldest_key);
            }
        }
        self.data.insert(entry.text_hash.clone(), entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reputation_store_upsert_and_get() {
        let mut store = InMemoryReputationStore::new();
        store.upsert(SenderReputation {
            sender_id: "s1".to_string(),
            cumulative_risk: 0.5,
            threat_counts: HashMap::new(),
            first_seen_ms: 1000,
            last_seen_ms: 2000,
            total_requests: 3,
        });
        let rep = store.get("s1").unwrap();
        assert_eq!(rep.total_requests, 3);
    }

    #[test]
    fn inference_cache_evicts_oldest() {
        let mut cache = InMemoryInferenceCache::new(2);
        for i in 0..3 {
            cache.put(CachedInferenceEntry {
                text_hash: format!("h{i}"),
                primary_threat: ThreatType::None,
                score: 0.0,
                created_ms: i as u64,
                ttl_ms: 60_000,
            });
        }
        assert!(cache.get("h0").is_none());
        assert!(cache.get("h1").is_some());
        assert!(cache.get("h2").is_some());
    }
}
