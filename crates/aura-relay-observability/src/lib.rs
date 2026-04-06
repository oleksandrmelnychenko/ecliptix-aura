//! Relay observability layer: audit, tracing, metrics, and drift monitoring.
//!
//! Provides structured logging of relay decisions for compliance, debugging,
//! and model-drift detection.

use aura_contracts::{Confidence, ThreatType};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayAuditEntry {
    pub request_id: String,
    pub timestamp_ms: u64,
    pub primary_threat: ThreatType,
    pub score: f32,
    pub confidence: Confidence,
    pub model_ids: Vec<String>,
    pub latency_us: u64,
    pub was_filtered: bool,
}

pub struct AuditLog {
    entries: Vec<RelayAuditEntry>,
    capacity: usize,
}

impl AuditLog {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity.min(10_000)),
            capacity,
        }
    }

    pub fn record(&mut self, entry: RelayAuditEntry) {
        if self.entries.len() >= self.capacity {
            self.entries.remove(0);
        }
        self.entries.push(entry);
    }

    pub fn entries(&self) -> &[RelayAuditEntry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new(1_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_log_respects_capacity() {
        let mut log = AuditLog::new(2);
        for i in 0..5 {
            log.record(RelayAuditEntry {
                request_id: format!("req_{i}"),
                timestamp_ms: i as u64,
                primary_threat: ThreatType::None,
                score: 0.0,
                confidence: Confidence::Low,
                model_ids: Vec::new(),
                latency_us: 0,
                was_filtered: false,
            });
        }
        assert_eq!(log.len(), 2);
        assert_eq!(log.entries()[0].request_id, "req_3");
    }
}
