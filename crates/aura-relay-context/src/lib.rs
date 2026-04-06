//! Relay context enrichment layer.
//!
//! Provides cross-conversation memory, sender/network intelligence, and
//! coordination signal detection that requires global state unavailable
//! on any single device.
//!
//! This crate is the relay's answer to the agent's local conversation tracker.
//! Where the agent sees one conversation at a time, the relay can correlate
//! across conversations, senders, and cohorts.

use aura_contracts::ThreatType;
use aura_relay_store::{ReputationStore, SenderReputation};

#[derive(Debug, Clone)]
pub struct ContextEnrichment {
    pub sender_reputation: Option<SenderReputation>,
    pub cross_conversation_threat: Option<ThreatType>,
    pub network_risk_signal: f32,
    pub is_coordinated_behaviour: bool,
}

impl Default for ContextEnrichment {
    fn default() -> Self {
        Self {
            sender_reputation: None,
            cross_conversation_threat: None,
            network_risk_signal: 0.0,
            is_coordinated_behaviour: false,
        }
    }
}

pub fn enrich_context(
    sender_id: &str,
    reputation_store: &dyn ReputationStore,
) -> ContextEnrichment {
    let sender_reputation = reputation_store.get(sender_id);

    let cross_conversation_threat = sender_reputation.as_ref().and_then(|rep| {
        if rep.cumulative_risk >= 0.7 {
            Some(ThreatType::Manipulation)
        } else {
            None
        }
    });

    let network_risk_signal = sender_reputation
        .as_ref()
        .map(|rep| rep.cumulative_risk)
        .unwrap_or(0.0);

    ContextEnrichment {
        sender_reputation,
        cross_conversation_threat,
        network_risk_signal,
        is_coordinated_behaviour: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aura_relay_store::InMemoryReputationStore;
    use std::collections::HashMap;

    #[test]
    fn enrichment_returns_empty_for_unknown_sender() {
        let store = InMemoryReputationStore::new();
        let enrichment = enrich_context("unknown", &store);
        assert!(enrichment.sender_reputation.is_none());
        assert!(enrichment.cross_conversation_threat.is_none());
    }

    #[test]
    fn enrichment_flags_high_risk_sender() {
        let mut store = InMemoryReputationStore::new();
        store.upsert(SenderReputation {
            sender_id: "risky_user".to_string(),
            cumulative_risk: 0.85,
            threat_counts: HashMap::new(),
            first_seen_ms: 1000,
            last_seen_ms: 5000,
            total_requests: 20,
        });

        let enrichment = enrich_context("risky_user", &store);
        assert!(enrichment.sender_reputation.is_some());
        assert_eq!(
            enrichment.cross_conversation_threat,
            Some(ThreatType::Manipulation)
        );
    }
}
