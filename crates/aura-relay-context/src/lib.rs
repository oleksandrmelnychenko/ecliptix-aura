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
    use aura_contracts::{
        ClientSafetyTelemetryEvent, Confidence, SafetyTelemetryAction, SafetyTelemetrySeverity,
        SafetyTelemetrySurface,
    };
    use aura_relay_store::{InMemoryReputationStore, ReputationStore};
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
            ..SenderReputation::new("risky_user", 1000)
        });

        let enrichment = enrich_context("risky_user", &store);
        assert!(enrichment.sender_reputation.is_some());
        assert_eq!(
            enrichment.cross_conversation_threat,
            Some(ThreatType::Manipulation)
        );
    }

    #[test]
    fn enrichment_flags_repeated_privacy_safe_safety_telemetry() {
        let mut store = InMemoryReputationStore::new();
        let sender_token = "snd_01H00000000000000000000000".to_string();

        for hour in 0..3 {
            store.record_safety_telemetry(&ClientSafetyTelemetryEvent {
                event_id: format!("evt_01H0000000000000000000000{hour}"),
                sender_token: sender_token.clone(),
                protected_account_token: format!("acct_01H000000000000000000000{hour}"),
                conversation_token: Some(format!("conv_01H00000000000000000000{hour}")),
                surface: SafetyTelemetrySurface::DirectMessage,
                threat_type: ThreatType::Grooming,
                severity: SafetyTelemetrySeverity::High,
                confidence: Confidence::High,
                action: SafetyTelemetryAction::Warn,
                timestamp_bucket_ms: 1_778_652_000_000 + hour * 3_600_000,
                reason_family: Some("grooming".to_string()),
            });
        }

        let enrichment = enrich_context(&sender_token, &store);

        assert!(enrichment.network_risk_signal >= 0.7);
        assert_eq!(
            enrichment.cross_conversation_threat,
            Some(ThreatType::Manipulation)
        );
    }

    #[test]
    fn enrichment_does_not_flag_single_child_flood_as_cross_conversation_threat() {
        let mut store = InMemoryReputationStore::new();
        let sender_token = "snd_01H00000000000000000000000".to_string();

        for hour in 0..48 {
            store.record_safety_telemetry(&ClientSafetyTelemetryEvent {
                event_id: format!("evt_single_child_flood_{hour:04}"),
                sender_token: sender_token.clone(),
                protected_account_token: "acct_01H0000000000000000000000".to_string(),
                conversation_token: Some(format!("conv_single_child_flood_{hour:04}")),
                surface: SafetyTelemetrySurface::DirectMessage,
                threat_type: ThreatType::Grooming,
                severity: SafetyTelemetrySeverity::Critical,
                confidence: Confidence::High,
                action: SafetyTelemetryAction::Warn,
                timestamp_bucket_ms: 1_778_652_000_000 + hour * 3_600_000,
                reason_family: Some("grooming".to_string()),
            });
        }

        let enrichment = enrich_context(&sender_token, &store);

        assert!(enrichment.network_risk_signal <= 0.64);
        assert!(enrichment.network_risk_signal < 0.7);
        assert!(enrichment.cross_conversation_threat.is_none());
    }

    #[test]
    fn enrichment_does_not_flag_single_conversation_sybil_flood() {
        let mut store = InMemoryReputationStore::new();
        let sender_token = "snd_01H00000000000000000000000".to_string();

        for hour in 0..48 {
            store.record_safety_telemetry(&ClientSafetyTelemetryEvent {
                event_id: format!("evt_single_conv_sybil_{hour:04}"),
                sender_token: sender_token.clone(),
                protected_account_token: format!("acct_single_conv_sybil_{hour:04}"),
                conversation_token: Some("conv_single_conversation_sybil".to_string()),
                surface: SafetyTelemetrySurface::DirectMessage,
                threat_type: ThreatType::Grooming,
                severity: SafetyTelemetrySeverity::Critical,
                confidence: Confidence::High,
                action: SafetyTelemetryAction::Warn,
                timestamp_bucket_ms: 1_778_652_000_000 + hour * 3_600_000,
                reason_family: Some("grooming".to_string()),
            });
        }

        let enrichment = enrich_context(&sender_token, &store);

        assert!(enrichment.network_risk_signal <= 0.58);
        assert!(enrichment.network_risk_signal < 0.7);
        assert!(enrichment.cross_conversation_threat.is_none());
    }
}
