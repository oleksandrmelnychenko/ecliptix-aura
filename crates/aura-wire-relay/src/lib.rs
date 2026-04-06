//! Versioned wire exports for AURA Agent <-> Relay communication.

pub mod v1alpha1 {
    pub use aura_contracts::{
        default_relay_schema_version, AgentAnalyzeRequest, AgentCapabilities, ConfirmedEvent,
        LocalContextSummary, MessageWindowEntry, RawObservation, RelayAnalyzeResponse,
        RelayPrivacyMode, RemoteFinding, RemoteInferenceSummary, RiskHorizon, ThreatContextFrame,
        AURA_RELAY_SCHEMA_VERSION,
    };
}

pub use v1alpha1::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trip_preserves_wire_shape() {
        let request = AgentAnalyzeRequest {
            request_id: "req_alpha".to_string(),
            text: "dont tell your parents".to_string(),
            ..AgentAnalyzeRequest::default()
        };

        let json = serde_json::to_string(&request).unwrap();
        let parsed: AgentAnalyzeRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.schema_version, AURA_RELAY_SCHEMA_VERSION);
        assert_eq!(parsed.request_id, "req_alpha");
        assert_eq!(parsed.text, "dont tell your parents");
    }
}
