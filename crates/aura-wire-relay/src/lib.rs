//! Versioned wire exports for AURA Agent <-> Relay communication.

pub mod v1alpha1 {
    pub use aura_contracts::{
        default_relay_schema_version, sign_protected_account_token_attestation,
        sign_relay_request_auth, sign_relay_response_auth,
        verify_protected_account_token_attestation, verify_relay_request_auth,
        verify_relay_response_auth, AgentAnalyzeRequest, AgentCapabilities,
        ClientSafetyTelemetryEvent, ConfirmedEvent, LocalContextSummary, MessageWindowEntry,
        ProtectedAccountTokenAttestation, RawObservation, RelayAnalyzeResponse, RelayPrivacyMode,
        RelayRequestAuth, RelayResponseAuth, RemoteFinding, RemoteInferenceSummary, RiskHorizon,
        SafetyTelemetryAction, SafetyTelemetrySeverity, SafetyTelemetrySurface, ThreatContextFrame,
        AURA_RELAY_SCHEMA_VERSION, PROTECTED_ACCOUNT_TOKEN_ATTESTATION_ALG, RELAY_REQUEST_AUTH_ALG,
        RELAY_RESPONSE_AUTH_ALG,
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
