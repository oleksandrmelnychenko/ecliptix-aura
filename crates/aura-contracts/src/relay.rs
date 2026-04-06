use serde::{Deserialize, Serialize};

use crate::common::{AccountType, Confidence, ConversationType, ProtectionLevel, ThreatType};
use crate::context::ThreatContextFrame;
use crate::event::ConfirmedEvent;
use crate::observation::RawObservation;

pub const AURA_RELAY_SCHEMA_VERSION: &str = "aura.relay.v1alpha1";

pub fn default_relay_schema_version() -> String {
    AURA_RELAY_SCHEMA_VERSION.to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RelayPrivacyMode {
    MetadataOnly,
    #[default]
    MessageOnly,
    MessageAndWindow,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct MessageWindowEntry {
    #[serde(default)]
    pub sender_id: String,
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct LocalContextSummary {
    #[serde(default)]
    pub context_markers: Vec<String>,
    #[serde(default)]
    pub recent_observations: Vec<RawObservation>,
    #[serde(default)]
    pub recent_confirmed_events: Vec<ConfirmedEvent>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct AgentCapabilities {
    #[serde(default)]
    pub local_context_interpreter: bool,
    #[serde(default)]
    pub local_tracker: bool,
    #[serde(default)]
    pub supports_remote_correlation: bool,
    #[serde(default)]
    pub relay_timeout_ms: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentAnalyzeRequest {
    #[serde(default = "default_relay_schema_version")]
    pub schema_version: String,
    #[serde(default)]
    pub request_id: String,
    #[serde(default)]
    pub message_id: String,
    #[serde(default)]
    pub account_type: AccountType,
    #[serde(default)]
    pub protection_level: ProtectionLevel,
    #[serde(default)]
    pub conversation_type: ConversationType,
    #[serde(default)]
    pub language: Option<String>,
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub local_observations: Vec<RawObservation>,
    #[serde(default)]
    pub local_context: Option<ThreatContextFrame>,
    #[serde(default)]
    pub local_context_summary: LocalContextSummary,
    #[serde(default)]
    pub recent_message_window: Vec<MessageWindowEntry>,
    #[serde(default)]
    pub server_sender_risk_hint: Option<f32>,
    #[serde(default)]
    pub privacy_mode: RelayPrivacyMode,
    #[serde(default)]
    pub capabilities: AgentCapabilities,
    #[serde(default)]
    pub deadline_ms: Option<u32>,
}

impl Default for AgentAnalyzeRequest {
    fn default() -> Self {
        Self {
            schema_version: default_relay_schema_version(),
            request_id: String::new(),
            message_id: String::new(),
            account_type: AccountType::default(),
            protection_level: ProtectionLevel::default(),
            conversation_type: ConversationType::default(),
            language: None,
            text: String::new(),
            local_observations: Vec::new(),
            local_context: None,
            local_context_summary: LocalContextSummary::default(),
            recent_message_window: Vec::new(),
            server_sender_risk_hint: None,
            privacy_mode: RelayPrivacyMode::default(),
            capabilities: AgentCapabilities::default(),
            deadline_ms: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RiskHorizon {
    #[default]
    Unknown,
    Immediate,
    NearTerm,
    Sustained,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct RemoteFinding {
    pub threat_type: ThreatType,
    #[serde(default)]
    pub score: f32,
    #[serde(default)]
    pub confidence: Confidence,
    #[serde(default)]
    pub reason_code: String,
    #[serde(default)]
    pub explanation: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct RemoteInferenceSummary {
    #[serde(default)]
    pub primary_threat: ThreatType,
    #[serde(default)]
    pub score: f32,
    #[serde(default)]
    pub confidence: Confidence,
    #[serde(default)]
    pub risk_horizon: RiskHorizon,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RelayAnalyzeResponse {
    #[serde(default = "default_relay_schema_version")]
    pub schema_version: String,
    #[serde(default)]
    pub request_id: String,
    #[serde(default)]
    pub remote_observations: Vec<RawObservation>,
    #[serde(default)]
    pub remote_context: Option<ThreatContextFrame>,
    #[serde(default)]
    pub remote_events: Vec<ConfirmedEvent>,
    #[serde(default)]
    pub findings: Vec<RemoteFinding>,
    #[serde(default)]
    pub inference: Option<RemoteInferenceSummary>,
    #[serde(default)]
    pub reason_codes: Vec<String>,
    #[serde(default)]
    pub context_markers: Vec<String>,
    #[serde(default)]
    pub confidence: Confidence,
    #[serde(default)]
    pub expires_at_ms: Option<u64>,
    #[serde(default)]
    pub sender_reputation_hint: Option<f32>,
    #[serde(default)]
    pub correlation_findings: Vec<String>,
}

impl Default for RelayAnalyzeResponse {
    fn default() -> Self {
        Self {
            schema_version: default_relay_schema_version(),
            request_id: String::new(),
            remote_observations: Vec::new(),
            remote_context: None,
            remote_events: Vec::new(),
            findings: Vec::new(),
            inference: None,
            reason_codes: Vec::new(),
            context_markers: Vec::new(),
            confidence: Confidence::default(),
            expires_at_ms: None,
            sender_reputation_hint: None,
            correlation_findings: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_defaults_to_current_schema_version() {
        let request = AgentAnalyzeRequest::default();
        assert_eq!(request.schema_version, AURA_RELAY_SCHEMA_VERSION);
        assert_eq!(request.privacy_mode, RelayPrivacyMode::MessageOnly);
    }

    #[test]
    fn relay_response_round_trips_through_json() {
        let response = RelayAnalyzeResponse {
            request_id: "req_42".to_string(),
            findings: vec![RemoteFinding {
                threat_type: ThreatType::Grooming,
                score: 0.94,
                confidence: Confidence::High,
                reason_code: "relay.grooming.sequence".to_string(),
                explanation: "remote grooming sequence corroborated".to_string(),
            }],
            inference: Some(RemoteInferenceSummary {
                primary_threat: ThreatType::Grooming,
                score: 0.94,
                confidence: Confidence::High,
                risk_horizon: RiskHorizon::NearTerm,
            }),
            sender_reputation_hint: Some(0.82),
            ..RelayAnalyzeResponse::default()
        };

        let json = serde_json::to_string(&response).unwrap();
        let parsed: RelayAnalyzeResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.request_id, "req_42");
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.findings[0].threat_type, ThreatType::Grooming);
        assert_eq!(parsed.sender_reputation_hint, Some(0.82));
    }
}
