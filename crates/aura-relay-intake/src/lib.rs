//! Relay intake layer: validates, normalizes, and privacy-filters incoming
//! agent requests before they reach inference.

use aura_contracts::{
    AgentAnalyzeRequest, ClientSafetyTelemetryEvent, RelayPrivacyMode, ThreatType,
};

#[derive(Debug, Clone)]
pub struct IntakeResult {
    pub request_id: String,
    pub text: String,
    pub language: Option<String>,
    pub sender_token: Option<String>,
    pub local_threat_hints: Vec<ThreatType>,
    pub local_score: f32,
    pub local_safety_telemetry: Vec<ClientSafetyTelemetryEvent>,
    pub privacy_mode: RelayPrivacyMode,
}

pub fn validate_and_normalize(request: &AgentAnalyzeRequest) -> IntakeResult {
    let local_threat_hints: Vec<ThreatType> = request
        .local_observations
        .iter()
        .map(|obs| obs.threat_type)
        .collect();

    let local_score = request
        .local_observations
        .iter()
        .map(|obs| obs.score)
        .fold(0.0_f32, f32::max);

    let text = match request.privacy_mode {
        RelayPrivacyMode::MetadataOnly => String::new(),
        RelayPrivacyMode::MessageOnly => request.text.clone(),
        RelayPrivacyMode::MessageAndWindow => request.text.clone(),
    };

    let local_safety_telemetry = request
        .local_safety_telemetry
        .iter()
        .filter(|event| event.privacy_safe())
        .cloned()
        .collect();

    IntakeResult {
        request_id: request.request_id.clone(),
        text,
        language: request.language.clone(),
        sender_token: request.privacy_safe_sender_token().map(str::to_string),
        local_threat_hints,
        local_score,
        local_safety_telemetry,
        privacy_mode: request.privacy_mode,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aura_contracts::{
        Confidence, SafetyTelemetryAction, SafetyTelemetrySeverity, SafetyTelemetrySurface,
    };

    #[test]
    fn metadata_only_strips_text() {
        let request = AgentAnalyzeRequest {
            text: "sensitive content".to_string(),
            privacy_mode: RelayPrivacyMode::MetadataOnly,
            ..AgentAnalyzeRequest::default()
        };
        let intake = validate_and_normalize(&request);
        assert!(intake.text.is_empty());
    }

    #[test]
    fn message_mode_preserves_text() {
        let request = AgentAnalyzeRequest {
            text: "check this".to_string(),
            privacy_mode: RelayPrivacyMode::MessageOnly,
            ..AgentAnalyzeRequest::default()
        };
        let intake = validate_and_normalize(&request);
        assert_eq!(intake.text, "check this");
    }

    #[test]
    fn metadata_only_preserves_privacy_safe_telemetry() {
        let request = AgentAnalyzeRequest {
            text: "sensitive content".to_string(),
            privacy_mode: RelayPrivacyMode::MetadataOnly,
            sender_token: Some("snd_01H00000000000000000000000".to_string()),
            local_safety_telemetry: vec![ClientSafetyTelemetryEvent {
                event_id: "evt_01H00000000000000000000000".to_string(),
                sender_token: "snd_01H00000000000000000000000".to_string(),
                protected_account_token: "acct_01H0000000000000000000000".to_string(),
                conversation_token: Some("conv_01H000000000000000000000".to_string()),
                surface: SafetyTelemetrySurface::DirectMessage,
                threat_type: ThreatType::Grooming,
                severity: SafetyTelemetrySeverity::High,
                confidence: Confidence::High,
                action: SafetyTelemetryAction::Warn,
                timestamp_bucket_ms: 1_778_652_000_000,
                reason_family: Some("grooming".to_string()),
            }],
            ..AgentAnalyzeRequest::default()
        };

        let intake = validate_and_normalize(&request);

        assert!(intake.text.is_empty());
        assert_eq!(
            intake.sender_token.as_deref(),
            Some("snd_01H00000000000000000000000")
        );
        assert_eq!(intake.local_safety_telemetry.len(), 1);
        assert_eq!(
            intake.local_safety_telemetry[0].threat_type,
            ThreatType::Grooming
        );
    }

    #[test]
    fn intake_drops_raw_looking_subject_sender_token() {
        let request = AgentAnalyzeRequest {
            sender_token: Some("mentor 42".to_string()),
            ..AgentAnalyzeRequest::default()
        };

        let intake = validate_and_normalize(&request);

        assert!(intake.sender_token.is_none());
    }

    #[test]
    fn intake_drops_raw_looking_telemetry_tokens() {
        let request = AgentAnalyzeRequest {
            local_safety_telemetry: vec![ClientSafetyTelemetryEvent {
                sender_token: "mentor 42".to_string(),
                protected_account_token: "kid@example.test".to_string(),
                threat_type: ThreatType::Grooming,
                severity: SafetyTelemetrySeverity::High,
                confidence: Confidence::High,
                ..ClientSafetyTelemetryEvent::default()
            }],
            ..AgentAnalyzeRequest::default()
        };

        let intake = validate_and_normalize(&request);

        assert!(intake.local_safety_telemetry.is_empty());
    }
}
