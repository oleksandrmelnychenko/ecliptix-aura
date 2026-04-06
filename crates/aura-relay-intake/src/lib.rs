//! Relay intake layer: validates, normalizes, and privacy-filters incoming
//! agent requests before they reach inference.

use aura_contracts::{AgentAnalyzeRequest, RelayPrivacyMode, ThreatType};

#[derive(Debug, Clone)]
pub struct IntakeResult {
    pub request_id: String,
    pub text: String,
    pub language: Option<String>,
    pub local_threat_hints: Vec<ThreatType>,
    pub local_score: f32,
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

    IntakeResult {
        request_id: request.request_id.clone(),
        text,
        language: request.language.clone(),
        local_threat_hints,
        local_score,
        privacy_mode: request.privacy_mode,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
