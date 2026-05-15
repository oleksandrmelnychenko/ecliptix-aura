//! Relay inference orchestration layer.
//!
//! Routes validated intake through ML models, fuses rule-based and
//! ML-based signals, and handles model fallback when specific backends
//! are unavailable.

use aura_contracts::{Confidence, ThreatType};
use aura_relay_intake::IntakeResult;

#[derive(Debug, Clone)]
pub struct InferenceResult {
    pub request_id: String,
    pub primary_threat: ThreatType,
    pub score: f32,
    pub confidence: Confidence,
    pub model_signals: Vec<ModelSignal>,
}

#[derive(Debug, Clone)]
pub struct ModelSignal {
    pub threat_type: ThreatType,
    pub score: f32,
    pub confidence: Confidence,
    pub model_id: String,
}

pub fn run_inference(intake: &IntakeResult) -> InferenceResult {
    // Stub: relay inference currently returns the local hints as-is.
    // Real implementation will plug aura-relay-ml here.
    let primary_threat = intake
        .local_threat_hints
        .first()
        .copied()
        .unwrap_or(ThreatType::None);

    InferenceResult {
        request_id: intake.request_id.clone(),
        primary_threat,
        score: intake.local_score,
        confidence: if intake.local_score >= 0.8 {
            Confidence::High
        } else if intake.local_score >= 0.5 {
            Confidence::Medium
        } else {
            Confidence::Low
        },
        model_signals: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aura_contracts::RelayPrivacyMode;

    #[test]
    fn inference_returns_local_hints_as_stub() {
        let intake = IntakeResult {
            request_id: "req_1".to_string(),
            text: "test".to_string(),
            language: None,
            sender_token: None,
            local_threat_hints: vec![ThreatType::Grooming],
            local_score: 0.85,
            local_safety_telemetry: Vec::new(),
            privacy_mode: RelayPrivacyMode::MessageOnly,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        };

        let result = run_inference(&intake);
        assert_eq!(result.primary_threat, ThreatType::Grooming);
        assert_eq!(result.confidence, Confidence::High);
    }
}
