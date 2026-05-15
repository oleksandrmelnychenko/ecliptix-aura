//! Relay risk assessment layer.
//!
//! Fuses local observations, remote inference results, and context signals
//! into a final risk assessment with typed findings.

use aura_contracts::{Confidence, RemoteFinding, ThreatType};
use aura_relay_inference::InferenceResult;
use aura_relay_intake::IntakeResult;

#[derive(Debug, Clone)]
pub struct RiskAssessment {
    pub request_id: String,
    pub findings: Vec<RemoteFinding>,
    pub final_threat: ThreatType,
    pub final_score: f32,
    pub final_confidence: Confidence,
    pub reason_codes: Vec<String>,
    pub context_markers: Vec<String>,
}

pub fn assess_risk(inference: &InferenceResult, _intake: &IntakeResult) -> RiskAssessment {
    let mut findings = Vec::new();

    if inference.score > 0.0 && inference.primary_threat != ThreatType::None {
        findings.push(RemoteFinding {
            threat_type: inference.primary_threat,
            score: inference.score,
            confidence: inference.confidence,
            reason_code: "relay.inference.primary".to_string(),
            explanation: format!(
                "relay inference: {:?} at {:.2}",
                inference.primary_threat, inference.score
            ),
        });
    }

    for signal in &inference.model_signals {
        findings.push(RemoteFinding {
            threat_type: signal.threat_type,
            score: signal.score,
            confidence: signal.confidence,
            reason_code: format!("relay.model.{}", signal.model_id),
            explanation: String::new(),
        });
    }

    RiskAssessment {
        request_id: inference.request_id.clone(),
        findings,
        final_threat: inference.primary_threat,
        final_score: inference.score,
        final_confidence: inference.confidence,
        reason_codes: Vec::new(),
        context_markers: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aura_contracts::RelayPrivacyMode;

    #[test]
    fn risk_assessment_includes_primary_finding() {
        let inference = InferenceResult {
            request_id: "req_1".to_string(),
            primary_threat: ThreatType::Bullying,
            score: 0.75,
            confidence: Confidence::Medium,
            model_signals: Vec::new(),
        };
        let intake = IntakeResult {
            request_id: "req_1".to_string(),
            text: "test".to_string(),
            language: None,
            sender_token: None,
            local_threat_hints: vec![],
            local_score: 0.0,
            local_safety_telemetry: Vec::new(),
            privacy_mode: RelayPrivacyMode::MessageOnly,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        };

        let assessment = assess_risk(&inference, &intake);
        assert_eq!(assessment.findings.len(), 1);
        assert_eq!(assessment.final_threat, ThreatType::Bullying);
    }
}
