//! Relay response policy layer.
//!
//! Decides what findings can be returned to the agent, applies confidence
//! thresholds, generates privacy-safe explanations, and enforces the
//! relay response contract.

use aura_contracts::{
    default_relay_schema_version, RelayAnalyzeResponse, RemoteInferenceSummary, RiskHorizon,
    ThreatType,
};
use aura_relay_risk::RiskAssessment;

pub struct PolicyFilter {
    min_score_to_return: f32,
}

impl PolicyFilter {
    pub fn new() -> Self {
        Self {
            min_score_to_return: 0.0,
        }
    }

    pub fn with_min_score(mut self, min_score: f32) -> Self {
        self.min_score_to_return = min_score;
        self
    }

    pub fn filter_response(
        &self,
        request_id: String,
        assessment: &RiskAssessment,
    ) -> RelayAnalyzeResponse {
        let findings = assessment
            .findings
            .iter()
            .filter(|f| f.score >= self.min_score_to_return)
            .cloned()
            .collect();

        let inference = if assessment.final_threat != ThreatType::None {
            Some(RemoteInferenceSummary {
                primary_threat: assessment.final_threat,
                score: assessment.final_score,
                confidence: assessment.final_confidence,
                risk_horizon: RiskHorizon::Unknown,
            })
        } else {
            None
        };

        RelayAnalyzeResponse {
            schema_version: default_relay_schema_version(),
            request_id,
            findings,
            inference,
            reason_codes: assessment.reason_codes.clone(),
            context_markers: assessment.context_markers.clone(),
            confidence: assessment.final_confidence,
            ..RelayAnalyzeResponse::default()
        }
    }
}

impl Default for PolicyFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aura_contracts::{Confidence, RemoteFinding};

    #[test]
    fn policy_filter_passes_findings_above_threshold() {
        let filter = PolicyFilter::new().with_min_score(0.5);
        let assessment = RiskAssessment {
            request_id: "req_1".to_string(),
            findings: vec![
                RemoteFinding {
                    threat_type: ThreatType::Grooming,
                    score: 0.9,
                    confidence: Confidence::High,
                    reason_code: "test.high".to_string(),
                    explanation: String::new(),
                },
                RemoteFinding {
                    threat_type: ThreatType::Spam,
                    score: 0.3,
                    confidence: Confidence::Low,
                    reason_code: "test.low".to_string(),
                    explanation: String::new(),
                },
            ],
            final_threat: ThreatType::Grooming,
            final_score: 0.9,
            final_confidence: Confidence::High,
            reason_codes: Vec::new(),
            context_markers: Vec::new(),
        };

        let response = filter.filter_response("req_1".to_string(), &assessment);
        assert_eq!(response.findings.len(), 1);
        assert_eq!(response.findings[0].threat_type, ThreatType::Grooming);
    }
}
