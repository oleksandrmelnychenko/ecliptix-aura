//! Relay risk assessment layer.
//!
//! Fuses local observations, remote inference results, and context signals
//! into a final risk assessment with typed findings.

use aura_contracts::{
    AccountType, Confidence, RelationshipTrustSource, RemoteFinding, SenderRelationship, ThreatType,
};
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

pub fn assess_risk(inference: &InferenceResult, intake: &IntakeResult) -> RiskAssessment {
    let mut findings = Vec::new();
    let mut reason_codes = Vec::new();
    let mut context_markers = Vec::new();
    let mut final_score = inference.score;

    apply_relationship_context(
        intake,
        inference.primary_threat,
        &mut final_score,
        &mut reason_codes,
        &mut context_markers,
    );
    final_score = final_score.clamp(0.0, 1.0);
    let final_confidence = std::cmp::max(inference.confidence, confidence_for_score(final_score));

    if final_score > 0.0 && inference.primary_threat != ThreatType::None {
        findings.push(RemoteFinding {
            threat_type: inference.primary_threat,
            score: final_score,
            confidence: final_confidence,
            reason_code: "relay.inference.primary".to_string(),
            explanation: format!(
                "relay inference: {:?} at {:.2}",
                inference.primary_threat, final_score
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
        final_score,
        final_confidence,
        reason_codes,
        context_markers,
    }
}

fn apply_relationship_context(
    intake: &IntakeResult,
    primary_threat: ThreatType,
    final_score: &mut f32,
    reason_codes: &mut Vec<String>,
    context_markers: &mut Vec<String>,
) {
    if intake.sender_relationship == SenderRelationship::Unknown {
        return;
    }

    context_markers.push(format!(
        "relay.relationship.sender.{}",
        sender_relationship_marker(intake.sender_relationship)
    ));
    context_markers.push(format!(
        "relay.relationship.source.{}",
        trust_source_marker(intake.relationship_trust_source)
    ));

    let minor_account = matches!(intake.account_type, AccountType::Child | AccountType::Teen);
    let has_threat_signal = primary_threat != ThreatType::None && *final_score > 0.0;

    if minor_account && intake.sender_relationship == SenderRelationship::UnknownAdult {
        context_markers.push("relay.relationship.unknown_adult_minor".to_string());
        reason_codes.push("relay.relationship.unknown_adult_minor".to_string());
        if has_threat_signal {
            *final_score += 0.08;
        }
    }

    if intake.relationship_trust_source == RelationshipTrustSource::SelfDeclared {
        context_markers.push("relay.relationship.self_declared_untrusted".to_string());
        if privileged_relationship_claim(intake.sender_relationship) {
            reason_codes.push("relay.relationship.self_declared_privileged_claim".to_string());
            if minor_account && has_threat_signal {
                *final_score += 0.05;
            }
        }
    }

    if verified_relationship_source(intake.relationship_trust_source)
        && trusted_family_or_guardian_relationship(intake.sender_relationship)
    {
        context_markers.push("relay.relationship.verified_family_context".to_string());
    }
}

fn confidence_for_score(score: f32) -> Confidence {
    if score >= 0.8 {
        Confidence::High
    } else if score >= 0.5 {
        Confidence::Medium
    } else {
        Confidence::Low
    }
}

fn privileged_relationship_claim(relationship: SenderRelationship) -> bool {
    matches!(
        relationship,
        SenderRelationship::Parent
            | SenderRelationship::Guardian
            | SenderRelationship::Teacher
            | SenderRelationship::Coach
            | SenderRelationship::Authority
    )
}

fn trusted_family_or_guardian_relationship(relationship: SenderRelationship) -> bool {
    matches!(
        relationship,
        SenderRelationship::Parent
            | SenderRelationship::Guardian
            | SenderRelationship::Family
            | SenderRelationship::Sibling
    )
}

fn verified_relationship_source(source: RelationshipTrustSource) -> bool {
    matches!(
        source,
        RelationshipTrustSource::UserVerified
            | RelationshipTrustSource::GuardianVerified
            | RelationshipTrustSource::PlatformVerified
            | RelationshipTrustSource::AddressBook
            | RelationshipTrustSource::SchoolDirectory
    )
}

fn sender_relationship_marker(relationship: SenderRelationship) -> &'static str {
    match relationship {
        SenderRelationship::Unknown => "unknown",
        SenderRelationship::Parent => "parent",
        SenderRelationship::Guardian => "guardian",
        SenderRelationship::Family => "family",
        SenderRelationship::Sibling => "sibling",
        SenderRelationship::Peer => "peer",
        SenderRelationship::Teacher => "teacher",
        SenderRelationship::Coach => "coach",
        SenderRelationship::Authority => "authority",
        SenderRelationship::Service => "service",
        SenderRelationship::UnknownAdult => "unknown_adult",
        SenderRelationship::UnknownPeer => "unknown_peer",
    }
}

fn trust_source_marker(source: RelationshipTrustSource) -> &'static str {
    match source {
        RelationshipTrustSource::Unknown => "unknown",
        RelationshipTrustSource::UserVerified => "user_verified",
        RelationshipTrustSource::GuardianVerified => "guardian_verified",
        RelationshipTrustSource::PlatformVerified => "platform_verified",
        RelationshipTrustSource::AddressBook => "address_book",
        RelationshipTrustSource::SchoolDirectory => "school_directory",
        RelationshipTrustSource::ServerReputation => "server_reputation",
        RelationshipTrustSource::LocalHeuristic => "local_heuristic",
        RelationshipTrustSource::SelfDeclared => "self_declared",
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
            account_type: Default::default(),
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

    #[test]
    fn unknown_adult_minor_context_boosts_existing_signal() {
        let inference = InferenceResult {
            request_id: "req_1".to_string(),
            primary_threat: ThreatType::Grooming,
            score: 0.47,
            confidence: Confidence::Low,
            model_signals: Vec::new(),
        };
        let intake = IntakeResult {
            request_id: "req_1".to_string(),
            text: String::new(),
            language: None,
            account_type: AccountType::Child,
            sender_token: None,
            local_threat_hints: vec![ThreatType::Grooming],
            local_score: 0.47,
            local_safety_telemetry: Vec::new(),
            privacy_mode: RelayPrivacyMode::MetadataOnly,
            sender_relationship: SenderRelationship::UnknownAdult,
            relationship_trust_source: RelationshipTrustSource::ServerReputation,
        };

        let assessment = assess_risk(&inference, &intake);

        assert!((assessment.final_score - 0.55).abs() < 0.0001);
        assert_eq!(assessment.final_confidence, Confidence::Medium);
        assert_eq!(assessment.findings[0].score, assessment.final_score);
        assert!(assessment
            .reason_codes
            .contains(&"relay.relationship.unknown_adult_minor".to_string()));
        assert!(assessment
            .context_markers
            .contains(&"relay.relationship.unknown_adult_minor".to_string()));
    }

    #[test]
    fn self_declared_privileged_relationship_is_not_trusted() {
        let inference = InferenceResult {
            request_id: "req_1".to_string(),
            primary_threat: ThreatType::Manipulation,
            score: 0.51,
            confidence: Confidence::Medium,
            model_signals: Vec::new(),
        };
        let intake = IntakeResult {
            request_id: "req_1".to_string(),
            text: String::new(),
            language: None,
            account_type: AccountType::Teen,
            sender_token: None,
            local_threat_hints: vec![ThreatType::Manipulation],
            local_score: 0.51,
            local_safety_telemetry: Vec::new(),
            privacy_mode: RelayPrivacyMode::MetadataOnly,
            sender_relationship: SenderRelationship::Parent,
            relationship_trust_source: RelationshipTrustSource::SelfDeclared,
        };

        let assessment = assess_risk(&inference, &intake);

        assert!((assessment.final_score - 0.56).abs() < 0.0001);
        assert!(assessment
            .reason_codes
            .contains(&"relay.relationship.self_declared_privileged_claim".to_string()));
        assert!(assessment
            .context_markers
            .contains(&"relay.relationship.self_declared_untrusted".to_string()));
        assert!(!assessment
            .context_markers
            .contains(&"relay.relationship.verified_family_context".to_string()));
    }

    #[test]
    fn verified_guardian_context_does_not_suppress_existing_signal() {
        let inference = InferenceResult {
            request_id: "req_1".to_string(),
            primary_threat: ThreatType::Grooming,
            score: 0.82,
            confidence: Confidence::High,
            model_signals: Vec::new(),
        };
        let intake = IntakeResult {
            request_id: "req_1".to_string(),
            text: String::new(),
            language: None,
            account_type: AccountType::Child,
            sender_token: None,
            local_threat_hints: vec![ThreatType::Grooming],
            local_score: 0.82,
            local_safety_telemetry: Vec::new(),
            privacy_mode: RelayPrivacyMode::MetadataOnly,
            sender_relationship: SenderRelationship::Guardian,
            relationship_trust_source: RelationshipTrustSource::GuardianVerified,
        };

        let assessment = assess_risk(&inference, &intake);

        assert!((assessment.final_score - 0.82).abs() < 0.0001);
        assert!(assessment
            .context_markers
            .contains(&"relay.relationship.verified_family_context".to_string()));
        assert!(assessment.reason_codes.is_empty());
    }
}
