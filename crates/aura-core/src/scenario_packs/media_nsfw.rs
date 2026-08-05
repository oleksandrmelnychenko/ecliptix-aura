//! Media NSFW protection simulation pack.
//!
//! Exercises the media stage end to end through the scenario harness:
//! verdict-driven classification (P2), the relationship trust gate (P0
//! fail-closed path), and send-side sextortion protection (P3). Client
//! verdicts act as the deterministic mock backend from the architecture's
//! evaluation strategy — no media bytes appear anywhere in fixtures.

use crate::eval_scenarios::{adult_config, teen_config};
use crate::ids::{ConversationId, SenderId};
use crate::types::{
    AccountType, ClientVisionVerdict, ContentType, ConversationType, MediaClass, MessageInput,
    ProtectionLevel, RelationshipTrustSource, SenderRelationship,
};
use crate::{
    AuraConfig, ScenarioCase, ScenarioQualityGates, ScenarioStep, ThreatCalibrationGate, ThreatType,
};

const SEC: u64 = 1_000;
const MIN: u64 = 60 * SEC;
const PROTECTED_TEEN: &str = "protected_teen";

fn child_config() -> AuraConfig {
    AuraConfig {
        account_type: AccountType::Child,
        protection_level: ProtectionLevel::High,
        language: "en".to_string(),
        ..AuraConfig::default()
    }
}

fn teen_send_side_config() -> AuraConfig {
    AuraConfig {
        protected_account_id: Some(PROTECTED_TEEN.to_string()),
        ..teen_config()
    }
}

fn media_input(
    content_type: ContentType,
    sender: &str,
    conversation: &str,
    verdict: Option<ClientVisionVerdict>,
) -> MessageInput {
    MessageInput {
        content_type,
        text: None,
        image_data: None,
        media_info: None,
        client_vision_verdict: verdict,
        sender_id: SenderId::from(sender),
        conversation_id: ConversationId::from(conversation),
        language: None,
        conversation_type: ConversationType::Direct,
        member_count: None,
        sender_relationship: SenderRelationship::Unknown,
        relationship_trust_source: RelationshipTrustSource::Unknown,
    }
}

fn text_input(text: &str, sender: &str, conversation: &str) -> MessageInput {
    MessageInput {
        content_type: ContentType::Text,
        text: Some(text.to_string()),
        ..media_input(ContentType::Text, sender, conversation, None)
    }
}

fn verdict(class: MediaClass, confidence: f32) -> ClientVisionVerdict {
    ClientVisionVerdict {
        class,
        confidence,
        provider: "apple.sca".to_string(),
    }
}

pub fn canonical_media_nsfw_scenarios() -> Vec<ScenarioCase> {
    vec![
        explicit_verdict_child_dm_case(),
        explicit_verdict_overrides_guardian_sender_case(),
        suggestive_verdict_teen_case(),
        trust_gate_child_unverified_case(),
        adult_cyberflashing_case(),
        send_attempt_coerced_case(),
        negative_neutral_verdict_release_case(),
        negative_text_only_case(),
    ]
}

pub fn adversarial_media_nsfw_scenarios() -> Vec<ScenarioCase> {
    vec![
        invalid_confidence_fails_closed_case(),
        low_confidence_neutral_fails_closed_case(),
    ]
}

pub fn long_context_media_nsfw_scenarios() -> Vec<ScenarioCase> {
    vec![long_grooming_to_coerced_send_case()]
}

pub fn false_positive_media_nsfw_scenarios() -> Vec<ScenarioCase> {
    vec![
        fp_confident_neutral_family_photo_case(),
        fp_voice_message_case(),
        fp_url_only_message_case(),
    ]
}

pub fn media_nsfw_quality_gates() -> ScenarioQualityGates {
    ScenarioQualityGates {
        max_brier_score: Some(0.25),
        max_expected_calibration_error: Some(0.18),
        min_positive_detection_rate: Some(0.80),
        max_negative_false_positive_rate: Some(0.10),
        // Media cases are short and verdict-driven; pre-onset lead time is a
        // text-conversation metric and does not apply here.
        min_pre_onset_detection_rate: None,
        per_threat: vec![ThreatCalibrationGate {
            threat_type: ThreatType::Nsfw,
            min_example_count: Some(10),
            max_brier_score: Some(0.30),
            max_expected_calibration_error: Some(0.20),
        }],
    }
}

// -- positives -------------------------------------------------------------

fn explicit_verdict_child_dm_case() -> ScenarioCase {
    ScenarioCase {
        name: "media_explicit_verdict_child_dm".to_string(),
        config: child_config(),
        primary_threat: Some(ThreatType::Nsfw),
        onset_step: Some(1),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Nsfw],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: text_input("hey, we met in the game lobby", "stranger_1", "dm"),
                observed_threats: vec![],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: media_input(
                    ContentType::Image,
                    "stranger_1",
                    "dm",
                    Some(verdict(MediaClass::Explicit, 0.9)),
                ),
                observed_threats: vec![ThreatType::Nsfw],
            },
        ],
    }
}

fn explicit_verdict_overrides_guardian_sender_case() -> ScenarioCase {
    let mut input = media_input(
        ContentType::Image,
        "verified_adult",
        "family_dm",
        Some(verdict(MediaClass::Explicit, 0.85)),
    );
    input.sender_relationship = SenderRelationship::Parent;
    input.relationship_trust_source = RelationshipTrustSource::GuardianVerified;
    ScenarioCase {
        name: "media_explicit_verdict_overrides_guardian_sender".to_string(),
        config: child_config(),
        primary_threat: Some(ThreatType::Nsfw),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Nsfw],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input,
            observed_threats: vec![ThreatType::Nsfw],
        }],
    }
}

fn suggestive_verdict_teen_case() -> ScenarioCase {
    ScenarioCase {
        name: "media_suggestive_verdict_teen".to_string(),
        config: teen_config(),
        primary_threat: Some(ThreatType::Nsfw),
        onset_step: Some(0),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Nsfw],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: media_input(
                ContentType::Image,
                "stranger_1",
                "dm",
                Some(verdict(MediaClass::Suggestive, 0.8)),
            ),
            observed_threats: vec![ThreatType::Nsfw],
        }],
    }
}

fn trust_gate_child_unverified_case() -> ScenarioCase {
    ScenarioCase {
        name: "media_trust_gate_child_unverified".to_string(),
        config: child_config(),
        primary_threat: Some(ThreatType::Nsfw),
        onset_step: Some(0),
        // The fail-closed gate is precautionary: score 0.50 for child + new
        // contact, so this case detects at a lower threshold by design.
        detection_threshold: 0.45,
        tracked_threats: vec![ThreatType::Nsfw],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: media_input(ContentType::Image, "stranger_1", "dm", None),
            observed_threats: vec![ThreatType::Nsfw],
        }],
    }
}

fn adult_cyberflashing_case() -> ScenarioCase {
    ScenarioCase {
        name: "media_adult_cyberflashing_blur".to_string(),
        config: adult_config(),
        primary_threat: Some(ThreatType::Nsfw),
        onset_step: Some(0),
        // Adult posture is a blur band (0.35 + 0.20 * confidence).
        detection_threshold: 0.45,
        tracked_threats: vec![ThreatType::Nsfw],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: media_input(
                ContentType::Image,
                "stranger_1",
                "dm",
                Some(verdict(MediaClass::Explicit, 0.9)),
            ),
            observed_threats: vec![ThreatType::Nsfw],
        }],
    }
}

fn send_attempt_coerced_case() -> ScenarioCase {
    ScenarioCase {
        name: "media_send_attempt_coerced".to_string(),
        config: teen_send_side_config(),
        primary_threat: Some(ThreatType::Nsfw),
        onset_step: Some(2),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Nsfw],
        steps: vec![
            ScenarioStep {
                timestamp_ms: 0,
                input: text_input("send me a photo of you", "older_user", "dm"),
                observed_threats: vec![],
            },
            ScenarioStep {
                timestamp_ms: MIN,
                input: text_input("this stays our little secret ok", "older_user", "dm"),
                observed_threats: vec![],
            },
            ScenarioStep {
                timestamp_ms: 2 * MIN,
                input: media_input(
                    ContentType::Image,
                    PROTECTED_TEEN,
                    "dm",
                    Some(verdict(MediaClass::Explicit, 0.9)),
                ),
                observed_threats: vec![ThreatType::Nsfw],
            },
        ],
    }
}

// -- negatives -------------------------------------------------------------

fn negative_neutral_verdict_release_case() -> ScenarioCase {
    ScenarioCase {
        name: "media_neg_neutral_verdict_release".to_string(),
        config: child_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.45,
        tracked_threats: vec![ThreatType::Nsfw],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: media_input(
                ContentType::Image,
                "stranger_1",
                "dm",
                Some(verdict(MediaClass::Neutral, 0.95)),
            ),
            observed_threats: vec![],
        }],
    }
}

fn negative_text_only_case() -> ScenarioCase {
    ScenarioCase {
        name: "media_neg_text_only".to_string(),
        config: child_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.45,
        tracked_threats: vec![ThreatType::Nsfw],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: text_input("did you finish the science homework?", "classmate", "dm"),
            observed_threats: vec![],
        }],
    }
}

// -- adversarial -----------------------------------------------------------

fn invalid_confidence_fails_closed_case() -> ScenarioCase {
    ScenarioCase {
        name: "media_adv_invalid_confidence_fails_closed".to_string(),
        config: child_config(),
        primary_threat: Some(ThreatType::Nsfw),
        onset_step: Some(0),
        detection_threshold: 0.45,
        tracked_threats: vec![ThreatType::Nsfw],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            // Out-of-range confidence must be rejected and fall back to the
            // trust gate, not silently trusted.
            input: media_input(
                ContentType::Image,
                "stranger_1",
                "dm",
                Some(verdict(MediaClass::Explicit, 1.5)),
            ),
            observed_threats: vec![ThreatType::Nsfw],
        }],
    }
}

fn low_confidence_neutral_fails_closed_case() -> ScenarioCase {
    ScenarioCase {
        name: "media_adv_low_confidence_neutral_fails_closed".to_string(),
        config: child_config(),
        primary_threat: Some(ThreatType::Nsfw),
        onset_step: Some(0),
        detection_threshold: 0.45,
        tracked_threats: vec![ThreatType::Nsfw],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: media_input(
                ContentType::Image,
                "stranger_1",
                "dm",
                Some(verdict(MediaClass::Neutral, 0.3)),
            ),
            observed_threats: vec![ThreatType::Nsfw],
        }],
    }
}

// -- long context ----------------------------------------------------------

fn long_grooming_to_coerced_send_case() -> ScenarioCase {
    let opener: &[(&str, &str)] = &[
        ("hey nice profile pic", "older_user"),
        ("thanks", PROTECTED_TEEN),
        ("u play after school right", "older_user"),
        ("yeah most days", PROTECTED_TEEN),
        ("same, we should squad up", "older_user"),
        ("ok", PROTECTED_TEEN),
        ("ur really easy to talk to", "older_user"),
        ("thx", PROTECTED_TEEN),
        ("i tell u stuff i tell nobody", "older_user"),
        ("same tbh", PROTECTED_TEEN),
        ("ur different from the others", "older_user"),
        ("haha maybe", PROTECTED_TEEN),
        ("promise to keep our chats private?", "older_user"),
        ("i guess", PROTECTED_TEEN),
        ("send me a photo of you", "older_user"),
        ("idk", PROTECTED_TEEN),
        ("come on, this stays our little secret ok", "older_user"),
        ("fine", PROTECTED_TEEN),
        ("something cuter this time", "older_user"),
        ("like what", PROTECTED_TEEN),
        ("you know what i mean, dont be shy", "older_user"),
        ("ok", PROTECTED_TEEN),
    ];
    let mut steps: Vec<ScenarioStep> = opener
        .iter()
        .enumerate()
        .map(|(idx, (body, sender))| ScenarioStep {
            timestamp_ms: (idx as u64) * 90 * SEC,
            input: text_input(body, sender, "long_dm"),
            observed_threats: vec![],
        })
        .collect();
    let send_idx = steps.len();
    steps.push(ScenarioStep {
        timestamp_ms: (send_idx as u64) * 90 * SEC,
        input: media_input(
            ContentType::Image,
            PROTECTED_TEEN,
            "long_dm",
            Some(verdict(MediaClass::Explicit, 0.9)),
        ),
        observed_threats: vec![ThreatType::Nsfw],
    });
    ScenarioCase {
        name: "media_long_ctx_grooming_to_coerced_send".to_string(),
        config: teen_send_side_config(),
        primary_threat: Some(ThreatType::Nsfw),
        onset_step: Some(send_idx),
        detection_threshold: 0.55,
        tracked_threats: vec![ThreatType::Nsfw],
        steps,
    }
}

// -- false positives -------------------------------------------------------

fn fp_confident_neutral_family_photo_case() -> ScenarioCase {
    ScenarioCase {
        name: "media_fp_confident_neutral_family_photo".to_string(),
        config: teen_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.45,
        tracked_threats: vec![ThreatType::Nsfw],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: media_input(
                ContentType::Image,
                "new_teammate",
                "team_chat",
                Some(verdict(MediaClass::Neutral, 0.9)),
            ),
            observed_threats: vec![],
        }],
    }
}

fn fp_voice_message_case() -> ScenarioCase {
    ScenarioCase {
        name: "media_fp_voice_message".to_string(),
        config: child_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.45,
        tracked_threats: vec![ThreatType::Nsfw],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: media_input(ContentType::Voice, "stranger_1", "dm", None),
            observed_threats: vec![],
        }],
    }
}

fn fp_url_only_message_case() -> ScenarioCase {
    ScenarioCase {
        name: "media_fp_url_only_message".to_string(),
        config: child_config(),
        primary_threat: None,
        onset_step: None,
        detection_threshold: 0.45,
        tracked_threats: vec![ThreatType::Nsfw],
        steps: vec![ScenarioStep {
            timestamp_ms: 0,
            input: MessageInput {
                content_type: ContentType::Url,
                text: Some("https://news.example/article".to_string()),
                ..media_input(ContentType::Url, "classmate", "dm", None)
            },
            observed_threats: vec![],
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{run_scenario_case, summarize_scenario_runs};
    use aura_patterns::PatternDatabase;

    fn all_scenarios() -> Vec<ScenarioCase> {
        let mut all = canonical_media_nsfw_scenarios();
        all.extend(adversarial_media_nsfw_scenarios());
        all.extend(long_context_media_nsfw_scenarios());
        all.extend(false_positive_media_nsfw_scenarios());
        all
    }

    #[test]
    fn canonical_has_positive_and_negative() {
        let pack = canonical_media_nsfw_scenarios();
        assert!(pack.iter().any(|c| c.primary_threat.is_some()));
        assert!(pack.iter().any(|c| c.primary_threat.is_none()));
    }

    #[test]
    fn long_context_has_minimum_messages() {
        let pack = long_context_media_nsfw_scenarios();
        let longest = pack.iter().map(|c| c.steps.len()).max().unwrap_or_default();
        assert!(
            longest >= 20,
            "long-context case must hold >=20 turns, got {longest}"
        );
    }

    #[test]
    fn pack_passes_its_quality_gates() {
        let db = PatternDatabase::default_mvp();
        let runs: Vec<_> = all_scenarios()
            .iter()
            .map(|case| run_scenario_case(&db, case))
            .collect();
        let summary = summarize_scenario_runs(&runs, 6);
        let report = crate::evaluate_scenario_quality_gates(&summary, &media_nsfw_quality_gates());
        assert!(
            report.passed,
            "media_nsfw pack must pass its own gates: {report:#?}"
        );
    }
}
