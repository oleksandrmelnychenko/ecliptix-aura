//! End-to-end tests for the P2 verdict-driven media stage.
//!
//! Asserts §5–§7 of `docs/nsfw-media-protection-architecture.md`: validated
//! platform verdicts (e.g. Apple SensitiveContentAnalysis) drive the policy —
//! confirmed explicit media escalates for minors even from trusted contacts,
//! suggestive media blurs for minors only, a confident Neutral verdict
//! releases the trust gate, and unusable verdicts fail closed into it.

use aura_core::config::AuraConfig;
use aura_core::ids::{ConversationId, SenderId};
use aura_core::types::{
    AccountType, Action, AlertPriority, ClientVisionVerdict, ContentType, ConversationType,
    MediaClass, MessageInput, ProtectionLevel, RelationshipTrustSource, SenderRelationship,
    ThreatType, UiAction,
};
use aura_core::Analyzer;
use aura_patterns::PatternDatabase;

fn analyzer_for(account_type: AccountType) -> Analyzer {
    let config = AuraConfig {
        account_type,
        protection_level: ProtectionLevel::High,
        language: "en".to_string(),
        ..AuraConfig::default()
    };
    Analyzer::new(config, &PatternDatabase::default_mvp())
}

fn media_msg(sender: &str, verdict: Option<ClientVisionVerdict>) -> MessageInput {
    MessageInput {
        content_type: ContentType::Image,
        text: None,
        image_data: None,
        media_info: None,
        client_vision_verdict: verdict,
        sender_id: SenderId::from(sender),
        conversation_id: ConversationId::from("dm"),
        language: None,
        conversation_type: ConversationType::Direct,
        member_count: None,
        sender_relationship: SenderRelationship::Unknown,
        relationship_trust_source: RelationshipTrustSource::Unknown,
    }
}

fn text_msg(text: &str, sender: &str) -> MessageInput {
    MessageInput {
        content_type: ContentType::Text,
        text: Some(text.to_string()),
        ..media_msg(sender, None)
    }
}

fn verdict(class: MediaClass, confidence: f32) -> ClientVisionVerdict {
    ClientVisionVerdict {
        class,
        confidence,
        provider: "apple.sca".to_string(),
    }
}

fn ui_actions(result: &aura_core::types::AnalysisResult) -> Vec<UiAction> {
    result
        .recommended_action
        .as_ref()
        .map(|recommendation| recommendation.ui_actions.clone())
        .unwrap_or_default()
}

#[test]
fn confirmed_explicit_media_to_child_blocks_and_escalates() {
    let mut analyzer = analyzer_for(AccountType::Child);
    let result = analyzer.analyze_with_context(
        &media_msg("stranger_1", Some(verdict(MediaClass::Explicit, 0.9))),
        1_000,
    );

    assert_eq!(result.threat_type, ThreatType::Nsfw);
    assert_eq!(result.action, Action::Block);
    assert!(result
        .reason_codes
        .iter()
        .any(|code| code == "media.vision.explicit"));
    let recommendation = result.recommended_action.as_ref().expect("recommendation");
    assert!(recommendation.parent_alert >= AlertPriority::High);
    let actions = ui_actions(&result);
    assert!(actions.contains(&UiAction::BlurUntilTap));
    assert!(actions.contains(&UiAction::SuggestBlockContact));
    assert!(actions.contains(&UiAction::SuggestReport));
    assert!(actions.contains(&UiAction::EscalateToGuardian));
}

#[test]
fn confirmed_explicit_media_flags_even_trusted_contact_for_minor() {
    let mut analyzer = analyzer_for(AccountType::Teen);
    analyzer.mark_contact_trusted("close_friend");
    analyzer.analyze_with_context(&text_msg("hi!", "close_friend"), 1_000);

    let result = analyzer.analyze_with_context(
        &media_msg("close_friend", Some(verdict(MediaClass::Explicit, 0.8))),
        60_000,
    );

    // Trust bypasses the unverified gate, never a confirmed-explicit verdict.
    assert_eq!(result.threat_type, ThreatType::Nsfw);
    assert!(result.action >= Action::Warn);
    assert!(result
        .reason_codes
        .iter()
        .any(|code| code == "media.vision.explicit"));
}

#[test]
fn suggestive_media_to_teen_is_blurred() {
    let mut analyzer = analyzer_for(AccountType::Teen);
    let result = analyzer.analyze_with_context(
        &media_msg("stranger_1", Some(verdict(MediaClass::Suggestive, 0.7))),
        1_000,
    );

    assert_eq!(result.action, Action::Blur);
    assert!(result
        .reason_codes
        .iter()
        .any(|code| code == "media.vision.suggestive"));
    // Suggestive alone never alerts a guardian.
    let recommendation = result.recommended_action.as_ref().expect("recommendation");
    assert_eq!(recommendation.parent_alert, AlertPriority::None);
}

#[test]
fn drawing_media_to_child_blurs_without_guardian_alert() {
    let mut analyzer = analyzer_for(AccountType::Child);
    let result = analyzer.analyze_with_context(
        &media_msg("stranger_1", Some(verdict(MediaClass::Drawing, 0.9))),
        1_000,
    );

    assert!(result.action >= Action::Blur);
    assert!(result
        .reason_codes
        .iter()
        .any(|code| code == "media.vision.drawing"));
    let recommendation = result.recommended_action.as_ref().expect("recommendation");
    assert_eq!(recommendation.parent_alert, AlertPriority::None);
}

#[test]
fn confident_neutral_verdict_releases_the_trust_gate() {
    let mut analyzer = analyzer_for(AccountType::Child);
    let result = analyzer.analyze_with_context(
        &media_msg("stranger_1", Some(verdict(MediaClass::Neutral, 0.95))),
        1_000,
    );

    assert_eq!(result.action, Action::Allow);
    assert!(!result
        .reason_codes
        .iter()
        .any(|code| code.starts_with("media.")));
}

#[test]
fn low_confidence_neutral_verdict_falls_back_to_trust_gate() {
    let mut analyzer = analyzer_for(AccountType::Child);
    let result = analyzer.analyze_with_context(
        &media_msg("stranger_1", Some(verdict(MediaClass::Neutral, 0.3))),
        1_000,
    );

    assert_eq!(result.action, Action::Blur);
    assert!(result
        .reason_codes
        .iter()
        .any(|code| code == "media.trust_gate.unverified_incoming"));
}

#[test]
fn invalid_verdict_confidence_fails_closed_to_trust_gate() {
    for confidence in [-0.5, 1.5, f32::NAN] {
        // Fresh analyzer per case: replaying identical inputs on one runtime
        // accumulates timing/repeat context that would outrank the gate.
        let mut analyzer = analyzer_for(AccountType::Child);
        let result = analyzer.analyze_with_context(
            &media_msg(
                "stranger_1",
                Some(verdict(MediaClass::Explicit, confidence)),
            ),
            1_000,
        );
        assert_eq!(
            result.action,
            Action::Blur,
            "invalid confidence {confidence} must fail closed into the gate"
        );
        assert!(result
            .reason_codes
            .iter()
            .any(|code| code == "media.trust_gate.unverified_incoming"));
    }
}

#[test]
fn explicit_media_to_adult_from_stranger_blurs_only() {
    let mut analyzer = analyzer_for(AccountType::Adult);
    let result = analyzer.analyze_with_context(
        &media_msg("stranger_1", Some(verdict(MediaClass::Explicit, 0.9))),
        1_000,
    );

    // Cyberflashing posture: blur, no block, no guardian machinery.
    assert_eq!(result.action, Action::Blur);
    let recommendation = result.recommended_action.as_ref().expect("recommendation");
    assert_eq!(recommendation.parent_alert, AlertPriority::None);
}

#[test]
fn explicit_media_between_established_adults_is_untouched() {
    let mut analyzer = analyzer_for(AccountType::Adult);
    analyzer.mark_contact_trusted("partner");
    analyzer.analyze_with_context(&text_msg("good evening", "partner"), 1_000);

    let result = analyzer.analyze_with_context(
        &media_msg("partner", Some(verdict(MediaClass::Explicit, 0.9))),
        60_000,
    );

    assert_eq!(result.action, Action::Allow);
    assert!(!result
        .reason_codes
        .iter()
        .any(|code| code.starts_with("media.")));
}

#[test]
fn suggestive_media_to_adult_is_untouched() {
    let mut analyzer = analyzer_for(AccountType::Adult);
    let result = analyzer.analyze_with_context(
        &media_msg("stranger_1", Some(verdict(MediaClass::Suggestive, 0.9))),
        1_000,
    );

    assert_eq!(result.action, Action::Allow);
}

#[test]
fn explicit_media_event_degrades_sender_contact_rating() {
    let mut analyzer = analyzer_for(AccountType::Teen);
    let mut ts = 1_000;
    for _ in 0..3 {
        analyzer.analyze_with_context(&text_msg("see you at practice", "friend_1"), ts);
        ts += 60_000;
    }
    for _ in 0..3 {
        analyzer.analyze_with_context(
            &media_msg("flasher_1", Some(verdict(MediaClass::Explicit, 0.9))),
            ts,
        );
        ts += 60_000;
    }

    let profiler = analyzer.context_tracker().contact_profiler();
    let benign = profiler
        .snapshot(&SenderId::from("friend_1"))
        .expect("benign profile");
    let flasher = profiler
        .snapshot(&SenderId::from("flasher_1"))
        .expect("flasher profile");
    assert!(
        flasher.rating < benign.rating,
        "ExplicitMediaReceived must degrade rating: flasher {} vs benign {}",
        flasher.rating,
        benign.rating
    );
}
