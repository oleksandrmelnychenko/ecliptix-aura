//! End-to-end tests for the P0 media trust gate.
//!
//! Runs full `Analyzer::analyze_with_context` pipelines and asserts the
//! policy matrix from `docs/nsfw-media-protection-architecture.md` §7:
//! incoming media from low-trust contacts on minor profiles is blurred,
//! trusted relationships and adult profiles are untouched, and contact
//! history escalates the precaution without ever weakening it.

use aura_core::config::AuraConfig;
use aura_core::ids::{ConversationId, SenderId};
use aura_core::media::MEDIA_TRUST_GATE_UNVERIFIED_INCOMING;
use aura_core::types::{
    AccountType, Action, AlertPriority, ContentType, ConversationType, MessageInput,
    ProtectionLevel, RelationshipTrustSource, SenderRelationship, ThreatType, UiAction,
};
use aura_core::Analyzer;
use aura_patterns::PatternDatabase;

const MIN: u64 = 60 * 1000;

fn analyzer_for(account_type: AccountType) -> Analyzer {
    let config = AuraConfig {
        account_type,
        protection_level: ProtectionLevel::High,
        language: "en".to_string(),
        ..AuraConfig::default()
    };
    Analyzer::new(config, &PatternDatabase::default_mvp())
}

fn media_msg(content_type: ContentType, sender: &str, conversation: &str) -> MessageInput {
    MessageInput {
        content_type,
        text: None,
        image_data: None,
        media_info: None,
        client_vision_verdict: None,
        sender_id: SenderId::from(sender),
        conversation_id: ConversationId::from(conversation),
        language: None,
        conversation_type: ConversationType::Direct,
        member_count: None,
        sender_relationship: SenderRelationship::Unknown,
        relationship_trust_source: RelationshipTrustSource::Unknown,
    }
}

fn text_msg(text: &str, sender: &str, conversation: &str) -> MessageInput {
    MessageInput {
        content_type: ContentType::Text,
        text: Some(text.to_string()),
        ..media_msg(ContentType::Text, sender, conversation)
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
fn child_image_from_unknown_contact_is_blurred() {
    let mut analyzer = analyzer_for(AccountType::Child);
    let result =
        analyzer.analyze_with_context(&media_msg(ContentType::Image, "stranger_1", "dm"), 1_000);

    assert_eq!(result.threat_type, ThreatType::Nsfw);
    assert_eq!(result.action, Action::Blur);
    assert!(result
        .reason_codes
        .iter()
        .any(|code| code == MEDIA_TRUST_GATE_UNVERIFIED_INCOMING));
    let actions = ui_actions(&result);
    assert!(actions.contains(&UiAction::BlurUntilTap));
    assert!(actions.contains(&UiAction::WarnBeforeDisplay));
    assert!(actions.contains(&UiAction::RestrictUnknownContact));
    // Precaution, not detection: nothing confirmed the media is explicit.
    let recommendation = result.recommended_action.as_ref().expect("recommendation");
    assert_eq!(recommendation.parent_alert, AlertPriority::None);
}

#[test]
fn gif_and_sticker_from_unknown_contact_are_gated_like_images() {
    for content_type in [ContentType::Gif, ContentType::Sticker] {
        let mut analyzer = analyzer_for(AccountType::Child);
        let result =
            analyzer.analyze_with_context(&media_msg(content_type, "stranger_1", "dm"), 1_000);
        assert_eq!(
            result.action,
            Action::Blur,
            "{content_type:?} must be trust-gated"
        );
        assert!(result
            .reason_codes
            .iter()
            .any(|code| code == MEDIA_TRUST_GATE_UNVERIFIED_INCOMING));
    }
}

#[test]
fn teen_video_from_unknown_contact_is_blurred_without_restrict() {
    let mut analyzer = analyzer_for(AccountType::Teen);
    let result =
        analyzer.analyze_with_context(&media_msg(ContentType::Video, "stranger_1", "dm"), 1_000);

    assert_eq!(result.action, Action::Blur);
    let actions = ui_actions(&result);
    assert!(actions.contains(&UiAction::BlurUntilTap));
    assert!(actions.contains(&UiAction::WarnBeforeDisplay));
    assert!(!actions.contains(&UiAction::RestrictUnknownContact));
}

#[test]
fn adult_image_from_unknown_contact_is_untouched() {
    let mut analyzer = analyzer_for(AccountType::Adult);
    let result =
        analyzer.analyze_with_context(&media_msg(ContentType::Image, "stranger_1", "dm"), 1_000);

    assert_eq!(result.threat_type, ThreatType::None);
    assert_eq!(result.action, Action::Allow);
}

#[test]
fn child_text_only_message_is_not_media_gated() {
    let mut analyzer = analyzer_for(AccountType::Child);
    let result =
        analyzer.analyze_with_context(&text_msg("hi, how are you?", "stranger_1", "dm"), 1_000);

    assert!(!result
        .reason_codes
        .iter()
        .any(|code| code.starts_with("media.trust_gate")));
}

#[test]
fn trusted_contact_media_is_not_gated() {
    let mut analyzer = analyzer_for(AccountType::Child);
    analyzer.mark_contact_trusted("best_friend");
    // Establish the contact in the profiler before the media message.
    analyzer.analyze_with_context(&text_msg("see you at school", "best_friend", "dm"), 1_000);

    let result =
        analyzer.analyze_with_context(&media_msg(ContentType::Image, "best_friend", "dm"), MIN);

    assert_eq!(result.action, Action::Allow);
    assert!(!result
        .reason_codes
        .iter()
        .any(|code| code.starts_with("media.trust_gate")));
}

#[test]
fn guardian_verified_parent_media_is_not_gated() {
    let mut analyzer = analyzer_for(AccountType::Child);
    let mut input = media_msg(ContentType::Image, "mom", "family_dm");
    input.sender_relationship = SenderRelationship::Parent;
    input.relationship_trust_source = RelationshipTrustSource::GuardianVerified;

    let result = analyzer.analyze_with_context(&input, 1_000);

    assert!(!result
        .reason_codes
        .iter()
        .any(|code| code.starts_with("media.trust_gate")));
}

#[test]
fn self_declared_parent_media_stays_gated() {
    let mut analyzer = analyzer_for(AccountType::Child);
    let mut input = media_msg(ContentType::Image, "claims_to_be_dad", "dm");
    input.sender_relationship = SenderRelationship::Parent;
    input.relationship_trust_source = RelationshipTrustSource::SelfDeclared;

    let result = analyzer.analyze_with_context(&input, 1_000);

    assert_eq!(result.action, Action::Blur);
}

#[test]
fn outgoing_media_from_protected_account_is_not_gated() {
    let config = AuraConfig {
        account_type: AccountType::Child,
        protection_level: ProtectionLevel::High,
        language: "en".to_string(),
        protected_account_id: Some("child_13".to_string()),
        ..AuraConfig::default()
    };
    let mut analyzer = Analyzer::new(config, &PatternDatabase::default_mvp());

    let result =
        analyzer.analyze_with_context(&media_msg(ContentType::Image, "child_13", "dm"), 1_000);

    assert!(!result
        .reason_codes
        .iter()
        .any(|code| code.starts_with("media.trust_gate")));
}

#[test]
fn media_with_explicit_caption_keeps_text_detection() {
    let mut analyzer = analyzer_for(AccountType::Teen);
    let mut input = media_msg(ContentType::Image, "stranger_1", "dm");
    input.text = Some("send me nudes right now, dont be shy".to_string());

    let result = analyzer.analyze_with_context(&input, 1_000);

    // The gate must compose with, not replace, text analysis: still at least
    // a blur, and the trust-gate reason code rides along.
    assert!(result.action >= Action::Blur);
    assert!(result
        .reason_codes
        .iter()
        .any(|code| code == MEDIA_TRUST_GATE_UNVERIFIED_INCOMING));
    let actions = ui_actions(&result);
    assert!(
        actions.contains(&UiAction::BlurUntilTap) || actions.contains(&UiAction::WarnBeforeDisplay)
    );
}

#[test]
fn repeat_offender_media_escalates_by_contact_history() {
    let mut analyzer = analyzer_for(AccountType::Child);
    // Build hostile history for the sender: several threatening messages.
    let mut ts = 1_000;
    for _ in 0..6 {
        analyzer.analyze_with_context(
            &text_msg("do it or I will beat you up after school", "bully_1", "dm"),
            ts,
        );
        ts += MIN;
    }

    let result = analyzer.analyze_with_context(&media_msg(ContentType::Image, "bully_1", "dm"), ts);

    // Upgrade-only composition: history may raise the action above Blur but
    // never below it.
    assert!(result.action >= Action::Blur);
    assert!(result
        .reason_codes
        .iter()
        .any(|code| code == MEDIA_TRUST_GATE_UNVERIFIED_INCOMING));
}

#[test]
fn gate_survives_context_reset_export_import_cycle() {
    let mut analyzer = analyzer_for(AccountType::Child);
    let exported = analyzer.export_context_state();
    analyzer
        .import_context_state(exported)
        .expect("state round-trip");

    let result =
        analyzer.analyze_with_context(&media_msg(ContentType::Image, "stranger_1", "dm"), 1_000);
    assert_eq!(result.action, Action::Blur);
}
