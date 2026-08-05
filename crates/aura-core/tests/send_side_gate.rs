//! End-to-end tests for the P3 send-side (outgoing) explicit-media protection.
//!
//! Asserts §6.3 of `docs/nsfw-media-protection-architecture.md`: an outgoing
//! explicit-media attempt by a minor produces a pause-and-think
//! `WarnBeforeSend` — never punitive — and escalates to a guardian only when
//! the sextortion signature (recent coercive pressure from the conversation
//! partner) is active. Video keyframe inputs ride the same media stage.

use aura_core::config::AuraConfig;
use aura_core::context::events::EventKind;
use aura_core::ids::{ConversationId, SenderId};
use aura_core::types::{
    AccountType, Action, AlertPriority, ClientVisionVerdict, ContentType, ConversationType,
    MediaClass, MediaInfo, MessageInput, ProtectionLevel, RelationshipTrustSource,
    SenderRelationship, ThreatType, UiAction,
};
use aura_core::Analyzer;
use aura_patterns::PatternDatabase;

const MIN: u64 = 60 * 1000;
const PROTECTED: &str = "teen_15";

fn analyzer_for(account_type: AccountType) -> Analyzer {
    let config = AuraConfig {
        account_type,
        protection_level: ProtectionLevel::High,
        language: "en".to_string(),
        protected_account_id: Some(PROTECTED.to_string()),
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

fn explicit_verdict(confidence: f32) -> ClientVisionVerdict {
    ClientVisionVerdict {
        class: MediaClass::Explicit,
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
fn outgoing_explicit_media_warns_before_send_without_guardian_alert() {
    let mut analyzer = analyzer_for(AccountType::Teen);
    let result =
        analyzer.analyze_with_context(&media_msg(PROTECTED, Some(explicit_verdict(0.9))), 1_000);

    assert_eq!(result.threat_type, ThreatType::Nsfw);
    assert_eq!(result.action, Action::Warn);
    assert!(result
        .reason_codes
        .iter()
        .any(|code| code == "media.send_attempt.explicit"));
    let actions = ui_actions(&result);
    assert!(actions.contains(&UiAction::WarnBeforeSend));
    assert!(actions.contains(&UiAction::SlowDownConversation));
    assert!(!actions.contains(&UiAction::EscalateToGuardian));
    // Never punitive without coercion evidence.
    let recommendation = result.recommended_action.as_ref().expect("recommendation");
    assert_eq!(recommendation.parent_alert, AlertPriority::None);
}

#[test]
fn outgoing_explicit_media_under_coercion_escalates_to_guardian() {
    let mut analyzer = analyzer_for(AccountType::Teen);
    // Partner builds the sextortion signature: photo request + secrecy.
    analyzer.analyze_with_context(&text_msg("send me a photo of you", "older_user"), 1_000);
    analyzer.analyze_with_context(
        &text_msg("this stays our little secret ok", "older_user"),
        MIN,
    );

    let result =
        analyzer.analyze_with_context(&media_msg(PROTECTED, Some(explicit_verdict(0.9))), 2 * MIN);

    assert!(result
        .reason_codes
        .iter()
        .any(|code| code == "media.send_attempt.explicit.coerced"));
    let recommendation = result.recommended_action.as_ref().expect("recommendation");
    assert!(recommendation.parent_alert >= AlertPriority::High);
    let actions = ui_actions(&result);
    assert!(actions.contains(&UiAction::WarnBeforeSend));
    assert!(actions.contains(&UiAction::EscalateToGuardian));
    assert!(actions.contains(&UiAction::SuggestBlockContact));
}

#[test]
fn old_pressure_outside_lookback_does_not_mark_coercion() {
    let mut analyzer = analyzer_for(AccountType::Teen);
    analyzer.analyze_with_context(&text_msg("send me a photo of you", "older_user"), 1_000);

    // Three days later: the pressure event is outside the 48h lookback.
    let three_days = 3 * 24 * 3600 * 1000;
    let result = analyzer.analyze_with_context(
        &media_msg(PROTECTED, Some(explicit_verdict(0.9))),
        three_days,
    );

    assert!(result
        .reason_codes
        .iter()
        .any(|code| code == "media.send_attempt.explicit"));
    assert!(!result
        .reason_codes
        .iter()
        .any(|code| code == "media.send_attempt.explicit.coerced"));
}

#[test]
fn outgoing_media_without_verdict_is_untouched() {
    let mut analyzer = analyzer_for(AccountType::Teen);
    let result = analyzer.analyze_with_context(&media_msg(PROTECTED, None), 1_000);

    assert!(!result
        .reason_codes
        .iter()
        .any(|code| code.starts_with("media.")));
}

#[test]
fn outgoing_suggestive_media_is_untouched() {
    let mut analyzer = analyzer_for(AccountType::Teen);
    let result = analyzer.analyze_with_context(
        &media_msg(
            PROTECTED,
            Some(ClientVisionVerdict {
                class: MediaClass::Suggestive,
                confidence: 0.9,
                provider: "apple.sca".to_string(),
            }),
        ),
        1_000,
    );

    assert!(!result
        .reason_codes
        .iter()
        .any(|code| code.starts_with("media.")));
}

#[test]
fn adult_outgoing_explicit_media_is_untouched() {
    let config = AuraConfig {
        account_type: AccountType::Adult,
        protection_level: ProtectionLevel::High,
        language: "en".to_string(),
        protected_account_id: Some("adult_1".to_string()),
        ..AuraConfig::default()
    };
    let mut analyzer = Analyzer::new(config, &PatternDatabase::default_mvp());

    let result =
        analyzer.analyze_with_context(&media_msg("adult_1", Some(explicit_verdict(0.9))), 1_000);

    assert!(!result
        .reason_codes
        .iter()
        .any(|code| code.starts_with("media.")));
}

#[test]
fn send_attempt_event_lands_in_conversation_timeline() {
    let mut analyzer = analyzer_for(AccountType::Teen);
    analyzer.analyze_with_context(&media_msg(PROTECTED, Some(explicit_verdict(0.9))), 1_000);

    let state = analyzer.export_context_state();
    let recorded = state.timelines.iter().any(|timeline| {
        timeline
            .events
            .iter()
            .any(|event| event.kind == EventKind::ExplicitMediaSendAttempt)
    });
    assert!(
        recorded,
        "ExplicitMediaSendAttempt must be recorded in the conversation timeline"
    );
}

#[test]
fn video_keyframe_with_explicit_verdict_is_flagged_like_image() {
    let mut analyzer = analyzer_for(AccountType::Teen);
    let mut input = media_msg("stranger_1", Some(explicit_verdict(0.9)));
    input.content_type = ContentType::Video;
    input.media_info = Some(MediaInfo {
        width: 512,
        height: 288,
        mime_type: "video/mp4".to_string(),
        original_size_bytes: 4_000_000,
        keyframe_index: 2,
        keyframe_count: 8,
    });

    let result = analyzer.analyze_with_context(&input, 1_000);

    assert_eq!(result.threat_type, ThreatType::Nsfw);
    assert!(result.action >= Action::Warn);
    assert!(result
        .reason_codes
        .iter()
        .any(|code| code == "media.vision.explicit"));
}
