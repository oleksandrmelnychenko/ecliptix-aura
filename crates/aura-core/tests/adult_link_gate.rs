//! End-to-end tests for the P1 adult-link category.
//!
//! Asserts the link layer from `docs/nsfw-media-protection-architecture.md`
//! §9: adult-content URLs toward minor profiles produce an NSFW link signal,
//! a `ConfirmBeforeOpenLink` UI action, and an `AdultLinkShared` context
//! event, while adult accounts and benign look-alike hosts stay untouched.

use aura_core::config::AuraConfig;
use aura_core::ids::{ConversationId, SenderId};
use aura_core::types::{
    AccountType, Action, ContentType, ConversationType, MessageInput, ProtectionLevel,
    RelationshipTrustSource, SenderRelationship, SignalFamily, ThreatType, UiAction,
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

fn text_msg(text: &str, sender: &str, conversation: &str) -> MessageInput {
    MessageInput {
        content_type: ContentType::Text,
        text: Some(text.to_string()),
        image_data: None,
        sender_id: SenderId::from(sender),
        conversation_id: ConversationId::from(conversation),
        language: None,
        conversation_type: ConversationType::Direct,
        member_count: None,
        sender_relationship: SenderRelationship::Unknown,
        relationship_trust_source: RelationshipTrustSource::Unknown,
    }
}

#[test]
fn adult_tld_link_to_child_confirms_before_open() {
    let mut analyzer = analyzer_for(AccountType::Child);
    let result = analyzer.analyze_with_context(
        &text_msg("look at this https://teens.xxx/free", "stranger_1", "dm"),
        1_000,
    );

    assert_eq!(result.threat_type, ThreatType::Nsfw);
    assert!(result.action >= Action::Warn);
    assert!(result
        .reason_codes
        .iter()
        .any(|code| code == "link.adult_content"));
    let actions = &result
        .recommended_action
        .as_ref()
        .expect("recommendation")
        .ui_actions;
    assert!(actions.contains(&UiAction::ConfirmBeforeOpenLink));
    assert!(result.signals.iter().any(
        |signal| signal.family == SignalFamily::Link && signal.threat_type == ThreatType::Nsfw
    ));
}

#[test]
fn adult_host_keyword_link_to_teen_is_flagged() {
    let mut analyzer = analyzer_for(AccountType::Teen);
    let result = analyzer.analyze_with_context(
        &text_msg(
            "нове відео тут http://порно.example/добірка",
            "spammer_1",
            "group",
        ),
        1_000,
    );

    // The ML text layer may outrank the link signal as the primary threat
    // (e.g. Explicit for the same message); the link category must still be
    // present in the detected set and reason codes.
    assert!(result
        .detected_threats
        .iter()
        .any(|(threat, _)| *threat == ThreatType::Nsfw));
    assert!(result
        .reason_codes
        .iter()
        .any(|code| code == "link.adult_content"));
}

#[test]
fn adult_account_links_are_untouched() {
    let mut analyzer = analyzer_for(AccountType::Adult);
    let result = analyzer.analyze_with_context(
        &text_msg("look at this https://teens.xxx/free", "friend_1", "dm"),
        1_000,
    );

    assert!(!result
        .reason_codes
        .iter()
        .any(|code| code == "link.adult_content"));
}

#[test]
fn benign_lookalike_links_to_child_stay_clean() {
    let mut analyzer = analyzer_for(AccountType::Child);
    for text in [
        "homework portal https://essex.gov.uk/schools",
        "recipe https://nudeln.de/spaghetti",
        "campus map sussex.ac.uk/map",
    ] {
        let result = analyzer.analyze_with_context(&text_msg(text, "teacher_1", "class"), 1_000);
        assert!(
            !result
                .reason_codes
                .iter()
                .any(|code| code == "link.adult_content"),
            "false positive for {text}"
        );
    }
}

#[test]
fn repeated_adult_links_degrade_contact_rating() {
    let mut analyzer = analyzer_for(AccountType::Teen);
    // Baseline: a sender with the same volume of benign messages.
    let mut ts = 1_000;
    for _ in 0..3 {
        analyzer.analyze_with_context(&text_msg("see you at practice", "friend_1", "group"), ts);
        ts += 60_000;
    }
    for _ in 0..3 {
        analyzer.analyze_with_context(
            &text_msg("fresh drop https://teens.xxx/new", "spammer_1", "group"),
            ts,
        );
        ts += 60_000;
    }

    let profiler = analyzer.context_tracker().contact_profiler();
    let benign = profiler
        .snapshot(&SenderId::from("friend_1"))
        .expect("benign contact profile exists");
    let spammer = profiler
        .snapshot(&SenderId::from("spammer_1"))
        .expect("spammer contact profile exists");
    assert!(
        spammer.rating < benign.rating,
        "AdultLinkShared must degrade contact rating: spammer {} vs benign {}",
        spammer.rating,
        benign.rating
    );
}
