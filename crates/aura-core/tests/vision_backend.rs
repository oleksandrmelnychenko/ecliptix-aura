//! Fallback-chain tests for the on-device vision backend wiring (P2b).
//!
//! Without a loadable `nsfw_image.onnx`, the analyzer must stay on the
//! abstaining Noop backend: no Image modality in runtime capabilities, and
//! media with undecodable bytes still fails closed into the trust gate.
#![cfg(feature = "onnx")]

use aura_core::config::AuraConfig;
use aura_core::ids::{ConversationId, SenderId};
use aura_core::runtime_capabilities::RuntimeModality;
use aura_core::types::{
    AccountType, Action, ContentType, ConversationType, MessageInput, ProtectionLevel,
    RelationshipTrustSource, SenderRelationship,
};
use aura_core::Analyzer;
use aura_patterns::PatternDatabase;

fn analyzer_with_models_path(models_path: Option<String>) -> Analyzer {
    let config = AuraConfig {
        account_type: AccountType::Child,
        protection_level: ProtectionLevel::High,
        language: "en".to_string(),
        models_path,
        ..AuraConfig::default()
    };
    Analyzer::new(config, &PatternDatabase::default_mvp())
}

fn image_msg(bytes: Option<Vec<u8>>) -> MessageInput {
    MessageInput {
        content_type: ContentType::Image,
        text: None,
        image_data: bytes,
        media_info: None,
        client_vision_verdict: None,
        sender_id: SenderId::from("stranger_1"),
        conversation_id: ConversationId::from("dm"),
        language: None,
        conversation_type: ConversationType::Direct,
        member_count: None,
        sender_relationship: SenderRelationship::Unknown,
        relationship_trust_source: RelationshipTrustSource::Unknown,
    }
}

#[test]
fn missing_model_keeps_noop_backend_and_text_url_modalities() {
    let dir = std::env::temp_dir().join("aura_vision_backend_missing_model");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let mut analyzer = analyzer_with_models_path(Some(dir.to_string_lossy().into_owned()));

    let capabilities = analyzer.runtime_capabilities();
    assert!(!capabilities
        .supported_modalities
        .contains(&RuntimeModality::Image));
    assert!(!capabilities
        .models
        .iter()
        .any(|model| model.component == "vision.nsfw_image"));

    // Media with bytes but no usable classifier still fails closed.
    let result = analyzer.analyze_with_context(&image_msg(Some(vec![0xde, 0xad])), 1_000);
    assert_eq!(result.action, Action::Blur);
    assert!(result
        .reason_codes
        .iter()
        .any(|code| code == "media.trust_gate.unverified_incoming"));
}

#[test]
fn unloadable_model_file_falls_back_to_noop() {
    // Touching ort::Session requires the ONNX Runtime dynamic library
    // (load-dynamic); environments without it (plain CI) must skip, same
    // convention as aura-ml's onnx_integration tests.
    let enabled = std::env::var("AURA_RUN_VISION_ONNX")
        .map(|value| value == "1")
        .unwrap_or(false);
    if !enabled {
        eprintln!(
            "skipping unloadable_model_file_falls_back_to_noop: set AURA_RUN_VISION_ONNX=1 \
             (requires the ONNX Runtime dylib)"
        );
        return;
    }

    let dir = std::env::temp_dir().join("aura_vision_backend_bad_model");
    std::fs::create_dir_all(&dir).expect("temp dir");
    std::fs::write(dir.join("nsfw_image.onnx"), b"garbage, not a model").expect("write");

    let mut analyzer = analyzer_with_models_path(Some(dir.to_string_lossy().into_owned()));

    let capabilities = analyzer.runtime_capabilities();
    assert!(!capabilities
        .supported_modalities
        .contains(&RuntimeModality::Image));

    let result = analyzer.analyze_with_context(&image_msg(None), 1_000);
    assert_eq!(result.action, Action::Blur);
}

#[test]
fn no_models_path_stays_on_noop_backend() {
    let analyzer = analyzer_with_models_path(None);
    let capabilities = analyzer.runtime_capabilities();
    assert!(!capabilities
        .supported_modalities
        .contains(&RuntimeModality::Image));
}
