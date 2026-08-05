//! Media stage: trust-gated blur (P0) and verdict-driven classification (P2).
//!
//! From `docs/nsfw-media-protection-architecture.md`: incoming image and
//! video messages flow through a two-tier decision. When a validated
//! classification verdict exists (today: platform-native classifiers via
//! `ClientVisionVerdict`, e.g. Apple SensitiveContentAnalysis), the verdict
//! drives the signal — explicit media is flagged for every profile with
//! trust-aware severity, suggestive media only for minors. Without a usable
//! verdict, the deterministic relationship trust gate blurs unverified media
//! from low-trust contacts on minor profiles — the fail-closed path. Media
//! bytes are never inspected here and never persisted.

use aura_vision::{accept_client_verdict, MediaClass, MediaVerdict, VerdictSource, VisionBackend};

use crate::context::events::EventKind;
use crate::types::{
    AccountType, CircleTier, Confidence, ContactSnapshot, ContentType, DetectionSignal,
    MessageInput, RelationshipTrustSource, SenderRelationship, ThreatType,
};

/// Reason-code prefix shared by every media trust-gate signal. The policy
/// layer routes on this prefix to keep the gate's action precautionary
/// (blur, no guardian alert) instead of treating it as confirmed NSFW.
pub const MEDIA_TRUST_GATE_REASON_PREFIX: &str = "media.trust_gate";

/// Reason code for the P0 incoming-media gate.
pub const MEDIA_TRUST_GATE_UNVERIFIED_INCOMING: &str = "media.trust_gate.unverified_incoming";

/// Reason code for classifier-confirmed explicit media.
pub const MEDIA_VISION_EXPLICIT: &str = "media.vision.explicit";

/// Reason code for classifier-confirmed suggestive media.
pub const MEDIA_VISION_SUGGESTIVE: &str = "media.vision.suggestive";

/// Reason code for classifier-confirmed drawn/animated sexual content.
pub const MEDIA_VISION_DRAWING: &str = "media.vision.drawing";

/// Reason-code prefix for send-side (outgoing) explicit-media protection.
pub const MEDIA_SEND_ATTEMPT_PREFIX: &str = "media.send_attempt";

/// Reason code for an outgoing explicit-media attempt by a minor.
pub const MEDIA_SEND_ATTEMPT_EXPLICIT: &str = "media.send_attempt.explicit";

/// Reason code for an outgoing explicit-media attempt under recent coercive
/// pressure from the conversation partner (the sextortion signature).
pub const MEDIA_SEND_ATTEMPT_EXPLICIT_COERCED: &str = "media.send_attempt.explicit.coerced";

/// Minimum confidence for a Neutral verdict to release the trust gate.
const NEUTRAL_RELEASE_CONFIDENCE: f32 = 0.7;

/// Output of the media stage: a detection signal, optionally paired with a
/// context event for the conversation timeline and contact profile.
pub(crate) struct MediaStageOutput {
    pub signal: DetectionSignal,
    pub event: Option<MediaStageEvent>,
}

pub(crate) struct MediaStageEvent {
    pub kind: EventKind,
    pub confidence: f32,
    pub subtype: Option<String>,
}

fn is_guardian_managed_sender(input: &MessageInput) -> bool {
    // Self-declared relationship data is not trust; only guardian- or
    // platform-verified parent/guardian senders bypass the gate. Verified
    // teachers, coaches, and family stay gated — those roles appear in
    // grooming case history too often to exempt.
    let verified_source = matches!(
        input.relationship_trust_source,
        RelationshipTrustSource::GuardianVerified | RelationshipTrustSource::PlatformVerified
    );
    verified_source
        && matches!(
            input.sender_relationship,
            SenderRelationship::Parent | SenderRelationship::Guardian
        )
}

fn is_historically_trusted(snapshot: Option<&ContactSnapshot>) -> bool {
    let circle_tier = snapshot.map_or(CircleTier::New, |s| s.circle_tier);
    snapshot.is_some_and(|s| s.is_trusted)
        || matches!(circle_tier, CircleTier::Inner | CircleTier::Regular)
}

/// Runs the media stage for one message: verdict-driven classification when a
/// validated verdict exists, the relationship trust gate otherwise.
///
/// Incoming media (verdict path, any profile): explicit media is flagged
/// with trust-aware severity — a guardian-verified sender does NOT bypass a
/// confirmed-explicit verdict, only the unverified gate. Suggestive/drawn
/// content is flagged for minor profiles only. A confident Neutral verdict
/// releases the trust gate.
///
/// Incoming media (trust-gate path, minor profiles only): unverified media
/// from a low-trust contact is blurred; absent history counts as `New` —
/// fail closed.
///
/// Outgoing media (the protected account is the sender, minor profiles
/// only): a confirmed-explicit verdict produces a pause-and-think
/// `WarnBeforeSend` signal — never punitive — and escalates to a guardian
/// only when `coercion_pressure` marks the sextortion signature (recent
/// photo/secrecy/sexual pressure from the conversation partner).
pub(crate) fn media_stage_output(
    input: &MessageInput,
    account_type: AccountType,
    protected_account_id: Option<&str>,
    snapshot: Option<&ContactSnapshot>,
    coercion_pressure: bool,
    vision_backend: &dyn VisionBackend,
) -> Option<MediaStageOutput> {
    match input.content_type {
        ContentType::Image | ContentType::Video => {}
        ContentType::Text | ContentType::Voice | ContentType::Url => return None,
    }
    if protected_account_id == Some(&*input.sender_id) {
        return send_attempt_output(input, account_type, coercion_pressure, vision_backend);
    }

    let trusted = is_historically_trusted(snapshot);

    if let Some(verdict) = resolve_media_verdict(input, vision_backend) {
        match verdict.class {
            MediaClass::Explicit => {
                return explicit_media_output(input, account_type, trusted, &verdict);
            }
            MediaClass::Suggestive | MediaClass::Drawing => {
                return suggestive_media_output(input, account_type, trusted, &verdict);
            }
            MediaClass::Neutral => {
                if verdict.confidence >= NEUTRAL_RELEASE_CONFIDENCE {
                    return None;
                }
                // Low-confidence Neutral: fall through to the trust gate.
            }
            MediaClass::Unclear => {}
        }
    }

    trust_gate_output(input, account_type, snapshot, trusted)
}

/// Resolves the best available media verdict for this message.
///
/// A validated, non-abstaining client verdict (platform-native classifier)
/// takes priority; otherwise the on-device backend classifies the supplied
/// thumbnail bytes. Backend errors and abstentions resolve to `None` so
/// policy fails closed into the trust gate.
fn resolve_media_verdict(
    input: &MessageInput,
    vision_backend: &dyn VisionBackend,
) -> Option<MediaVerdict> {
    if let Some(client) = input
        .client_vision_verdict
        .as_ref()
        .and_then(accept_client_verdict)
    {
        if !client.abstained {
            return Some(client);
        }
    }
    if let Some(bytes) = input.image_data.as_deref() {
        if let Ok(verdict) = vision_backend.classify(bytes) {
            if !verdict.abstained {
                return Some(verdict);
            }
        }
    }
    None
}

fn send_attempt_output(
    input: &MessageInput,
    account_type: AccountType,
    coercion_pressure: bool,
    vision_backend: &dyn VisionBackend,
) -> Option<MediaStageOutput> {
    // Adults' outgoing media is their business.
    match account_type {
        AccountType::Child | AccountType::Teen => {}
        AccountType::Adult => return None,
    }
    // Send-side protection needs a confirmed verdict; without one there is
    // nothing to warn about, and suggestive content alone must not generate
    // warnings for a minor's own messages.
    let verdict = resolve_media_verdict(input, vision_backend)?;
    if verdict.class != MediaClass::Explicit {
        return None;
    }

    let (reason_code, score) = if coercion_pressure {
        (MEDIA_SEND_ATTEMPT_EXPLICIT_COERCED, 0.85)
    } else {
        (MEDIA_SEND_ATTEMPT_EXPLICIT, 0.65)
    };
    let signal = DetectionSignal::pattern(
        ThreatType::Nsfw,
        score,
        Confidence::High,
        reason_code,
        "Outgoing explicit media detected before send",
    )
    .with_threat_subtype(verdict_subtype(&verdict));
    Some(MediaStageOutput {
        signal,
        event: Some(MediaStageEvent {
            kind: EventKind::ExplicitMediaSendAttempt,
            confidence: verdict.confidence,
            subtype: Some(verdict_source_label(input, &verdict)),
        }),
    })
}

/// Stable signal subtype naming the verdict source.
fn verdict_subtype(verdict: &MediaVerdict) -> &'static str {
    match verdict.source {
        VerdictSource::ClientPlatform => "client_platform",
        VerdictSource::OnDeviceModel => "on_device_model",
        VerdictSource::PolicyOnly => "policy_only",
    }
}

/// Event subtype identifying who produced the verdict.
fn verdict_source_label(input: &MessageInput, verdict: &MediaVerdict) -> String {
    // Provider is host-supplied text that lands in exported timeline state;
    // cap it so a misbehaving host cannot inflate context memory.
    const MAX_PROVIDER_CHARS: usize = 64;
    match verdict.source {
        VerdictSource::ClientPlatform => input
            .client_vision_verdict
            .as_ref()
            .map(|client| client.provider.chars().take(MAX_PROVIDER_CHARS).collect())
            .unwrap_or_default(),
        VerdictSource::OnDeviceModel => "core.onnx".to_string(),
        VerdictSource::PolicyOnly => String::new(),
    }
}

fn explicit_media_output(
    input: &MessageInput,
    account_type: AccountType,
    trusted: bool,
    verdict: &MediaVerdict,
) -> Option<MediaStageOutput> {
    let score = match account_type {
        // Minor profiles: confirmed explicit is a serious incident even from
        // an otherwise trusted contact.
        AccountType::Child | AccountType::Teen => (0.60 + 0.35 * verdict.confidence).min(0.95),
        // Adults: media between established contacts is their business;
        // unsolicited explicit media from low-trust senders gets a blur band.
        AccountType::Adult => {
            if trusted {
                return None;
            }
            0.35 + 0.20 * verdict.confidence
        }
    };
    let signal = DetectionSignal::pattern(
        ThreatType::Nsfw,
        score,
        Confidence::High,
        MEDIA_VISION_EXPLICIT,
        "Classifier-confirmed explicit media",
    )
    .with_threat_subtype(verdict_subtype(verdict));
    Some(MediaStageOutput {
        signal,
        event: Some(MediaStageEvent {
            kind: EventKind::ExplicitMediaReceived,
            confidence: verdict.confidence,
            subtype: Some(verdict_source_label(input, verdict)),
        }),
    })
}

fn suggestive_media_output(
    input: &MessageInput,
    account_type: AccountType,
    trusted: bool,
    verdict: &MediaVerdict,
) -> Option<MediaStageOutput> {
    match account_type {
        AccountType::Child | AccountType::Teen => {}
        AccountType::Adult => return None,
    }
    // Suggestive from an established contact stays a soft mark; never a
    // guardian alert (scores are capped well below the alert band).
    let score = if trusted {
        0.30
    } else {
        (0.45 + 0.15 * verdict.confidence).min(0.60)
    };
    let reason_code = if verdict.class == MediaClass::Drawing {
        MEDIA_VISION_DRAWING
    } else {
        MEDIA_VISION_SUGGESTIVE
    };
    let signal = DetectionSignal::pattern(
        ThreatType::Nsfw,
        score,
        Confidence::Medium,
        reason_code,
        "Classifier-flagged suggestive media",
    )
    .with_threat_subtype(verdict_subtype(verdict));
    Some(MediaStageOutput {
        signal,
        event: Some(MediaStageEvent {
            kind: EventKind::SuggestiveMediaReceived,
            confidence: verdict.confidence,
            subtype: Some(verdict_source_label(input, verdict)),
        }),
    })
}

fn trust_gate_output(
    input: &MessageInput,
    account_type: AccountType,
    snapshot: Option<&ContactSnapshot>,
    trusted: bool,
) -> Option<MediaStageOutput> {
    match account_type {
        AccountType::Child | AccountType::Teen => {}
        AccountType::Adult => return None,
    }
    if is_guardian_managed_sender(input) {
        return None;
    }
    if trusted {
        return None;
    }

    let circle_tier = snapshot.map_or(CircleTier::New, |s| s.circle_tier);
    let (score, subtype) = match (account_type, circle_tier) {
        (AccountType::Child, CircleTier::New) => (0.50, "child_new_contact"),
        (AccountType::Child, CircleTier::Occasional) => (0.45, "child_occasional_contact"),
        (AccountType::Teen, CircleTier::New) => (0.45, "teen_new_contact"),
        (AccountType::Teen, CircleTier::Occasional) => (0.40, "teen_occasional_contact"),
        // Adult and trusted tiers returned above.
        _ => return None,
    };

    // Pattern layer, not context layer: the gate is a deterministic rule on
    // metadata, and context-only signals are damped in signal combination.
    Some(MediaStageOutput {
        signal: DetectionSignal::pattern(
            ThreatType::Nsfw,
            score,
            Confidence::Medium,
            MEDIA_TRUST_GATE_UNVERIFIED_INCOMING,
            "Unverified media from a low-trust contact; blur until the user opts in",
        )
        .with_threat_subtype(subtype),
        event: None,
    })
}

/// Compatibility wrapper used by the unit tests below and the orchestrator's
/// P0 trust-gate behavior checks.
#[cfg(test)]
pub(crate) fn media_trust_gate_signal(
    input: &MessageInput,
    account_type: AccountType,
    protected_account_id: Option<&str>,
    snapshot: Option<&ContactSnapshot>,
) -> Option<DetectionSignal> {
    media_stage_output(
        input,
        account_type,
        protected_account_id,
        snapshot,
        false,
        &aura_vision::NoopBackend,
    )
    .map(|output| output.signal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{ConversationId, SenderId};
    use crate::types::ConversationType;

    fn media_input(content_type: ContentType, sender: &str) -> MessageInput {
        MessageInput {
            content_type,
            text: None,
            image_data: None,
            media_info: None,
            client_vision_verdict: None,
            sender_id: SenderId::from(sender),
            conversation_id: ConversationId::from("dm_1"),
            language: None,
            conversation_type: ConversationType::Direct,
            member_count: None,
            sender_relationship: SenderRelationship::Unknown,
            relationship_trust_source: RelationshipTrustSource::Unknown,
        }
    }

    fn snapshot(tier: CircleTier, is_trusted: bool) -> ContactSnapshot {
        ContactSnapshot {
            sender_id: SenderId::from("stranger_1"),
            rating: 50.0,
            trust_level: 0.2,
            circle_tier: tier,
            trend: crate::types::BehavioralTrend::Stable,
            is_trusted,
            is_new_contact: tier == CircleTier::New,
            first_seen_ms: 0,
            last_seen_ms: 0,
            conversation_count: 1,
            grooming_event_count: 0,
            bullying_event_count: 0,
            manipulation_event_count: 0,
            total_threat_events: 0,
        }
    }

    #[test]
    fn child_receiving_image_from_unknown_contact_is_gated() {
        let input = media_input(ContentType::Image, "stranger_1");
        let signal = media_trust_gate_signal(&input, AccountType::Child, None, None)
            .expect("gate must fire for child + unknown sender");
        assert_eq!(signal.threat_type, ThreatType::Nsfw);
        assert_eq!(signal.reason_code, MEDIA_TRUST_GATE_UNVERIFIED_INCOMING);
        assert_eq!(signal.threat_subtype, "child_new_contact");
        assert!((signal.score - 0.50).abs() < f32::EPSILON);
    }

    #[test]
    fn video_is_gated_like_image() {
        let input = media_input(ContentType::Video, "stranger_1");
        assert!(media_trust_gate_signal(&input, AccountType::Teen, None, None).is_some());
    }

    #[test]
    fn text_voice_and_url_are_not_gated() {
        for content_type in [ContentType::Text, ContentType::Voice, ContentType::Url] {
            let input = media_input(content_type, "stranger_1");
            assert!(media_trust_gate_signal(&input, AccountType::Child, None, None).is_none());
        }
    }

    #[test]
    fn adult_account_is_not_gated() {
        let input = media_input(ContentType::Image, "stranger_1");
        assert!(media_trust_gate_signal(&input, AccountType::Adult, None, None).is_none());
    }

    #[test]
    fn outgoing_media_from_protected_account_is_not_gated() {
        let input = media_input(ContentType::Image, "child_13");
        assert!(
            media_trust_gate_signal(&input, AccountType::Child, Some("child_13"), None).is_none()
        );
    }

    #[test]
    fn trusted_and_inner_circle_contacts_bypass_the_gate() {
        let input = media_input(ContentType::Image, "stranger_1");
        let trusted = snapshot(CircleTier::Occasional, true);
        assert!(
            media_trust_gate_signal(&input, AccountType::Child, None, Some(&trusted)).is_none()
        );
        for tier in [CircleTier::Inner, CircleTier::Regular] {
            let familiar = snapshot(tier, false);
            assert!(
                media_trust_gate_signal(&input, AccountType::Child, None, Some(&familiar))
                    .is_none()
            );
        }
    }

    #[test]
    fn occasional_contact_is_gated_with_lower_score() {
        let input = media_input(ContentType::Image, "stranger_1");
        let occasional = snapshot(CircleTier::Occasional, false);
        let child = media_trust_gate_signal(&input, AccountType::Child, None, Some(&occasional))
            .expect("child occasional gated");
        assert_eq!(child.threat_subtype, "child_occasional_contact");
        let teen = media_trust_gate_signal(&input, AccountType::Teen, None, Some(&occasional))
            .expect("teen occasional gated");
        assert_eq!(teen.threat_subtype, "teen_occasional_contact");
        assert!(teen.score < child.score);
    }

    #[test]
    fn guardian_verified_parent_bypasses_but_self_declared_does_not() {
        let mut input = media_input(ContentType::Image, "parent_1");
        input.sender_relationship = SenderRelationship::Parent;
        input.relationship_trust_source = RelationshipTrustSource::GuardianVerified;
        assert!(media_trust_gate_signal(&input, AccountType::Child, None, None).is_none());

        input.relationship_trust_source = RelationshipTrustSource::SelfDeclared;
        assert!(media_trust_gate_signal(&input, AccountType::Child, None, None).is_some());
    }

    #[test]
    fn verified_teacher_stays_gated() {
        let mut input = media_input(ContentType::Image, "teacher_1");
        input.sender_relationship = SenderRelationship::Teacher;
        input.relationship_trust_source = RelationshipTrustSource::PlatformVerified;
        assert!(media_trust_gate_signal(&input, AccountType::Child, None, None).is_some());
    }
}
