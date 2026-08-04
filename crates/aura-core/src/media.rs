//! Trust-gated media protection.
//!
//! Phase P0 of the NSFW media protection architecture
//! (`docs/nsfw-media-protection-architecture.md`): incoming image and video
//! messages from low-trust contacts on minor profiles are blurred before any
//! pixel-level classification exists. The gate is deterministic policy on
//! relationship metadata — it never inspects media bytes, so it also serves
//! as the fail-closed path once a vision backend exists and is unavailable.

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

/// Returns the trust-gate signal for an incoming media message, or `None`
/// when the gate does not apply.
///
/// The gate applies when all of the following hold:
/// - content is an image or video (`ContentType::Image` / `ContentType::Video`);
/// - the protected account is a minor profile (`Child` or `Teen`);
/// - the sender is not the protected account itself (send-side protection is
///   phase P3);
/// - the sender is not a guardian-verified parent/guardian;
/// - contact history has not established trust (`is_trusted`, `Inner`, or
///   `Regular` tier all bypass; absent history counts as `New` — fail closed).
pub(crate) fn media_trust_gate_signal(
    input: &MessageInput,
    account_type: AccountType,
    protected_account_id: Option<&str>,
    snapshot: Option<&ContactSnapshot>,
) -> Option<DetectionSignal> {
    match input.content_type {
        ContentType::Image | ContentType::Video => {}
        ContentType::Text | ContentType::Voice | ContentType::Url => return None,
    }
    match account_type {
        AccountType::Child | AccountType::Teen => {}
        AccountType::Adult => return None,
    }
    if protected_account_id == Some(&*input.sender_id) {
        return None;
    }
    if is_guardian_managed_sender(input) {
        return None;
    }

    let circle_tier = snapshot.map_or(CircleTier::New, |s| s.circle_tier);
    let is_trusted = snapshot.is_some_and(|s| s.is_trusted);
    if is_trusted || matches!(circle_tier, CircleTier::Inner | CircleTier::Regular) {
        return None;
    }

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
    Some(
        DetectionSignal::pattern(
            ThreatType::Nsfw,
            score,
            Confidence::Medium,
            MEDIA_TRUST_GATE_UNVERIFIED_INCOMING,
            "Unverified media from a low-trust contact; blur until the user opts in",
        )
        .with_threat_subtype(subtype),
    )
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
