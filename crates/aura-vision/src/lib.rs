//! Media classification contract for the NSFW media protection architecture
//! (P2, `docs/nsfw-media-protection-architecture.md` §5).
//!
//! This crate owns the verdict vocabulary shared by every media source:
//! platform-native classifiers delivered by the client (`ClientVisionVerdict`,
//! e.g. Apple SensitiveContentAnalysis), the future on-device ONNX backend,
//! and the policy-only fail-closed path. `aura-core` consumes [`MediaVerdict`]
//! and never needs to know which source produced it.
//!
//! Media bytes never leave the device and are never persisted; backends
//! classify in memory and return only a class + calibrated confidence.

use serde::{Deserialize, Serialize};

/// Classification outcome for a single media item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MediaClass {
    /// No sensitive content detected.
    Neutral,
    /// Suggestive but not explicit content.
    Suggestive,
    /// Sexually explicit content.
    Explicit,
    /// Drawn or animated content (hentai-style); policy treats it separately.
    Drawing,
    /// The classifier could not produce a usable decision.
    #[default]
    Unclear,
}

/// Which subsystem produced a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictSource {
    /// On-device model executed inside the core runtime.
    OnDeviceModel,
    /// Platform-native classifier verdict supplied by the client.
    ClientPlatform,
    /// No classification available; relationship policy only.
    PolicyOnly,
}

/// A validated media verdict ready for policy consumption.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MediaVerdict {
    pub class: MediaClass,
    /// Calibrated confidence in `0.0..=1.0`.
    pub confidence: f32,
    pub source: VerdictSource,
    /// True when no usable classification exists and policy must fail closed.
    pub abstained: bool,
}

/// Metadata about a media attachment supplied by the host application.
///
/// The runtime receives a client-downscaled thumbnail at most — original
/// media bytes never cross the boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MediaInfo {
    pub width: u32,
    pub height: u32,
    pub mime_type: String,
    pub original_size_bytes: u64,
    /// Video keyframe sampling: which sampled frame this input represents.
    pub keyframe_index: u32,
    pub keyframe_count: u32,
}

/// Pre-computed verdict from a platform-native classifier, as supplied by the
/// client. Untrusted until it passes [`accept_client_verdict`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClientVisionVerdict {
    pub class: MediaClass,
    pub confidence: f32,
    /// Provider identifier, e.g. `"apple.sca"`.
    pub provider: String,
}

/// Validates a client-supplied verdict and converts it into a [`MediaVerdict`].
///
/// Returns `None` for values that cannot be trusted at all (non-finite or
/// out-of-range confidence). An `Unclear` class is accepted but marked
/// abstained so downstream policy fails closed.
pub fn accept_client_verdict(verdict: &ClientVisionVerdict) -> Option<MediaVerdict> {
    if !verdict.confidence.is_finite() || !(0.0..=1.0).contains(&verdict.confidence) {
        return None;
    }
    let abstained = verdict.class == MediaClass::Unclear;
    Some(MediaVerdict {
        class: verdict.class,
        confidence: verdict.confidence,
        source: VerdictSource::ClientPlatform,
        abstained,
    })
}

/// Error produced by a vision backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VisionError {
    /// The backend has no model loaded.
    BackendUnavailable,
    /// The media bytes could not be decoded.
    DecodeFailed(String),
}

impl std::fmt::Display for VisionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BackendUnavailable => write!(f, "vision backend unavailable"),
            Self::DecodeFailed(reason) => write!(f, "media decode failed: {reason}"),
        }
    }
}

impl std::error::Error for VisionError {}

/// Identity of a loaded vision backend for runtime-capabilities reporting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendDescriptor {
    pub identifier: String,
    pub version: String,
}

/// A media classification backend.
///
/// The P2 ONNX classifier implements this trait behind an `onnx` feature;
/// [`NoopBackend`] is the always-available fallback that forces the policy
/// layer onto the fail-closed path.
pub trait VisionBackend: Send + Sync {
    /// Classifies decoded media bytes (client-downscaled thumbnail).
    fn classify(&self, image_bytes: &[u8]) -> Result<MediaVerdict, VisionError>;
    /// Returns the backend identity for capability reporting.
    fn descriptor(&self) -> BackendDescriptor;
}

/// Backend that always abstains. Decode failures and missing models resolve
/// to the same outcome: `Unclear`, abstained, policy fails closed.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopBackend;

impl VisionBackend for NoopBackend {
    fn classify(&self, _image_bytes: &[u8]) -> Result<MediaVerdict, VisionError> {
        Ok(MediaVerdict {
            class: MediaClass::Unclear,
            confidence: 0.0,
            source: VerdictSource::PolicyOnly,
            abstained: true,
        })
    }

    fn descriptor(&self) -> BackendDescriptor {
        BackendDescriptor {
            identifier: "noop".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_verdict(class: MediaClass, confidence: f32) -> ClientVisionVerdict {
        ClientVisionVerdict {
            class,
            confidence,
            provider: "apple.sca".to_string(),
        }
    }

    #[test]
    fn valid_explicit_verdict_is_accepted() {
        let verdict = accept_client_verdict(&client_verdict(MediaClass::Explicit, 0.9))
            .expect("valid verdict accepted");
        assert_eq!(verdict.class, MediaClass::Explicit);
        assert_eq!(verdict.source, VerdictSource::ClientPlatform);
        assert!(!verdict.abstained);
    }

    #[test]
    fn unclear_verdict_is_accepted_but_abstains() {
        let verdict = accept_client_verdict(&client_verdict(MediaClass::Unclear, 0.9))
            .expect("unclear verdict accepted");
        assert!(verdict.abstained);
    }

    #[test]
    fn out_of_range_confidence_is_rejected() {
        for confidence in [-0.1, 1.1, f32::NAN, f32::INFINITY] {
            assert!(
                accept_client_verdict(&client_verdict(MediaClass::Explicit, confidence)).is_none(),
                "confidence {confidence} must be rejected"
            );
        }
    }

    #[test]
    fn noop_backend_always_abstains() {
        let verdict = NoopBackend.classify(&[1, 2, 3]).expect("noop never errors");
        assert!(verdict.abstained);
        assert_eq!(verdict.class, MediaClass::Unclear);
        assert_eq!(verdict.source, VerdictSource::PolicyOnly);
    }
}
