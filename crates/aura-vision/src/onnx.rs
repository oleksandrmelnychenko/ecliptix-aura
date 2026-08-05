//! On-device ONNX NSFW image classifier.
//!
//! Model contract (architecture §5.2): int8-quantized classifier, ≤20 MB on
//! disk, 224×224 RGB input, five output classes in fixed order —
//! `[neutral, suggestive, explicit, drawing, unclear]`. The model file is
//! checksum-verified before the session is created, media bytes are
//! size-capped before decoding, and every failure path resolves to an error
//! the caller treats as an abstention (policy fails closed).

use std::sync::Mutex;

use sha2::{Digest, Sha256};

use crate::{
    BackendDescriptor, MediaClass, MediaVerdict, VerdictSource, VisionBackend, VisionError,
};

/// Model input edge length in pixels.
pub const INPUT_SIZE: u32 = 224;

/// Number of output classes, in the fixed order
/// `[neutral, suggestive, explicit, drawing, unclear]`.
pub const CLASS_COUNT: usize = 5;

/// Minimum winning probability for a decisive verdict; below this the
/// classifier abstains and downstream policy fails closed.
pub const DECISION_FLOOR: f32 = 0.55;

/// On-device NSFW image classifier backed by ONNX Runtime.
pub struct OnnxNsfwClassifier {
    session: Mutex<ort::session::Session>,
    descriptor: BackendDescriptor,
}

impl OnnxNsfwClassifier {
    /// Loads the classifier from a model file, verifying its checksum first
    /// when one is supplied.
    pub fn load(model_path: &str, expected_sha256: Option<[u8; 32]>) -> Result<Self, VisionError> {
        let bytes = std::fs::read(model_path)
            .map_err(|error| VisionError::ModelLoadFailed(error.to_string()))?;
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        if let Some(expected) = expected_sha256 {
            if digest != expected {
                return Err(VisionError::IntegrityMismatch);
            }
        }

        let session = ort::session::Session::builder()
            .map_err(|error| VisionError::ModelLoadFailed(error.to_string()))?
            .with_intra_threads(2)
            .map_err(|error| VisionError::ModelLoadFailed(error.to_string()))?
            .commit_from_memory(&bytes)
            .map_err(|error| VisionError::ModelLoadFailed(error.to_string()))?;

        Ok(Self {
            session: Mutex::new(session),
            descriptor: BackendDescriptor {
                identifier: format!("nsfw_image.onnx@{}", hex_digest(&digest)),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
        })
    }
}

impl VisionBackend for OnnxNsfwClassifier {
    fn classify(&self, image_bytes: &[u8]) -> Result<MediaVerdict, VisionError> {
        let tensor = decode_and_preprocess(image_bytes)?;
        let probabilities = self.run_inference(tensor)?;
        Ok(verdict_from_probabilities(&probabilities))
    }

    fn descriptor(&self) -> BackendDescriptor {
        self.descriptor.clone()
    }
}

impl OnnxNsfwClassifier {
    fn run_inference(
        &self,
        tensor: ndarray::Array4<f32>,
    ) -> Result<[f32; CLASS_COUNT], VisionError> {
        let input = ort::value::Tensor::from_array(tensor)
            .map_err(|error| VisionError::InferenceFailed(error.to_string()))?;
        let mut session = self
            .session
            .lock()
            .map_err(|_| VisionError::InferenceFailed("session lock poisoned".to_string()))?;
        let outputs = session
            .run(ort::inputs![input])
            .map_err(|error| VisionError::InferenceFailed(error.to_string()))?;
        let (_shape, logits) = outputs[0]
            .try_extract_tensor::<f32>()
            .map_err(|error| VisionError::InferenceFailed(error.to_string()))?;
        if logits.len() < CLASS_COUNT {
            return Err(VisionError::InferenceFailed(format!(
                "expected {CLASS_COUNT} logits, got {}",
                logits.len()
            )));
        }
        let mut head = [0.0f32; CLASS_COUNT];
        head.copy_from_slice(&logits[..CLASS_COUNT]);
        Ok(softmax(head))
    }
}

/// Decodes media bytes and converts them into a normalized NCHW tensor.
///
/// Enforces [`crate::MAX_MEDIA_BYTES`] before touching the decoder so a
/// hostile payload cannot force a large allocation.
pub(crate) fn decode_and_preprocess(
    image_bytes: &[u8],
) -> Result<ndarray::Array4<f32>, VisionError> {
    if image_bytes.is_empty() {
        return Err(VisionError::DecodeFailed("empty media bytes".to_string()));
    }
    if image_bytes.len() > crate::MAX_MEDIA_BYTES {
        return Err(VisionError::DecodeFailed(format!(
            "media bytes exceed cap: {} > {}",
            image_bytes.len(),
            crate::MAX_MEDIA_BYTES
        )));
    }

    let decoded = image::load_from_memory(image_bytes)
        .map_err(|error| VisionError::DecodeFailed(error.to_string()))?;
    let resized = image::imageops::resize(
        &decoded.to_rgb8(),
        INPUT_SIZE,
        INPUT_SIZE,
        image::imageops::FilterType::Triangle,
    );

    // Standard ImageNet-style normalization; the model contract calibrates
    // against these constants.
    const MEAN: [f32; 3] = [0.485, 0.456, 0.406];
    const STD: [f32; 3] = [0.229, 0.224, 0.225];

    let size = INPUT_SIZE as usize;
    let mut tensor = ndarray::Array4::<f32>::zeros((1, 3, size, size));
    for (x, y, pixel) in resized.enumerate_pixels() {
        for channel in 0..3 {
            let value = pixel.0[channel] as f32 / 255.0;
            tensor[[0, channel, y as usize, x as usize]] = (value - MEAN[channel]) / STD[channel];
        }
    }
    Ok(tensor)
}

fn softmax(logits: [f32; CLASS_COUNT]) -> [f32; CLASS_COUNT] {
    let max = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let mut exps = [0.0f32; CLASS_COUNT];
    let mut sum = 0.0f32;
    for (slot, logit) in exps.iter_mut().zip(logits.iter()) {
        *slot = (logit - max).exp();
        sum += *slot;
    }
    if sum <= 0.0 || !sum.is_finite() {
        return [1.0 / CLASS_COUNT as f32; CLASS_COUNT];
    }
    for slot in &mut exps {
        *slot /= sum;
    }
    exps
}

pub(crate) fn verdict_from_probabilities(probabilities: &[f32; CLASS_COUNT]) -> MediaVerdict {
    let (winner_idx, winner_prob) =
        probabilities
            .iter()
            .enumerate()
            .fold((0usize, f32::NEG_INFINITY), |best, (idx, prob)| {
                if *prob > best.1 {
                    (idx, *prob)
                } else {
                    best
                }
            });

    let class = match winner_idx {
        0 => MediaClass::Neutral,
        1 => MediaClass::Suggestive,
        2 => MediaClass::Explicit,
        3 => MediaClass::Drawing,
        _ => MediaClass::Unclear,
    };
    let abstained = class == MediaClass::Unclear || winner_prob < DECISION_FLOOR;

    MediaVerdict {
        class: if abstained {
            MediaClass::Unclear
        } else {
            class
        },
        confidence: winner_prob.clamp(0.0, 1.0),
        source: VerdictSource::OnDeviceModel,
        abstained,
    }
}

fn hex_digest(digest: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_png(width: u32, height: u32) -> Vec<u8> {
        let mut buffer = image::RgbImage::new(width, height);
        for (x, y, pixel) in buffer.enumerate_pixels_mut() {
            *pixel = image::Rgb([(x % 256) as u8, (y % 256) as u8, ((x + y) % 256) as u8]);
        }
        let mut bytes = Vec::new();
        image::DynamicImage::ImageRgb8(buffer)
            .write_to(
                &mut std::io::Cursor::new(&mut bytes),
                image::ImageFormat::Png,
            )
            .expect("png encode");
        bytes
    }

    #[test]
    fn missing_model_file_fails_to_load() {
        let error = OnnxNsfwClassifier::load("/nonexistent/nsfw_image.onnx", None)
            .err()
            .expect("load must fail");
        assert!(matches!(error, VisionError::ModelLoadFailed(_)));
    }

    #[test]
    fn checksum_mismatch_is_rejected_before_session_creation() {
        let dir = std::env::temp_dir().join("aura_vision_integrity_test");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("bogus_model.onnx");
        std::fs::write(&path, b"not a real model").expect("write");

        let error = OnnxNsfwClassifier::load(path.to_str().expect("path"), Some([0u8; 32]))
            .err()
            .expect("load must fail");
        assert_eq!(error, VisionError::IntegrityMismatch);
    }

    #[test]
    fn preprocess_produces_normalized_nchw_tensor() {
        let bytes = synthetic_png(64, 48);
        let tensor = decode_and_preprocess(&bytes).expect("preprocess");
        assert_eq!(tensor.shape(), &[1, 3, 224, 224]);
        // ImageNet normalization bounds: (0-mean)/std .. (1-mean)/std.
        for value in tensor.iter() {
            assert!(
                (-3.0..=3.0).contains(value),
                "normalized value out of range: {value}"
            );
        }
    }

    #[test]
    fn oversized_and_garbage_bytes_fail_decode() {
        let oversized = vec![0u8; crate::MAX_MEDIA_BYTES + 1];
        assert!(matches!(
            decode_and_preprocess(&oversized),
            Err(VisionError::DecodeFailed(_))
        ));
        assert!(matches!(
            decode_and_preprocess(&[]),
            Err(VisionError::DecodeFailed(_))
        ));
        assert!(matches!(
            decode_and_preprocess(&[0xde, 0xad, 0xbe, 0xef]),
            Err(VisionError::DecodeFailed(_))
        ));
    }

    #[test]
    fn decisive_probabilities_map_to_classes() {
        let explicit = verdict_from_probabilities(&[0.05, 0.05, 0.8, 0.05, 0.05]);
        assert_eq!(explicit.class, MediaClass::Explicit);
        assert!(!explicit.abstained);
        assert_eq!(explicit.source, VerdictSource::OnDeviceModel);

        let neutral = verdict_from_probabilities(&[0.9, 0.04, 0.03, 0.02, 0.01]);
        assert_eq!(neutral.class, MediaClass::Neutral);
        assert!(!neutral.abstained);
    }

    #[test]
    fn indecisive_or_unclear_probabilities_abstain() {
        let indecisive = verdict_from_probabilities(&[0.30, 0.25, 0.25, 0.10, 0.10]);
        assert!(indecisive.abstained);
        assert_eq!(indecisive.class, MediaClass::Unclear);

        let unclear_winner = verdict_from_probabilities(&[0.1, 0.1, 0.1, 0.1, 0.6]);
        assert!(unclear_winner.abstained);
        assert_eq!(unclear_winner.class, MediaClass::Unclear);
    }

    #[test]
    fn softmax_is_a_probability_distribution() {
        let probs = softmax([1.0, 2.0, 3.0, 4.0, 5.0]);
        let sum: f32 = probs.iter().sum();
        assert!((sum - 1.0).abs() < 1e-5);
        assert!(probs.windows(2).all(|pair| pair[0] < pair[1]));
    }
}
