//! Relay-side ML inference layer for AURA.
//!
//! This crate wraps the full ONNX-enabled `aura-ml` pipeline and adds
//! relay-specific orchestration:
//!
//! - model routing (which model handles which request)
//! - request batching for throughput
//! - calibration-aware inference
//! - model versioning and hot-reload
//!
//! On the agent side, `aura-ml` runs in fallback-only mode (no ONNX).
//! On the relay side, this crate enables the full ONNX inference path.

pub use aura_ml;

use aura_contracts::{Confidence, ThreatType};
use aura_ml::{MlConfig, MlPipeline};
use tracing::info;

pub struct RelayInferenceEngine {
    pipeline: MlPipeline,
}

impl RelayInferenceEngine {
    pub fn new(config: MlConfig) -> Self {
        let pipeline = MlPipeline::new(config);
        info!("relay inference engine initialised (ONNX-enabled)");
        Self { pipeline }
    }

    pub fn pipeline(&self) -> &MlPipeline {
        &self.pipeline
    }

    pub fn pipeline_mut(&mut self) -> &mut MlPipeline {
        &mut self.pipeline
    }
}

#[derive(Debug, Clone)]
pub struct RelayInferenceResult {
    pub primary_threat: ThreatType,
    pub score: f32,
    pub confidence: Confidence,
    pub model_version: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_creates_with_default_config() {
        let engine = RelayInferenceEngine::new(MlConfig::default());
        let _ = engine.pipeline();
    }
}
