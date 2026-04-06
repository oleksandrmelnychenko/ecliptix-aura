//! HTTP/gRPC ingress layer for AURA Relay.
//!
//! Responsibilities:
//! - accept and validate incoming `AgentAnalyzeRequest` envelopes
//! - authenticate and rate-limit callers
//! - enforce idempotency and version negotiation
//! - route validated requests through intake → inference → risk → policy
//! - return typed `RelayAnalyzeResponse` envelopes

use aura_contracts::{AgentAnalyzeRequest, RelayAnalyzeResponse};
use aura_relay_policy::PolicyFilter;
use tracing::info;

pub struct RelayService {
    policy_filter: PolicyFilter,
}

impl RelayService {
    pub fn new() -> Self {
        Self {
            policy_filter: PolicyFilter::new(),
        }
    }

    pub fn handle_analyze(&self, request: AgentAnalyzeRequest) -> RelayAnalyzeResponse {
        info!(request_id = %request.request_id, "relay: processing request");

        let intake = aura_relay_intake::validate_and_normalize(&request);

        let inference = aura_relay_inference::run_inference(&intake);

        let risk = aura_relay_risk::assess_risk(&inference, &intake);

        self.policy_filter.filter_response(request.request_id.clone(), &risk)
    }
}

impl Default for RelayService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_service_handles_default_request() {
        let service = RelayService::new();
        let request = AgentAnalyzeRequest {
            request_id: "test_1".to_string(),
            text: "hello world".to_string(),
            ..AgentAnalyzeRequest::default()
        };

        let response = service.handle_analyze(request);
        assert_eq!(response.request_id, "test_1");
    }
}
