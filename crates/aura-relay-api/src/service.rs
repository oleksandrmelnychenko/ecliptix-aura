//! HTTP/gRPC ingress layer for AURA Relay.
//!
//! Responsibilities:
//! - accept and validate incoming `AgentAnalyzeRequest` envelopes
//! - authenticate and rate-limit callers
//! - enforce idempotency and version negotiation
//! - route validated requests through intake → inference → risk → policy
//! - return typed `RelayAnalyzeResponse` envelopes

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use aura_contracts::{
    default_relay_schema_version, sign_protected_account_token_attestation,
    sign_relay_response_auth, verify_protected_account_token_attestation,
    verify_relay_request_auth, AgentAnalyzeRequest, ProtectedAccountTokenAttestation,
    RelayAnalyzeResponse, ThreatType,
};
use aura_relay_context::ContextEnrichment;
use aura_relay_policy::PolicyFilter;
use aura_relay_store::{InMemoryReputationStore, JsonFileReputationStore, ReputationStore};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use zeroize::Zeroizing;

const RELAY_RESPONSE_TTL_MS: u64 = 6 * 60 * 60 * 1_000;
const REQUEST_REPLAY_WINDOW_MS: u64 = 10 * 60 * 1_000;
const MAX_SEEN_REQUEST_IDS: usize = 4096;
const DEFAULT_PROTECTED_ACCOUNT_ATTESTATION_MAX_FUTURE_TTL_MS: u64 = 24 * 60 * 60 * 1_000;
const MAX_PROTECTED_ACCOUNT_ATTESTATION_MAX_FUTURE_TTL_MS: u64 = 7 * 24 * 60 * 60 * 1_000;
const AUTH_REJECTION_AUDIT_CAPACITY: usize = 512;
const ATTESTATION_ISSUER_AUDIT_CAPACITY: usize = 512;
const MIN_RELAY_AUTH_SECRET_BYTES: usize = 16;
const MAX_RELAY_AUTH_SECRET_BYTES: usize = 128;
const MAX_RELAY_AUTH_KEYS: usize = 4;
const DEFAULT_PROTECTED_ACCOUNT_ATTESTATION_ISSUER_TTL_MS: u64 = 5 * 60 * 1_000;
const MAX_PROTECTED_ACCOUNT_ATTESTATION_ISSUER_TTL_MS: u64 = 24 * 60 * 60 * 1_000;
const RELAY_PERSISTENT_STORE_SCHEMA_VERSION: u32 = 1;

mod adapters;
mod config;

use adapters::validate_optional_persistent_store_path;
pub use adapters::{
    InMemoryProtectedAccountAttestationIssuerAuditStore, InMemoryRelayAuthRejectionAuditStore,
    InMemoryRelayRequestReplayStore, JsonFileProtectedAccountAttestationIssuerAuditStore,
    JsonFileRelayAuthRejectionAuditStore, JsonFileRelayRequestReplayStore,
    ProtectedAccountAttestationIssuerAuditEntry, ProtectedAccountAttestationIssuerAuditStore,
    RelayAuthRejectionAuditEntry, RelayAuthRejectionAuditStore, RelayPersistentStoreError,
    RelayRequestReplayStore,
};
pub use config::{
    ProtectedAccountAttestationIssueError, ProtectedAccountAttestationIssuer,
    ProtectedAccountAttestationIssuerConfig, ProtectedAccountAttestationIssuerConfigError,
    ProtectedAccountAttestationIssuerPersistenceConfig, RelayAuthConfig, RelayAuthConfigError,
    RelayPersistenceConfig, RelayPersistenceConfigError, RelayProtectedAccountAttestationKeyConfig,
    RelaySharedSecretKeyConfig,
};

pub struct RelayService {
    policy_filter: PolicyFilter,
    reputation_store: Mutex<Box<dyn ReputationStore>>,
    request_replay_store: Arc<dyn RelayRequestReplayStore>,
    request_auth_keys: Vec<RelayRequestAuthKey>,
    response_auth_key: Option<RelayResponseAuthKey>,
    protected_account_attestation_keys: Vec<ProtectedAccountAttestationKey>,
    protected_account_attestation_max_future_ttl_ms: Option<u64>,
    auth_rejection_audit_store: Arc<dyn RelayAuthRejectionAuditStore>,
}

#[derive(Clone)]
struct RelayRequestAuthKey {
    key_id: String,
    secret: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for RelayRequestAuthKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RelayRequestAuthKey")
            .field("key_id", &self.key_id)
            .field("secret", &"[redacted]")
            .finish()
    }
}

#[derive(Clone)]
struct RelayResponseAuthKey {
    key_id: String,
    secret: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for RelayResponseAuthKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RelayResponseAuthKey")
            .field("key_id", &self.key_id)
            .field("secret", &"[redacted]")
            .finish()
    }
}

#[derive(Clone)]
struct ProtectedAccountAttestationKey {
    key_id: String,
    secret: Zeroizing<Vec<u8>>,
    not_before_ms: Option<u64>,
    not_after_ms: Option<u64>,
    revoked: bool,
}

impl std::fmt::Debug for ProtectedAccountAttestationKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProtectedAccountAttestationKey")
            .field("key_id", &self.key_id)
            .field("secret", &"[redacted]")
            .field("not_before_ms", &self.not_before_ms)
            .field("not_after_ms", &self.not_after_ms)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl ProtectedAccountAttestationKey {
    fn active(key_id: impl Into<String>, secret: impl Into<Vec<u8>>) -> Self {
        Self {
            key_id: key_id.into(),
            secret: Zeroizing::new(secret.into()),
            not_before_ms: None,
            not_after_ms: None,
            revoked: false,
        }
    }

    fn with_lifecycle(
        key_id: impl Into<String>,
        secret: impl Into<Vec<u8>>,
        not_before_ms: Option<u64>,
        not_after_ms: Option<u64>,
        revoked: bool,
    ) -> Self {
        Self {
            key_id: key_id.into(),
            secret: Zeroizing::new(secret.into()),
            not_before_ms,
            not_after_ms,
            revoked,
        }
    }

    fn lifecycle_rejection_reason(&self, now_ms: u64) -> Option<&'static str> {
        if self.revoked {
            return Some("relay.auth.protected_account_attestation_key_revoked");
        }
        if self
            .not_before_ms
            .is_some_and(|not_before_ms| now_ms < not_before_ms)
        {
            return Some("relay.auth.protected_account_attestation_key_not_yet_valid");
        }
        if self
            .not_after_ms
            .is_some_and(|not_after_ms| now_ms > not_after_ms)
        {
            return Some("relay.auth.protected_account_attestation_key_expired");
        }
        None
    }
}

#[derive(Debug, Clone)]
pub struct RelayCallerContext {
    pub protected_account_token: String,
}

impl RelayCallerContext {
    pub fn new(protected_account_token: impl Into<String>) -> Self {
        Self {
            protected_account_token: protected_account_token.into(),
        }
    }
}

fn default_protected_account_attestation_max_future_ttl_ms() -> Option<u64> {
    Some(DEFAULT_PROTECTED_ACCOUNT_ATTESTATION_MAX_FUTURE_TTL_MS)
}

fn default_protected_account_attestation_issuer_ttl_ms() -> u64 {
    DEFAULT_PROTECTED_ACCOUNT_ATTESTATION_ISSUER_TTL_MS
}

fn default_reputation_store_capacity() -> usize {
    16_384
}

fn default_request_replay_store_capacity() -> usize {
    MAX_SEEN_REQUEST_IDS
}

fn default_auth_rejection_audit_store_capacity() -> usize {
    AUTH_REJECTION_AUDIT_CAPACITY
}

fn default_attestation_issuer_audit_store_capacity() -> usize {
    ATTESTATION_ISSUER_AUDIT_CAPACITY
}

fn relay_auth_config_error(reason: impl Into<String>) -> RelayAuthConfigError {
    RelayAuthConfigError {
        reason: reason.into(),
    }
}

fn protected_account_attestation_issuer_config_error(
    reason: impl Into<String>,
) -> ProtectedAccountAttestationIssuerConfigError {
    ProtectedAccountAttestationIssuerConfigError {
        reason: reason.into(),
    }
}

fn relay_persistence_config_error(reason: impl Into<String>) -> RelayPersistenceConfigError {
    RelayPersistenceConfigError {
        reason: reason.into(),
    }
}

fn protected_account_attestation_issue_error(
    reason_code: impl Into<String>,
) -> ProtectedAccountAttestationIssueError {
    ProtectedAccountAttestationIssueError {
        reason_code: reason_code.into(),
    }
}

fn validate_shared_secret_key_set(
    keys: &[RelaySharedSecretKeyConfig],
    direction: &'static str,
    max_keys: usize,
) -> Result<(), RelayAuthConfigError> {
    if keys.len() > max_keys {
        return Err(relay_auth_config_error(format!(
            "relay {direction} auth key set exceeds limit of {max_keys}"
        )));
    }

    let mut seen_key_ids = HashSet::new();
    for key in keys {
        let key_id = validate_shared_secret_key(key, direction)?;
        if !seen_key_ids.insert(key_id.clone()) {
            return Err(relay_auth_config_error(format!(
                "relay {direction} auth key_id {key_id} is duplicated"
            )));
        }
    }

    Ok(())
}

fn validate_shared_secret_key(
    key: &RelaySharedSecretKeyConfig,
    direction: &'static str,
) -> Result<String, RelayAuthConfigError> {
    validate_key_id_and_secret(&key.key_id, key.secret.as_bytes(), direction)
}

fn validate_protected_account_attestation_key_set(
    keys: &[RelayProtectedAccountAttestationKeyConfig],
) -> Result<(), RelayAuthConfigError> {
    if keys.len() > MAX_RELAY_AUTH_KEYS {
        return Err(relay_auth_config_error(format!(
            "protected account attestation key set exceeds limit of {MAX_RELAY_AUTH_KEYS}"
        )));
    }

    let mut seen_key_ids = HashSet::new();
    for key in keys {
        let key_id = validate_key_id_and_secret(
            &key.key_id,
            key.secret.as_bytes(),
            "protected account attestation",
        )?;
        if !seen_key_ids.insert(key_id.clone()) {
            return Err(relay_auth_config_error(format!(
                "protected account attestation key_id {key_id} is duplicated"
            )));
        }
        if key
            .not_before_ms
            .zip(key.not_after_ms)
            .is_some_and(|(not_before_ms, not_after_ms)| not_before_ms > not_after_ms)
        {
            return Err(relay_auth_config_error(format!(
                "protected account attestation key_id {key_id} has invalid lifecycle window"
            )));
        }
    }

    Ok(())
}

fn validate_allowed_protected_account_tokens(
    tokens: &[String],
) -> Result<(), ProtectedAccountAttestationIssuerConfigError> {
    let mut seen_tokens = HashSet::new();
    for token in tokens {
        if !privacy_safe_protected_account_token(token) {
            return Err(protected_account_attestation_issuer_config_error(
                "protected account attestation issuer allowed tokens must be privacy-safe acct_ tokens",
            ));
        }
        if !seen_tokens.insert(token.clone()) {
            return Err(protected_account_attestation_issuer_config_error(
                "protected account attestation issuer allowed token is duplicated",
            ));
        }
    }

    Ok(())
}

fn validate_key_id_and_secret(
    key_id: &str,
    secret: &[u8],
    direction: &'static str,
) -> Result<String, RelayAuthConfigError> {
    let key_id = key_id.trim();
    if !relay_auth_key_id_is_valid(key_id) {
        return Err(relay_auth_config_error(format!(
            "relay {direction} key_id must be 1..64 ASCII [A-Za-z0-9_.-] characters"
        )));
    }
    if secret.len() < MIN_RELAY_AUTH_SECRET_BYTES || secret.len() > MAX_RELAY_AUTH_SECRET_BYTES {
        return Err(relay_auth_config_error(format!(
            "relay {direction} secret must be {MIN_RELAY_AUTH_SECRET_BYTES}..={MAX_RELAY_AUTH_SECRET_BYTES} bytes"
        )));
    }

    Ok(key_id.to_string())
}

fn relay_auth_key_id_is_valid(key_id: &str) -> bool {
    !key_id.is_empty()
        && key_id.len() <= 64
        && key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

impl RelayService {
    pub fn new() -> Self {
        Self {
            policy_filter: PolicyFilter::new(),
            reputation_store: Mutex::new(Box::new(InMemoryReputationStore::new())),
            request_replay_store: Arc::new(InMemoryRelayRequestReplayStore::default()),
            request_auth_keys: Vec::new(),
            response_auth_key: None,
            protected_account_attestation_keys: Vec::new(),
            protected_account_attestation_max_future_ttl_ms: Some(
                DEFAULT_PROTECTED_ACCOUNT_ATTESTATION_MAX_FUTURE_TTL_MS,
            ),
            auth_rejection_audit_store: Arc::new(InMemoryRelayAuthRejectionAuditStore::default()),
        }
    }

    pub fn from_auth_config(config: RelayAuthConfig) -> Result<Self, RelayAuthConfigError> {
        Self::new().with_auth_config(config)
    }

    pub fn with_auth_config(
        mut self,
        config: RelayAuthConfig,
    ) -> Result<Self, RelayAuthConfigError> {
        config.validate()?;
        self.request_auth_keys = config
            .request_auth_keys
            .iter()
            .map(|key| RelayRequestAuthKey {
                key_id: key.key_id.trim().to_string(),
                secret: Zeroizing::new(key.secret.as_bytes().to_vec()),
            })
            .collect();
        self.response_auth_key =
            config
                .response_auth_key
                .as_ref()
                .map(|key| RelayResponseAuthKey {
                    key_id: key.key_id.trim().to_string(),
                    secret: Zeroizing::new(key.secret.as_bytes().to_vec()),
                });
        self.protected_account_attestation_keys = config
            .protected_account_attestation_keys
            .iter()
            .map(|key| {
                ProtectedAccountAttestationKey::with_lifecycle(
                    key.key_id.trim(),
                    key.secret.as_bytes().to_vec(),
                    key.not_before_ms,
                    key.not_after_ms,
                    key.revoked,
                )
            })
            .collect();
        self.protected_account_attestation_max_future_ttl_ms =
            config.protected_account_attestation_max_future_ttl_ms;
        Ok(self)
    }

    pub fn with_persistence_config(
        mut self,
        config: RelayPersistenceConfig,
    ) -> Result<Self, RelayPersistenceConfigError> {
        config.validate()?;
        if let Some(path) = config.reputation_store_path {
            self.reputation_store = Mutex::new(Box::new(
                JsonFileReputationStore::open(path, config.reputation_store_capacity)
                    .map_err(|error| relay_persistence_config_error(error.to_string()))?,
            ));
        }
        if let Some(path) = config.request_replay_store_path {
            self.request_replay_store = Arc::new(
                JsonFileRelayRequestReplayStore::open(path, config.request_replay_store_capacity)
                    .map_err(|error| relay_persistence_config_error(error.to_string()))?,
            );
        }
        if let Some(path) = config.auth_rejection_audit_store_path {
            self.auth_rejection_audit_store = Arc::new(
                JsonFileRelayAuthRejectionAuditStore::open(
                    path,
                    config.auth_rejection_audit_store_capacity,
                )
                .map_err(|error| relay_persistence_config_error(error.to_string()))?,
            );
        }
        Ok(self)
    }

    pub fn with_reputation_store(mut self, store: Box<dyn ReputationStore>) -> Self {
        self.reputation_store = Mutex::new(store);
        self
    }

    pub fn with_request_auth_key(
        mut self,
        key_id: impl Into<String>,
        secret: impl Into<Vec<u8>>,
    ) -> Self {
        self.request_auth_keys = vec![RelayRequestAuthKey {
            key_id: key_id.into(),
            secret: Zeroizing::new(secret.into()),
        }];
        self
    }

    pub fn with_additional_request_auth_key(
        mut self,
        key_id: impl Into<String>,
        secret: impl Into<Vec<u8>>,
    ) -> Self {
        self.request_auth_keys.push(RelayRequestAuthKey {
            key_id: key_id.into(),
            secret: Zeroizing::new(secret.into()),
        });
        self
    }

    pub fn with_response_auth_key(
        mut self,
        key_id: impl Into<String>,
        secret: impl Into<Vec<u8>>,
    ) -> Self {
        self.response_auth_key = Some(RelayResponseAuthKey {
            key_id: key_id.into(),
            secret: Zeroizing::new(secret.into()),
        });
        self
    }

    pub fn with_protected_account_attestation_key(
        mut self,
        key_id: impl Into<String>,
        secret: impl Into<Vec<u8>>,
    ) -> Self {
        self.protected_account_attestation_keys =
            vec![ProtectedAccountAttestationKey::active(key_id, secret)];
        self
    }

    pub fn with_protected_account_attestation_key_lifecycle(
        mut self,
        key_id: impl Into<String>,
        secret: impl Into<Vec<u8>>,
        not_before_ms: Option<u64>,
        not_after_ms: Option<u64>,
        revoked: bool,
    ) -> Self {
        self.protected_account_attestation_keys =
            vec![ProtectedAccountAttestationKey::with_lifecycle(
                key_id,
                secret,
                not_before_ms,
                not_after_ms,
                revoked,
            )];
        self
    }

    pub fn with_additional_protected_account_attestation_key(
        mut self,
        key_id: impl Into<String>,
        secret: impl Into<Vec<u8>>,
    ) -> Self {
        self.protected_account_attestation_keys
            .push(ProtectedAccountAttestationKey::active(key_id, secret));
        self
    }

    pub fn with_additional_protected_account_attestation_key_lifecycle(
        mut self,
        key_id: impl Into<String>,
        secret: impl Into<Vec<u8>>,
        not_before_ms: Option<u64>,
        not_after_ms: Option<u64>,
        revoked: bool,
    ) -> Self {
        self.protected_account_attestation_keys.push(
            ProtectedAccountAttestationKey::with_lifecycle(
                key_id,
                secret,
                not_before_ms,
                not_after_ms,
                revoked,
            ),
        );
        self
    }

    pub fn with_protected_account_attestation_max_future_ttl_ms(
        mut self,
        max_future_ttl_ms: u64,
    ) -> Self {
        self.protected_account_attestation_max_future_ttl_ms = Some(max_future_ttl_ms);
        self
    }

    pub fn without_protected_account_attestation_max_future_ttl(mut self) -> Self {
        self.protected_account_attestation_max_future_ttl_ms = None;
        self
    }

    pub fn with_request_replay_store(mut self, store: Arc<dyn RelayRequestReplayStore>) -> Self {
        self.request_replay_store = store;
        self
    }

    pub fn with_auth_rejection_audit_store(
        mut self,
        store: Arc<dyn RelayAuthRejectionAuditStore>,
    ) -> Self {
        self.auth_rejection_audit_store = store;
        self
    }

    pub fn auth_rejection_audit_entries(&self) -> Vec<RelayAuthRejectionAuditEntry> {
        self.auth_rejection_audit_store.entries()
    }

    pub fn handle_analyze(&self, request: AgentAnalyzeRequest) -> RelayAnalyzeResponse {
        self.handle_analyze_with_caller_context(request, None)
    }

    pub fn handle_authenticated_analyze(
        &self,
        request: AgentAnalyzeRequest,
        caller_context: RelayCallerContext,
    ) -> RelayAnalyzeResponse {
        self.handle_analyze_with_caller_context(request, Some(&caller_context))
    }

    fn handle_analyze_with_caller_context(
        &self,
        request: AgentAnalyzeRequest,
        caller_context: Option<&RelayCallerContext>,
    ) -> RelayAnalyzeResponse {
        info!(request_id = %request.request_id, "relay: processing request");

        if let Some(reason_code) = self.request_auth_rejection_reason(&request, caller_context) {
            self.record_auth_rejection(&request, caller_context, reason_code);
            return rejected_response(request.request_id.clone(), reason_code);
        }
        if let Some(reason_code) = protected_account_binding_rejection_reason(
            &request,
            caller_context,
            &self.protected_account_attestation_keys,
            self.protected_account_attestation_max_future_ttl_ms,
        ) {
            self.record_auth_rejection(&request, caller_context, reason_code);
            return rejected_response(request.request_id.clone(), reason_code);
        }

        let intake = aura_relay_intake::validate_and_normalize(&request);

        let context_enrichment = {
            let mut reputation_store = self
                .reputation_store
                .lock()
                .expect("relay reputation store lock poisoned");
            for event in &intake.local_safety_telemetry {
                reputation_store.record_safety_telemetry(event);
            }
            let mut best_enrichment: Option<ContextEnrichment> = None;
            let reputation_store_ref: &dyn ReputationStore = reputation_store.as_ref();
            if let Some(sender_token) = intake.sender_token.as_deref() {
                let enrichment =
                    aura_relay_context::enrich_context(sender_token, reputation_store_ref);
                if enrichment.sender_reputation.is_some() {
                    best_enrichment = Some(enrichment);
                }
            }
            for event in &intake.local_safety_telemetry {
                let enrichment =
                    aura_relay_context::enrich_context(&event.sender_token, reputation_store_ref);
                let replace_best = match &best_enrichment {
                    Some(current) => enrichment.network_risk_signal > current.network_risk_signal,
                    None => true,
                };
                if replace_best {
                    best_enrichment = Some(enrichment);
                }
            }
            best_enrichment
        };

        let inference = aura_relay_inference::run_inference(&intake);

        let risk = aura_relay_risk::assess_risk(&inference, &intake);

        let mut response = self
            .policy_filter
            .filter_response(request.request_id.clone(), &risk);
        if let Some(enrichment) = context_enrichment {
            response.sender_reputation_hint = Some(enrichment.network_risk_signal);
            response.expires_at_ms = Some(relay_response_expires_at_ms(&request));
            if enrichment.cross_conversation_threat == Some(ThreatType::Manipulation) {
                response
                    .correlation_findings
                    .push("relay.context.cross_conversation_safety_telemetry".to_string());
            }
        }
        self.sign_response_if_configured(&request, &mut response);
        response
    }

    fn request_auth_rejection_reason(
        &self,
        request: &AgentAnalyzeRequest,
        caller_context: Option<&RelayCallerContext>,
    ) -> Option<&'static str> {
        if self.request_auth_keys.is_empty() {
            if caller_context.is_none() && !self.protected_account_attestation_keys.is_empty() {
                return Some("relay.auth.request_required_for_account_attestation");
            }
            return None;
        }
        if !self
            .request_auth_keys
            .iter()
            .any(|key| verify_relay_request_auth(request, &key.key_id, &key.secret))
        {
            return Some("relay.auth.request_invalid");
        }
        if !self.accept_request_id_once(&request.request_id) {
            return Some("relay.auth.request_replay");
        }
        None
    }

    fn accept_request_id_once(&self, request_id: &str) -> bool {
        self.request_replay_store.accept_once(
            request_id,
            current_unix_ms(),
            REQUEST_REPLAY_WINDOW_MS,
        )
    }

    fn sign_response_if_configured(
        &self,
        request: &AgentAnalyzeRequest,
        response: &mut RelayAnalyzeResponse,
    ) {
        let Some(key) = self.response_auth_key.as_ref() else {
            return;
        };
        let Some(sender_token) = response_auth_sender_token(request) else {
            return;
        };
        response.auth = sign_relay_response_auth(response, sender_token, &key.key_id, &key.secret);
    }

    fn record_auth_rejection(
        &self,
        request: &AgentAnalyzeRequest,
        caller_context: Option<&RelayCallerContext>,
        reason_code: &'static str,
    ) {
        self.auth_rejection_audit_store
            .record(RelayAuthRejectionAuditEntry {
                request_id: request.request_id.clone(),
                timestamp_ms: current_unix_ms(),
                reason_code: reason_code.to_string(),
                request_auth_key_id: request.auth.as_ref().map(|auth| auth.key_id.clone()),
                protected_account_attestation_key_id: request
                    .protected_account_attestation
                    .as_ref()
                    .map(|attestation| attestation.key_id.clone()),
                has_protected_account_token: request.protected_account_token.is_some(),
                caller_context_present: caller_context.is_some(),
                local_safety_telemetry_count: request.local_safety_telemetry.len(),
            });
    }
}

fn protected_account_binding_rejection_reason(
    request: &AgentAnalyzeRequest,
    caller_context: Option<&RelayCallerContext>,
    attestation_keys: &[ProtectedAccountAttestationKey],
    max_future_ttl_ms: Option<u64>,
) -> Option<&'static str> {
    if let Some(reason_code) = caller_context_rejection_reason(request, caller_context) {
        return Some(reason_code);
    }
    if caller_context.is_some() {
        return None;
    }

    protected_account_attestation_rejection_reason(request, attestation_keys, max_future_ttl_ms)
}

fn caller_context_rejection_reason(
    request: &AgentAnalyzeRequest,
    caller_context: Option<&RelayCallerContext>,
) -> Option<&'static str> {
    let caller_context = caller_context?;
    let protected_account_token = caller_context.protected_account_token.as_str();
    if !privacy_safe_protected_account_token(protected_account_token) {
        return Some("relay.auth.caller_protected_account_invalid");
    }

    if request
        .protected_account_token
        .as_deref()
        .is_some_and(|request_token| request_token != protected_account_token)
    {
        return Some("relay.auth.protected_account_mismatch");
    }

    if request
        .local_safety_telemetry
        .iter()
        .filter(|event| event.privacy_safe())
        .any(|event| event.protected_account_token != protected_account_token)
    {
        return Some("relay.auth.protected_account_mismatch");
    }

    None
}

fn protected_account_attestation_rejection_reason(
    request: &AgentAnalyzeRequest,
    attestation_keys: &[ProtectedAccountAttestationKey],
    max_future_ttl_ms: Option<u64>,
) -> Option<&'static str> {
    if attestation_keys.is_empty() {
        return None;
    }

    if request.protected_account_token.is_none() {
        return Some("relay.auth.protected_account_missing");
    }
    let Some(protected_account_token) = request.privacy_safe_protected_account_token() else {
        return Some("relay.auth.protected_account_invalid");
    };

    if request
        .local_safety_telemetry
        .iter()
        .filter(|event| event.privacy_safe())
        .any(|event| event.protected_account_token != protected_account_token)
    {
        return Some("relay.auth.protected_account_mismatch");
    }

    let Some(attestation) = request.protected_account_attestation.as_ref() else {
        return Some("relay.auth.protected_account_attestation_missing");
    };
    if attestation.protected_account_token != protected_account_token {
        return Some("relay.auth.protected_account_mismatch");
    }

    let now_ms = current_unix_ms();
    if attestation.expires_at_ms < now_ms {
        return Some("relay.auth.protected_account_attestation_expired");
    }
    if max_future_ttl_ms.is_some_and(|max_future_ttl_ms| {
        attestation.expires_at_ms > now_ms.saturating_add(max_future_ttl_ms)
    }) {
        return Some("relay.auth.protected_account_attestation_ttl_exceeded");
    }
    let mut saw_matching_key = false;
    let mut saw_active_matching_key = false;
    let mut lifecycle_rejection_reason = None;
    for key in attestation_keys
        .iter()
        .filter(|key| key.key_id == attestation.key_id)
    {
        saw_matching_key = true;
        if let Some(reason_code) = key.lifecycle_rejection_reason(now_ms) {
            lifecycle_rejection_reason.get_or_insert(reason_code);
            continue;
        }
        saw_active_matching_key = true;
        if verify_protected_account_token_attestation(
            attestation,
            protected_account_token,
            now_ms,
            &key.key_id,
            &key.secret,
        ) {
            return None;
        }
    }
    if !saw_matching_key {
        return Some("relay.auth.protected_account_attestation_invalid");
    }
    if saw_active_matching_key {
        return Some("relay.auth.protected_account_attestation_invalid");
    }

    lifecycle_rejection_reason.or(Some("relay.auth.protected_account_attestation_invalid"))
}

fn privacy_safe_protected_account_token(token: &str) -> bool {
    AgentAnalyzeRequest {
        protected_account_token: Some(token.to_string()),
        ..AgentAnalyzeRequest::default()
    }
    .privacy_safe_protected_account_token()
    .is_some()
}

fn rejected_response(request_id: String, reason_code: &'static str) -> RelayAnalyzeResponse {
    RelayAnalyzeResponse {
        schema_version: default_relay_schema_version(),
        request_id,
        reason_codes: vec![reason_code.to_string()],
        ..RelayAnalyzeResponse::default()
    }
}

fn response_auth_sender_token(request: &AgentAnalyzeRequest) -> Option<&str> {
    request.privacy_safe_sender_token().or_else(|| {
        request
            .local_safety_telemetry
            .iter()
            .find(|event| event.privacy_safe())
            .map(|event| event.sender_token.as_str())
    })
}

fn relay_response_expires_at_ms(request: &AgentAnalyzeRequest) -> u64 {
    let anchor_ms = request
        .local_safety_telemetry
        .iter()
        .map(|event| event.timestamp_bucket_ms)
        .max()
        .unwrap_or_else(current_unix_ms);
    anchor_ms.saturating_add(RELAY_RESPONSE_TTL_MS)
}

fn current_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn current_unix_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}

impl Default for RelayService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests;
