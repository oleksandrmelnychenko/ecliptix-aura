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

#[derive(Debug, thiserror::Error)]
pub enum RelayPersistentStoreError {
    #[error("relay persistent store path is empty")]
    EmptyPath,
    #[error("relay persistent store I/O error for {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("relay persistent store JSON error for {path}: {source}")]
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RelayRequestReplayStoreState {
    schema_version: u32,
    seen_request_ids: HashMap<String, u64>,
}

impl Default for RelayRequestReplayStoreState {
    fn default() -> Self {
        Self {
            schema_version: RELAY_PERSISTENT_STORE_SCHEMA_VERSION,
            seen_request_ids: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RelayAuditStoreState<T> {
    schema_version: u32,
    entries: Vec<T>,
}

impl<T> Default for RelayAuditStoreState<T> {
    fn default() -> Self {
        Self {
            schema_version: RELAY_PERSISTENT_STORE_SCHEMA_VERSION,
            entries: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayAuthRejectionAuditEntry {
    pub request_id: String,
    pub timestamp_ms: u64,
    pub reason_code: String,
    pub request_auth_key_id: Option<String>,
    pub protected_account_attestation_key_id: Option<String>,
    pub has_protected_account_token: bool,
    pub caller_context_present: bool,
    pub local_safety_telemetry_count: usize,
}

pub trait RelayRequestReplayStore: Send + Sync {
    fn accept_once(&self, request_id: &str, now_ms: u64, ttl_ms: u64) -> bool;
}

pub struct InMemoryRelayRequestReplayStore {
    seen_request_ids: Mutex<HashMap<String, u64>>,
    capacity: usize,
}

impl InMemoryRelayRequestReplayStore {
    pub fn new(capacity: usize) -> Self {
        Self {
            seen_request_ids: Mutex::new(HashMap::new()),
            capacity,
        }
    }
}

impl Default for InMemoryRelayRequestReplayStore {
    fn default() -> Self {
        Self::new(MAX_SEEN_REQUEST_IDS)
    }
}

impl RelayRequestReplayStore for InMemoryRelayRequestReplayStore {
    fn accept_once(&self, request_id: &str, now_ms: u64, ttl_ms: u64) -> bool {
        if request_id.trim().is_empty() || self.capacity == 0 {
            return false;
        }

        let mut seen_request_ids = self
            .seen_request_ids
            .lock()
            .expect("relay seen request id lock poisoned");
        seen_request_ids.retain(|_, expires_at_ms| *expires_at_ms > now_ms);
        if seen_request_ids.contains_key(request_id) {
            return false;
        }
        if seen_request_ids.len() >= self.capacity {
            if let Some(oldest_request_id) = seen_request_ids
                .iter()
                .min_by_key(|(_, expires_at_ms)| *expires_at_ms)
                .map(|(request_id, _)| request_id.clone())
            {
                seen_request_ids.remove(&oldest_request_id);
            }
        }
        seen_request_ids.insert(request_id.to_string(), now_ms.saturating_add(ttl_ms));
        true
    }
}

pub struct JsonFileRelayRequestReplayStore {
    path: PathBuf,
    seen_request_ids: Mutex<HashMap<String, u64>>,
    capacity: usize,
}

impl JsonFileRelayRequestReplayStore {
    pub fn open(
        path: impl Into<PathBuf>,
        capacity: usize,
    ) -> Result<Self, RelayPersistentStoreError> {
        let path = validate_persistent_store_path(path.into())?;
        let mut state: RelayRequestReplayStoreState = read_json_or_default(&path)?;
        trim_replay_state_to_capacity(&mut state.seen_request_ids, capacity);
        Ok(Self {
            path,
            seen_request_ids: Mutex::new(state.seen_request_ids),
            capacity,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn entries(&self) -> HashMap<String, u64> {
        self.seen_request_ids
            .lock()
            .expect("relay persistent replay store lock poisoned")
            .clone()
    }
}

impl RelayRequestReplayStore for JsonFileRelayRequestReplayStore {
    fn accept_once(&self, request_id: &str, now_ms: u64, ttl_ms: u64) -> bool {
        if request_id.trim().is_empty() || self.capacity == 0 {
            return false;
        }

        let mut seen_request_ids = self
            .seen_request_ids
            .lock()
            .expect("relay persistent replay store lock poisoned");
        let previous = seen_request_ids.clone();
        seen_request_ids.retain(|_, expires_at_ms| *expires_at_ms > now_ms);
        if seen_request_ids.contains_key(request_id) {
            return false;
        }
        if seen_request_ids.len() >= self.capacity {
            if let Some(oldest_request_id) = seen_request_ids
                .iter()
                .min_by_key(|(_, expires_at_ms)| *expires_at_ms)
                .map(|(request_id, _)| request_id.clone())
            {
                seen_request_ids.remove(&oldest_request_id);
            }
        }
        seen_request_ids.insert(request_id.to_string(), now_ms.saturating_add(ttl_ms));

        let state = RelayRequestReplayStoreState {
            schema_version: RELAY_PERSISTENT_STORE_SCHEMA_VERSION,
            seen_request_ids: seen_request_ids.clone(),
        };
        if let Err(error) = write_json_atomic(&self.path, &state) {
            *seen_request_ids = previous;
            warn!(
                path = %self.path.display(),
                error = %error,
                "relay: failed to persist replay store; rejecting request"
            );
            return false;
        }

        true
    }
}

pub trait RelayAuthRejectionAuditStore: Send + Sync {
    fn record(&self, entry: RelayAuthRejectionAuditEntry);

    fn entries(&self) -> Vec<RelayAuthRejectionAuditEntry> {
        Vec::new()
    }
}

pub struct InMemoryRelayAuthRejectionAuditStore {
    entries: Mutex<Vec<RelayAuthRejectionAuditEntry>>,
    capacity: usize,
}

impl InMemoryRelayAuthRejectionAuditStore {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Mutex::new(Vec::with_capacity(capacity.min(10_000))),
            capacity,
        }
    }
}

impl Default for InMemoryRelayAuthRejectionAuditStore {
    fn default() -> Self {
        Self::new(AUTH_REJECTION_AUDIT_CAPACITY)
    }
}

impl RelayAuthRejectionAuditStore for InMemoryRelayAuthRejectionAuditStore {
    fn record(&self, entry: RelayAuthRejectionAuditEntry) {
        if self.capacity == 0 {
            return;
        }
        let mut entries = self
            .entries
            .lock()
            .expect("relay auth rejection audit log lock poisoned");
        if entries.len() >= self.capacity {
            entries.remove(0);
        }
        entries.push(entry);
    }

    fn entries(&self) -> Vec<RelayAuthRejectionAuditEntry> {
        self.entries
            .lock()
            .expect("relay auth rejection audit log lock poisoned")
            .clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedAccountAttestationIssuerAuditEntry {
    pub timestamp_ms: u64,
    pub outcome: String,
    pub reason_code: String,
    pub key_id: Option<String>,
    pub has_protected_account_token: bool,
    pub requested_ttl_ms: Option<u64>,
    pub expires_at_ms: Option<u64>,
}

pub trait ProtectedAccountAttestationIssuerAuditStore: Send + Sync {
    fn record(&self, entry: ProtectedAccountAttestationIssuerAuditEntry);

    fn entries(&self) -> Vec<ProtectedAccountAttestationIssuerAuditEntry> {
        Vec::new()
    }
}

pub struct InMemoryProtectedAccountAttestationIssuerAuditStore {
    entries: Mutex<Vec<ProtectedAccountAttestationIssuerAuditEntry>>,
    capacity: usize,
}

impl InMemoryProtectedAccountAttestationIssuerAuditStore {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Mutex::new(Vec::with_capacity(capacity.min(10_000))),
            capacity,
        }
    }
}

impl Default for InMemoryProtectedAccountAttestationIssuerAuditStore {
    fn default() -> Self {
        Self::new(ATTESTATION_ISSUER_AUDIT_CAPACITY)
    }
}

impl ProtectedAccountAttestationIssuerAuditStore
    for InMemoryProtectedAccountAttestationIssuerAuditStore
{
    fn record(&self, entry: ProtectedAccountAttestationIssuerAuditEntry) {
        if self.capacity == 0 {
            return;
        }
        let mut entries = self
            .entries
            .lock()
            .expect("protected account attestation issuer audit log lock poisoned");
        if entries.len() >= self.capacity {
            entries.remove(0);
        }
        entries.push(entry);
    }

    fn entries(&self) -> Vec<ProtectedAccountAttestationIssuerAuditEntry> {
        self.entries
            .lock()
            .expect("protected account attestation issuer audit log lock poisoned")
            .clone()
    }
}

struct BoundedJsonFileAuditStore<T> {
    path: PathBuf,
    entries: Mutex<Vec<T>>,
    capacity: usize,
}

impl<T> BoundedJsonFileAuditStore<T>
where
    T: Clone + Serialize + DeserializeOwned,
{
    fn open(path: impl Into<PathBuf>, capacity: usize) -> Result<Self, RelayPersistentStoreError> {
        let path = validate_persistent_store_path(path.into())?;
        let mut state: RelayAuditStoreState<T> = read_json_or_default(&path)?;
        trim_entries_to_capacity(&mut state.entries, capacity);
        Ok(Self {
            path,
            entries: Mutex::new(state.entries),
            capacity,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn record(&self, entry: T, store_name: &'static str) {
        if self.capacity == 0 {
            return;
        }

        let mut entries = self
            .entries
            .lock()
            .expect("relay persistent audit store lock poisoned");
        let previous = entries.clone();
        entries.push(entry);
        trim_entries_to_capacity(&mut entries, self.capacity);

        let state = RelayAuditStoreState {
            schema_version: RELAY_PERSISTENT_STORE_SCHEMA_VERSION,
            entries: entries.clone(),
        };
        if let Err(error) = write_json_atomic(&self.path, &state) {
            *entries = previous;
            warn!(
                path = %self.path.display(),
                error = %error,
                store = store_name,
                "relay: failed to persist audit store"
            );
        }
    }

    fn entries(&self) -> Vec<T> {
        self.entries
            .lock()
            .expect("relay persistent audit store lock poisoned")
            .clone()
    }
}

pub struct JsonFileRelayAuthRejectionAuditStore {
    inner: BoundedJsonFileAuditStore<RelayAuthRejectionAuditEntry>,
}

impl JsonFileRelayAuthRejectionAuditStore {
    pub fn open(
        path: impl Into<PathBuf>,
        capacity: usize,
    ) -> Result<Self, RelayPersistentStoreError> {
        Ok(Self {
            inner: BoundedJsonFileAuditStore::open(path, capacity)?,
        })
    }

    pub fn path(&self) -> &Path {
        self.inner.path()
    }
}

impl RelayAuthRejectionAuditStore for JsonFileRelayAuthRejectionAuditStore {
    fn record(&self, entry: RelayAuthRejectionAuditEntry) {
        self.inner.record(entry, "relay_auth_rejection_audit");
    }

    fn entries(&self) -> Vec<RelayAuthRejectionAuditEntry> {
        self.inner.entries()
    }
}

pub struct JsonFileProtectedAccountAttestationIssuerAuditStore {
    inner: BoundedJsonFileAuditStore<ProtectedAccountAttestationIssuerAuditEntry>,
}

impl JsonFileProtectedAccountAttestationIssuerAuditStore {
    pub fn open(
        path: impl Into<PathBuf>,
        capacity: usize,
    ) -> Result<Self, RelayPersistentStoreError> {
        Ok(Self {
            inner: BoundedJsonFileAuditStore::open(path, capacity)?,
        })
    }

    pub fn path(&self) -> &Path {
        self.inner.path()
    }
}

impl ProtectedAccountAttestationIssuerAuditStore
    for JsonFileProtectedAccountAttestationIssuerAuditStore
{
    fn record(&self, entry: ProtectedAccountAttestationIssuerAuditEntry) {
        self.inner
            .record(entry, "protected_account_attestation_issuer_audit");
    }

    fn entries(&self) -> Vec<ProtectedAccountAttestationIssuerAuditEntry> {
        self.inner.entries()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{reason}")]
pub struct RelayAuthConfigError {
    pub reason: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelaySharedSecretKeyConfig {
    pub key_id: String,
    pub secret: String,
}

impl std::fmt::Debug for RelaySharedSecretKeyConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RelaySharedSecretKeyConfig")
            .field("key_id", &self.key_id)
            .field("secret", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayProtectedAccountAttestationKeyConfig {
    pub key_id: String,
    pub secret: String,
    #[serde(default)]
    pub not_before_ms: Option<u64>,
    #[serde(default)]
    pub not_after_ms: Option<u64>,
    #[serde(default)]
    pub revoked: bool,
}

impl std::fmt::Debug for RelayProtectedAccountAttestationKeyConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RelayProtectedAccountAttestationKeyConfig")
            .field("key_id", &self.key_id)
            .field("secret", &"[redacted]")
            .field("not_before_ms", &self.not_before_ms)
            .field("not_after_ms", &self.not_after_ms)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayAuthConfig {
    #[serde(default)]
    pub request_auth_keys: Vec<RelaySharedSecretKeyConfig>,
    #[serde(default)]
    pub response_auth_key: Option<RelaySharedSecretKeyConfig>,
    #[serde(default)]
    pub protected_account_attestation_keys: Vec<RelayProtectedAccountAttestationKeyConfig>,
    #[serde(default = "default_protected_account_attestation_max_future_ttl_ms")]
    pub protected_account_attestation_max_future_ttl_ms: Option<u64>,
}

impl std::fmt::Debug for RelayAuthConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RelayAuthConfig")
            .field("request_auth_keys", &self.request_auth_keys)
            .field("response_auth_key", &self.response_auth_key)
            .field(
                "protected_account_attestation_keys",
                &self.protected_account_attestation_keys,
            )
            .field(
                "protected_account_attestation_max_future_ttl_ms",
                &self.protected_account_attestation_max_future_ttl_ms,
            )
            .finish()
    }
}

impl Default for RelayAuthConfig {
    fn default() -> Self {
        Self {
            request_auth_keys: Vec::new(),
            response_auth_key: None,
            protected_account_attestation_keys: Vec::new(),
            protected_account_attestation_max_future_ttl_ms:
                default_protected_account_attestation_max_future_ttl_ms(),
        }
    }
}

impl RelayAuthConfig {
    pub fn validate(&self) -> Result<(), RelayAuthConfigError> {
        validate_shared_secret_key_set(&self.request_auth_keys, "request", MAX_RELAY_AUTH_KEYS)?;
        if let Some(key) = self.response_auth_key.as_ref() {
            validate_shared_secret_key(key, "response")?;
        }
        validate_protected_account_attestation_key_set(&self.protected_account_attestation_keys)?;
        if let Some(max_future_ttl_ms) = self.protected_account_attestation_max_future_ttl_ms {
            if max_future_ttl_ms == 0
                || max_future_ttl_ms > MAX_PROTECTED_ACCOUNT_ATTESTATION_MAX_FUTURE_TTL_MS
            {
                return Err(relay_auth_config_error(format!(
                    "protected account attestation max future ttl must be 1..={MAX_PROTECTED_ACCOUNT_ATTESTATION_MAX_FUTURE_TTL_MS} ms"
                )));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{reason}")]
pub struct ProtectedAccountAttestationIssuerConfigError {
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{reason}")]
pub struct RelayPersistenceConfigError {
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayPersistenceConfig {
    #[serde(default)]
    pub reputation_store_path: Option<PathBuf>,
    #[serde(default = "default_reputation_store_capacity")]
    pub reputation_store_capacity: usize,
    #[serde(default)]
    pub request_replay_store_path: Option<PathBuf>,
    #[serde(default = "default_request_replay_store_capacity")]
    pub request_replay_store_capacity: usize,
    #[serde(default)]
    pub auth_rejection_audit_store_path: Option<PathBuf>,
    #[serde(default = "default_auth_rejection_audit_store_capacity")]
    pub auth_rejection_audit_store_capacity: usize,
}

impl Default for RelayPersistenceConfig {
    fn default() -> Self {
        Self {
            reputation_store_path: None,
            reputation_store_capacity: default_reputation_store_capacity(),
            request_replay_store_path: None,
            request_replay_store_capacity: default_request_replay_store_capacity(),
            auth_rejection_audit_store_path: None,
            auth_rejection_audit_store_capacity: default_auth_rejection_audit_store_capacity(),
        }
    }
}

impl RelayPersistenceConfig {
    pub fn validate(&self) -> Result<(), RelayPersistenceConfigError> {
        if self.reputation_store_path.is_some() && self.reputation_store_capacity == 0 {
            return Err(relay_persistence_config_error(
                "reputation persistent store capacity must be greater than zero",
            ));
        }
        if self.request_replay_store_path.is_some() && self.request_replay_store_capacity == 0 {
            return Err(relay_persistence_config_error(
                "request replay persistent store capacity must be greater than zero",
            ));
        }
        validate_optional_persistent_store_path(&self.reputation_store_path)?;
        validate_optional_persistent_store_path(&self.request_replay_store_path)?;
        validate_optional_persistent_store_path(&self.auth_rejection_audit_store_path)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedAccountAttestationIssuerPersistenceConfig {
    #[serde(default)]
    pub audit_store_path: Option<PathBuf>,
    #[serde(default = "default_attestation_issuer_audit_store_capacity")]
    pub audit_store_capacity: usize,
}

impl Default for ProtectedAccountAttestationIssuerPersistenceConfig {
    fn default() -> Self {
        Self {
            audit_store_path: None,
            audit_store_capacity: default_attestation_issuer_audit_store_capacity(),
        }
    }
}

impl ProtectedAccountAttestationIssuerPersistenceConfig {
    pub fn validate(&self) -> Result<(), RelayPersistenceConfigError> {
        validate_optional_persistent_store_path(&self.audit_store_path)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedAccountAttestationIssuerConfig {
    pub signing_keys: Vec<RelayProtectedAccountAttestationKeyConfig>,
    #[serde(default = "default_protected_account_attestation_issuer_ttl_ms")]
    pub ttl_ms: u64,
    #[serde(default)]
    pub allowed_protected_account_tokens: Vec<String>,
}

impl std::fmt::Debug for ProtectedAccountAttestationIssuerConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProtectedAccountAttestationIssuerConfig")
            .field("signing_keys", &self.signing_keys)
            .field("ttl_ms", &self.ttl_ms)
            .field(
                "allowed_protected_account_tokens_count",
                &self.allowed_protected_account_tokens.len(),
            )
            .finish()
    }
}

impl ProtectedAccountAttestationIssuerConfig {
    pub fn validate(&self) -> Result<(), ProtectedAccountAttestationIssuerConfigError> {
        validate_protected_account_attestation_key_set(&self.signing_keys)
            .map_err(|error| protected_account_attestation_issuer_config_error(error.reason))?;
        if self.signing_keys.is_empty() {
            return Err(protected_account_attestation_issuer_config_error(
                "protected account attestation issuer requires at least one signing key",
            ));
        }
        if self.ttl_ms == 0 || self.ttl_ms > MAX_PROTECTED_ACCOUNT_ATTESTATION_ISSUER_TTL_MS {
            return Err(protected_account_attestation_issuer_config_error(format!(
                "protected account attestation issuer ttl must be 1..={MAX_PROTECTED_ACCOUNT_ATTESTATION_ISSUER_TTL_MS} ms"
            )));
        }
        validate_allowed_protected_account_tokens(&self.allowed_protected_account_tokens)?;
        Ok(())
    }
}

pub struct ProtectedAccountAttestationIssuer {
    signing_keys: Vec<ProtectedAccountAttestationKey>,
    ttl_ms: u64,
    allowed_protected_account_tokens: HashSet<String>,
    audit_store: Arc<dyn ProtectedAccountAttestationIssuerAuditStore>,
}

impl ProtectedAccountAttestationIssuer {
    pub fn from_config(
        config: ProtectedAccountAttestationIssuerConfig,
    ) -> Result<Self, ProtectedAccountAttestationIssuerConfigError> {
        config.validate()?;
        Ok(Self {
            signing_keys: config
                .signing_keys
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
                .collect(),
            ttl_ms: config.ttl_ms,
            allowed_protected_account_tokens: config
                .allowed_protected_account_tokens
                .into_iter()
                .collect(),
            audit_store: Arc::new(InMemoryProtectedAccountAttestationIssuerAuditStore::default()),
        })
    }

    pub fn with_audit_store(
        mut self,
        audit_store: Arc<dyn ProtectedAccountAttestationIssuerAuditStore>,
    ) -> Self {
        self.audit_store = audit_store;
        self
    }

    pub fn with_persistence_config(
        mut self,
        config: ProtectedAccountAttestationIssuerPersistenceConfig,
    ) -> Result<Self, RelayPersistenceConfigError> {
        config.validate()?;
        if let Some(path) = config.audit_store_path {
            self.audit_store = Arc::new(
                JsonFileProtectedAccountAttestationIssuerAuditStore::open(
                    path,
                    config.audit_store_capacity,
                )
                .map_err(|error| relay_persistence_config_error(error.to_string()))?,
            );
        }
        Ok(self)
    }

    pub fn audit_entries(&self) -> Vec<ProtectedAccountAttestationIssuerAuditEntry> {
        self.audit_store.entries()
    }

    pub fn issue(
        &self,
        protected_account_token: &str,
        requested_ttl_ms: Option<u64>,
        now_ms: u64,
    ) -> Result<ProtectedAccountTokenAttestation, ProtectedAccountAttestationIssueError> {
        let requested_ttl_ms = requested_ttl_ms.unwrap_or(self.ttl_ms);
        let issue_result =
            self.issue_without_audit(protected_account_token, requested_ttl_ms, now_ms);
        self.record_issue_audit(
            protected_account_token,
            requested_ttl_ms,
            now_ms,
            issue_result.as_ref(),
        );
        issue_result
    }

    fn issue_without_audit(
        &self,
        protected_account_token: &str,
        requested_ttl_ms: u64,
        now_ms: u64,
    ) -> Result<ProtectedAccountTokenAttestation, ProtectedAccountAttestationIssueError> {
        if !privacy_safe_protected_account_token(protected_account_token) {
            return Err(protected_account_attestation_issue_error(
                "issuer.protected_account_token_invalid",
            ));
        }
        if !self.allowed_protected_account_tokens.is_empty()
            && !self
                .allowed_protected_account_tokens
                .contains(protected_account_token)
        {
            return Err(protected_account_attestation_issue_error(
                "issuer.protected_account_token_not_allowed",
            ));
        }
        if requested_ttl_ms == 0 || requested_ttl_ms > self.ttl_ms {
            return Err(protected_account_attestation_issue_error(
                "issuer.requested_ttl_exceeded",
            ));
        }

        for key in &self.signing_keys {
            if key.lifecycle_rejection_reason(now_ms).is_some() {
                continue;
            }
            let Some(expires_at_ms) = now_ms.checked_add(requested_ttl_ms) else {
                return Err(protected_account_attestation_issue_error(
                    "issuer.expires_at_overflow",
                ));
            };
            let expires_at_ms = key
                .not_after_ms
                .map(|not_after_ms| expires_at_ms.min(not_after_ms))
                .unwrap_or(expires_at_ms);
            if expires_at_ms <= now_ms {
                continue;
            }
            if let Some(attestation) = sign_protected_account_token_attestation(
                protected_account_token,
                expires_at_ms,
                &key.key_id,
                &key.secret,
            ) {
                return Ok(attestation);
            }
        }

        Err(protected_account_attestation_issue_error(
            "issuer.signing_key_unavailable",
        ))
    }

    fn record_issue_audit(
        &self,
        protected_account_token: &str,
        requested_ttl_ms: u64,
        now_ms: u64,
        issue_result: Result<
            &ProtectedAccountTokenAttestation,
            &ProtectedAccountAttestationIssueError,
        >,
    ) {
        let (outcome, reason_code, key_id, expires_at_ms) = match issue_result {
            Ok(attestation) => (
                "issued".to_string(),
                "issuer.attestation_issued".to_string(),
                Some(attestation.key_id.clone()),
                Some(attestation.expires_at_ms),
            ),
            Err(error) => (
                "rejected".to_string(),
                error.reason_code.clone(),
                None,
                None,
            ),
        };
        self.audit_store
            .record(ProtectedAccountAttestationIssuerAuditEntry {
                timestamp_ms: now_ms,
                outcome,
                reason_code,
                key_id,
                has_protected_account_token: !protected_account_token.trim().is_empty(),
                requested_ttl_ms: Some(requested_ttl_ms),
                expires_at_ms,
            });
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{reason_code}")]
pub struct ProtectedAccountAttestationIssueError {
    pub reason_code: String,
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

fn validate_optional_persistent_store_path(
    path: &Option<PathBuf>,
) -> Result<(), RelayPersistenceConfigError> {
    if path
        .as_ref()
        .is_some_and(|path| path.as_os_str().is_empty())
    {
        return Err(relay_persistence_config_error(
            "persistent store path must not be empty",
        ));
    }
    Ok(())
}

fn validate_persistent_store_path(path: PathBuf) -> Result<PathBuf, RelayPersistentStoreError> {
    if path.as_os_str().is_empty() {
        return Err(RelayPersistentStoreError::EmptyPath);
    }
    Ok(path)
}

fn read_json_or_default<T>(path: &Path) -> Result<T, RelayPersistentStoreError>
where
    T: DeserializeOwned + Default,
{
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(T::default()),
        Err(source) => {
            return Err(RelayPersistentStoreError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if bytes.is_empty() {
        return Ok(T::default());
    }

    serde_json::from_slice(&bytes).map_err(|source| RelayPersistentStoreError::Json {
        path: path.to_path_buf(),
        source,
    })
}

fn write_json_atomic<T>(path: &Path, value: &T) -> Result<(), RelayPersistentStoreError>
where
    T: Serialize,
{
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|source| RelayPersistentStoreError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    let bytes =
        serde_json::to_vec_pretty(value).map_err(|source| RelayPersistentStoreError::Json {
            path: path.to_path_buf(),
            source,
        })?;
    let tmp_path = persistent_store_tmp_path(path);
    fs::write(&tmp_path, bytes).map_err(|source| RelayPersistentStoreError::Io {
        path: tmp_path.clone(),
        source,
    })?;
    fs::rename(&tmp_path, path).map_err(|source| RelayPersistentStoreError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

fn persistent_store_tmp_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|file_name| file_name.to_str())
        .unwrap_or("relay-store.json");
    path.with_file_name(format!(
        "{file_name}.tmp.{}.{}",
        std::process::id(),
        current_unix_nanos()
    ))
}

fn trim_replay_state_to_capacity(seen_request_ids: &mut HashMap<String, u64>, capacity: usize) {
    if capacity == 0 {
        seen_request_ids.clear();
        return;
    }
    while seen_request_ids.len() > capacity {
        let Some(oldest_request_id) = seen_request_ids
            .iter()
            .min_by_key(|(_, expires_at_ms)| *expires_at_ms)
            .map(|(request_id, _)| request_id.clone())
        else {
            break;
        };
        seen_request_ids.remove(&oldest_request_id);
    }
}

fn trim_entries_to_capacity<T>(entries: &mut Vec<T>, capacity: usize) {
    if capacity == 0 {
        entries.clear();
        return;
    }
    if entries.len() > capacity {
        entries.drain(0..entries.len() - capacity);
    }
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
mod tests {
    use super::*;
    use aura_agent_core::{
        AccountType, AgentRelayPolicy, AgentRuntime, AuraConfig, ContentType, ConversationType,
        DomainMode, MessageInput, ProtectionLevel, SenderId,
    };
    use aura_contracts::{
        sign_protected_account_token_attestation, sign_relay_request_auth,
        verify_relay_request_auth, verify_relay_response_auth, ClientSafetyTelemetryEvent,
        Confidence, DetectionLayer, RawObservation, RelationshipTrustSource, RelayPrivacyMode,
        SafetyTelemetryAction, SafetyTelemetrySeverity, SafetyTelemetrySurface, SenderRelationship,
    };
    use aura_patterns::PatternDatabase;

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

    #[test]
    fn relay_service_returns_relationship_context_markers() {
        let service = RelayService::new();
        let response = service.handle_analyze(AgentAnalyzeRequest {
            request_id: "test_relationship_context".to_string(),
            account_type: AccountType::Child,
            sender_relationship: SenderRelationship::UnknownAdult,
            relationship_trust_source: RelationshipTrustSource::ServerReputation,
            local_observations: vec![RawObservation {
                threat_type: ThreatType::Grooming,
                layer: DetectionLayer::PatternMatching,
                score: 0.47,
                confidence: Confidence::Low,
                reason_code: "local.grooming.seed".to_string(),
                ..RawObservation::default()
            }],
            ..AgentAnalyzeRequest::default()
        });

        assert_eq!(response.request_id, "test_relationship_context");
        assert!(response
            .context_markers
            .contains(&"relay.relationship.unknown_adult_minor".to_string()));
        assert!(response
            .reason_codes
            .contains(&"relay.relationship.unknown_adult_minor".to_string()));
        assert!(response.inference.expect("missing inference").score >= 0.55);
    }

    #[test]
    fn protected_account_attestation_issuer_issues_proof_that_strict_relay_accepts() {
        let request_secret = b"relay request auth test secret";
        let attestation_secret = "protected account attestation secret";
        let account_token = protected_account_token(0);
        let now_ms = current_unix_ms();
        let issuer = ProtectedAccountAttestationIssuer::from_config(
            ProtectedAccountAttestationIssuerConfig {
                signing_keys: vec![RelayProtectedAccountAttestationKeyConfig {
                    key_id: "acct-attest-key-1".to_string(),
                    secret: attestation_secret.to_string(),
                    not_before_ms: Some(1),
                    not_after_ms: Some(now_ms.saturating_add(600_000)),
                    revoked: false,
                }],
                ttl_ms: 60_000,
                allowed_protected_account_tokens: vec![account_token.clone()],
            },
        )
        .expect("issuer config should validate");
        let attestation = issuer
            .issue(&account_token, None, now_ms)
            .expect("issuer should issue account attestation");
        assert_eq!(attestation.key_id, "acct-attest-key-1");
        assert_eq!(attestation.protected_account_token, account_token);
        assert_eq!(attestation.expires_at_ms, now_ms.saturating_add(60_000));

        let service = RelayService::new()
            .with_request_auth_key("relay-req-key-1", request_secret.to_vec())
            .with_protected_account_attestation_key(
                "acct-attest-key-1",
                attestation_secret.as_bytes().to_vec(),
            );
        let sender_token = "snd_01H00000000000000000000000".to_string();
        let mut request = request_with_safety_telemetry_from_account(&sender_token, 0, 0);
        request.protected_account_attestation = Some(attestation);
        request.auth = sign_relay_request_auth(&request, "relay-req-key-1", request_secret);

        let response = service.handle_analyze(request);

        assert!(
            !response
                .reason_codes
                .iter()
                .any(|code| code.starts_with("relay.auth.")),
            "strict relay should accept issuer proof, got {:?}",
            response.reason_codes
        );
        let audit_entries = issuer.audit_entries();
        assert_eq!(audit_entries.len(), 1);
        assert_eq!(audit_entries[0].outcome, "issued");
        assert_eq!(audit_entries[0].reason_code, "issuer.attestation_issued");
        assert_eq!(
            audit_entries[0].key_id.as_deref(),
            Some("acct-attest-key-1")
        );
        let serialized = serde_json::to_string(&audit_entries[0]).expect("audit serializes");
        assert!(!serialized.contains(&account_token));
    }

    #[test]
    fn protected_account_attestation_issuer_rejects_not_allowed_or_bad_ttl_without_token_leak() {
        let account_token = protected_account_token(0);
        let other_account_token = protected_account_token(7);
        let issuer = ProtectedAccountAttestationIssuer::from_config(
            ProtectedAccountAttestationIssuerConfig {
                signing_keys: vec![RelayProtectedAccountAttestationKeyConfig {
                    key_id: "acct-attest-key-1".to_string(),
                    secret: "protected account attestation secret".to_string(),
                    not_before_ms: None,
                    not_after_ms: None,
                    revoked: false,
                }],
                ttl_ms: 60_000,
                allowed_protected_account_tokens: vec![account_token.clone()],
            },
        )
        .expect("issuer config should validate");
        let now_ms = current_unix_ms();

        let not_allowed = issuer.issue(&other_account_token, None, now_ms);
        let ttl_exceeded = issuer.issue(&account_token, Some(120_000), now_ms);

        assert_eq!(
            not_allowed
                .expect_err("not allowed token should reject")
                .reason_code,
            "issuer.protected_account_token_not_allowed"
        );
        assert_eq!(
            ttl_exceeded
                .expect_err("too long requested ttl should reject")
                .reason_code,
            "issuer.requested_ttl_exceeded"
        );
        let audit_json =
            serde_json::to_string(&issuer.audit_entries()).expect("audit entries serialize");
        assert!(!audit_json.contains(&other_account_token));
        assert!(audit_json.contains("issuer.protected_account_token_not_allowed"));
    }

    #[test]
    fn protected_account_attestation_issuer_enforces_config_and_revoked_keys() {
        let invalid_config = ProtectedAccountAttestationIssuerConfig {
            signing_keys: Vec::new(),
            ttl_ms: 60_000,
            allowed_protected_account_tokens: Vec::new(),
        };
        assert!(invalid_config.validate().is_err());

        let invalid_allowed_token_config = ProtectedAccountAttestationIssuerConfig {
            signing_keys: vec![RelayProtectedAccountAttestationKeyConfig {
                key_id: "acct-attest-key-1".to_string(),
                secret: "protected account attestation secret".to_string(),
                not_before_ms: None,
                not_after_ms: None,
                revoked: false,
            }],
            ttl_ms: 60_000,
            allowed_protected_account_tokens: vec!["child@example.test".to_string()],
        };
        assert!(invalid_allowed_token_config.validate().is_err());

        let issuer = ProtectedAccountAttestationIssuer::from_config(
            ProtectedAccountAttestationIssuerConfig {
                signing_keys: vec![RelayProtectedAccountAttestationKeyConfig {
                    key_id: "acct-attest-key-1".to_string(),
                    secret: "protected account attestation secret".to_string(),
                    not_before_ms: None,
                    not_after_ms: None,
                    revoked: true,
                }],
                ttl_ms: 60_000,
                allowed_protected_account_tokens: vec![protected_account_token(0)],
            },
        )
        .expect("revoked key is valid config but cannot issue");

        let rejected = issuer.issue(&protected_account_token(0), None, current_unix_ms());

        assert_eq!(
            rejected
                .expect_err("revoked key should not issue")
                .reason_code,
            "issuer.signing_key_unavailable"
        );
        assert_eq!(issuer.audit_entries()[0].outcome, "rejected");
    }

    #[test]
    fn protected_account_attestation_issuer_debug_and_zero_capacity_audit_are_safe() {
        let account_token = protected_account_token(0);
        let config = ProtectedAccountAttestationIssuerConfig {
            signing_keys: vec![RelayProtectedAccountAttestationKeyConfig {
                key_id: "acct-attest-key-1".to_string(),
                secret: "protected account attestation secret".to_string(),
                not_before_ms: None,
                not_after_ms: None,
                revoked: false,
            }],
            ttl_ms: 60_000,
            allowed_protected_account_tokens: vec![account_token.clone()],
        };

        let debug = format!("{config:?}");

        assert!(!debug.contains("protected account attestation secret"));
        assert!(!debug.contains(&account_token));
        assert!(debug.contains("allowed_protected_account_tokens_count"));

        let auth_audit = InMemoryRelayAuthRejectionAuditStore::new(0);
        auth_audit.record(RelayAuthRejectionAuditEntry {
            request_id: "request_1".to_string(),
            timestamp_ms: current_unix_ms(),
            reason_code: "relay.auth.test".to_string(),
            request_auth_key_id: None,
            protected_account_attestation_key_id: None,
            has_protected_account_token: true,
            caller_context_present: false,
            local_safety_telemetry_count: 0,
        });
        assert!(auth_audit.entries().is_empty());

        let issuer_audit = InMemoryProtectedAccountAttestationIssuerAuditStore::new(0);
        issuer_audit.record(ProtectedAccountAttestationIssuerAuditEntry {
            timestamp_ms: current_unix_ms(),
            outcome: "rejected".to_string(),
            reason_code: "issuer.test".to_string(),
            key_id: None,
            has_protected_account_token: true,
            requested_ttl_ms: Some(60_000),
            expires_at_ms: None,
        });
        assert!(issuer_audit.entries().is_empty());
    }

    #[test]
    fn json_file_protected_account_attestation_issuer_audit_persists_without_token_leak() {
        let path = relay_temp_path("issuer-audit");
        let account_token = protected_account_token(0);
        let issuer = ProtectedAccountAttestationIssuer::from_config(
            ProtectedAccountAttestationIssuerConfig {
                signing_keys: vec![RelayProtectedAccountAttestationKeyConfig {
                    key_id: "acct-attest-key-1".to_string(),
                    secret: "protected account attestation secret".to_string(),
                    not_before_ms: None,
                    not_after_ms: None,
                    revoked: false,
                }],
                ttl_ms: 60_000,
                allowed_protected_account_tokens: vec![account_token.clone()],
            },
        )
        .expect("issuer config should validate")
        .with_persistence_config(ProtectedAccountAttestationIssuerPersistenceConfig {
            audit_store_path: Some(path.clone()),
            audit_store_capacity: 8,
        })
        .expect("persistent issuer audit config should wire file store");

        issuer
            .issue(&account_token, None, current_unix_ms())
            .expect("issuer should issue attestation");

        let reopened = JsonFileProtectedAccountAttestationIssuerAuditStore::open(&path, 8)
            .expect("persistent issuer audit store should reopen");
        let audit_entries = reopened.entries();
        let audit_json = fs::read_to_string(&path).expect("audit file should be readable");

        assert_eq!(audit_entries.len(), 1);
        assert_eq!(audit_entries[0].outcome, "issued");
        assert_eq!(audit_entries[0].reason_code, "issuer.attestation_issued");
        assert!(!audit_json.contains(&account_token));
        assert!(!audit_json.contains("protected account attestation secret"));
    }

    #[test]
    fn relay_service_records_privacy_safe_telemetry_as_reputation_hint() {
        let service = RelayService::new();
        let sender_token = "snd_01H00000000000000000000000".to_string();

        for hour in 0..2 {
            service.handle_analyze(request_with_safety_telemetry_from_account(
                &sender_token,
                hour,
                hour,
            ));
        }

        let response = service.handle_analyze(request_with_safety_telemetry_from_account(
            &sender_token,
            2,
            2,
        ));

        assert!(response.sender_reputation_hint.unwrap_or_default() >= 0.7);
        assert_eq!(
            response.expires_at_ms,
            Some(1_778_652_000_000 + 2 * 3_600_000 + RELAY_RESPONSE_TTL_MS)
        );
        assert!(response
            .correlation_findings
            .contains(&"relay.context.cross_conversation_safety_telemetry".to_string()));
    }

    #[test]
    fn relay_service_uses_subject_sender_token_without_new_telemetry() {
        let service = RelayService::new();
        let sender_token = "snd_01H00000000000000000000000".to_string();

        for hour in 0..3 {
            service.handle_analyze(request_with_safety_telemetry_from_account(
                &sender_token,
                hour,
                hour,
            ));
        }

        let response = service.handle_analyze(AgentAnalyzeRequest {
            request_id: "req_lookup_only".to_string(),
            sender_token: Some(sender_token),
            privacy_mode: RelayPrivacyMode::MetadataOnly,
            ..AgentAnalyzeRequest::default()
        });

        assert!(response.sender_reputation_hint.unwrap_or_default() >= 0.7);
        assert!(response
            .correlation_findings
            .contains(&"relay.context.cross_conversation_safety_telemetry".to_string()));
    }

    #[test]
    fn relay_service_signs_response_when_auth_key_configured() {
        let service = RelayService::new()
            .with_response_auth_key("relay-key-1", b"relay response auth test secret".to_vec());
        let sender_token = "snd_01H00000000000000000000000".to_string();

        let response = service.handle_analyze(AgentAnalyzeRequest {
            request_id: "req_signed_response".to_string(),
            sender_token: Some(sender_token.clone()),
            privacy_mode: RelayPrivacyMode::MetadataOnly,
            ..AgentAnalyzeRequest::default()
        });

        assert!(response.auth.is_some());
        assert!(verify_relay_response_auth(
            &response,
            &sender_token,
            "relay-key-1",
            b"relay response auth test secret"
        ));
    }

    #[test]
    fn relay_service_can_sign_against_privacy_safe_telemetry_sender_token() {
        let service = RelayService::new()
            .with_response_auth_key("relay-key-1", b"relay response auth test secret".to_vec());
        let sender_token = "snd_01H00000000000000000000000".to_string();

        let response = service.handle_analyze(request_with_safety_telemetry_from_account(
            &sender_token,
            0,
            0,
        ));

        assert!(response.auth.is_some());
        assert!(verify_relay_response_auth(
            &response,
            &sender_token,
            "relay-key-1",
            b"relay response auth test secret"
        ));
    }

    #[test]
    fn relay_service_builds_from_serialized_auth_config_with_rotation_and_lifecycle() {
        let request_secret_previous = "relay request previous secret";
        let request_secret_current = "relay request current secret";
        let response_secret_current = "relay response current secret";
        let attestation_secret_previous = "previous account attestation secret";
        let config = RelayAuthConfig {
            request_auth_keys: vec![
                RelaySharedSecretKeyConfig {
                    key_id: "relay-req-current".to_string(),
                    secret: request_secret_current.to_string(),
                },
                RelaySharedSecretKeyConfig {
                    key_id: "relay-req-previous".to_string(),
                    secret: request_secret_previous.to_string(),
                },
            ],
            response_auth_key: Some(RelaySharedSecretKeyConfig {
                key_id: "relay-resp-current".to_string(),
                secret: response_secret_current.to_string(),
            }),
            protected_account_attestation_keys: vec![
                RelayProtectedAccountAttestationKeyConfig {
                    key_id: "acct-attest-current".to_string(),
                    secret: "current account attestation secret".to_string(),
                    not_before_ms: Some(1),
                    not_after_ms: Some(current_unix_ms().saturating_add(600_000)),
                    revoked: false,
                },
                RelayProtectedAccountAttestationKeyConfig {
                    key_id: "acct-attest-previous".to_string(),
                    secret: attestation_secret_previous.to_string(),
                    not_before_ms: Some(1),
                    not_after_ms: Some(current_unix_ms().saturating_add(600_000)),
                    revoked: false,
                },
            ],
            protected_account_attestation_max_future_ttl_ms: Some(600_000),
        };
        let json = serde_json::to_string(&config).expect("relay auth config serializes");
        let decoded: RelayAuthConfig =
            serde_json::from_str(&json).expect("relay auth config deserializes");
        let service = RelayService::from_auth_config(decoded).expect("valid relay auth config");

        let sender_token = "snd_01H00000000000000000000000".to_string();
        let mut request = request_with_safety_telemetry_from_account(&sender_token, 0, 0);
        let token = request
            .protected_account_token
            .as_deref()
            .expect("test request has protected account token");
        request.protected_account_attestation = sign_protected_account_token_attestation(
            token,
            attestation_expires_at_ms(),
            "acct-attest-previous",
            attestation_secret_previous.as_bytes(),
        );
        request.auth = sign_relay_request_auth(
            &request,
            "relay-req-previous",
            request_secret_previous.as_bytes(),
        );

        let response = service.handle_analyze(request);

        assert!(!response
            .reason_codes
            .contains(&"relay.auth.request_invalid".to_string()));
        assert!(!response
            .reason_codes
            .contains(&"relay.auth.protected_account_attestation_invalid".to_string()));
        assert!(response.sender_reputation_hint.is_some());
        assert!(verify_relay_response_auth(
            &response,
            &sender_token,
            "relay-resp-current",
            response_secret_current.as_bytes()
        ));
    }

    #[test]
    fn relay_auth_config_validation_rejects_deploy_footguns() {
        let duplicate_request_keys = RelayAuthConfig {
            request_auth_keys: vec![
                RelaySharedSecretKeyConfig {
                    key_id: "relay-req-key".to_string(),
                    secret: "relay request auth test secret".to_string(),
                },
                RelaySharedSecretKeyConfig {
                    key_id: " relay-req-key ".to_string(),
                    secret: "relay request auth other secret".to_string(),
                },
            ],
            ..RelayAuthConfig::default()
        };
        assert_config_error_contains(
            duplicate_request_keys.validate(),
            "relay request auth key_id relay-req-key is duplicated",
        );

        let invalid_key_id = RelayAuthConfig {
            response_auth_key: Some(RelaySharedSecretKeyConfig {
                key_id: "bad key id".to_string(),
                secret: "relay response auth test secret".to_string(),
            }),
            ..RelayAuthConfig::default()
        };
        assert_config_error_contains(
            invalid_key_id.validate(),
            "relay response key_id must be 1..64 ASCII",
        );

        let short_secret = RelayAuthConfig {
            request_auth_keys: vec![RelaySharedSecretKeyConfig {
                key_id: "relay-req-key".to_string(),
                secret: "short".to_string(),
            }],
            ..RelayAuthConfig::default()
        };
        assert_config_error_contains(short_secret.validate(), "secret must be 16..=128 bytes");

        let invalid_lifecycle = RelayAuthConfig {
            protected_account_attestation_keys: vec![RelayProtectedAccountAttestationKeyConfig {
                key_id: "acct-attest-key".to_string(),
                secret: "protected account attestation secret".to_string(),
                not_before_ms: Some(200),
                not_after_ms: Some(100),
                revoked: false,
            }],
            ..RelayAuthConfig::default()
        };
        assert_config_error_contains(
            invalid_lifecycle.validate(),
            "protected account attestation key_id acct-attest-key has invalid lifecycle window",
        );

        let zero_ttl = RelayAuthConfig {
            protected_account_attestation_max_future_ttl_ms: Some(0),
            ..RelayAuthConfig::default()
        };
        assert_config_error_contains(
            zero_ttl.validate(),
            "protected account attestation max future ttl must be",
        );
    }

    #[test]
    fn relay_auth_config_debug_redacts_shared_secrets() {
        let config = RelayAuthConfig {
            request_auth_keys: vec![RelaySharedSecretKeyConfig {
                key_id: "relay-req-key".to_string(),
                secret: "relay request auth test secret".to_string(),
            }],
            response_auth_key: Some(RelaySharedSecretKeyConfig {
                key_id: "relay-resp-key".to_string(),
                secret: "relay response auth test secret".to_string(),
            }),
            protected_account_attestation_keys: vec![RelayProtectedAccountAttestationKeyConfig {
                key_id: "acct-attest-key".to_string(),
                secret: "protected account attestation secret".to_string(),
                not_before_ms: None,
                not_after_ms: None,
                revoked: false,
            }],
            ..RelayAuthConfig::default()
        };

        let debug = format!("{config:?}");

        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("relay request auth test secret"));
        assert!(!debug.contains("relay response auth test secret"));
        assert!(!debug.contains("protected account attestation secret"));
    }

    #[test]
    fn relay_service_rejects_unsigned_tampered_or_replayed_requests_when_auth_key_configured() {
        let service = RelayService::new().with_request_auth_key(
            "relay-req-key-1",
            b"relay request auth test secret".to_vec(),
        );
        let sender_token = "snd_01H00000000000000000000000".to_string();
        let mut request = AgentAnalyzeRequest {
            request_id: "req_signed_request".to_string(),
            sender_token: Some(sender_token),
            privacy_mode: RelayPrivacyMode::MetadataOnly,
            ..AgentAnalyzeRequest::default()
        };

        let unsigned_response = service.handle_analyze(request.clone());
        assert!(unsigned_response
            .reason_codes
            .contains(&"relay.auth.request_invalid".to_string()));

        request.auth = sign_relay_request_auth(
            &request,
            "relay-req-key-1",
            b"relay request auth test secret",
        );
        assert!(verify_relay_request_auth(
            &request,
            "relay-req-key-1",
            b"relay request auth test secret"
        ));

        let mut tampered = request.clone();
        tampered.privacy_mode = RelayPrivacyMode::MessageOnly;
        let tampered_response = service.handle_analyze(tampered);
        assert!(tampered_response
            .reason_codes
            .contains(&"relay.auth.request_invalid".to_string()));

        let accepted_response = service.handle_analyze(request.clone());
        assert!(!accepted_response
            .reason_codes
            .contains(&"relay.auth.request_invalid".to_string()));
        assert!(!accepted_response
            .reason_codes
            .contains(&"relay.auth.request_replay".to_string()));

        let replay_response = service.handle_analyze(request);
        assert!(replay_response
            .reason_codes
            .contains(&"relay.auth.request_replay".to_string()));
    }

    #[test]
    fn relay_service_replay_store_is_shared_across_relay_instances() {
        let replay_store: Arc<dyn RelayRequestReplayStore> =
            Arc::new(InMemoryRelayRequestReplayStore::default());
        let request_secret = b"relay request auth test secret";
        let service_a = RelayService::new()
            .with_request_auth_key("relay-req-key-1", request_secret.to_vec())
            .with_request_replay_store(replay_store.clone());
        let service_b = RelayService::new()
            .with_request_auth_key("relay-req-key-1", request_secret.to_vec())
            .with_request_replay_store(replay_store);
        let mut request = AgentAnalyzeRequest {
            request_id: "req_cluster_replay".to_string(),
            sender_token: Some("snd_01H00000000000000000000000".to_string()),
            privacy_mode: RelayPrivacyMode::MetadataOnly,
            ..AgentAnalyzeRequest::default()
        };
        request.auth = sign_relay_request_auth(&request, "relay-req-key-1", request_secret);

        let accepted = service_a.handle_analyze(request.clone());
        let replayed_on_other_instance = service_b.handle_analyze(request);

        assert!(!accepted
            .reason_codes
            .contains(&"relay.auth.request_replay".to_string()));
        assert!(replayed_on_other_instance
            .reason_codes
            .contains(&"relay.auth.request_replay".to_string()));
    }

    #[test]
    fn json_file_relay_request_replay_store_persists_across_restarts() {
        let path = relay_temp_path("request-replay");
        let request_secret = b"relay request auth test secret";
        let service_a = RelayService::new()
            .with_request_auth_key("relay-req-key-1", request_secret.to_vec())
            .with_request_replay_store(Arc::new(
                JsonFileRelayRequestReplayStore::open(&path, 16)
                    .expect("persistent replay store should open"),
            ));
        let mut request = AgentAnalyzeRequest {
            request_id: "req_persistent_replay".to_string(),
            sender_token: Some("snd_01H00000000000000000000000".to_string()),
            privacy_mode: RelayPrivacyMode::MetadataOnly,
            ..AgentAnalyzeRequest::default()
        };
        request.auth = sign_relay_request_auth(&request, "relay-req-key-1", request_secret);

        let accepted = service_a.handle_analyze(request.clone());
        let service_b = RelayService::new()
            .with_request_auth_key("relay-req-key-1", request_secret.to_vec())
            .with_request_replay_store(Arc::new(
                JsonFileRelayRequestReplayStore::open(&path, 16)
                    .expect("persistent replay store should reopen"),
            ));
        let replayed_after_restart = service_b.handle_analyze(request);

        assert!(!accepted
            .reason_codes
            .contains(&"relay.auth.request_replay".to_string()));
        assert!(replayed_after_restart
            .reason_codes
            .contains(&"relay.auth.request_replay".to_string()));
    }

    #[test]
    fn relay_service_auth_rejection_audit_store_is_shared_and_bounded() {
        let audit_store: Arc<dyn RelayAuthRejectionAuditStore> =
            Arc::new(InMemoryRelayAuthRejectionAuditStore::new(1));
        let request_secret = b"relay request auth test secret";
        let service_a = RelayService::new()
            .with_request_auth_key("relay-req-key-1", request_secret.to_vec())
            .with_auth_rejection_audit_store(audit_store.clone());
        let service_b = RelayService::new()
            .with_request_auth_key("relay-req-key-1", request_secret.to_vec())
            .with_auth_rejection_audit_store(audit_store);

        let first = AgentAnalyzeRequest {
            request_id: "req_invalid_a".to_string(),
            sender_token: Some("snd_01H00000000000000000000000".to_string()),
            privacy_mode: RelayPrivacyMode::MetadataOnly,
            ..AgentAnalyzeRequest::default()
        };
        let second = AgentAnalyzeRequest {
            request_id: "req_invalid_b".to_string(),
            sender_token: Some("snd_01H00000000000000000000001".to_string()),
            privacy_mode: RelayPrivacyMode::MetadataOnly,
            ..AgentAnalyzeRequest::default()
        };

        service_a.handle_analyze(first);
        service_b.handle_analyze(second);

        let audit_entries = service_a.auth_rejection_audit_entries();
        assert_eq!(audit_entries.len(), 1);
        assert_eq!(audit_entries[0].request_id, "req_invalid_b");
        assert_eq!(audit_entries[0].reason_code, "relay.auth.request_invalid");
    }

    #[test]
    fn json_file_relay_auth_rejection_audit_store_persists_and_bounds_entries() {
        let path = relay_temp_path("auth-rejection-audit");
        let audit_store: Arc<dyn RelayAuthRejectionAuditStore> = Arc::new(
            JsonFileRelayAuthRejectionAuditStore::open(&path, 1)
                .expect("persistent auth rejection audit store should open"),
        );
        let request_secret = b"relay request auth test secret";
        let service = RelayService::new()
            .with_request_auth_key("relay-req-key-1", request_secret.to_vec())
            .with_auth_rejection_audit_store(audit_store);

        service.handle_analyze(AgentAnalyzeRequest {
            request_id: "req_persistent_invalid_a".to_string(),
            sender_token: Some("snd_01H00000000000000000000000".to_string()),
            privacy_mode: RelayPrivacyMode::MetadataOnly,
            ..AgentAnalyzeRequest::default()
        });
        service.handle_analyze(AgentAnalyzeRequest {
            request_id: "req_persistent_invalid_b".to_string(),
            sender_token: Some("snd_01H00000000000000000000001".to_string()),
            privacy_mode: RelayPrivacyMode::MetadataOnly,
            ..AgentAnalyzeRequest::default()
        });

        let reopened = JsonFileRelayAuthRejectionAuditStore::open(&path, 1)
            .expect("persistent auth rejection audit store should reopen");
        let audit_entries = reopened.entries();

        assert_eq!(audit_entries.len(), 1);
        assert_eq!(audit_entries[0].request_id, "req_persistent_invalid_b");
        assert_eq!(audit_entries[0].reason_code, "relay.auth.request_invalid");
    }

    #[test]
    fn relay_service_persistence_config_wires_json_file_stores() {
        let replay_path = relay_temp_path("persistence-config-replay");
        let audit_path = relay_temp_path("persistence-config-audit");
        let request_secret = b"relay request auth test secret";
        let persistence_config = RelayPersistenceConfig {
            reputation_store_path: None,
            reputation_store_capacity: default_reputation_store_capacity(),
            request_replay_store_path: Some(replay_path),
            request_replay_store_capacity: 16,
            auth_rejection_audit_store_path: Some(audit_path.clone()),
            auth_rejection_audit_store_capacity: 8,
        };
        let service_a = RelayService::new()
            .with_request_auth_key("relay-req-key-1", request_secret.to_vec())
            .with_persistence_config(persistence_config.clone())
            .expect("persistence config should wire file stores");
        let mut request = AgentAnalyzeRequest {
            request_id: "req_configured_persistent_replay".to_string(),
            sender_token: Some("snd_01H00000000000000000000000".to_string()),
            privacy_mode: RelayPrivacyMode::MetadataOnly,
            ..AgentAnalyzeRequest::default()
        };
        request.auth = sign_relay_request_auth(&request, "relay-req-key-1", request_secret);

        let accepted = service_a.handle_analyze(request.clone());
        let service_b = RelayService::new()
            .with_request_auth_key("relay-req-key-1", request_secret.to_vec())
            .with_persistence_config(persistence_config)
            .expect("persistence config should reopen file stores");
        let replayed_after_restart = service_b.handle_analyze(request);
        let audit_entries = JsonFileRelayAuthRejectionAuditStore::open(&audit_path, 8)
            .expect("audit store should reopen")
            .entries();

        assert!(!accepted
            .reason_codes
            .contains(&"relay.auth.request_replay".to_string()));
        assert!(replayed_after_restart
            .reason_codes
            .contains(&"relay.auth.request_replay".to_string()));
        assert_eq!(audit_entries.len(), 1);
        assert_eq!(audit_entries[0].reason_code, "relay.auth.request_replay");

        let invalid_config = RelayPersistenceConfig {
            request_replay_store_path: Some(relay_temp_path("invalid-replay-capacity")),
            request_replay_store_capacity: 0,
            ..RelayPersistenceConfig::default()
        };
        assert!(invalid_config.validate().is_err());
    }

    #[test]
    fn relay_service_persistence_config_reopens_reputation_store_for_sender_hints() {
        let reputation_path = relay_temp_path("persistence-config-reputation");
        let persistence_config = RelayPersistenceConfig {
            reputation_store_path: Some(reputation_path),
            reputation_store_capacity: 8,
            ..RelayPersistenceConfig::default()
        };
        let sender_token = "snd_01H00000000000000000000000".to_string();
        let service_a = RelayService::new()
            .with_persistence_config(persistence_config.clone())
            .expect("persistence config should wire reputation store");

        let first_response = service_a.handle_analyze(request_with_safety_telemetry_from_account(
            &sender_token,
            0,
            0,
        ));
        let service_b = RelayService::new()
            .with_persistence_config(persistence_config)
            .expect("persistence config should reopen reputation store");
        let lookup = AgentAnalyzeRequest {
            request_id: "req_reputation_lookup_after_restart".to_string(),
            sender_token: Some(sender_token),
            privacy_mode: RelayPrivacyMode::MetadataOnly,
            ..AgentAnalyzeRequest::default()
        };
        let reopened_response = service_b.handle_analyze(lookup);

        assert!(first_response.sender_reputation_hint.unwrap_or_default() > 0.0);
        assert!(reopened_response.sender_reputation_hint.unwrap_or_default() > 0.0);

        let invalid_config = RelayPersistenceConfig {
            reputation_store_path: Some(relay_temp_path("invalid-reputation-capacity")),
            reputation_store_capacity: 0,
            ..RelayPersistenceConfig::default()
        };
        assert!(invalid_config.validate().is_err());
    }

    #[test]
    fn relay_service_rejects_unsigned_poisoning_without_recording_reputation() {
        let request_secret = b"relay request auth test secret";
        let service =
            RelayService::new().with_request_auth_key("relay-req-key-1", request_secret.to_vec());
        let sender_token = "snd_01H00000000000000000000000".to_string();

        let unsigned_poisoning = request_with_safety_telemetry_from_account(&sender_token, 0, 0);
        let rejected = service.handle_analyze(unsigned_poisoning);
        assert!(rejected
            .reason_codes
            .contains(&"relay.auth.request_invalid".to_string()));

        let mut lookup = AgentAnalyzeRequest {
            request_id: "req_lookup_after_unsigned_poisoning".to_string(),
            sender_token: Some(sender_token),
            privacy_mode: RelayPrivacyMode::MetadataOnly,
            ..AgentAnalyzeRequest::default()
        };
        lookup.auth = sign_relay_request_auth(&lookup, "relay-req-key-1", request_secret);

        let response = service.handle_analyze(lookup);

        assert!(!response
            .reason_codes
            .contains(&"relay.auth.request_invalid".to_string()));
        assert!(response.sender_reputation_hint.is_none());
        assert!(!response
            .correlation_findings
            .contains(&"relay.context.cross_conversation_safety_telemetry".to_string()));
    }

    #[test]
    fn relay_service_caps_signed_single_child_poisoning_flood() {
        let request_secret = b"relay request auth test secret";
        let service =
            RelayService::new().with_request_auth_key("relay-req-key-1", request_secret.to_vec());
        let sender_token = "snd_01H00000000000000000000000".to_string();
        let mut response = RelayAnalyzeResponse::default();

        for hour in 0..32 {
            let mut request = request_with_safety_telemetry_from_account(&sender_token, hour, 0);
            request.auth = sign_relay_request_auth(&request, "relay-req-key-1", request_secret);
            response = service.handle_analyze(request);
        }

        assert!(response.sender_reputation_hint.unwrap_or_default() <= 0.64);
        assert!(response.sender_reputation_hint.unwrap_or_default() < 0.7);
        assert!(!response
            .correlation_findings
            .contains(&"relay.context.cross_conversation_safety_telemetry".to_string()));
    }

    #[test]
    fn relay_service_rejects_authenticated_account_token_mismatch_without_recording_reputation() {
        let request_secret = b"relay request auth test secret";
        let service =
            RelayService::new().with_request_auth_key("relay-req-key-1", request_secret.to_vec());
        let sender_token = "snd_01H00000000000000000000000".to_string();
        let caller_token = protected_account_token(0);

        let mut mismatched = request_with_safety_telemetry_from_account(&sender_token, 0, 7);
        mismatched.protected_account_token = Some(protected_account_token(7));
        mismatched.auth = sign_relay_request_auth(&mismatched, "relay-req-key-1", request_secret);

        let rejected = service.handle_authenticated_analyze(
            mismatched,
            RelayCallerContext::new(caller_token.clone()),
        );

        assert!(rejected
            .reason_codes
            .contains(&"relay.auth.protected_account_mismatch".to_string()));

        let mut lookup = AgentAnalyzeRequest {
            request_id: "req_lookup_after_account_mismatch".to_string(),
            sender_token: Some(sender_token),
            protected_account_token: Some(caller_token.clone()),
            privacy_mode: RelayPrivacyMode::MetadataOnly,
            ..AgentAnalyzeRequest::default()
        };
        lookup.auth = sign_relay_request_auth(&lookup, "relay-req-key-1", request_secret);

        let response =
            service.handle_authenticated_analyze(lookup, RelayCallerContext::new(caller_token));

        assert!(response.sender_reputation_hint.is_none());
        assert!(!response
            .correlation_findings
            .contains(&"relay.context.cross_conversation_safety_telemetry".to_string()));
    }

    #[test]
    fn relay_service_allows_independent_authenticated_accounts_to_escalate_reputation() {
        let request_secret = b"relay request auth test secret";
        let service =
            RelayService::new().with_request_auth_key("relay-req-key-1", request_secret.to_vec());
        let sender_token = "snd_01H00000000000000000000000".to_string();
        let mut response = RelayAnalyzeResponse::default();

        for account_index in 0..3 {
            let account_token = protected_account_token(account_index);
            let mut request = request_with_safety_telemetry_from_account(
                &sender_token,
                account_index,
                account_index,
            );
            request.protected_account_token = Some(account_token.clone());
            request.auth = sign_relay_request_auth(&request, "relay-req-key-1", request_secret);
            response = service
                .handle_authenticated_analyze(request, RelayCallerContext::new(account_token));
        }

        assert!(response.sender_reputation_hint.unwrap_or_default() >= 0.7);
        assert!(response
            .correlation_findings
            .contains(&"relay.context.cross_conversation_safety_telemetry".to_string()));
    }

    #[test]
    fn relay_service_requires_account_attestation_when_key_configured() {
        let request_secret = b"relay request auth test secret";
        let attestation_secret = b"protected account attestation secret";
        let service = RelayService::new()
            .with_request_auth_key("relay-req-key-1", request_secret.to_vec())
            .with_protected_account_attestation_key(
                "acct-attest-key-1",
                attestation_secret.to_vec(),
            );
        let sender_token = "snd_01H00000000000000000000000".to_string();
        let mut request = request_with_safety_telemetry_from_account(&sender_token, 0, 0);
        request.auth = sign_relay_request_auth(&request, "relay-req-key-1", request_secret);

        let rejected = service.handle_analyze(request);

        assert!(rejected
            .reason_codes
            .contains(&"relay.auth.protected_account_attestation_missing".to_string()));

        let mut lookup = AgentAnalyzeRequest {
            request_id: "req_lookup_after_missing_account_attestation".to_string(),
            sender_token: Some(sender_token),
            protected_account_token: Some(protected_account_token(0)),
            privacy_mode: RelayPrivacyMode::MetadataOnly,
            ..AgentAnalyzeRequest::default()
        };
        sign_request_with_account_attestation(&mut lookup, request_secret, attestation_secret);

        let response = service.handle_analyze(lookup);

        assert!(response.sender_reputation_hint.is_none());
    }

    #[test]
    fn relay_service_rejects_unsigned_attested_payload_without_recording_reputation() {
        let attestation_secret = b"protected account attestation secret";
        let service = RelayService::new().with_protected_account_attestation_key(
            "acct-attest-key-1",
            attestation_secret.to_vec(),
        );
        let sender_token = "snd_01H00000000000000000000000".to_string();
        let account_token = protected_account_token(0);
        let mut request = request_with_safety_telemetry_from_account(&sender_token, 0, 0);
        request.protected_account_attestation = sign_protected_account_token_attestation(
            &account_token,
            attestation_expires_at_ms(),
            "acct-attest-key-1",
            attestation_secret,
        );

        let rejected = service.handle_analyze(request);

        assert!(rejected
            .reason_codes
            .contains(&"relay.auth.request_required_for_account_attestation".to_string()));

        let lookup = AgentAnalyzeRequest {
            request_id: "req_lookup_after_unsigned_attested_poisoning".to_string(),
            sender_token: Some(sender_token),
            protected_account_token: Some(account_token.clone()),
            privacy_mode: RelayPrivacyMode::MetadataOnly,
            ..AgentAnalyzeRequest::default()
        };
        let response =
            service.handle_authenticated_analyze(lookup, RelayCallerContext::new(account_token));

        assert!(response.sender_reputation_hint.is_none());
        assert!(!response
            .correlation_findings
            .contains(&"relay.context.cross_conversation_safety_telemetry".to_string()));
    }

    #[test]
    fn relay_service_rejects_invalid_account_attestation_after_valid_request_auth() {
        let request_secret = b"relay request auth test secret";
        let attestation_secret = b"protected account attestation secret";
        let service = RelayService::new()
            .with_request_auth_key("relay-req-key-1", request_secret.to_vec())
            .with_protected_account_attestation_key(
                "acct-attest-key-1",
                attestation_secret.to_vec(),
            );
        let sender_token = "snd_01H00000000000000000000000".to_string();
        let mut request = request_with_safety_telemetry_from_account(&sender_token, 0, 0);
        let token = request
            .protected_account_token
            .as_deref()
            .expect("test request has protected account token");
        request.protected_account_attestation = sign_protected_account_token_attestation(
            token,
            attestation_expires_at_ms(),
            "acct-attest-key-1",
            b"wrong attestation secret",
        );
        request.auth = sign_relay_request_auth(&request, "relay-req-key-1", request_secret);

        let rejected = service.handle_analyze(request);

        assert!(!rejected
            .reason_codes
            .contains(&"relay.auth.request_invalid".to_string()));
        assert!(rejected
            .reason_codes
            .contains(&"relay.auth.protected_account_attestation_invalid".to_string()));
    }

    #[test]
    fn relay_service_rejects_expired_account_attestation_after_valid_request_auth() {
        let request_secret = b"relay request auth test secret";
        let attestation_secret = b"protected account attestation secret";
        let service = RelayService::new()
            .with_request_auth_key("relay-req-key-1", request_secret.to_vec())
            .with_protected_account_attestation_key(
                "acct-attest-key-1",
                attestation_secret.to_vec(),
            );
        let sender_token = "snd_01H00000000000000000000000".to_string();
        let mut request = request_with_safety_telemetry_from_account(&sender_token, 0, 0);
        let token = request
            .protected_account_token
            .as_deref()
            .expect("test request has protected account token");
        request.protected_account_attestation = sign_protected_account_token_attestation(
            token,
            1,
            "acct-attest-key-1",
            attestation_secret,
        );
        request.auth = sign_relay_request_auth(&request, "relay-req-key-1", request_secret);

        let rejected = service.handle_analyze(request);

        assert!(!rejected
            .reason_codes
            .contains(&"relay.auth.request_invalid".to_string()));
        assert!(rejected
            .reason_codes
            .contains(&"relay.auth.protected_account_attestation_expired".to_string()));
    }

    #[test]
    fn relay_service_rejects_attested_top_level_token_mismatched_to_telemetry() {
        let request_secret = b"relay request auth test secret";
        let attestation_secret = b"protected account attestation secret";
        let service = RelayService::new()
            .with_request_auth_key("relay-req-key-1", request_secret.to_vec())
            .with_protected_account_attestation_key(
                "acct-attest-key-1",
                attestation_secret.to_vec(),
            );
        let sender_token = "snd_01H00000000000000000000000".to_string();
        let mut request = request_with_safety_telemetry_from_account(&sender_token, 0, 7);
        request.protected_account_token = Some(protected_account_token(0));
        sign_request_with_account_attestation(&mut request, request_secret, attestation_secret);

        let rejected = service.handle_analyze(request);

        assert!(rejected
            .reason_codes
            .contains(&"relay.auth.protected_account_mismatch".to_string()));
    }

    #[test]
    fn relay_service_accepts_attested_independent_accounts_to_escalate_reputation() {
        let request_secret = b"relay request auth test secret";
        let attestation_secret = b"protected account attestation secret";
        let service = RelayService::new()
            .with_request_auth_key("relay-req-key-1", request_secret.to_vec())
            .with_protected_account_attestation_key(
                "acct-attest-key-1",
                attestation_secret.to_vec(),
            );
        let sender_token = "snd_01H00000000000000000000000".to_string();
        let mut response = RelayAnalyzeResponse::default();

        for account_index in 0..3 {
            let mut request = request_with_safety_telemetry_from_account(
                &sender_token,
                account_index,
                account_index,
            );
            sign_request_with_account_attestation(&mut request, request_secret, attestation_secret);
            response = service.handle_analyze(request);
        }

        assert!(response.sender_reputation_hint.unwrap_or_default() >= 0.7);
        assert!(response
            .correlation_findings
            .contains(&"relay.context.cross_conversation_safety_telemetry".to_string()));
    }

    #[test]
    fn relay_service_accepts_account_attestation_rotation_key_set() {
        let request_secret = b"relay request auth test secret";
        let previous_attestation_secret = b"previous account attestation secret";
        let service = RelayService::new()
            .with_request_auth_key("relay-req-key-1", request_secret.to_vec())
            .with_protected_account_attestation_key(
                "acct-attest-current",
                b"current account attestation secret".to_vec(),
            )
            .with_additional_protected_account_attestation_key(
                "acct-attest-previous",
                previous_attestation_secret.to_vec(),
            );
        let sender_token = "snd_01H00000000000000000000000".to_string();
        let mut request = request_with_safety_telemetry_from_account(&sender_token, 0, 0);
        let token = request
            .protected_account_token
            .as_deref()
            .expect("test request has protected account token");
        request.protected_account_attestation = sign_protected_account_token_attestation(
            token,
            attestation_expires_at_ms(),
            "acct-attest-previous",
            previous_attestation_secret,
        );
        request.auth = sign_relay_request_auth(&request, "relay-req-key-1", request_secret);

        let response = service.handle_analyze(request);

        assert!(!response
            .reason_codes
            .contains(&"relay.auth.protected_account_attestation_invalid".to_string()));
        assert!(response.sender_reputation_hint.is_some());
    }

    #[test]
    fn relay_service_enforces_account_attestation_key_lifecycle_window() {
        let request_secret = b"relay request auth test secret";
        let attestation_secret = b"protected account attestation secret";
        let sender_token = "snd_01H00000000000000000000000".to_string();

        let not_yet_valid_service = RelayService::new()
            .with_request_auth_key("relay-req-key-1", request_secret.to_vec())
            .with_protected_account_attestation_key_lifecycle(
                "acct-attest-key-1",
                attestation_secret.to_vec(),
                Some(current_unix_ms().saturating_add(60_000)),
                None,
                false,
            );
        let mut not_yet_valid_request =
            request_with_safety_telemetry_from_account(&sender_token, 0, 0);
        sign_request_with_account_attestation(
            &mut not_yet_valid_request,
            request_secret,
            attestation_secret,
        );

        let not_yet_valid = not_yet_valid_service.handle_analyze(not_yet_valid_request);

        assert!(not_yet_valid
            .reason_codes
            .contains(&"relay.auth.protected_account_attestation_key_not_yet_valid".to_string()));

        let expired_service = RelayService::new()
            .with_request_auth_key("relay-req-key-1", request_secret.to_vec())
            .with_protected_account_attestation_key_lifecycle(
                "acct-attest-key-1",
                attestation_secret.to_vec(),
                None,
                Some(1),
                false,
            );
        let mut expired_request = request_with_safety_telemetry_from_account(&sender_token, 1, 0);
        sign_request_with_account_attestation(
            &mut expired_request,
            request_secret,
            attestation_secret,
        );

        let expired = expired_service.handle_analyze(expired_request);

        assert!(expired
            .reason_codes
            .contains(&"relay.auth.protected_account_attestation_key_expired".to_string()));

        let active_service = RelayService::new()
            .with_request_auth_key("relay-req-key-1", request_secret.to_vec())
            .with_protected_account_attestation_key_lifecycle(
                "acct-attest-key-1",
                attestation_secret.to_vec(),
                Some(1),
                Some(current_unix_ms().saturating_add(600_000)),
                false,
            );
        let mut active_request = request_with_safety_telemetry_from_account(&sender_token, 2, 0);
        sign_request_with_account_attestation(
            &mut active_request,
            request_secret,
            attestation_secret,
        );

        let active = active_service.handle_analyze(active_request);

        assert!(!active
            .reason_codes
            .iter()
            .any(|code| code.starts_with("relay.auth.protected_account_attestation_key")));
        assert!(active.sender_reputation_hint.is_some());
    }

    #[test]
    fn relay_service_rejects_account_attestation_expiry_too_far_in_future_without_recording_reputation(
    ) {
        let request_secret = b"relay request auth test secret";
        let attestation_secret = b"protected account attestation secret";
        let service = RelayService::new()
            .with_request_auth_key("relay-req-key-1", request_secret.to_vec())
            .with_protected_account_attestation_key(
                "acct-attest-key-1",
                attestation_secret.to_vec(),
            )
            .with_protected_account_attestation_max_future_ttl_ms(60_000);
        let sender_token = "snd_01H00000000000000000000000".to_string();
        let account_token = protected_account_token(0);
        let mut request = request_with_safety_telemetry_from_account(&sender_token, 0, 0);
        request.protected_account_attestation = sign_protected_account_token_attestation(
            &account_token,
            current_unix_ms().saturating_add(600_000),
            "acct-attest-key-1",
            attestation_secret,
        );
        request.auth = sign_relay_request_auth(&request, "relay-req-key-1", request_secret);

        let rejected = service.handle_analyze(request);

        assert!(rejected
            .reason_codes
            .contains(&"relay.auth.protected_account_attestation_ttl_exceeded".to_string()));

        let mut lookup = AgentAnalyzeRequest {
            request_id: "req_lookup_after_far_future_attestation".to_string(),
            sender_token: Some(sender_token),
            protected_account_token: Some(account_token.clone()),
            privacy_mode: RelayPrivacyMode::MetadataOnly,
            ..AgentAnalyzeRequest::default()
        };
        lookup.auth = sign_relay_request_auth(&lookup, "relay-req-key-1", request_secret);

        let response =
            service.handle_authenticated_analyze(lookup, RelayCallerContext::new(account_token));

        assert!(response.sender_reputation_hint.is_none());
    }

    #[test]
    fn relay_service_records_privacy_safe_auth_rejection_audit_entries() {
        let request_secret = b"relay request auth test secret";
        let attestation_secret = b"protected account attestation secret";
        let service = RelayService::new()
            .with_request_auth_key("relay-req-key-1", request_secret.to_vec())
            .with_protected_account_attestation_key(
                "acct-attest-key-1",
                attestation_secret.to_vec(),
            )
            .with_protected_account_attestation_max_future_ttl_ms(60_000);
        let sender_token = "snd_01H00000000000000000000000".to_string();
        let account_token = protected_account_token(0);
        let mut request = request_with_safety_telemetry_from_account(&sender_token, 0, 0);
        let request_id = request.request_id.clone();
        request.protected_account_attestation = sign_protected_account_token_attestation(
            &account_token,
            current_unix_ms().saturating_add(600_000),
            "acct-attest-key-1",
            attestation_secret,
        );
        request.auth = sign_relay_request_auth(&request, "relay-req-key-1", request_secret);

        let rejected = service.handle_analyze(request);

        assert!(rejected
            .reason_codes
            .contains(&"relay.auth.protected_account_attestation_ttl_exceeded".to_string()));
        let audit_entries = service.auth_rejection_audit_entries();
        assert_eq!(audit_entries.len(), 1);
        let entry = &audit_entries[0];
        assert_eq!(entry.request_id, request_id);
        assert_eq!(
            entry.reason_code,
            "relay.auth.protected_account_attestation_ttl_exceeded"
        );
        assert_eq!(
            entry.request_auth_key_id.as_deref(),
            Some("relay-req-key-1")
        );
        assert_eq!(
            entry.protected_account_attestation_key_id.as_deref(),
            Some("acct-attest-key-1")
        );
        assert!(entry.has_protected_account_token);
        assert_eq!(entry.local_safety_telemetry_count, 1);

        let serialized = serde_json::to_string(entry).expect("audit entry serializes");
        assert!(!serialized.contains(&sender_token));
        assert!(!serialized.contains(&account_token));
    }

    #[test]
    fn relay_service_rejects_revoked_account_attestation_key_without_recording_reputation() {
        let request_secret = b"relay request auth test secret";
        let attestation_secret = b"protected account attestation secret";
        let service = RelayService::new()
            .with_request_auth_key("relay-req-key-1", request_secret.to_vec())
            .with_protected_account_attestation_key_lifecycle(
                "acct-attest-key-1",
                attestation_secret.to_vec(),
                None,
                None,
                true,
            );
        let sender_token = "snd_01H00000000000000000000000".to_string();
        let account_token = protected_account_token(0);
        let mut request = request_with_safety_telemetry_from_account(&sender_token, 0, 0);
        sign_request_with_account_attestation(&mut request, request_secret, attestation_secret);

        let rejected = service.handle_analyze(request);

        assert!(rejected
            .reason_codes
            .contains(&"relay.auth.protected_account_attestation_key_revoked".to_string()));

        let mut lookup = AgentAnalyzeRequest {
            request_id: "req_lookup_after_revoked_attestation_key".to_string(),
            sender_token: Some(sender_token),
            protected_account_token: Some(account_token.clone()),
            privacy_mode: RelayPrivacyMode::MetadataOnly,
            ..AgentAnalyzeRequest::default()
        };
        lookup.auth = sign_relay_request_auth(&lookup, "relay-req-key-1", request_secret);

        let response =
            service.handle_authenticated_analyze(lookup, RelayCallerContext::new(account_token));

        assert!(response.sender_reputation_hint.is_none());
        assert!(!response
            .correlation_findings
            .contains(&"relay.context.cross_conversation_safety_telemetry".to_string()));
    }

    #[test]
    fn relay_service_caller_context_satisfies_account_binding_without_client_attestation() {
        let request_secret = b"relay request auth test secret";
        let attestation_secret = b"protected account attestation secret";
        let service = RelayService::new()
            .with_request_auth_key("relay-req-key-1", request_secret.to_vec())
            .with_protected_account_attestation_key(
                "acct-attest-key-1",
                attestation_secret.to_vec(),
            );
        let sender_token = "snd_01H00000000000000000000000".to_string();
        let account_token = protected_account_token(0);
        let mut request = request_with_safety_telemetry_from_account(&sender_token, 0, 0);
        request.auth = sign_relay_request_auth(&request, "relay-req-key-1", request_secret);

        let response =
            service.handle_authenticated_analyze(request, RelayCallerContext::new(account_token));

        assert!(!response
            .reason_codes
            .contains(&"relay.auth.protected_account_attestation_missing".to_string()));
        assert!(response.sender_reputation_hint.is_some());
    }

    #[test]
    fn relay_service_accepts_request_auth_rotation_key_set() {
        let service = RelayService::new()
            .with_request_auth_key(
                "relay-req-current",
                b"relay request current secret".to_vec(),
            )
            .with_additional_request_auth_key(
                "relay-req-previous",
                b"relay request previous secret".to_vec(),
            );
        let mut request = AgentAnalyzeRequest {
            request_id: "req_previous_signed".to_string(),
            sender_token: Some("snd_01H00000000000000000000000".to_string()),
            privacy_mode: RelayPrivacyMode::MetadataOnly,
            ..AgentAnalyzeRequest::default()
        };
        request.auth = sign_relay_request_auth(
            &request,
            "relay-req-previous",
            b"relay request previous secret",
        );

        let response = service.handle_analyze(request);

        assert!(!response
            .reason_codes
            .contains(&"relay.auth.request_invalid".to_string()));
        assert!(!response
            .reason_codes
            .contains(&"relay.auth.request_replay".to_string()));
    }

    #[test]
    fn authenticated_agent_relay_loop_feeds_sender_hint_back_to_client() {
        aura_agent_core::aura_kids::pipeline::clear_kids_memory();
        let pattern_db = PatternDatabase::default_mvp();
        let mut runtime = AgentRuntime::new(child_config(), &pattern_db)
            .with_relay_policy(AgentRelayPolicy {
                enabled: true,
                score_threshold: 0.01,
                privacy_mode: RelayPrivacyMode::MetadataOnly,
                protected_account_id: Some("child_account_1".to_string()),
                ..AgentRelayPolicy::default()
            })
            .with_relay_request_auth_key(
                "relay-req-key-1",
                b"relay request auth test secret".to_vec(),
            )
            .with_relay_response_auth_key(
                "relay-key-1",
                b"relay response auth test secret".to_vec(),
            );
        let service = RelayService::new()
            .with_request_auth_key(
                "relay-req-key-1",
                b"relay request auth test secret".to_vec(),
            )
            .with_response_auth_key("relay-key-1", b"relay response auth test secret".to_vec());
        let sender_id: SenderId = "repeat_risky_sender_auth".into();
        let base_ms = 1_778_652_000_000;

        for hour in 0..3 {
            let timestamp_ms = base_ms + hour * 3_600_000;
            let input = message_input(
                "dont tell your parents, this is our little secret",
                sender_id.clone(),
                format!("conv_relay_auth_loop_{hour}"),
            );
            let request = runtime
                .analyze_for_relay(&input, timestamp_ms)
                .relay_request
                .expect("high-risk child safety message should query relay");
            assert!(request.auth.is_some());

            let response = service.handle_analyze(request);
            assert!(response.auth.is_some());
            assert!(!response
                .reason_codes
                .contains(&"relay.auth.request_invalid".to_string()));
            assert!(runtime.record_relay_response_for_sender(
                &input.sender_id,
                &response,
                timestamp_ms
            ));
        }

        assert!(
            runtime
                .relay_sender_hint(&sender_id, base_ms + 3 * 3_600_000)
                .unwrap_or_default()
                >= 0.5
        );
    }

    #[test]
    fn attested_agent_relay_loop_satisfies_strict_account_attestation() {
        aura_agent_core::aura_kids::pipeline::clear_kids_memory();
        let pattern_db = PatternDatabase::default_mvp();
        let request_secret = b"relay request auth test secret";
        let response_secret = b"relay response auth test secret";
        let attestation_secret = b"protected account attestation secret";
        let protected_account_token = format!(
            "acct_{}",
            aura_agent_core::tokenize_identifier("child_account_1").token
        );
        let mut runtime = AgentRuntime::new(child_config(), &pattern_db)
            .with_relay_policy(AgentRelayPolicy {
                enabled: true,
                score_threshold: 0.01,
                privacy_mode: RelayPrivacyMode::MetadataOnly,
                protected_account_id: Some("child_account_1".to_string()),
                protected_account_attestation: sign_protected_account_token_attestation(
                    &protected_account_token,
                    current_unix_ms().saturating_add(60_000),
                    "acct-attest-key-1",
                    attestation_secret,
                ),
                require_protected_account_attestation: true,
                ..AgentRelayPolicy::default()
            })
            .with_relay_request_auth_key("relay-req-key-1", request_secret.to_vec())
            .with_relay_response_auth_key("relay-key-1", response_secret.to_vec());
        let service = RelayService::new()
            .with_request_auth_key("relay-req-key-1", request_secret.to_vec())
            .with_response_auth_key("relay-key-1", response_secret.to_vec())
            .with_protected_account_attestation_key(
                "acct-attest-key-1",
                attestation_secret.to_vec(),
            );
        let sender_id: SenderId = "repeat_risky_sender_attested".into();
        let base_ms = 1_778_652_000_000;

        for hour in 0..3 {
            let timestamp_ms = base_ms + hour * 3_600_000;
            let input = message_input(
                "dont tell your parents, this is our little secret",
                sender_id.clone(),
                format!("conv_relay_attested_loop_{hour}"),
            );
            let request = runtime
                .analyze_for_relay(&input, timestamp_ms)
                .relay_request
                .expect("high-risk child safety message should query relay");
            assert!(request.auth.is_some());
            assert!(request.protected_account_attestation.is_some());

            let response = service.handle_analyze(request);
            assert!(response.auth.is_some());
            assert!(!response
                .reason_codes
                .iter()
                .any(|code| code.starts_with("relay.auth.protected_account_attestation")));
            assert!(runtime.record_relay_response_for_sender(
                &input.sender_id,
                &response,
                timestamp_ms
            ));
        }

        assert!(
            runtime
                .relay_sender_hint(&sender_id, base_ms + 3 * 3_600_000)
                .unwrap_or_default()
                >= 0.5
        );
    }

    #[test]
    fn metadata_only_agent_relay_loop_feeds_sender_hint_back_to_client() {
        aura_agent_core::aura_kids::pipeline::clear_kids_memory();
        let pattern_db = PatternDatabase::default_mvp();
        let mut runtime =
            AgentRuntime::new(child_config(), &pattern_db).with_relay_policy(AgentRelayPolicy {
                enabled: true,
                score_threshold: 0.01,
                privacy_mode: RelayPrivacyMode::MetadataOnly,
                protected_account_id: Some("child_account_1".to_string()),
                ..AgentRelayPolicy::default()
            });
        let service = RelayService::new();
        let sender_id: SenderId = "repeat_risky_sender".into();
        let base_ms = 1_778_652_000_000;

        for hour in 0..3 {
            let timestamp_ms = base_ms + hour * 3_600_000;
            let input = message_input(
                "dont tell your parents, this is our little secret",
                sender_id.clone(),
                format!("conv_relay_loop_{hour}"),
            );
            let envelope = runtime.analyze_for_relay(&input, timestamp_ms);
            let request = envelope
                .relay_request
                .expect("high-risk child safety message should query relay");
            assert!(request.text.is_empty());
            assert!(request
                .sender_token
                .as_deref()
                .unwrap_or_default()
                .starts_with("snd_"));
            assert_eq!(request.local_safety_telemetry.len(), 1);

            let response = service.handle_analyze(request);
            assert_eq!(
                response.expires_at_ms,
                Some(timestamp_ms + RELAY_RESPONSE_TTL_MS)
            );
            runtime.record_relay_response_for_sender(&input.sender_id, &response, timestamp_ms);
        }

        assert!(
            runtime
                .relay_sender_hint(&sender_id, base_ms + 3 * 3_600_000)
                .unwrap_or_default()
                >= 0.5
        );

        let result = runtime.analyze_local_with_context(
            &message_input("our little secret", sender_id, "conv_relay_loop_final"),
            base_ms + 3 * 3_600_000,
        );

        assert!(
            result
                .reason_codes
                .iter()
                .any(|code| code == "domain.kids.memory.sender_risk_accumulation"),
            "relay reputation hint should trigger local kids sender-risk signal, got {:?}",
            result.reason_codes
        );
    }

    fn request_with_safety_telemetry_from_account(
        sender_token: &str,
        hour: u64,
        account_index: u64,
    ) -> AgentAnalyzeRequest {
        let account_token = protected_account_token(account_index);
        AgentAnalyzeRequest {
            request_id: format!("test_telemetry_{hour}"),
            sender_token: Some(sender_token.to_string()),
            protected_account_token: Some(account_token.clone()),
            local_safety_telemetry: vec![ClientSafetyTelemetryEvent {
                event_id: format!("evt_01H0000000000000000000000{hour}"),
                sender_token: sender_token.to_string(),
                protected_account_token: account_token,
                conversation_token: Some(format!("conv_01H00000000000000000000{hour}")),
                surface: SafetyTelemetrySurface::DirectMessage,
                threat_type: ThreatType::Grooming,
                severity: SafetyTelemetrySeverity::High,
                confidence: Confidence::High,
                action: SafetyTelemetryAction::Warn,
                timestamp_bucket_ms: 1_778_652_000_000 + hour * 3_600_000,
                reason_family: Some("grooming".to_string()),
            }],
            ..AgentAnalyzeRequest::default()
        }
    }

    fn assert_config_error_contains(
        result: Result<(), RelayAuthConfigError>,
        expected_fragment: &str,
    ) {
        match result {
            Ok(()) => panic!("expected relay auth config validation error"),
            Err(error) => assert!(
                error.reason.contains(expected_fragment),
                "expected config error containing {expected_fragment:?}, got {:?}",
                error.reason
            ),
        }
    }

    fn protected_account_token(account_index: u64) -> String {
        format!("acct_01H0000000000000000000{account_index:03}")
    }

    fn sign_request_with_account_attestation(
        request: &mut AgentAnalyzeRequest,
        request_secret: &[u8],
        attestation_secret: &[u8],
    ) {
        let token = request
            .protected_account_token
            .as_deref()
            .expect("test request has protected account token");
        request.protected_account_attestation = sign_protected_account_token_attestation(
            token,
            attestation_expires_at_ms(),
            "acct-attest-key-1",
            attestation_secret,
        );
        request.auth = sign_relay_request_auth(request, "relay-req-key-1", request_secret);
    }

    fn attestation_expires_at_ms() -> u64 {
        current_unix_ms().saturating_add(60_000)
    }

    fn relay_temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "aura-relay-api-{name}-{}-{}.json",
            std::process::id(),
            current_unix_nanos()
        ))
    }

    fn child_config() -> AuraConfig {
        AuraConfig {
            account_type: AccountType::Child,
            protection_level: ProtectionLevel::High,
            language: "en".to_string(),
            domain_mode: DomainMode::Kids,
            ..AuraConfig::default()
        }
    }

    fn message_input(
        text: &str,
        sender_id: SenderId,
        conversation_id: impl Into<String>,
    ) -> MessageInput {
        MessageInput {
            content_type: ContentType::Text,
            text: Some(text.to_string()),
            image_data: None,
            sender_id,
            conversation_id: conversation_id.into().into(),
            language: Some("en".to_string()),
            conversation_type: ConversationType::Direct,
            member_count: None,
            server_sender_risk_hint: None,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        }
    }
}
