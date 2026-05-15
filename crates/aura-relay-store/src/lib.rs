//! Relay persistence layer.
//!
//! Abstracts storage for sender reputation, cross-conversation memory,
//! cached inference results, and feature store entries.
//!
//! The initial implementation uses in-memory stores with TTL eviction.
//! Production will plug in Postgres/Redis backends behind the same traits.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use aura_contracts::{ClientSafetyTelemetryEvent, Confidence, SafetyTelemetrySeverity, ThreatType};
use serde::{Deserialize, Serialize};
use tracing::warn;

const MAX_RECENT_TELEMETRY_EVENT_IDS: usize = 128;
const MAX_RECENT_TELEMETRY_FINGERPRINTS: usize = 256;
const MAX_TRACKED_SOURCE_TOKENS: usize = 256;
const SAFETY_REPUTATION_HALF_LIFE_MS: u64 = 7 * 24 * 60 * 60 * 1_000;
const SINGLE_PROTECTED_ACCOUNT_RISK_CAP: f32 = 0.64;
const SINGLE_CONVERSATION_RISK_CAP: f32 = 0.58;
const REPUTATION_STORE_SCHEMA_VERSION: u32 = 1;
const DEFAULT_JSON_FILE_REPUTATION_CAPACITY: usize = 16_384;

#[derive(Debug, thiserror::Error)]
pub enum ReputationPersistenceError {
    #[error("reputation store path is empty")]
    EmptyPath,
    #[error("reputation store I/O error for {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("reputation store JSON error for {path}: {source}")]
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderReputation {
    pub sender_id: String,
    pub cumulative_risk: f32,
    pub threat_counts: HashMap<String, u64>,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub total_requests: u64,
    #[serde(default)]
    pub recent_event_ids: Vec<String>,
    #[serde(default)]
    pub recent_event_fingerprints: Vec<String>,
    #[serde(default)]
    pub protected_account_counts: HashMap<String, u64>,
    #[serde(default)]
    pub conversation_counts: HashMap<String, u64>,
}

impl SenderReputation {
    pub fn new(sender_id: impl Into<String>, timestamp_ms: u64) -> Self {
        Self {
            sender_id: sender_id.into(),
            cumulative_risk: 0.0,
            threat_counts: HashMap::new(),
            first_seen_ms: timestamp_ms,
            last_seen_ms: timestamp_ms,
            total_requests: 0,
            recent_event_ids: Vec::new(),
            recent_event_fingerprints: Vec::new(),
            protected_account_counts: HashMap::new(),
            conversation_counts: HashMap::new(),
        }
    }
}

pub trait ReputationStore: Send + Sync {
    fn get(&self, sender_id: &str) -> Option<SenderReputation>;
    fn upsert(&mut self, reputation: SenderReputation);

    fn record_safety_telemetry(
        &mut self,
        event: &ClientSafetyTelemetryEvent,
    ) -> Option<SenderReputation> {
        if !event.privacy_safe() {
            return None;
        }

        let mut reputation = self.get(&event.sender_token).unwrap_or_else(|| {
            SenderReputation::new(&event.sender_token, event.timestamp_bucket_ms)
        });
        if is_duplicate_event(&reputation, event) {
            return Some(reputation);
        }
        apply_safety_telemetry(&mut reputation, event);
        self.upsert(reputation.clone());

        Some(reputation)
    }
}

pub struct InMemoryReputationStore {
    data: HashMap<String, SenderReputation>,
}

impl InMemoryReputationStore {
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }
}

fn apply_safety_telemetry(reputation: &mut SenderReputation, event: &ClientSafetyTelemetryEvent) {
    let risk_increment = telemetry_risk_increment(reputation, event);
    if reputation.sender_id.is_empty() {
        reputation.sender_id = event.sender_token.clone();
    }
    reputation.cumulative_risk = decayed_risk(
        reputation.cumulative_risk,
        reputation.last_seen_ms,
        event.timestamp_bucket_ms,
    );
    if reputation.first_seen_ms == 0 {
        reputation.first_seen_ms = event.timestamp_bucket_ms;
    } else if event.timestamp_bucket_ms != 0 {
        reputation.first_seen_ms = reputation.first_seen_ms.min(event.timestamp_bucket_ms);
    }
    reputation.last_seen_ms = reputation.last_seen_ms.max(event.timestamp_bucket_ms);
    reputation.total_requests += 1;
    *reputation
        .threat_counts
        .entry(format!("{:?}", event.threat_type))
        .or_insert(0) += 1;
    remember_source_tokens(reputation, event);
    let source_cap = source_diversity_risk_cap(reputation);
    reputation.cumulative_risk = (reputation.cumulative_risk + risk_increment)
        .min(1.0)
        .min(source_cap);
    remember_event_id(reputation, event);
    remember_event_fingerprint(reputation, event);
}

fn telemetry_risk_increment(
    reputation: &SenderReputation,
    event: &ClientSafetyTelemetryEvent,
) -> f32 {
    let severity_weight = match event.severity {
        SafetyTelemetrySeverity::Low => 0.08,
        SafetyTelemetrySeverity::Medium => 0.16,
        SafetyTelemetrySeverity::High => 0.28,
        SafetyTelemetrySeverity::Critical => 0.40,
    };
    let confidence_weight = match event.confidence {
        Confidence::Low => 0.55,
        Confidence::Medium => 0.80,
        Confidence::High => 1.0,
    };

    severity_weight * confidence_weight * source_repetition_factor(reputation, event)
}

fn source_repetition_factor(
    reputation: &SenderReputation,
    event: &ClientSafetyTelemetryEvent,
) -> f32 {
    let protected_count = reputation
        .protected_account_counts
        .get(&event.protected_account_token)
        .copied()
        .unwrap_or(0);
    let conversation_count = event
        .conversation_token
        .as_ref()
        .and_then(|token| reputation.conversation_counts.get(token))
        .copied()
        .unwrap_or(0);

    let protected_factor = if protected_count >= 2 {
        0.50
    } else if protected_count == 1 {
        0.75
    } else {
        1.0
    };
    let conversation_factor = if conversation_count >= 1 { 0.50 } else { 1.0 };

    protected_factor * conversation_factor
}

fn source_diversity_risk_cap(reputation: &SenderReputation) -> f32 {
    let mut cap: f32 = 1.0;
    if reputation.protected_account_counts.len() <= 1 {
        cap = cap.min(SINGLE_PROTECTED_ACCOUNT_RISK_CAP);
    }
    if reputation.conversation_counts.len() <= 1 {
        cap = cap.min(SINGLE_CONVERSATION_RISK_CAP);
    }
    cap
}

fn decayed_risk(current: f32, last_seen_ms: u64, event_timestamp_ms: u64) -> f32 {
    if current <= 0.0 || last_seen_ms == 0 || event_timestamp_ms <= last_seen_ms {
        return current;
    }

    let elapsed_ms = event_timestamp_ms - last_seen_ms;
    let half_lives = elapsed_ms as f32 / SAFETY_REPUTATION_HALF_LIFE_MS as f32;
    current * 0.5_f32.powf(half_lives)
}

fn is_duplicate_event(reputation: &SenderReputation, event: &ClientSafetyTelemetryEvent) -> bool {
    let duplicate_event_id = !event.event_id.trim().is_empty()
        && reputation
            .recent_event_ids
            .iter()
            .any(|event_id| event_id == &event.event_id);
    duplicate_event_id
        || reputation
            .recent_event_fingerprints
            .iter()
            .any(|fingerprint| fingerprint == &telemetry_fingerprint(event))
}

fn remember_event_id(reputation: &mut SenderReputation, event: &ClientSafetyTelemetryEvent) {
    if event.event_id.trim().is_empty() || is_duplicate_event(reputation, event) {
        return;
    }

    reputation.recent_event_ids.push(event.event_id.clone());
    let overflow = reputation
        .recent_event_ids
        .len()
        .saturating_sub(MAX_RECENT_TELEMETRY_EVENT_IDS);
    if overflow > 0 {
        reputation.recent_event_ids.drain(0..overflow);
    }
}

fn remember_event_fingerprint(
    reputation: &mut SenderReputation,
    event: &ClientSafetyTelemetryEvent,
) {
    let fingerprint = telemetry_fingerprint(event);
    if reputation
        .recent_event_fingerprints
        .iter()
        .any(|existing| existing == &fingerprint)
    {
        return;
    }

    reputation.recent_event_fingerprints.push(fingerprint);
    let overflow = reputation
        .recent_event_fingerprints
        .len()
        .saturating_sub(MAX_RECENT_TELEMETRY_FINGERPRINTS);
    if overflow > 0 {
        reputation.recent_event_fingerprints.drain(0..overflow);
    }
}

fn telemetry_fingerprint(event: &ClientSafetyTelemetryEvent) -> String {
    format!(
        "{}:{}:{}:{:?}:{:?}:{}",
        event.protected_account_token,
        event.conversation_token.as_deref().unwrap_or(""),
        event.timestamp_bucket_ms,
        event.threat_type,
        event.action,
        event.reason_family.as_deref().unwrap_or("")
    )
}

fn remember_source_tokens(reputation: &mut SenderReputation, event: &ClientSafetyTelemetryEvent) {
    increment_bounded_count(
        &mut reputation.protected_account_counts,
        &event.protected_account_token,
    );
    if let Some(conversation_token) = event.conversation_token.as_deref() {
        increment_bounded_count(&mut reputation.conversation_counts, conversation_token);
    }
}

fn increment_bounded_count(counts: &mut HashMap<String, u64>, token: &str) {
    if token.trim().is_empty() {
        return;
    }
    if counts.contains_key(token) || counts.len() < MAX_TRACKED_SOURCE_TOKENS {
        *counts.entry(token.to_string()).or_insert(0) += 1;
    }
}

impl Default for InMemoryReputationStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ReputationStore for InMemoryReputationStore {
    fn get(&self, sender_id: &str) -> Option<SenderReputation> {
        self.data.get(sender_id).cloned()
    }

    fn upsert(&mut self, reputation: SenderReputation) {
        self.data.insert(reputation.sender_id.clone(), reputation);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JsonFileReputationStoreState {
    schema_version: u32,
    data: HashMap<String, SenderReputation>,
}

impl Default for JsonFileReputationStoreState {
    fn default() -> Self {
        Self {
            schema_version: REPUTATION_STORE_SCHEMA_VERSION,
            data: HashMap::new(),
        }
    }
}

pub struct JsonFileReputationStore {
    path: PathBuf,
    data: HashMap<String, SenderReputation>,
    capacity: usize,
}

impl JsonFileReputationStore {
    pub fn open(
        path: impl Into<PathBuf>,
        capacity: usize,
    ) -> Result<Self, ReputationPersistenceError> {
        let path = validate_reputation_store_path(path.into())?;
        let mut state: JsonFileReputationStoreState = read_reputation_json_or_default(&path)?;
        trim_reputation_data_to_capacity(&mut state.data, capacity);
        Ok(Self {
            path,
            data: state.data,
            capacity,
        })
    }

    pub fn open_default(path: impl Into<PathBuf>) -> Result<Self, ReputationPersistenceError> {
        Self::open(path, DEFAULT_JSON_FILE_REPUTATION_CAPACITY)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn entries(&self) -> HashMap<String, SenderReputation> {
        self.data.clone()
    }

    fn persist(&self) -> Result<(), ReputationPersistenceError> {
        write_reputation_json_atomic(
            &self.path,
            &JsonFileReputationStoreState {
                schema_version: REPUTATION_STORE_SCHEMA_VERSION,
                data: self.data.clone(),
            },
        )
    }
}

impl ReputationStore for JsonFileReputationStore {
    fn get(&self, sender_id: &str) -> Option<SenderReputation> {
        self.data.get(sender_id).cloned()
    }

    fn upsert(&mut self, reputation: SenderReputation) {
        if self.capacity == 0 {
            return;
        }
        self.data.insert(reputation.sender_id.clone(), reputation);
        trim_reputation_data_to_capacity(&mut self.data, self.capacity);
        if let Err(error) = self.persist() {
            warn!(
                path = %self.path.display(),
                error = %error,
                "relay: failed to persist reputation store"
            );
        }
    }
}

fn validate_reputation_store_path(path: PathBuf) -> Result<PathBuf, ReputationPersistenceError> {
    if path.as_os_str().is_empty() {
        return Err(ReputationPersistenceError::EmptyPath);
    }
    Ok(path)
}

fn read_reputation_json_or_default<T>(path: &Path) -> Result<T, ReputationPersistenceError>
where
    T: for<'de> Deserialize<'de> + Default,
{
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(T::default()),
        Err(source) => {
            return Err(ReputationPersistenceError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if bytes.is_empty() {
        return Ok(T::default());
    }

    serde_json::from_slice(&bytes).map_err(|source| ReputationPersistenceError::Json {
        path: path.to_path_buf(),
        source,
    })
}

fn write_reputation_json_atomic<T>(path: &Path, value: &T) -> Result<(), ReputationPersistenceError>
where
    T: Serialize,
{
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|source| ReputationPersistenceError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    let bytes =
        serde_json::to_vec_pretty(value).map_err(|source| ReputationPersistenceError::Json {
            path: path.to_path_buf(),
            source,
        })?;
    let tmp_path = reputation_store_tmp_path(path);
    fs::write(&tmp_path, bytes).map_err(|source| ReputationPersistenceError::Io {
        path: tmp_path.clone(),
        source,
    })?;
    fs::rename(&tmp_path, path).map_err(|source| ReputationPersistenceError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

fn reputation_store_tmp_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|file_name| file_name.to_str())
        .unwrap_or("relay-reputation.json");
    path.with_file_name(format!(
        "{file_name}.tmp.{}.{}",
        std::process::id(),
        current_unix_nanos()
    ))
}

fn trim_reputation_data_to_capacity(data: &mut HashMap<String, SenderReputation>, capacity: usize) {
    if capacity == 0 {
        data.clear();
        return;
    }
    while data.len() > capacity {
        let Some(oldest_sender_id) = data
            .iter()
            .min_by_key(|(_, reputation)| reputation.last_seen_ms)
            .map(|(sender_id, _)| sender_id.clone())
        else {
            break;
        };
        data.remove(&oldest_sender_id);
    }
}

fn current_unix_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedInferenceEntry {
    pub text_hash: String,
    pub primary_threat: ThreatType,
    pub score: f32,
    pub created_ms: u64,
    pub ttl_ms: u64,
}

pub trait InferenceCache: Send + Sync {
    fn get(&self, text_hash: &str) -> Option<CachedInferenceEntry>;
    fn put(&mut self, entry: CachedInferenceEntry);
}

pub struct InMemoryInferenceCache {
    data: HashMap<String, CachedInferenceEntry>,
    capacity: usize,
}

impl InMemoryInferenceCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            data: HashMap::new(),
            capacity,
        }
    }
}

impl InferenceCache for InMemoryInferenceCache {
    fn get(&self, text_hash: &str) -> Option<CachedInferenceEntry> {
        self.data.get(text_hash).cloned()
    }

    fn put(&mut self, entry: CachedInferenceEntry) {
        if self.data.len() >= self.capacity {
            if let Some(oldest_key) = self
                .data
                .iter()
                .min_by_key(|(_, v)| v.created_ms)
                .map(|(k, _)| k.clone())
            {
                self.data.remove(&oldest_key);
            }
        }
        self.data.insert(entry.text_hash.clone(), entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aura_contracts::{SafetyTelemetryAction, SafetyTelemetrySeverity, SafetyTelemetrySurface};

    #[test]
    fn reputation_store_upsert_and_get() {
        let mut store = InMemoryReputationStore::new();
        store.upsert(SenderReputation {
            sender_id: "s1".to_string(),
            cumulative_risk: 0.5,
            threat_counts: HashMap::new(),
            first_seen_ms: 1000,
            last_seen_ms: 2000,
            total_requests: 3,
            ..SenderReputation::new("s1", 1000)
        });
        let rep = store.get("s1").unwrap();
        assert_eq!(rep.total_requests, 3);
    }

    #[test]
    fn reputation_store_records_privacy_safe_telemetry() {
        let mut store = InMemoryReputationStore::new();
        let event = ClientSafetyTelemetryEvent {
            event_id: "evt_01H00000000000000000000000".to_string(),
            sender_token: "snd_01H00000000000000000000000".to_string(),
            protected_account_token: "acct_01H0000000000000000000000".to_string(),
            conversation_token: Some("conv_01H000000000000000000000".to_string()),
            surface: SafetyTelemetrySurface::DirectMessage,
            threat_type: ThreatType::Grooming,
            severity: SafetyTelemetrySeverity::High,
            confidence: Confidence::High,
            action: SafetyTelemetryAction::Warn,
            timestamp_bucket_ms: 1_778_652_000_000,
            reason_family: Some("grooming".to_string()),
        };

        let updated = store.record_safety_telemetry(&event).unwrap();
        let rep = store.get(&event.sender_token).unwrap();

        assert_eq!(updated.total_requests, 1);
        assert_eq!(rep.total_requests, 1);
        assert!(rep.cumulative_risk >= 0.28);
        assert_eq!(rep.threat_counts.get("Grooming"), Some(&1));
        assert_eq!(rep.recent_event_ids, vec![event.event_id]);
        assert_eq!(
            rep.protected_account_counts
                .get("acct_01H0000000000000000000000"),
            Some(&1)
        );
        assert_eq!(
            rep.conversation_counts.get("conv_01H000000000000000000000"),
            Some(&1)
        );
    }

    #[test]
    fn reputation_store_dedupes_retried_telemetry_event() {
        let mut store = InMemoryReputationStore::new();
        let event = safety_telemetry_event(
            "evt_01H00000000000000000000000",
            1_778_652_000_000,
            SafetyTelemetrySeverity::High,
        );

        let first = store.record_safety_telemetry(&event).unwrap();
        let second = store.record_safety_telemetry(&event).unwrap();

        assert_eq!(first.total_requests, 1);
        assert_eq!(second.total_requests, 1);
        assert_eq!(second.threat_counts.get("Grooming"), Some(&1));
        assert_eq!(second.recent_event_ids.len(), 1);
        assert!((first.cumulative_risk - second.cumulative_risk).abs() < f32::EPSILON);
    }

    #[test]
    fn reputation_store_dedupes_same_signal_fingerprint_with_new_event_id() {
        let mut store = InMemoryReputationStore::new();
        let first = safety_telemetry_event(
            "evt_01H00000000000000000000000",
            1_778_652_000_000,
            SafetyTelemetrySeverity::High,
        );
        let mut retried = first.clone();
        retried.event_id = "evt_01H00000000000000000000001".to_string();

        let first_rep = store.record_safety_telemetry(&first).unwrap();
        let retried_rep = store.record_safety_telemetry(&retried).unwrap();

        assert_eq!(retried_rep.total_requests, 1);
        assert_eq!(retried_rep.threat_counts.get("Grooming"), Some(&1));
        assert!((first_rep.cumulative_risk - retried_rep.cumulative_risk).abs() < f32::EPSILON);
    }

    #[test]
    fn reputation_store_caps_single_protected_account_reputation_poisoning() {
        let mut store = InMemoryReputationStore::new();

        for index in 0..10 {
            let mut event = safety_telemetry_event(
                &format!("evt_01H00000000000000000000{index:03}"),
                1_778_652_000_000 + index as u64 * 3_600_000,
                SafetyTelemetrySeverity::High,
            );
            event.conversation_token = Some(format!("conv_01H00000000000000000000{index:03}"));
            store.record_safety_telemetry(&event);
        }

        let rep = store
            .get("snd_01H00000000000000000000000")
            .expect("reputation should exist");
        assert_eq!(rep.protected_account_counts.len(), 1);
        assert_eq!(rep.total_requests, 10);
        assert!(rep.cumulative_risk <= SINGLE_PROTECTED_ACCOUNT_RISK_CAP);
        assert!(rep.cumulative_risk < 0.7);
    }

    #[test]
    fn reputation_store_caps_single_protected_account_flood_across_many_conversations() {
        let mut store = InMemoryReputationStore::new();

        for index in 0..64 {
            let mut event = safety_telemetry_event(
                &format!("evt_single_child_flood_{index:04}"),
                1_778_652_000_000 + index as u64 * 3_600_000,
                SafetyTelemetrySeverity::Critical,
            );
            event.conversation_token = Some(format!("conv_single_child_flood_{index:04}"));
            store.record_safety_telemetry(&event);
        }

        let rep = store
            .get("snd_01H00000000000000000000000")
            .expect("reputation should exist");
        assert_eq!(rep.protected_account_counts.len(), 1);
        assert_eq!(rep.conversation_counts.len(), 64);
        assert_eq!(rep.total_requests, 64);
        assert!(rep.cumulative_risk <= SINGLE_PROTECTED_ACCOUNT_RISK_CAP);
        assert!(rep.cumulative_risk < 0.7);
    }

    #[test]
    fn reputation_store_caps_single_conversation_many_account_poisoning() {
        let mut store = InMemoryReputationStore::new();

        for index in 0..64 {
            let mut event = safety_telemetry_event(
                &format!("evt_single_conv_sybil_{index:04}"),
                1_778_652_000_000 + index as u64 * 3_600_000,
                SafetyTelemetrySeverity::Critical,
            );
            event.protected_account_token = format!("acct_single_conv_sybil_{index:04}");
            event.conversation_token = Some("conv_single_conversation_sybil".to_string());
            store.record_safety_telemetry(&event);
        }

        let rep = store
            .get("snd_01H00000000000000000000000")
            .expect("reputation should exist");
        assert_eq!(rep.protected_account_counts.len(), 64);
        assert_eq!(rep.conversation_counts.len(), 1);
        assert_eq!(rep.total_requests, 64);
        assert!(rep.cumulative_risk <= SINGLE_CONVERSATION_RISK_CAP);
        assert!(rep.cumulative_risk < 0.7);
    }

    #[test]
    fn reputation_store_allows_independent_accounts_to_escalate_reputation() {
        let mut store = InMemoryReputationStore::new();

        for index in 0..3 {
            let mut event = safety_telemetry_event(
                &format!("evt_01H00000000000000000000{index:03}"),
                1_778_652_000_000 + index as u64 * 3_600_000,
                SafetyTelemetrySeverity::High,
            );
            event.protected_account_token = format!("acct_01H00000000000000000000{index:03}");
            event.conversation_token = Some(format!("conv_01H00000000000000000000{index:03}"));
            store.record_safety_telemetry(&event);
        }

        let rep = store
            .get("snd_01H00000000000000000000000")
            .expect("reputation should exist");
        assert_eq!(rep.protected_account_counts.len(), 3);
        assert!(rep.cumulative_risk >= 0.7);
    }

    #[test]
    fn reputation_store_decays_old_risk_before_new_telemetry() {
        let mut store = InMemoryReputationStore::new();
        let first = safety_telemetry_event(
            "evt_01H00000000000000000000000",
            1_778_652_000_000,
            SafetyTelemetrySeverity::Critical,
        );
        let second = safety_telemetry_event(
            "evt_01H00000000000000000000001",
            1_778_652_000_000 + SAFETY_REPUTATION_HALF_LIFE_MS,
            SafetyTelemetrySeverity::Low,
        );

        let first_rep = store.record_safety_telemetry(&first).unwrap();
        let second_rep = store.record_safety_telemetry(&second).unwrap();

        assert!(first_rep.cumulative_risk >= 0.40);
        assert!(second_rep.cumulative_risk < first_rep.cumulative_risk);
        assert_eq!(second_rep.total_requests, 2);
        assert_eq!(second_rep.threat_counts.get("Grooming"), Some(&2));
    }

    #[test]
    fn reputation_store_bounds_recent_event_id_memory() {
        let mut store = InMemoryReputationStore::new();
        let first_event_id = format!("evt_01H00000000000000000000{:03}", 0);

        for index in 0..(MAX_RECENT_TELEMETRY_EVENT_IDS + 5) {
            let event = safety_telemetry_event(
                &format!("evt_01H00000000000000000000{index:03}"),
                1_778_652_000_000 + index as u64,
                SafetyTelemetrySeverity::Low,
            );
            store.record_safety_telemetry(&event);
        }

        let rep = store
            .get("snd_01H00000000000000000000000")
            .expect("reputation should exist");
        assert_eq!(rep.recent_event_ids.len(), MAX_RECENT_TELEMETRY_EVENT_IDS);
        assert!(!rep.recent_event_ids.contains(&first_event_id));
    }

    #[test]
    fn reputation_store_dedupes_replay_after_event_id_window_rollover() {
        let mut store = InMemoryReputationStore::new();
        let original = safety_telemetry_event(
            "evt_01H00000000000000000000000",
            1_778_652_000_000,
            SafetyTelemetrySeverity::High,
        );
        let original_fingerprint = telemetry_fingerprint(&original);
        store.record_safety_telemetry(&original);

        for index in 1..=(MAX_RECENT_TELEMETRY_EVENT_IDS + 8) {
            let mut event = safety_telemetry_event(
                &format!("evt_rollover_noise_{index:04}"),
                1_778_652_000_000 + index as u64 * 3_600_000,
                SafetyTelemetrySeverity::Low,
            );
            event.protected_account_token = format!("acct_rollover_noise_{index:04}");
            event.conversation_token = Some(format!("conv_rollover_noise_{index:04}"));
            store.record_safety_telemetry(&event);
        }

        let before_replay = store
            .get("snd_01H00000000000000000000000")
            .expect("reputation should exist");
        assert_eq!(
            before_replay.recent_event_ids.len(),
            MAX_RECENT_TELEMETRY_EVENT_IDS
        );
        assert!(!before_replay.recent_event_ids.contains(&original.event_id));
        assert!(before_replay
            .recent_event_fingerprints
            .contains(&original_fingerprint));

        let replayed = store.record_safety_telemetry(&original).unwrap();
        assert_eq!(replayed.total_requests, before_replay.total_requests);
        assert_eq!(replayed.threat_counts, before_replay.threat_counts);
        assert!((replayed.cumulative_risk - before_replay.cumulative_risk).abs() < f32::EPSILON);
    }

    #[test]
    fn reputation_store_bounds_source_token_memory_under_sybil_flood() {
        let mut store = InMemoryReputationStore::new();

        for index in 0..(MAX_TRACKED_SOURCE_TOKENS + 32) {
            let mut event = safety_telemetry_event(
                &format!("evt_source_bounds_{index:04}"),
                1_778_652_000_000 + index as u64 * 3_600_000,
                SafetyTelemetrySeverity::Low,
            );
            event.protected_account_token = format!("acct_source_bounds_{index:04}");
            event.conversation_token = Some(format!("conv_source_bounds_{index:04}"));
            store.record_safety_telemetry(&event);
        }

        let rep = store
            .get("snd_01H00000000000000000000000")
            .expect("reputation should exist");
        assert_eq!(rep.total_requests, (MAX_TRACKED_SOURCE_TOKENS + 32) as u64);
        assert_eq!(
            rep.protected_account_counts.len(),
            MAX_TRACKED_SOURCE_TOKENS
        );
        assert_eq!(rep.conversation_counts.len(), MAX_TRACKED_SOURCE_TOKENS);
    }

    #[test]
    fn reputation_store_ignores_raw_looking_telemetry_tokens() {
        let mut store = InMemoryReputationStore::new();
        let event = ClientSafetyTelemetryEvent {
            sender_token: "mentor 42".to_string(),
            protected_account_token: "kid@example.test".to_string(),
            threat_type: ThreatType::Grooming,
            severity: SafetyTelemetrySeverity::High,
            confidence: Confidence::High,
            ..ClientSafetyTelemetryEvent::default()
        };

        assert!(store.record_safety_telemetry(&event).is_none());
        assert!(store.get("mentor 42").is_none());
    }

    #[test]
    fn json_file_reputation_store_persists_and_reopens_reputation() {
        let path = reputation_temp_path("persist-reopen");
        let mut store =
            JsonFileReputationStore::open(&path, 16).expect("json reputation store opens");
        let event = safety_telemetry_event(
            "evt_01H00000000000000000000000",
            1_778_652_000_000,
            SafetyTelemetrySeverity::High,
        );

        let updated = store.record_safety_telemetry(&event).unwrap();
        let reopened =
            JsonFileReputationStore::open(&path, 16).expect("json reputation store reopens");
        let persisted = reopened
            .get(&event.sender_token)
            .expect("reputation should persist");

        assert_eq!(updated.total_requests, 1);
        assert_eq!(persisted.total_requests, 1);
        assert_eq!(persisted.threat_counts.get("Grooming"), Some(&1));
        let serialized = fs::read_to_string(&path).expect("reputation file should be readable");
        assert!(!serialized.contains("kid@example.test"));
        assert!(serialized.contains("snd_01H00000000000000000000000"));
    }

    #[test]
    fn json_file_reputation_store_bounds_capacity_by_oldest_last_seen() {
        let path = reputation_temp_path("capacity");
        let mut store =
            JsonFileReputationStore::open(&path, 2).expect("json reputation store opens");

        for index in 0..3 {
            let mut event = safety_telemetry_event(
                &format!("evt_reputation_capacity_{index}"),
                1_778_652_000_000 + index as u64,
                SafetyTelemetrySeverity::Low,
            );
            event.sender_token = format!("snd_01H00000000000000000000{index:03}");
            store.record_safety_telemetry(&event);
        }

        let reopened =
            JsonFileReputationStore::open(&path, 2).expect("json reputation store reopens");
        let entries = reopened.entries();

        assert_eq!(entries.len(), 2);
        assert!(!entries.contains_key("snd_01H00000000000000000000000"));
        assert!(entries.contains_key("snd_01H00000000000000000000001"));
        assert!(entries.contains_key("snd_01H00000000000000000000002"));
    }

    #[test]
    fn inference_cache_evicts_oldest() {
        let mut cache = InMemoryInferenceCache::new(2);
        for i in 0..3 {
            cache.put(CachedInferenceEntry {
                text_hash: format!("h{i}"),
                primary_threat: ThreatType::None,
                score: 0.0,
                created_ms: i as u64,
                ttl_ms: 60_000,
            });
        }
        assert!(cache.get("h0").is_none());
        assert!(cache.get("h1").is_some());
        assert!(cache.get("h2").is_some());
    }

    fn safety_telemetry_event(
        event_id: &str,
        timestamp_bucket_ms: u64,
        severity: SafetyTelemetrySeverity,
    ) -> ClientSafetyTelemetryEvent {
        ClientSafetyTelemetryEvent {
            event_id: event_id.to_string(),
            sender_token: "snd_01H00000000000000000000000".to_string(),
            protected_account_token: "acct_01H0000000000000000000000".to_string(),
            conversation_token: Some("conv_01H000000000000000000000".to_string()),
            surface: SafetyTelemetrySurface::DirectMessage,
            threat_type: ThreatType::Grooming,
            severity,
            confidence: Confidence::High,
            action: SafetyTelemetryAction::Warn,
            timestamp_bucket_ms,
            reason_family: Some("grooming".to_string()),
        }
    }

    fn reputation_temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "aura-relay-store-{name}-{}-{}.json",
            std::process::id(),
            current_unix_nanos()
        ))
    }
}
