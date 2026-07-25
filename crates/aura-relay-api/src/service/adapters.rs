use super::*;

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

pub(super) fn validate_optional_persistent_store_path(
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

pub(super) fn validate_persistent_store_path(
    path: PathBuf,
) -> Result<PathBuf, RelayPersistentStoreError> {
    if path.as_os_str().is_empty() {
        return Err(RelayPersistentStoreError::EmptyPath);
    }
    Ok(path)
}

pub(super) fn read_json_or_default<T>(path: &Path) -> Result<T, RelayPersistentStoreError>
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

pub(super) fn write_json_atomic<T>(path: &Path, value: &T) -> Result<(), RelayPersistentStoreError>
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

pub(super) fn persistent_store_tmp_path(path: &Path) -> PathBuf {
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

pub(super) fn trim_replay_state_to_capacity(
    seen_request_ids: &mut HashMap<String, u64>,
    capacity: usize,
) {
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

pub(super) fn trim_entries_to_capacity<T>(entries: &mut Vec<T>, capacity: usize) {
    if capacity == 0 {
        entries.clear();
        return;
    }
    if entries.len() > capacity {
        entries.drain(0..entries.len() - capacity);
    }
}
