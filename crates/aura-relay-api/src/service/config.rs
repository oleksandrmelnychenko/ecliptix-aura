use super::*;

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
