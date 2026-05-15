use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::common::{
    AccountType, Confidence, ConversationType, DetectionLayer, ProtectionLevel, ThreatType,
};
use crate::context::{
    Directionality, RelationshipTag, SpeechAct, Stance, ThreatContextFrame, TrajectoryTag,
};
use crate::event::ConfirmedEvent;
use crate::observation::RawObservation;

pub const AURA_RELAY_SCHEMA_VERSION: &str = "aura.relay.v1alpha1";
pub const RELAY_REQUEST_AUTH_ALG: &str = "hmac-sha256-v1";
pub const RELAY_RESPONSE_AUTH_ALG: &str = "hmac-sha256-v1";
pub const PROTECTED_ACCOUNT_TOKEN_ATTESTATION_ALG: &str = "hmac-sha256-v1";

pub fn default_relay_schema_version() -> String {
    AURA_RELAY_SCHEMA_VERSION.to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RelayPrivacyMode {
    MetadataOnly,
    #[default]
    MessageOnly,
    MessageAndWindow,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct MessageWindowEntry {
    #[serde(default)]
    pub sender_id: String,
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct LocalContextSummary {
    #[serde(default)]
    pub context_markers: Vec<String>,
    #[serde(default)]
    pub recent_observations: Vec<RawObservation>,
    #[serde(default)]
    pub recent_confirmed_events: Vec<ConfirmedEvent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SafetyTelemetrySurface {
    #[default]
    Unknown,
    DirectMessage,
    GroupChat,
    PublicComment,
    LivestreamComment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SafetyTelemetrySeverity {
    #[default]
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SafetyTelemetryAction {
    #[default]
    None,
    Mark,
    Blur,
    Warn,
    Block,
    GuardianAlert,
    ReportQueued,
    RestrictContact,
    CrisisSupport,
}

/// Privacy-safe local safety signal emitted by a client-side AURA runtime.
///
/// This contract intentionally carries no message body, matched phrase,
/// decrypted attachment, raw conversation identifier, or free-form explanation.
/// Sender/account/conversation values must be stable pseudonymous tokens
/// using the `snd_`, `acct_`, `conv_`, and `evt_` prefixes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ClientSafetyTelemetryEvent {
    #[serde(default)]
    pub event_id: String,
    #[serde(default)]
    pub sender_token: String,
    #[serde(default)]
    pub protected_account_token: String,
    #[serde(default)]
    pub conversation_token: Option<String>,
    #[serde(default)]
    pub surface: SafetyTelemetrySurface,
    #[serde(default)]
    pub threat_type: ThreatType,
    #[serde(default)]
    pub severity: SafetyTelemetrySeverity,
    #[serde(default)]
    pub confidence: Confidence,
    #[serde(default)]
    pub action: SafetyTelemetryAction,
    /// Coarse timestamp bucket chosen by the client, e.g. hour/day boundary.
    #[serde(default)]
    pub timestamp_bucket_ms: u64,
    /// Optional coarse reason family, e.g. "grooming", not a matched phrase.
    #[serde(default)]
    pub reason_family: Option<String>,
}

impl ClientSafetyTelemetryEvent {
    pub fn privacy_errors(&self) -> Vec<&'static str> {
        let mut errors = Vec::new();
        if self.sender_token.trim().is_empty() {
            errors.push("sender_token_empty");
        }
        if !self.sender_token.starts_with("snd_") {
            errors.push("sender_token_bad_prefix");
        }
        if self.protected_account_token.trim().is_empty() {
            errors.push("protected_account_token_empty");
        }
        if !self.protected_account_token.starts_with("acct_") {
            errors.push("protected_account_token_bad_prefix");
        }
        if token_looks_raw(&self.sender_token) {
            errors.push("sender_token_looks_raw");
        }
        if token_looks_raw(&self.protected_account_token) {
            errors.push("protected_account_token_looks_raw");
        }
        if self
            .conversation_token
            .as_deref()
            .is_some_and(token_looks_raw)
        {
            errors.push("conversation_token_looks_raw");
        }
        if self
            .conversation_token
            .as_deref()
            .is_some_and(|token| !token.starts_with("conv_"))
        {
            errors.push("conversation_token_bad_prefix");
        }
        if self.event_id.trim().is_empty() {
            errors.push("event_id_empty");
        } else {
            if token_looks_raw(&self.event_id) {
                errors.push("event_id_looks_raw");
            }
            if !self.event_id.starts_with("evt_") {
                errors.push("event_id_bad_prefix");
            }
        }
        if self.timestamp_bucket_ms == 0 {
            errors.push("timestamp_bucket_empty");
        }
        if self
            .reason_family
            .as_deref()
            .is_some_and(reason_family_looks_raw)
        {
            errors.push("reason_family_looks_raw");
        }
        errors
    }

    pub fn privacy_safe(&self) -> bool {
        self.privacy_errors().is_empty()
    }
}

fn token_looks_raw(token: &str) -> bool {
    let trimmed = token.trim();
    let phone_like = trimmed.chars().filter(|ch| ch.is_ascii_digit()).count() >= 7
        && trimmed
            .chars()
            .all(|ch| ch.is_ascii_digit() || matches!(ch, '+' | '-' | '(' | ')' | '.'));

    trimmed.is_empty()
        || trimmed.len() < 8
        || trimmed.chars().any(char::is_whitespace)
        || trimmed.contains('@')
        || trimmed.contains("://")
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || phone_like
}

fn reason_family_looks_raw(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.len() > 64
        || trimmed.chars().any(char::is_whitespace)
        || trimmed.contains('@')
        || trimmed.contains("://")
        || !trimmed.chars().all(|ch| {
            ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '_' | '-' | '.')
        })
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct AgentCapabilities {
    #[serde(default)]
    pub local_context_interpreter: bool,
    #[serde(default)]
    pub local_tracker: bool,
    #[serde(default)]
    pub supports_remote_correlation: bool,
    #[serde(default)]
    pub relay_timeout_ms: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RelayRequestAuth {
    #[serde(default)]
    pub key_id: String,
    #[serde(default)]
    pub alg: String,
    #[serde(default)]
    pub tag: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ProtectedAccountTokenAttestation {
    #[serde(default)]
    pub key_id: String,
    #[serde(default)]
    pub alg: String,
    #[serde(default)]
    pub protected_account_token: String,
    #[serde(default)]
    pub expires_at_ms: u64,
    #[serde(default)]
    pub tag: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentAnalyzeRequest {
    #[serde(default = "default_relay_schema_version")]
    pub schema_version: String,
    #[serde(default)]
    pub request_id: String,
    #[serde(default)]
    pub message_id: String,
    #[serde(default)]
    pub sender_token: Option<String>,
    #[serde(default)]
    pub protected_account_token: Option<String>,
    #[serde(default)]
    pub conversation_token: Option<String>,
    #[serde(default)]
    pub account_type: AccountType,
    #[serde(default)]
    pub protection_level: ProtectionLevel,
    #[serde(default)]
    pub conversation_type: ConversationType,
    #[serde(default)]
    pub language: Option<String>,
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub local_observations: Vec<RawObservation>,
    #[serde(default)]
    pub local_context: Option<ThreatContextFrame>,
    #[serde(default)]
    pub local_context_summary: LocalContextSummary,
    #[serde(default)]
    pub local_safety_telemetry: Vec<ClientSafetyTelemetryEvent>,
    #[serde(default)]
    pub recent_message_window: Vec<MessageWindowEntry>,
    #[serde(default)]
    pub server_sender_risk_hint: Option<f32>,
    #[serde(default)]
    pub privacy_mode: RelayPrivacyMode,
    #[serde(default)]
    pub capabilities: AgentCapabilities,
    #[serde(default)]
    pub deadline_ms: Option<u32>,
    #[serde(default)]
    pub protected_account_attestation: Option<ProtectedAccountTokenAttestation>,
    #[serde(default)]
    pub auth: Option<RelayRequestAuth>,
}

impl Default for AgentAnalyzeRequest {
    fn default() -> Self {
        Self {
            schema_version: default_relay_schema_version(),
            request_id: String::new(),
            message_id: String::new(),
            sender_token: None,
            protected_account_token: None,
            conversation_token: None,
            account_type: AccountType::default(),
            protection_level: ProtectionLevel::default(),
            conversation_type: ConversationType::default(),
            language: None,
            text: String::new(),
            local_observations: Vec::new(),
            local_context: None,
            local_context_summary: LocalContextSummary::default(),
            local_safety_telemetry: Vec::new(),
            recent_message_window: Vec::new(),
            server_sender_risk_hint: None,
            privacy_mode: RelayPrivacyMode::default(),
            capabilities: AgentCapabilities::default(),
            deadline_ms: None,
            protected_account_attestation: None,
            auth: None,
        }
    }
}

impl AgentAnalyzeRequest {
    pub fn privacy_safe_sender_token(&self) -> Option<&str> {
        privacy_safe_token_with_prefix(self.sender_token.as_deref(), "snd_")
    }

    pub fn privacy_safe_protected_account_token(&self) -> Option<&str> {
        privacy_safe_token_with_prefix(self.protected_account_token.as_deref(), "acct_")
    }

    pub fn privacy_safe_conversation_token(&self) -> Option<&str> {
        privacy_safe_token_with_prefix(self.conversation_token.as_deref(), "conv_")
    }
}

pub fn sign_protected_account_token_attestation(
    protected_account_token: &str,
    expires_at_ms: u64,
    key_id: &str,
    secret: &[u8],
) -> Option<ProtectedAccountTokenAttestation> {
    if key_id.trim().is_empty()
        || secret.is_empty()
        || expires_at_ms == 0
        || privacy_safe_token_with_prefix(Some(protected_account_token), "acct_").is_none()
    {
        return None;
    }

    let payload =
        protected_account_token_attestation_payload(protected_account_token, expires_at_ms);
    let payload = serde_json::to_vec(&payload).ok()?;
    let tag = hmac_sha256(secret, &payload);

    Some(ProtectedAccountTokenAttestation {
        key_id: key_id.to_string(),
        alg: PROTECTED_ACCOUNT_TOKEN_ATTESTATION_ALG.to_string(),
        protected_account_token: protected_account_token.to_string(),
        expires_at_ms,
        tag: hex_encode(&tag),
    })
}

pub fn verify_protected_account_token_attestation(
    attestation: &ProtectedAccountTokenAttestation,
    protected_account_token: &str,
    now_ms: u64,
    expected_key_id: &str,
    secret: &[u8],
) -> bool {
    if attestation.alg != PROTECTED_ACCOUNT_TOKEN_ATTESTATION_ALG
        || attestation.key_id != expected_key_id
        || attestation.protected_account_token != protected_account_token
        || attestation.expires_at_ms < now_ms
    {
        return false;
    }
    let Some(expected) = sign_protected_account_token_attestation(
        protected_account_token,
        attestation.expires_at_ms,
        expected_key_id,
        secret,
    ) else {
        return false;
    };
    let Some(actual_tag) = hex_decode_32(&attestation.tag) else {
        return false;
    };
    let Some(expected_tag) = hex_decode_32(&expected.tag) else {
        return false;
    };

    constant_time_eq_32(&actual_tag, &expected_tag)
}

pub fn sign_relay_request_auth(
    request: &AgentAnalyzeRequest,
    key_id: &str,
    secret: &[u8],
) -> Option<RelayRequestAuth> {
    if key_id.trim().is_empty()
        || secret.is_empty()
        || request.request_id.trim().is_empty()
        || request.privacy_safe_sender_token().is_none()
    {
        return None;
    }

    let payload = relay_request_auth_payload(request);
    let payload = serde_json::to_vec(&payload).ok()?;
    let tag = hmac_sha256(secret, &payload);

    Some(RelayRequestAuth {
        key_id: key_id.to_string(),
        alg: RELAY_REQUEST_AUTH_ALG.to_string(),
        tag: hex_encode(&tag),
    })
}

pub fn verify_relay_request_auth(
    request: &AgentAnalyzeRequest,
    expected_key_id: &str,
    secret: &[u8],
) -> bool {
    let Some(auth) = request.auth.as_ref() else {
        return false;
    };
    if auth.alg != RELAY_REQUEST_AUTH_ALG || auth.key_id != expected_key_id {
        return false;
    }
    let Some(expected) = sign_relay_request_auth(request, expected_key_id, secret) else {
        return false;
    };
    let Some(actual_tag) = hex_decode_32(&auth.tag) else {
        return false;
    };
    let Some(expected_tag) = hex_decode_32(&expected.tag) else {
        return false;
    };

    constant_time_eq_32(&actual_tag, &expected_tag)
}

#[derive(Serialize)]
struct AgentAnalyzeRequestAuthPayload<'a> {
    auth_scope: &'static str,
    schema_version: &'a str,
    request_id: &'a str,
    message_id: &'a str,
    sender_token: Option<&'a str>,
    protected_account_token: Option<&'a str>,
    conversation_token: Option<&'a str>,
    account_type: AccountType,
    protection_level: ProtectionLevel,
    conversation_type: ConversationType,
    language: Option<&'a str>,
    text: &'a str,
    local_observations: Vec<RawObservationAuthPayload<'a>>,
    local_context: Option<ThreatContextFrameAuthPayload<'a>>,
    local_context_summary: LocalContextSummaryAuthPayload<'a>,
    local_safety_telemetry: Vec<ClientSafetyTelemetryAuthPayload<'a>>,
    recent_message_window: Vec<MessageWindowEntryAuthPayload<'a>>,
    server_sender_risk_hint_bits: Option<u32>,
    privacy_mode: RelayPrivacyMode,
    capabilities: AgentCapabilitiesAuthPayload,
    deadline_ms: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protected_account_attestation: Option<ProtectedAccountTokenAttestationAuthPayload<'a>>,
}

#[derive(Serialize)]
struct ProtectedAccountTokenAttestationAuthPayload<'a> {
    key_id: &'a str,
    alg: &'a str,
    protected_account_token: &'a str,
    expires_at_ms: u64,
    tag: &'a str,
}

#[derive(Serialize)]
struct ProtectedAccountTokenAttestationPayload<'a> {
    auth_scope: &'static str,
    protected_account_token: &'a str,
    expires_at_ms: u64,
}

#[derive(Serialize)]
struct LocalContextSummaryAuthPayload<'a> {
    context_markers: &'a [String],
    recent_observations: Vec<RawObservationAuthPayload<'a>>,
    recent_confirmed_events: Vec<ConfirmedEventAuthPayload<'a>>,
}

#[derive(Serialize)]
struct ClientSafetyTelemetryAuthPayload<'a> {
    event_id: &'a str,
    sender_token: &'a str,
    protected_account_token: &'a str,
    conversation_token: Option<&'a str>,
    surface: SafetyTelemetrySurface,
    threat_type: ThreatType,
    severity: SafetyTelemetrySeverity,
    confidence: Confidence,
    action: SafetyTelemetryAction,
    timestamp_bucket_ms: u64,
    reason_family: Option<&'a str>,
}

#[derive(Serialize)]
struct MessageWindowEntryAuthPayload<'a> {
    sender_id: &'a str,
    text: &'a str,
    timestamp_ms: u64,
}

#[derive(Serialize)]
struct AgentCapabilitiesAuthPayload {
    local_context_interpreter: bool,
    local_tracker: bool,
    supports_remote_correlation: bool,
    relay_timeout_ms: Option<u32>,
}

fn relay_request_auth_payload(request: &AgentAnalyzeRequest) -> AgentAnalyzeRequestAuthPayload<'_> {
    AgentAnalyzeRequestAuthPayload {
        auth_scope: "relay_analyze_request",
        schema_version: &request.schema_version,
        request_id: &request.request_id,
        message_id: &request.message_id,
        sender_token: request.sender_token.as_deref(),
        protected_account_token: request.protected_account_token.as_deref(),
        conversation_token: request.conversation_token.as_deref(),
        account_type: request.account_type,
        protection_level: request.protection_level,
        conversation_type: request.conversation_type,
        language: request.language.as_deref(),
        text: &request.text,
        local_observations: request
            .local_observations
            .iter()
            .map(raw_observation_auth_payload)
            .collect(),
        local_context: request
            .local_context
            .as_ref()
            .map(threat_context_auth_payload),
        local_context_summary: local_context_summary_auth_payload(&request.local_context_summary),
        local_safety_telemetry: request
            .local_safety_telemetry
            .iter()
            .map(client_safety_telemetry_auth_payload)
            .collect(),
        recent_message_window: request
            .recent_message_window
            .iter()
            .map(message_window_entry_auth_payload)
            .collect(),
        server_sender_risk_hint_bits: request.server_sender_risk_hint.map(f32::to_bits),
        privacy_mode: request.privacy_mode,
        capabilities: AgentCapabilitiesAuthPayload {
            local_context_interpreter: request.capabilities.local_context_interpreter,
            local_tracker: request.capabilities.local_tracker,
            supports_remote_correlation: request.capabilities.supports_remote_correlation,
            relay_timeout_ms: request.capabilities.relay_timeout_ms,
        },
        deadline_ms: request.deadline_ms,
        protected_account_attestation: request
            .protected_account_attestation
            .as_ref()
            .map(protected_account_token_attestation_auth_payload),
    }
}

fn protected_account_token_attestation_payload(
    protected_account_token: &str,
    expires_at_ms: u64,
) -> ProtectedAccountTokenAttestationPayload<'_> {
    ProtectedAccountTokenAttestationPayload {
        auth_scope: "protected_account_token_attestation",
        protected_account_token,
        expires_at_ms,
    }
}

fn protected_account_token_attestation_auth_payload(
    attestation: &ProtectedAccountTokenAttestation,
) -> ProtectedAccountTokenAttestationAuthPayload<'_> {
    ProtectedAccountTokenAttestationAuthPayload {
        key_id: &attestation.key_id,
        alg: &attestation.alg,
        protected_account_token: &attestation.protected_account_token,
        expires_at_ms: attestation.expires_at_ms,
        tag: &attestation.tag,
    }
}

fn local_context_summary_auth_payload(
    summary: &LocalContextSummary,
) -> LocalContextSummaryAuthPayload<'_> {
    LocalContextSummaryAuthPayload {
        context_markers: &summary.context_markers,
        recent_observations: summary
            .recent_observations
            .iter()
            .map(raw_observation_auth_payload)
            .collect(),
        recent_confirmed_events: summary
            .recent_confirmed_events
            .iter()
            .map(confirmed_event_auth_payload)
            .collect(),
    }
}

fn client_safety_telemetry_auth_payload(
    event: &ClientSafetyTelemetryEvent,
) -> ClientSafetyTelemetryAuthPayload<'_> {
    ClientSafetyTelemetryAuthPayload {
        event_id: &event.event_id,
        sender_token: &event.sender_token,
        protected_account_token: &event.protected_account_token,
        conversation_token: event.conversation_token.as_deref(),
        surface: event.surface,
        threat_type: event.threat_type,
        severity: event.severity,
        confidence: event.confidence,
        action: event.action,
        timestamp_bucket_ms: event.timestamp_bucket_ms,
        reason_family: event.reason_family.as_deref(),
    }
}

fn message_window_entry_auth_payload(
    entry: &MessageWindowEntry,
) -> MessageWindowEntryAuthPayload<'_> {
    MessageWindowEntryAuthPayload {
        sender_id: &entry.sender_id,
        text: &entry.text,
        timestamp_ms: entry.timestamp_ms,
    }
}

fn privacy_safe_token_with_prefix<'a>(token: Option<&'a str>, prefix: &str) -> Option<&'a str> {
    let token = token?;
    (token.starts_with(prefix) && !token_looks_raw(token)).then_some(token)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RiskHorizon {
    #[default]
    Unknown,
    Immediate,
    NearTerm,
    Sustained,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct RemoteFinding {
    pub threat_type: ThreatType,
    #[serde(default)]
    pub score: f32,
    #[serde(default)]
    pub confidence: Confidence,
    #[serde(default)]
    pub reason_code: String,
    #[serde(default)]
    pub explanation: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct RemoteInferenceSummary {
    #[serde(default)]
    pub primary_threat: ThreatType,
    #[serde(default)]
    pub score: f32,
    #[serde(default)]
    pub confidence: Confidence,
    #[serde(default)]
    pub risk_horizon: RiskHorizon,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RelayResponseAuth {
    #[serde(default)]
    pub key_id: String,
    #[serde(default)]
    pub alg: String,
    #[serde(default)]
    pub tag: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RelayAnalyzeResponse {
    #[serde(default = "default_relay_schema_version")]
    pub schema_version: String,
    #[serde(default)]
    pub request_id: String,
    #[serde(default)]
    pub remote_observations: Vec<RawObservation>,
    #[serde(default)]
    pub remote_context: Option<ThreatContextFrame>,
    #[serde(default)]
    pub remote_events: Vec<ConfirmedEvent>,
    #[serde(default)]
    pub findings: Vec<RemoteFinding>,
    #[serde(default)]
    pub inference: Option<RemoteInferenceSummary>,
    #[serde(default)]
    pub reason_codes: Vec<String>,
    #[serde(default)]
    pub context_markers: Vec<String>,
    #[serde(default)]
    pub confidence: Confidence,
    #[serde(default)]
    pub expires_at_ms: Option<u64>,
    #[serde(default)]
    pub sender_reputation_hint: Option<f32>,
    #[serde(default)]
    pub correlation_findings: Vec<String>,
    #[serde(default)]
    pub auth: Option<RelayResponseAuth>,
}

impl Default for RelayAnalyzeResponse {
    fn default() -> Self {
        Self {
            schema_version: default_relay_schema_version(),
            request_id: String::new(),
            remote_observations: Vec::new(),
            remote_context: None,
            remote_events: Vec::new(),
            findings: Vec::new(),
            inference: None,
            reason_codes: Vec::new(),
            context_markers: Vec::new(),
            confidence: Confidence::default(),
            expires_at_ms: None,
            sender_reputation_hint: None,
            correlation_findings: Vec::new(),
            auth: None,
        }
    }
}

pub fn sign_relay_response_auth(
    response: &RelayAnalyzeResponse,
    sender_token: &str,
    key_id: &str,
    secret: &[u8],
) -> Option<RelayResponseAuth> {
    if key_id.trim().is_empty()
        || secret.is_empty()
        || privacy_safe_token_with_prefix(Some(sender_token), "snd_").is_none()
    {
        return None;
    }

    let payload = relay_response_auth_payload(response, sender_token);
    let payload = serde_json::to_vec(&payload).ok()?;
    let tag = hmac_sha256(secret, &payload);

    Some(RelayResponseAuth {
        key_id: key_id.to_string(),
        alg: RELAY_RESPONSE_AUTH_ALG.to_string(),
        tag: hex_encode(&tag),
    })
}

pub fn verify_relay_response_auth(
    response: &RelayAnalyzeResponse,
    sender_token: &str,
    expected_key_id: &str,
    secret: &[u8],
) -> bool {
    let Some(auth) = response.auth.as_ref() else {
        return false;
    };
    if auth.alg != RELAY_RESPONSE_AUTH_ALG || auth.key_id != expected_key_id {
        return false;
    }
    let Some(expected) = sign_relay_response_auth(response, sender_token, expected_key_id, secret)
    else {
        return false;
    };
    let Some(actual_tag) = hex_decode_32(&auth.tag) else {
        return false;
    };
    let Some(expected_tag) = hex_decode_32(&expected.tag) else {
        return false;
    };

    constant_time_eq_32(&actual_tag, &expected_tag)
}

#[derive(Serialize)]
struct RelayResponseAuthPayload<'a> {
    schema_version: &'a str,
    request_id: &'a str,
    sender_token: &'a str,
    remote_observations: Vec<RawObservationAuthPayload<'a>>,
    remote_context: Option<ThreatContextFrameAuthPayload<'a>>,
    remote_events: Vec<ConfirmedEventAuthPayload<'a>>,
    findings: Vec<RemoteFindingAuthPayload<'a>>,
    inference: Option<RemoteInferenceAuthPayload>,
    reason_codes: &'a [String],
    context_markers: &'a [String],
    confidence: Confidence,
    expires_at_ms: Option<u64>,
    sender_reputation_hint_bits: Option<u32>,
    correlation_findings: &'a [String],
}

#[derive(Serialize)]
struct RawObservationAuthPayload<'a> {
    threat_type: ThreatType,
    threat_subtype: &'a str,
    layer: DetectionLayer,
    score_bits: u32,
    confidence: Confidence,
    reason_code: &'a str,
    explanation: &'a str,
}

#[derive(Serialize)]
struct ThreatContextFrameAuthPayload<'a> {
    speech_act: SpeechAct,
    stance: Stance,
    directionality: Directionality,
    relationship: &'a [RelationshipTag],
    trajectory: &'a [TrajectoryTag],
    confidence_bits: u32,
}

#[derive(Serialize)]
struct ConfirmedEventAuthPayload<'a> {
    threat_type: ThreatType,
    score_bits: u32,
    confidence: Confidence,
    context: ThreatContextFrameAuthPayload<'a>,
    reason_codes: &'a [String],
    context_markers: &'a [String],
}

#[derive(Serialize)]
struct RemoteFindingAuthPayload<'a> {
    threat_type: ThreatType,
    score_bits: u32,
    confidence: Confidence,
    reason_code: &'a str,
    explanation: &'a str,
}

#[derive(Serialize)]
struct RemoteInferenceAuthPayload {
    primary_threat: ThreatType,
    score_bits: u32,
    confidence: Confidence,
    risk_horizon: RiskHorizon,
}

fn relay_response_auth_payload<'a>(
    response: &'a RelayAnalyzeResponse,
    sender_token: &'a str,
) -> RelayResponseAuthPayload<'a> {
    RelayResponseAuthPayload {
        schema_version: &response.schema_version,
        request_id: &response.request_id,
        sender_token,
        remote_observations: response
            .remote_observations
            .iter()
            .map(raw_observation_auth_payload)
            .collect(),
        remote_context: response
            .remote_context
            .as_ref()
            .map(threat_context_auth_payload),
        remote_events: response
            .remote_events
            .iter()
            .map(confirmed_event_auth_payload)
            .collect(),
        findings: response
            .findings
            .iter()
            .map(remote_finding_auth_payload)
            .collect(),
        inference: response
            .inference
            .as_ref()
            .map(remote_inference_auth_payload),
        reason_codes: &response.reason_codes,
        context_markers: &response.context_markers,
        confidence: response.confidence,
        expires_at_ms: response.expires_at_ms,
        sender_reputation_hint_bits: response.sender_reputation_hint.map(f32::to_bits),
        correlation_findings: &response.correlation_findings,
    }
}

fn raw_observation_auth_payload(observation: &RawObservation) -> RawObservationAuthPayload<'_> {
    RawObservationAuthPayload {
        threat_type: observation.threat_type,
        threat_subtype: &observation.threat_subtype,
        layer: observation.layer,
        score_bits: observation.score.to_bits(),
        confidence: observation.confidence,
        reason_code: &observation.reason_code,
        explanation: &observation.explanation,
    }
}

fn threat_context_auth_payload(context: &ThreatContextFrame) -> ThreatContextFrameAuthPayload<'_> {
    ThreatContextFrameAuthPayload {
        speech_act: context.speech_act,
        stance: context.stance,
        directionality: context.directionality,
        relationship: &context.relationship,
        trajectory: &context.trajectory,
        confidence_bits: context.confidence.to_bits(),
    }
}

fn confirmed_event_auth_payload(event: &ConfirmedEvent) -> ConfirmedEventAuthPayload<'_> {
    ConfirmedEventAuthPayload {
        threat_type: event.threat_type,
        score_bits: event.score.to_bits(),
        confidence: event.confidence,
        context: threat_context_auth_payload(&event.context),
        reason_codes: &event.reason_codes,
        context_markers: &event.context_markers,
    }
}

fn remote_finding_auth_payload(finding: &RemoteFinding) -> RemoteFindingAuthPayload<'_> {
    RemoteFindingAuthPayload {
        threat_type: finding.threat_type,
        score_bits: finding.score.to_bits(),
        confidence: finding.confidence,
        reason_code: &finding.reason_code,
        explanation: &finding.explanation,
    }
}

fn remote_inference_auth_payload(inference: &RemoteInferenceSummary) -> RemoteInferenceAuthPayload {
    RemoteInferenceAuthPayload {
        primary_threat: inference.primary_threat,
        score_bits: inference.score.to_bits(),
        confidence: inference.confidence,
        risk_horizon: inference.risk_horizon,
    }
}

fn hmac_sha256(secret: &[u8], payload: &[u8]) -> [u8; 32] {
    const BLOCK_BYTES: usize = 64;

    let mut key_block = [0u8; BLOCK_BYTES];
    if secret.len() > BLOCK_BYTES {
        let digest = Sha256::digest(secret);
        let digest_bytes: &[u8] = digest.as_ref();
        key_block[..digest_bytes.len()].copy_from_slice(digest_bytes);
    } else {
        key_block[..secret.len()].copy_from_slice(secret);
    }

    let mut inner_pad = [0x36u8; BLOCK_BYTES];
    let mut outer_pad = [0x5cu8; BLOCK_BYTES];
    for (index, key_byte) in key_block.iter().enumerate() {
        inner_pad[index] ^= key_byte;
        outer_pad[index] ^= key_byte;
    }

    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(payload);
    let inner_hash = inner.finalize();
    let inner_hash_bytes: &[u8] = inner_hash.as_ref();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_hash_bytes);
    let outer_hash = outer.finalize();
    let outer_hash_bytes: &[u8] = outer_hash.as_ref();

    let mut output = [0u8; 32];
    output.copy_from_slice(outer_hash_bytes);
    output
}

fn hex_encode(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn hex_decode_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }

    let mut decoded = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        decoded[index] = (high << 4) | low;
    }
    Some(decoded)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn constant_time_eq_32(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for index in 0..left.len() {
        diff |= left[index] ^ right[index];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_defaults_to_current_schema_version() {
        let request = AgentAnalyzeRequest::default();
        assert_eq!(request.schema_version, AURA_RELAY_SCHEMA_VERSION);
        assert_eq!(request.privacy_mode, RelayPrivacyMode::MessageOnly);
        assert!(request.privacy_safe_sender_token().is_none());
    }

    #[test]
    fn request_subject_tokens_are_prefix_checked() {
        let request = AgentAnalyzeRequest {
            sender_token: Some("snd_01H00000000000000000000000".to_string()),
            protected_account_token: Some("acct_01H0000000000000000000000".to_string()),
            conversation_token: Some("conv_01H000000000000000000000".to_string()),
            ..AgentAnalyzeRequest::default()
        };

        assert_eq!(
            request.privacy_safe_sender_token(),
            Some("snd_01H00000000000000000000000")
        );
        assert_eq!(
            request.privacy_safe_protected_account_token(),
            Some("acct_01H0000000000000000000000")
        );
        assert_eq!(
            request.privacy_safe_conversation_token(),
            Some("conv_01H000000000000000000000")
        );

        let raw_request = AgentAnalyzeRequest {
            sender_token: Some("mentor 42".to_string()),
            protected_account_token: Some("kid@example.test".to_string()),
            conversation_token: Some("conv room 1".to_string()),
            ..AgentAnalyzeRequest::default()
        };

        assert!(raw_request.privacy_safe_sender_token().is_none());
        assert!(raw_request.privacy_safe_protected_account_token().is_none());
        assert!(raw_request.privacy_safe_conversation_token().is_none());
    }

    #[test]
    fn client_safety_telemetry_is_serialized_without_plaintext_fields() {
        let telemetry = ClientSafetyTelemetryEvent {
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

        assert!(telemetry.privacy_safe());
        let json = serde_json::to_string(&telemetry).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let object = value.as_object().unwrap();
        assert!(!object.contains_key("text"));
        assert!(!object.contains_key("message"));
        assert!(!object.contains_key("message_body"));
        assert!(!object.contains_key("raw_message"));
        assert!(!object.contains_key("explanation"));
        assert!(!object.contains_key("matched_phrase"));
    }

    #[test]
    fn client_safety_telemetry_rejects_raw_looking_tokens() {
        let telemetry = ClientSafetyTelemetryEvent {
            event_id: "event 42".to_string(),
            sender_token: "mentor 42".to_string(),
            protected_account_token: "kid@example.test".to_string(),
            reason_family: Some("dont tell parents".to_string()),
            ..ClientSafetyTelemetryEvent::default()
        };

        let errors = telemetry.privacy_errors();
        assert!(errors.contains(&"event_id_looks_raw"));
        assert!(errors.contains(&"sender_token_looks_raw"));
        assert!(errors.contains(&"protected_account_token_looks_raw"));
        assert!(errors.contains(&"reason_family_looks_raw"));
    }

    #[test]
    fn protected_account_token_attestation_binds_token_and_expiry() {
        let token = "acct_01H0000000000000000000000";
        let secret = b"protected account token attestation secret";
        let attestation = sign_protected_account_token_attestation(
            token,
            1_900_000_000_000,
            "acct-attest-key-1",
            secret,
        )
        .expect("privacy-safe token should be attestable");

        assert!(verify_protected_account_token_attestation(
            &attestation,
            token,
            1_778_652_000_000,
            "acct-attest-key-1",
            secret,
        ));
        assert!(!verify_protected_account_token_attestation(
            &attestation,
            "acct_01H0000000000000000000001",
            1_778_652_000_000,
            "acct-attest-key-1",
            secret,
        ));
        assert!(!verify_protected_account_token_attestation(
            &attestation,
            token,
            1_950_000_000_000,
            "acct-attest-key-1",
            secret,
        ));
    }

    #[test]
    fn relay_response_round_trips_through_json() {
        let response = RelayAnalyzeResponse {
            request_id: "req_42".to_string(),
            findings: vec![RemoteFinding {
                threat_type: ThreatType::Grooming,
                score: 0.94,
                confidence: Confidence::High,
                reason_code: "relay.grooming.sequence".to_string(),
                explanation: "remote grooming sequence corroborated".to_string(),
            }],
            inference: Some(RemoteInferenceSummary {
                primary_threat: ThreatType::Grooming,
                score: 0.94,
                confidence: Confidence::High,
                risk_horizon: RiskHorizon::NearTerm,
            }),
            sender_reputation_hint: Some(0.82),
            ..RelayAnalyzeResponse::default()
        };

        let json = serde_json::to_string(&response).unwrap();
        let parsed: RelayAnalyzeResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.request_id, "req_42");
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.findings[0].threat_type, ThreatType::Grooming);
        assert_eq!(parsed.sender_reputation_hint, Some(0.82));
    }

    #[test]
    fn relay_request_auth_binds_payload() {
        let secret = b"relay request auth test secret";
        let mut request = AgentAnalyzeRequest {
            request_id: "req_01H00000000000000000000000".to_string(),
            message_id: "msg_01H00000000000000000000000".to_string(),
            sender_token: Some("snd_01H00000000000000000000000".to_string()),
            protected_account_token: Some("acct_01H0000000000000000000000".to_string()),
            conversation_token: Some("conv_01H000000000000000000000".to_string()),
            privacy_mode: RelayPrivacyMode::MetadataOnly,
            local_safety_telemetry: vec![ClientSafetyTelemetryEvent {
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
            }],
            ..AgentAnalyzeRequest::default()
        };

        request.auth = sign_relay_request_auth(&request, "relay-req-key-1", secret);

        assert!(verify_relay_request_auth(
            &request,
            "relay-req-key-1",
            secret
        ));

        let mut tampered = request.clone();
        tampered.local_safety_telemetry[0].reason_family = Some("bullying".to_string());
        assert!(!verify_relay_request_auth(
            &tampered,
            "relay-req-key-1",
            secret
        ));
    }

    #[test]
    fn relay_request_auth_binds_protected_account_attestation() {
        let request_secret = b"relay request auth test secret";
        let attestation_secret = b"protected account token attestation secret";
        let protected_account_token = "acct_01H0000000000000000000000";
        let mut request = AgentAnalyzeRequest {
            request_id: "req_01H00000000000000000000000".to_string(),
            sender_token: Some("snd_01H00000000000000000000000".to_string()),
            protected_account_token: Some(protected_account_token.to_string()),
            protected_account_attestation: sign_protected_account_token_attestation(
                protected_account_token,
                1_900_000_000_000,
                "acct-attest-key-1",
                attestation_secret,
            ),
            privacy_mode: RelayPrivacyMode::MetadataOnly,
            ..AgentAnalyzeRequest::default()
        };

        request.auth = sign_relay_request_auth(&request, "relay-req-key-1", request_secret);

        assert!(verify_relay_request_auth(
            &request,
            "relay-req-key-1",
            request_secret
        ));

        let mut tampered = request.clone();
        tampered
            .protected_account_attestation
            .as_mut()
            .expect("attestation should exist")
            .expires_at_ms = 1_950_000_000_000;
        assert!(!verify_relay_request_auth(
            &tampered,
            "relay-req-key-1",
            request_secret
        ));
    }

    #[test]
    fn relay_response_auth_binds_sender_and_payload() {
        let sender_token = "snd_01H00000000000000000000000";
        let secret = b"relay response auth test secret";
        let mut response = RelayAnalyzeResponse {
            request_id: "req_01H00000000000000000000000".to_string(),
            findings: vec![RemoteFinding {
                threat_type: ThreatType::Grooming,
                score: 0.94,
                confidence: Confidence::High,
                reason_code: "relay.grooming.sequence".to_string(),
                explanation: String::new(),
            }],
            inference: Some(RemoteInferenceSummary {
                primary_threat: ThreatType::Grooming,
                score: 0.94,
                confidence: Confidence::High,
                risk_horizon: RiskHorizon::NearTerm,
            }),
            sender_reputation_hint: Some(0.82),
            expires_at_ms: Some(1_778_652_060_000),
            correlation_findings: vec![
                "relay.context.cross_conversation_safety_telemetry".to_string()
            ],
            ..RelayAnalyzeResponse::default()
        };

        response.auth = sign_relay_response_auth(&response, sender_token, "relay-key-1", secret);

        assert!(verify_relay_response_auth(
            &response,
            sender_token,
            "relay-key-1",
            secret
        ));
        assert!(!verify_relay_response_auth(
            &response,
            "snd_01H00000000000000000000001",
            "relay-key-1",
            secret
        ));

        let mut tampered = response.clone();
        tampered.sender_reputation_hint = Some(0.12);
        assert!(!verify_relay_response_auth(
            &tampered,
            sender_token,
            "relay-key-1",
            secret
        ));
    }

    #[test]
    fn relay_response_auth_rejects_unsafe_inputs() {
        let response = RelayAnalyzeResponse {
            request_id: "req_01H00000000000000000000000".to_string(),
            sender_reputation_hint: Some(0.82),
            ..RelayAnalyzeResponse::default()
        };

        assert!(sign_relay_response_auth(
            &response,
            "sender@example.test",
            "relay-key-1",
            b"secret"
        )
        .is_none());
        assert!(sign_relay_response_auth(
            &response,
            "snd_01H00000000000000000000000",
            "",
            b"secret"
        )
        .is_none());
        assert!(sign_relay_response_auth(
            &response,
            "snd_01H00000000000000000000000",
            "relay-key-1",
            b""
        )
        .is_none());
    }

    #[test]
    fn relay_request_auth_rejects_unsafe_inputs() {
        let request = AgentAnalyzeRequest {
            request_id: "req_01H00000000000000000000000".to_string(),
            sender_token: Some("sender@example.test".to_string()),
            ..AgentAnalyzeRequest::default()
        };

        assert!(sign_relay_request_auth(&request, "relay-req-key-1", b"secret").is_none());

        let request = AgentAnalyzeRequest {
            request_id: String::new(),
            sender_token: Some("snd_01H00000000000000000000000".to_string()),
            ..AgentAnalyzeRequest::default()
        };

        assert!(sign_relay_request_auth(&request, "relay-req-key-1", b"secret").is_none());
    }

    #[test]
    fn hmac_sha256_matches_rfc4231_test_vector() {
        let secret = [0x0b; 20];
        let tag = hmac_sha256(&secret, b"Hi There");

        assert_eq!(
            hex_encode(&tag),
            concat!(
                "b0344c61d8db38535ca8afceaf0bf12b",
                "881dc200c9833da726e9376c2e32cff7"
            )
        );
    }
}
