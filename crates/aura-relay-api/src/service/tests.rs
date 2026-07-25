use super::*;
use aura_contracts::{
    sign_protected_account_token_attestation, sign_relay_request_auth, verify_relay_request_auth,
    verify_relay_response_auth, AccountType, ClientSafetyTelemetryEvent, Confidence,
    DetectionLayer, RawObservation, RelationshipTrustSource, RelayPrivacyMode,
    SafetyTelemetryAction, SafetyTelemetrySeverity, SafetyTelemetrySurface, SenderRelationship,
};

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
    let issuer =
        ProtectedAccountAttestationIssuer::from_config(ProtectedAccountAttestationIssuerConfig {
            signing_keys: vec![RelayProtectedAccountAttestationKeyConfig {
                key_id: "acct-attest-key-1".to_string(),
                secret: attestation_secret.to_string(),
                not_before_ms: Some(1),
                not_after_ms: Some(now_ms.saturating_add(600_000)),
                revoked: false,
            }],
            ttl_ms: 60_000,
            allowed_protected_account_tokens: vec![account_token.clone()],
        })
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
    let issuer =
        ProtectedAccountAttestationIssuer::from_config(ProtectedAccountAttestationIssuerConfig {
            signing_keys: vec![RelayProtectedAccountAttestationKeyConfig {
                key_id: "acct-attest-key-1".to_string(),
                secret: "protected account attestation secret".to_string(),
                not_before_ms: None,
                not_after_ms: None,
                revoked: false,
            }],
            ttl_ms: 60_000,
            allowed_protected_account_tokens: vec![account_token.clone()],
        })
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

    let issuer =
        ProtectedAccountAttestationIssuer::from_config(ProtectedAccountAttestationIssuerConfig {
            signing_keys: vec![RelayProtectedAccountAttestationKeyConfig {
                key_id: "acct-attest-key-1".to_string(),
                secret: "protected account attestation secret".to_string(),
                not_before_ms: None,
                not_after_ms: None,
                revoked: true,
            }],
            ttl_ms: 60_000,
            allowed_protected_account_tokens: vec![protected_account_token(0)],
        })
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
    let issuer =
        ProtectedAccountAttestationIssuer::from_config(ProtectedAccountAttestationIssuerConfig {
            signing_keys: vec![RelayProtectedAccountAttestationKeyConfig {
                key_id: "acct-attest-key-1".to_string(),
                secret: "protected account attestation secret".to_string(),
                not_before_ms: None,
                not_after_ms: None,
                revoked: false,
            }],
            ttl_ms: 60_000,
            allowed_protected_account_tokens: vec![account_token.clone()],
        })
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

    let rejected = service
        .handle_authenticated_analyze(mismatched, RelayCallerContext::new(caller_token.clone()));

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
        let mut request =
            request_with_safety_telemetry_from_account(&sender_token, account_index, account_index);
        request.protected_account_token = Some(account_token.clone());
        request.auth = sign_relay_request_auth(&request, "relay-req-key-1", request_secret);
        response =
            service.handle_authenticated_analyze(request, RelayCallerContext::new(account_token));
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
        .with_protected_account_attestation_key("acct-attest-key-1", attestation_secret.to_vec());
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
    let service = RelayService::new()
        .with_protected_account_attestation_key("acct-attest-key-1", attestation_secret.to_vec());
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
        .with_protected_account_attestation_key("acct-attest-key-1", attestation_secret.to_vec());
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
        .with_protected_account_attestation_key("acct-attest-key-1", attestation_secret.to_vec());
    let sender_token = "snd_01H00000000000000000000000".to_string();
    let mut request = request_with_safety_telemetry_from_account(&sender_token, 0, 0);
    let token = request
        .protected_account_token
        .as_deref()
        .expect("test request has protected account token");
    request.protected_account_attestation =
        sign_protected_account_token_attestation(token, 1, "acct-attest-key-1", attestation_secret);
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
        .with_protected_account_attestation_key("acct-attest-key-1", attestation_secret.to_vec());
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
        .with_protected_account_attestation_key("acct-attest-key-1", attestation_secret.to_vec());
    let sender_token = "snd_01H00000000000000000000000".to_string();
    let mut response = RelayAnalyzeResponse::default();

    for account_index in 0..3 {
        let mut request =
            request_with_safety_telemetry_from_account(&sender_token, account_index, account_index);
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
    let mut not_yet_valid_request = request_with_safety_telemetry_from_account(&sender_token, 0, 0);
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
    sign_request_with_account_attestation(&mut expired_request, request_secret, attestation_secret);

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
    sign_request_with_account_attestation(&mut active_request, request_secret, attestation_secret);

    let active = active_service.handle_analyze(active_request);

    assert!(!active
        .reason_codes
        .iter()
        .any(|code| code.starts_with("relay.auth.protected_account_attestation_key")));
    assert!(active.sender_reputation_hint.is_some());
}

#[test]
fn relay_service_rejects_account_attestation_expiry_too_far_in_future_without_recording_reputation()
{
    let request_secret = b"relay request auth test secret";
    let attestation_secret = b"protected account attestation secret";
    let service = RelayService::new()
        .with_request_auth_key("relay-req-key-1", request_secret.to_vec())
        .with_protected_account_attestation_key("acct-attest-key-1", attestation_secret.to_vec())
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
        .with_protected_account_attestation_key("acct-attest-key-1", attestation_secret.to_vec())
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
        .with_protected_account_attestation_key("acct-attest-key-1", attestation_secret.to_vec());
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

fn assert_config_error_contains(result: Result<(), RelayAuthConfigError>, expected_fragment: &str) {
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
