use super::*;
use gaugedesk_core::ids::SecretHandleId;
use gaugedesk_core::model_connection::{ConnectionStatus, Material};
use gaugedesk_core::Lifecycle;
use serde_json::json;

#[test]
fn service_inspection_preserves_the_closed_request_identity() {
    let value = MetadataRequest::parse(intake_body()).unwrap();
    assert_eq!(value.operation_id(), "organization-provider.api-key.add");
    assert_eq!(value.expected_revision(), 0);
    assert_eq!(value.store_key(), "management:intake");
    assert_eq!(value.required_permission(), Permission::ManageConnections);
    let value = request(
        "organization-provider.grant.cap.set",
        json!({"grant":"grant-a", "caps":{"tokens":"0", "money":null}}),
        u64::MAX,
        "cap",
    );
    assert_eq!(value.operation_id(), "organization-provider.grant.cap.set");
    assert_eq!(value.expected_revision(), u64::MAX);
    assert_eq!(value.required_permission(), Permission::ManageGrants);
}

pub(super) fn binding() -> AuthorityBinding {
    AuthorityBinding {
        authority: AuthorityId::new("credential-authority"),
        organization: ScopeId::new("example-organization"),
        environment: "test".into(),
    }
}
pub(super) fn scope() -> String {
    store_scope(&binding().organization)
}
pub(super) fn connection() -> ModelConnectionId {
    ModelConnectionId::new("connection-a")
}
pub(super) fn version() -> CredentialVersionId {
    CredentialVersionId::new("version-a")
}
fn policy() -> Value {
    json!({"models": ["model-a"], "execution_classes": ["private_broker"]})
}
fn body(operation: &str, arguments: Value, revision: u64, key: &str) -> Value {
    json!({"v": 1, "idempotency_key": key, "expected_revision": revision.to_string(), "action": {"operation": operation, "arguments": arguments}})
}
fn request(operation: &str, arguments: Value, revision: u64, key: &str) -> MetadataRequest {
    MetadataRequest::parse(body(operation, arguments, revision, key)).unwrap()
}
fn intake_body() -> Value {
    body(
        "organization-provider.api-key.add",
        json!({
            "name": "Team provider", "provider": "isolated-provider",
            "endpoint": "https://provider.invalid/v1", "policy": policy(), "reconnects": null
        }),
        0,
        "intake",
    )
}
fn context(request: &MetadataRequest) -> ManagementContext {
    let actor = AuthorityId::new("authenticated-admin");
    ManagementContext {
        binding: binding(),
        actor: actor.clone(),
        permissions: [Permission::ManageConnections, Permission::ManageGrants].into(),
        approval: Approval {
            binding: binding(),
            actor,
            request: request.clone(),
            evidence: ObservationId::new("human-change-1"),
        },
        now: 100,
        intake_ttl_seconds: 300,
        validated_definition: None,
        validated_subject: None,
        validated_policy: None,
    }
}
fn apply(store: &mut Store, capability: Capability, operation: Operation) -> State {
    let state = store.fold::<ModelConnection>(&scope()).unwrap();
    store
        .admit_materialized::<ModelConnection>(
            &scope(),
            &format!("fixture-{}", state.revision),
            Command {
                binding: binding(),
                actor: AuthorityId::new("authenticated-admin"),
                capability,
                basis: Basis::Metadata(state.revision),
                now: state.last_at + 1,
                operation,
            },
        )
        .unwrap()
        .state
}
pub(super) fn ready(store: &mut Store) {
    let parsed = MetadataRequest::parse(intake_body()).unwrap();
    let definition = parsed.requested_definition().unwrap();
    let provider = definition.provider.clone();
    let handle = SecretHandleId::new("test-opaque-custody-handle");
    apply(
        store,
        Capability::ManageConnections,
        Operation::BeginIntake {
            connection: connection(),
            definition,
            reconnects: None,
            version: version(),
            expires_at: 1000,
        },
    );
    apply(
        store,
        Capability::SealCandidate,
        Operation::RecordSealed {
            connection: connection(),
            version: version(),
            handle: handle.clone(),
        },
    );
    apply(
        store,
        Capability::VerifyCandidate,
        Operation::RecordVerification {
            connection: connection(),
            version: version(),
            provider,
            handle,
            evidence: ObservationId::new("isolated-provider-check"),
            check: gaugedesk_core::model_connection::VerificationCheck::ModelCatalogRead,
            passed: true,
        },
    );
    apply(
        store,
        Capability::ManageConnections,
        Operation::Activate {
            connection: connection(),
            version: version(),
        },
    );
}
fn grant(subject: Value, caps: Value) -> MetadataRequest {
    request(
        "organization-provider.grant.create",
        json!({
            "connection": connection(), "subject": subject, "policy": policy(),
            "audiences": ["member"], "caps": caps,
        }),
        4,
        "grant",
    )
}
fn admit_subject(context: &mut ManagementContext, request: &MetadataRequest) {
    let (connection, subject) = request.requested_subject().unwrap();
    context.validated_subject = Some(SubjectAdmission {
        connection,
        subject,
        evidence: ObservationId::new("current-subject-and-funding-admission"),
    });
}

#[test]
fn only_closed_management_inputs_are_accepted() {
    for field in [
        "role",
        "capability",
        "approved",
        "actor",
        "secret",
        "secret_handle",
        "verified",
        "usage",
        "now",
    ] {
        for path in [
            "",
            "/action",
            "/action/arguments",
            "/action/arguments/policy",
        ] {
            let mut input = intake_body();
            input
                .pointer_mut(path)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert(field.into(), json!("must-not-be-echoed"));
            assert_eq!(
                MetadataRequest::parse(input).unwrap_err().reason,
                "invalid model-provider command schema",
                "{path}/{field}"
            );
        }
    }
    for operation in [
        "RecordSealed",
        "organization-provider.verified",
        "organization-provider.secret.get",
        "organization-provider.spend.settle",
    ] {
        assert!(MetadataRequest::parse(body(operation, json!({}), 0, "key")).is_err());
    }
    for field in ["connection", "grant", "version"] {
        let operation = match field {
            "connection" => "organization-provider.suspend",
            "grant" => "organization-provider.grant.suspend",
            _ => "organization-provider.intake.cancel",
        };
        let mut arguments = if field == "version" {
            json!({"connection": "connection-a"})
        } else {
            json!({})
        };
        arguments[field] = json!(" ");
        assert!(MetadataRequest::parse(body(operation, arguments, 0, "key")).is_err());
    }
    for version in [json!(0), json!(2), json!("1")] {
        let mut input = intake_body();
        input["v"] = version;
        assert!(MetadataRequest::parse(input).is_err());
    }
}

#[test]
fn nested_grant_fields_cannot_smuggle_proofs_or_counters() {
    let original = serde_json::to_value(grant(
        json!({"kind": "member", "id": "member-a"}),
        json!({"tokens": "0", "money": {"currency": "USD", "micros": "0"}}),
    ))
    .unwrap();
    for path in [
        "/action/arguments",
        "/action/arguments/subject",
        "/action/arguments/policy",
        "/action/arguments/caps",
        "/action/arguments/caps/money",
    ] {
        let mut input = original.clone();
        input
            .pointer_mut(path)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("admitted".into(), json!(true));
        assert!(MetadataRequest::parse(input).is_err(), "{path}");
    }
    let mut input = original;
    input["action"]["arguments"]["audiences"] = json!(["administrator"]);
    assert!(MetadataRequest::parse(input).is_err());
}

#[test]
fn limits_are_exact_strings_and_null_is_not_zero_or_a_missing_field() {
    let maximum = u64::MAX.to_string();
    let original = serde_json::to_value(grant(
        json!({"kind": "member", "id": "member-a"}),
        json!({"tokens": maximum, "money": {"currency": "USD", "micros": maximum}}),
    ))
    .unwrap();
    for path in [
        "/expected_revision",
        "/action/arguments/caps/tokens",
        "/action/arguments/caps/money/micros",
    ] {
        for invalid in [
            json!(1),
            json!(1.5),
            json!("01"),
            json!("+1"),
            json!("-1"),
            json!(" 1"),
            json!("1e3"),
            json!("18446744073709551616"),
        ] {
            let mut input = original.clone();
            *input.pointer_mut(path).unwrap() = invalid;
            assert!(MetadataRequest::parse(input).is_err(), "{path}");
        }
    }
    for missing in ["tokens", "money"] {
        let mut input = original.clone();
        input["action"]["arguments"]["caps"]
            .as_object_mut()
            .unwrap()
            .remove(missing);
        assert!(MetadataRequest::parse(input).is_err());
    }
    let mut store = Store::open_in_memory().unwrap();
    ready(&mut store);
    let req = MetadataRequest::parse(original).unwrap();
    let mut ctx = context(&req);
    admit_subject(&mut ctx, &req);
    let state = admit_metadata(&mut store, &ctx, &req).unwrap().state;
    let (id, record) = state.grants.iter().next().unwrap();
    assert_eq!(record.definition.caps.tokens, Some(u64::MAX));
    assert_eq!(
        record.definition.caps.money.as_ref().unwrap().micros,
        u64::MAX
    );
    let req = request(
        "organization-provider.grant.cap.set",
        json!({"grant": id, "caps": {"tokens": "0", "money": null}}),
        state.revision,
        "zero-cap",
    );
    let state = admit_metadata(&mut store, &context(&req), &req)
        .unwrap()
        .state;
    assert_eq!(
        state.grants[id].definition.caps,
        access::Caps {
            tokens: Some(0),
            money: None
        }
    );
    let req = request(
        "organization-provider.grant.cap.set",
        json!({"grant": id, "caps": {"tokens": null, "money": null}}),
        state.revision,
        "no-cap",
    );
    let state = admit_metadata(&mut store, &context(&req), &req)
        .unwrap()
        .state;
    assert_eq!(
        state.grants[id].definition.caps,
        access::Caps {
            tokens: None,
            money: None
        }
    );
}

#[test]
fn cap_edits_do_not_echo_or_reapprove_a_grants_policy_and_audience() {
    let mut store = Store::open_in_memory().unwrap();
    ready(&mut store);
    let req = grant(
        json!({"kind": "project", "authority": "customer-authority", "id": "customer-project"}),
        json!({"tokens": "100", "money": null}),
    );
    let mut ctx = context(&req);
    admit_subject(&mut ctx, &req);
    let state = admit_metadata(&mut store, &ctx, &req).unwrap().state;
    let (id, original) = state.grants.iter().next().unwrap();
    // Model removal must not prevent an administrator from reducing an existing
    // cap. It also must not implicitly restore the old approved model set.
    let state = apply(
        &mut store,
        Capability::ManageConnections,
        Operation::SetModelPolicy {
            connection: connection(),
            policy: ModelPolicy {
                models: BTreeSet::new(),
                execution_classes: [ExecutionClass::PrivateBroker].into(),
            },
        },
    );
    let req = request(
        "organization-provider.grant.cap.set",
        json!({"grant": id, "caps": {"tokens": "10", "money": null}}),
        state.revision,
        "reduce-cap",
    );
    let mut ctx = context(&req);
    ctx.now = state.last_at + 1;
    let state = admit_metadata(&mut store, &ctx, &req).unwrap().state;
    assert_eq!(
        state.grants[id].definition.policy,
        original.definition.policy
    );
    assert_eq!(
        state.grants[id].definition.audiences,
        original.definition.audiences
    );
    assert_eq!(state.grants[id].budget, original.budget);
    assert_eq!(state.grants[id].revision, original.revision + 1);
    assert_eq!(state.grants[id].definition.caps.tokens, Some(10));
    assert!(state.connections[&connection()]
        .definition
        .policy
        .models
        .is_empty());
}

#[test]
fn completed_intake_retry_uses_the_original_identity_and_deadline_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("authority.sqlite");
    let mut store = Store::open(path.to_str().unwrap()).unwrap();
    let req = MetadataRequest::parse(intake_body()).unwrap();
    let mut ctx = context(&req);
    ctx.validated_definition = req.requested_definition();
    let first = admit_metadata(&mut store, &ctx, &req).unwrap();
    assert!(!first.replayed);
    assert_eq!(first.state.connections.len(), 1);
    drop(store);
    let mut store = Store::open(path.to_str().unwrap()).unwrap();
    ctx.now = 9999;
    ctx.intake_ttl_seconds = 10;
    ctx.validated_definition = None;
    let retry = admit_metadata(&mut store, &ctx, &req).unwrap();
    assert!(retry.replayed);
    assert_eq!(retry.state, first.state);
    assert_eq!(
        store
            .records(&scope(), ModelConnection::KIND)
            .unwrap()
            .len(),
        1
    );
    ctx.permissions.clear();
    assert!(admit_metadata(&mut store, &ctx, &req).is_err());
}

#[test]
fn actor_authority_environment_and_approval_are_bound_before_receipt_access() {
    let req = MetadataRequest::parse(intake_body()).unwrap();
    let mut ctx = context(&req);
    ctx.validated_definition = req.requested_definition();
    let mut store = Store::open_in_memory().unwrap();
    let original = admit_metadata(&mut store, &ctx, &req).unwrap().state;
    for mutation in 0..7 {
        let mut ctx = context(&req);
        match mutation {
            0 => ctx.actor = AuthorityId::new("other-member"),
            1 => ctx.binding.authority = AuthorityId::new("other-authority"),
            2 => ctx.binding.environment = "live".into(),
            3 => ctx.approval.binding.organization = ScopeId::new("another-organization"),
            4 => ctx.approval.actor = AuthorityId::new("another-reviewer"),
            5 => ctx.approval.evidence = ObservationId::new("different-change"),
            _ => {
                ctx.approval.request = request(
                    "organization-provider.suspend",
                    json!({"connection": "connection-a"}),
                    0,
                    "intake",
                )
            }
        }
        assert!(
            admit_metadata(&mut store, &ctx, &req).is_err(),
            "case {mutation}"
        );
    }
    // The exact organization binding and approval must both match. Selecting a
    // different organization does not turn the old approval into fresh authority.
    let mut ctx = context(&req);
    ctx.binding.organization = ScopeId::new("another-organization");
    assert!(admit_metadata(&mut store, &ctx, &req).is_err());
    assert_eq!(store.fold::<ModelConnection>(&scope()).unwrap(), original);
}

#[test]
fn a_fresh_approved_body_cannot_reuse_a_completed_request_key() {
    let mut store = Store::open_in_memory().unwrap();
    ready(&mut store);
    let original = request(
        "organization-provider.rename",
        json!({"connection": connection(), "name": "First"}),
        4,
        "rename",
    );
    let state = admit_metadata(&mut store, &context(&original), &original)
        .unwrap()
        .state;
    let changed = request(
        "organization-provider.rename",
        json!({"connection": connection(), "name": "Different"}),
        state.revision,
        "rename",
    );
    assert!(admit_metadata(&mut store, &context(&changed), &changed).is_err());
    assert_eq!(store.fold::<ModelConnection>(&scope()).unwrap(), state);
    let stale = request(
        "organization-provider.rename",
        json!({"connection": connection(), "name": "Stale"}),
        4,
        "new-key",
    );
    assert!(admit_metadata(&mut store, &context(&stale), &stale).is_err());
    let retry = admit_metadata(&mut store, &context(&original), &original).unwrap();
    assert!(retry.replayed);
    assert_eq!(retry.state, state);
}

#[test]
fn subject_admission_requires_the_exact_connection_authority_project_or_member() {
    for subject in [
        json!({"kind": "member", "id": "member-a"}),
        json!({"kind": "project", "authority": "customer-authority", "id": "project-a"}),
    ] {
        for mutation in 0..4 {
            let mut store = Store::open_in_memory().unwrap();
            ready(&mut store);
            let req = grant(subject.clone(), json!({"tokens": "100", "money": null}));
            let mut ctx = context(&req);
            admit_subject(&mut ctx, &req);
            match mutation {
                0 => ctx.validated_subject = None,
                1 => {
                    ctx.validated_subject.as_mut().unwrap().connection =
                        ModelConnectionId::new("another-connection")
                }
                2 => {
                    ctx.validated_subject.as_mut().unwrap().subject =
                        access::Subject::Member(AuthorityId::new("different-member"))
                }
                _ => {
                    ctx.validated_subject.as_mut().unwrap().subject =
                        access::Subject::Project(access::Project {
                            authority: AuthorityId::new("different-authority"),
                            id: ProjectId::new("project-a"),
                        })
                }
            }
            assert!(admit_metadata(&mut store, &ctx, &req).is_err());
            assert!(store
                .fold::<ModelConnection>(&scope())
                .unwrap()
                .grants
                .is_empty());
        }
    }
}

#[test]
fn an_https_endpoint_is_not_provider_or_organization_oauth_admission() {
    for operation in [
        "organization-provider.api-key.add",
        "organization-provider.account.begin",
    ] {
        let mut input = intake_body();
        input["action"]["operation"] = json!(operation);
        let req = MetadataRequest::parse(input).unwrap();
        for incorrect in [false, true] {
            let mut store = Store::open_in_memory().unwrap();
            let mut ctx = context(&req);
            if incorrect {
                let mut definition = req.requested_definition().unwrap();
                definition.provider.endpoint = "https://different.invalid/v1".into();
                ctx.validated_definition = Some(definition);
            }
            assert!(admit_metadata(&mut store, &ctx, &req).is_err());
            assert!(store
                .fold::<ModelConnection>(&scope())
                .unwrap()
                .connections
                .is_empty());
        }
        let mut store = Store::open_in_memory().unwrap();
        let mut ctx = context(&req);
        ctx.validated_definition = req.requested_definition();
        let state = admit_metadata(&mut store, &ctx, &req).unwrap().state;
        let record = state.connections.values().next().unwrap();
        assert_eq!(record.status, ConnectionStatus::Pending);
        assert!(record.active_version().is_none());
    }
}

#[test]
fn endpoint_credentials_and_invalid_intake_deadlines_fail_closed() {
    for endpoint in [
        "http://provider.invalid",
        "https://user:credential@provider.invalid",
        "https://provider.invalid/?key=credential",
        "https://provider.invalid/#credential",
        "not an endpoint",
    ] {
        let mut input = intake_body();
        input["action"]["arguments"]["endpoint"] = json!(endpoint);
        let error = MetadataRequest::parse(input).unwrap_err();
        assert!(!error.reason.contains(endpoint));
    }
    for (now, ttl) in [(100, 0), (u64::MAX, 1)] {
        let mut store = Store::open_in_memory().unwrap();
        let req = MetadataRequest::parse(intake_body()).unwrap();
        let mut ctx = context(&req);
        ctx.validated_definition = req.requested_definition();
        ctx.now = now;
        ctx.intake_ttl_seconds = ttl;
        assert!(admit_metadata(&mut store, &ctx, &req).is_err());
        assert!(store
            .fold::<ModelConnection>(&scope())
            .unwrap()
            .connections
            .is_empty());
    }
}

#[test]
fn management_cannot_verify_its_own_candidate_and_cancellation_requires_cleanup() {
    let mut store = Store::open_in_memory().unwrap();
    let req = MetadataRequest::parse(intake_body()).unwrap();
    let mut ctx = context(&req);
    ctx.validated_definition = req.requested_definition();
    let state = admit_metadata(&mut store, &ctx, &req).unwrap().state;
    let (id, record) = state.connections.iter().next().unwrap();
    let version = record.versions.keys().next().unwrap();
    let args = json!({"connection": id, "version": version});
    let activate = request(
        "organization-provider.version.activate",
        args.clone(),
        state.revision,
        "activate",
    );
    assert!(admit_metadata(&mut store, &context(&activate), &activate).is_err());
    let cancel = request(
        "organization-provider.intake.cancel",
        args,
        state.revision,
        "cancel",
    );
    let state = admit_metadata(&mut store, &context(&cancel), &cancel)
        .unwrap()
        .state;
    assert_eq!(
        state.connections[id].versions[version].material,
        Material::ErasureRequired { handle: None }
    );
    assert!(state.connections[id].active_version().is_none());
}

#[test]
fn changing_approved_models_requires_current_exact_registry_validation() {
    for valid in [false, true] {
        let mut store = Store::open_in_memory().unwrap();
        ready(&mut store);
        let req = request(
            "organization-provider.model.approve",
            json!({"connection": connection(), "policy": policy()}),
            4,
            "policy",
        );
        let mut ctx = context(&req);
        let (connection, mut policy) = req.requested_policy().unwrap();
        if !valid {
            policy.models.insert("not-requested".into());
        }
        ctx.validated_policy = Some(PolicyAdmission { connection, policy });
        assert_eq!(admit_metadata(&mut store, &ctx, &req).is_ok(), valid);
    }
}

#[test]
fn resuming_a_grant_requires_fresh_admission_of_its_original_subject() {
    let mut store = Store::open_in_memory().unwrap();
    ready(&mut store);
    let req = grant(
        json!({"kind": "member", "id": "member-a"}),
        json!({"tokens": "100", "money": null}),
    );
    let mut ctx = context(&req);
    admit_subject(&mut ctx, &req);
    let state = admit_metadata(&mut store, &ctx, &req).unwrap().state;
    let (id, original) = state.grants.iter().next().unwrap();
    let suspend = request(
        "organization-provider.grant.suspend",
        json!({"grant": id}),
        state.revision,
        "suspend",
    );
    let suspended = admit_metadata(&mut store, &context(&suspend), &suspend)
        .unwrap()
        .state;
    for mutation in 0..3 {
        let resume = request(
            "organization-provider.grant.resume",
            json!({"grant": id}),
            suspended.revision,
            &format!("resume-{mutation}"),
        );
        assert_eq!(resume.grant_to_resume(), Some(id));
        let mut ctx = context(&resume);
        if mutation != 0 {
            ctx.validated_subject = Some(SubjectAdmission {
                connection: connection(),
                subject: if mutation == 1 {
                    access::Subject::Member(AuthorityId::new("different-member"))
                } else {
                    original.definition.subject.clone()
                },
                evidence: ObservationId::new("fresh-subject-check"),
            });
        }
        let result = admit_metadata(&mut store, &ctx, &resume);
        if mutation < 2 {
            assert!(result.is_err());
        } else {
            let state = result.unwrap().state;
            assert_eq!(state.grants[id].status, access::GrantStatus::Active);
            assert_eq!(state.grants[id].budget, original.budget);
            let events = store.records(&scope(), ModelConnection::KIND).unwrap();
            assert!(serde_json::to_string(&events)
                .unwrap()
                .contains("fresh-subject-check"));
        }
    }
}
