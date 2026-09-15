use super::*;

const TENANT: &str = "org::acme";
const PERSON: &str = "account::person";

fn context() -> FundingContext {
    FundingContext {
        issuer: AuthorityId::new("funding-service"),
        environment: FundingEnvironment::Live,
        now: 200,
    }
}

fn active(scope: &str) -> FundingRecord {
    FundingRecord {
        record: ManagedPlanRecord {
            id: "managed-inference".into(),
            op: RecordOp::Upsert,
            subscription: ManagedInferencePlan {
                plan: "team".into(),
                status: ManagedPlanStatus::Active,
                included_tokens: 1000,
            },
        },
        provenance: Some(FundingEvidence {
            v: 1,
            issuer: context().issuer,
            scope: ScopeId::new(scope),
            source_id: "subscription:one".into(),
            environment: FundingEnvironment::Live,
            verified_at: 150,
            valid_from: 100,
            valid_until: 300,
        }),
    }
}

fn append(store: &mut Store, scope: &str, record: &FundingRecord) {
    store
        .append_record(
            scope,
            MANAGED_PLAN_KIND,
            &serde_json::to_string(record).unwrap(),
        )
        .unwrap();
}

fn resolve(store: &Store) -> FundingResolution {
    resolve_plan(
        store,
        &ScopeId::new(PERSON),
        &ScopeId::new(TENANT),
        &context(),
    )
    .unwrap()
}

#[test]
fn verified_current_grant_retains_exact_source_scope_environment_and_quota() {
    let record = active(TENANT);
    let grant = decide(
        &ScopeId::new(TENANT),
        std::slice::from_ref(&record),
        &context(),
    )
    .unwrap();
    assert_eq!(grant.plan(), &record.record.subscription);
    assert_eq!(grant.evidence(), record.provenance.as_ref().unwrap());
    assert_eq!(grant.plan().included_tokens, 1000);
}

#[test]
fn legacy_active_plan_is_history_not_live_funding() {
    let legacy = serde_json::to_string(&active(TENANT).record).unwrap();
    let record: FundingRecord = serde_json::from_str(&legacy).unwrap();
    assert_eq!(record.provenance, None);
    assert_eq!(
        decide(&ScopeId::new(TENANT), &[record], &context()),
        Err(FundingDenial::Unverified)
    );
}

#[test]
fn known_other_mode_cannot_authorize_or_overwrite_selected_mode() {
    let live = active(TENANT);
    let mut test = live.clone();
    test.provenance.as_mut().unwrap().environment = FundingEnvironment::Test;
    test.record.subscription.status = ManagedPlanStatus::Lapsed;
    assert_eq!(
        decide(&ScopeId::new(TENANT), &[test.clone()], &context()),
        Err(FundingDenial::WrongContext)
    );
    let live_grant = decide(
        &ScopeId::new(TENANT),
        &[live.clone(), test.clone()],
        &context(),
    )
    .unwrap();
    assert_eq!(live_grant.evidence().environment, FundingEnvironment::Live);
    let test_context = FundingContext {
        environment: FundingEnvironment::Test,
        ..context()
    };
    assert_eq!(
        decide(&ScopeId::new(TENANT), &[live, test], &test_context),
        Err(FundingDenial::Lapsed)
    );
}

#[test]
fn issuer_and_scope_are_independent_required_bindings() {
    let mut foreign = active(TENANT);
    foreign.provenance.as_mut().unwrap().issuer = AuthorityId::new("another-service");
    assert_eq!(
        decide(&ScopeId::new(TENANT), &[foreign.clone()], &context()),
        Err(FundingDenial::WrongContext)
    );
    assert!(decide(
        &ScopeId::new(TENANT),
        &[active(TENANT), foreign],
        &context()
    )
    .is_ok());
    assert_eq!(
        decide(&ScopeId::new(TENANT), &[active(PERSON)], &context()),
        Err(FundingDenial::InvalidEvidence)
    );
}

#[test]
fn legacy_change_is_a_barrier_until_matching_evidence_is_reconciled() {
    for op in [RecordOp::Upsert, RecordOp::Tombstone] {
        let current = active(TENANT);
        let mut legacy = current.clone();
        legacy.record.op = op;
        legacy.provenance = None;
        let mut other = current.clone();
        other.provenance.as_mut().unwrap().environment = FundingEnvironment::Test;
        let mut history = vec![current.clone(), legacy, other];
        assert_eq!(
            decide(&ScopeId::new(TENANT), &history, &context()),
            Err(FundingDenial::Unverified)
        );
        history.push(current);
        assert!(decide(&ScopeId::new(TENANT), &history, &context()).is_ok());
    }
}

#[test]
fn future_evidence_versions_do_not_inherit_the_previous_live_grant() {
    let mut future = active(TENANT);
    future.provenance.as_mut().unwrap().v = 2;
    assert_eq!(
        decide(&ScopeId::new(TENANT), &[active(TENANT), future], &context()),
        Err(FundingDenial::Unverified)
    );
}

#[test]
fn tombstone_does_not_resurrect_previous_grant() {
    let mut tombstone = active(TENANT);
    tombstone.record.op = RecordOp::Tombstone;
    let mut other = active(TENANT);
    other.provenance.as_mut().unwrap().environment = FundingEnvironment::Test;
    assert_eq!(
        decide(
            &ScopeId::new(TENANT),
            &[active(TENANT), tombstone, other],
            &context()
        ),
        Err(FundingDenial::Revoked)
    );
}

#[test]
fn period_boundaries_and_future_verification_fail_closed() {
    let record = active(TENANT);
    for (now, expected) in [
        (0, FundingDenial::InvalidContext),
        (149, FundingDenial::InvalidEvidence),
        (300, FundingDenial::Expired),
        (301, FundingDenial::Expired),
    ] {
        assert_eq!(
            decide(
                &ScopeId::new(TENANT),
                std::slice::from_ref(&record),
                &FundingContext { now, ..context() }
            ),
            Err(expected)
        );
    }
    assert!(decide(
        &ScopeId::new(TENANT),
        std::slice::from_ref(&record),
        &FundingContext {
            now: 299,
            ..context()
        }
    )
    .is_ok());
    let mut future_period = record;
    future_period.provenance.as_mut().unwrap().valid_from = 201;
    assert_eq!(
        decide(&ScopeId::new(TENANT), &[future_period], &context()),
        Err(FundingDenial::NotYetValid)
    );
}

#[test]
fn missing_and_malformed_evidence_never_become_unbounded_grants() {
    for change in 0..8 {
        let mut record = active(TENANT);
        let evidence = record.provenance.as_mut().unwrap();
        match change {
            0 => evidence.verified_at = 0,
            1 => evidence.valid_from = 0,
            2 => evidence.valid_until = evidence.valid_from,
            3 => evidence.valid_until = 0,
            4 => evidence.source_id.clear(),
            5 => evidence.scope = ScopeId::new(""),
            6 => record.record.subscription.plan.clear(),
            7 => record.record.id.clear(),
            _ => unreachable!(),
        }
        assert_eq!(
            decide(&ScopeId::new(TENANT), &[record], &context()),
            Err(FundingDenial::InvalidEvidence)
        );
    }
    assert_eq!(
        decide(&ScopeId::new(TENANT), &[], &context()),
        Err(FundingDenial::NotConfigured)
    );
}

#[test]
fn admitted_order_not_source_timestamp_determines_current_status() {
    let current = active(TENANT);
    let mut suspended = current.clone();
    suspended.record.subscription.status = ManagedPlanStatus::Suspended;
    suspended.provenance.as_mut().unwrap().verified_at = 190;
    assert_eq!(
        decide(
            &ScopeId::new(TENANT),
            &[current.clone(), suspended.clone()],
            &context()
        ),
        Err(FundingDenial::Suspended)
    );
    // A separately admitted reconciliation may have an earlier/equal observed
    // time. Admission establishes its order, not ranking status or timestamps.
    assert!(decide(&ScopeId::new(TENANT), &[suspended, current], &context()).is_ok());
}

#[test]
fn organization_funding_failures_never_fall_through_to_personal_billing() {
    for change in 0..6 {
        let mut store = Store::open_in_memory().unwrap();
        append(&mut store, PERSON, &active(PERSON));
        let mut org = active(TENANT);
        match change {
            0 => org.provenance = None,
            1 => org.record.op = RecordOp::Tombstone,
            2 => org.record.subscription.status = ManagedPlanStatus::Suspended,
            3 => org.record.subscription.status = ManagedPlanStatus::Lapsed,
            4 => org.provenance.as_mut().unwrap().valid_until = 200,
            5 => org.provenance.as_mut().unwrap().environment = FundingEnvironment::Test,
            _ => unreachable!(),
        }
        append(&mut store, TENANT, &org);
        assert!(resolve(&store).is_err(), "case {change} charged the person");
    }
}

#[test]
fn personal_funding_applies_only_when_organization_has_no_selection() {
    let mut store = Store::open_in_memory().unwrap();
    append(&mut store, PERSON, &active(PERSON));
    assert_eq!(
        resolve(&store).unwrap().evidence().scope,
        ScopeId::new(PERSON)
    );
    append(&mut store, TENANT, &active(TENANT));
    assert_eq!(
        resolve(&store).unwrap().evidence().scope,
        ScopeId::new(TENANT)
    );
}

#[test]
fn editable_org_billing_does_not_mint_or_shadow_service_evidence() {
    let mut store = Store::open_in_memory().unwrap();
    append(&mut store, PERSON, &active(PERSON));
    store.append_record(TENANT, "billing", &serde_json::json!({
        "id": crate::org::ORG_ID, "op": "upsert", "plan": "business", "seats": 3,
        "managed_inference": {"plan": "editable", "status": "active", "included_tokens": 999999}
    }).to_string()).unwrap();
    assert_eq!(resolve(&store), Err(FundingDenial::Unverified));
    append(&mut store, TENANT, &active(TENANT));
    let grant = resolve(&store).unwrap();
    assert_eq!(grant.plan().plan, "team");
    assert_eq!(grant.plan().included_tokens, 1000);
}

#[test]
fn current_source_references_are_exact_and_legacy_references_are_not_upgraded() {
    let mut store = Store::open_in_memory().unwrap();
    let original = active(TENANT);
    append(&mut store, TENANT, &original);
    let grant = resolve(&store).unwrap();
    let reference = grant.reference();
    assert_eq!(
        resolve_reference(&store, &reference, &context()).unwrap(),
        Ok(grant)
    );
    for invalid in [
        "managed:guess".to_owned(),
        crate::managed_inference::funding_ref(TENANT, &original.record.subscription),
        format!("{reference}:extra"),
    ] {
        assert_eq!(
            resolve_reference(&store, &invalid, &context()).unwrap(),
            Err(FundingDenial::InvalidReference)
        );
    }
    let mut replacement = original;
    replacement.provenance.as_mut().unwrap().source_id = "replacement".into();
    append(&mut store, TENANT, &replacement);
    assert_eq!(
        resolve_reference(&store, &reference, &context()).unwrap(),
        Err(FundingDenial::SourceChanged)
    );
    assert_ne!(resolve(&store).unwrap().reference(), reference);
}

#[test]
fn reference_identity_binds_all_funding_dimensions_without_delimiter_ambiguity() {
    let original = active(TENANT);
    let original_ref = decide(
        &ScopeId::new(TENANT),
        std::slice::from_ref(&original),
        &context(),
    )
    .unwrap()
    .reference();
    for dimension in 0..5 {
        let mut record = original.clone();
        let mut ctx = context();
        let mut scope = ScopeId::new(TENANT);
        let proof = record.provenance.as_mut().unwrap();
        match dimension {
            0 => {
                scope = ScopeId::new("org::acme:other");
                proof.scope = scope.clone();
            }
            1 => record.record.subscription.plan = "team:other".into(),
            2 => {
                proof.issuer = AuthorityId::new("funding-service:other");
                ctx.issuer = proof.issuer.clone();
            }
            3 => {
                proof.environment = FundingEnvironment::Test;
                ctx.environment = FundingEnvironment::Test;
            }
            4 => proof.source_id = "subscription:other".into(),
            _ => unreachable!(),
        }
        assert_ne!(
            decide(&scope, &[record], &ctx).unwrap().reference(),
            original_ref
        );
    }
}

#[test]
fn reference_resolution_rechecks_expiry_and_revocation_without_fallback() {
    let mut store = Store::open_in_memory().unwrap();
    append(&mut store, PERSON, &active(PERSON));
    let mut record = active(TENANT);
    append(&mut store, TENANT, &record);
    let reference = resolve(&store).unwrap().reference();
    assert_eq!(
        resolve_reference(
            &store,
            &reference,
            &FundingContext {
                now: 300,
                ..context()
            }
        )
        .unwrap(),
        Err(FundingDenial::Expired)
    );
    record.record.op = RecordOp::Tombstone;
    append(&mut store, TENANT, &record);
    assert_eq!(
        resolve_reference(&store, &reference, &context()).unwrap(),
        Err(FundingDenial::Revoked)
    );
}

#[test]
fn malformed_persisted_evidence_errors_instead_of_skipping_to_personal() {
    let mut store = Store::open_in_memory().unwrap();
    append(&mut store, PERSON, &active(PERSON));
    append(&mut store, TENANT, &active(TENANT));
    store
        .append_record(TENANT, MANAGED_PLAN_KIND, "{broken")
        .unwrap();
    assert!(resolve_plan(
        &store,
        &ScopeId::new(PERSON),
        &ScopeId::new(TENANT),
        &context()
    )
    .is_err());
}

#[test]
fn reopen_replays_identical_grant_without_rewriting_legacy_history() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("funding.db");
    let expected;
    {
        let mut store = Store::open(path.to_str().unwrap()).unwrap();
        let mut legacy = active(TENANT);
        legacy.provenance = None;
        append(&mut store, TENANT, &legacy);
        append(&mut store, TENANT, &active(TENANT));
        expected = resolve(&store).unwrap();
        assert_eq!(store.records(TENANT, MANAGED_PLAN_KIND).unwrap().len(), 2);
    }
    let store = Store::open(path.to_str().unwrap()).unwrap();
    assert_eq!(resolve(&store), Ok(expected));
    assert_eq!(store.records(TENANT, MANAGED_PLAN_KIND).unwrap().len(), 2);
}
