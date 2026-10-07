use super::*;
use crate::identity::{revalidate_action_context, ActorAuthentication, AuthenticatedActionContext};

fn fixture() -> (
    Store,
    OfficeStaffLeases,
    crate::home_admission::HomeAdmissionStore,
    AuthenticatedActionContext,
) {
    fixture_with_store(Store::open_in_memory().unwrap())
}

fn fixture_with_store(
    mut store: Store,
) -> (
    Store,
    OfficeStaffLeases,
    crate::home_admission::HomeAdmissionStore,
    AuthenticatedActionContext,
) {
    super::super::tests::member(&mut store, "alice", crate::org::MembershipStatus::Active);
    let home = HomeId::new("office-home");
    let mut leases = OfficeStaffLeases::new(home.clone());
    let now = crate::account::session_now_ms();
    let lease = leases
        .observe(
            &mut store,
            "https://auth.example/account/identity",
            "source",
            SourceCheck::Verified(
                super::super::super::source::VerifiedSourceSession::for_test(
                    "https://auth.example/account/identity",
                    "alice",
                    crate::account_session::AccountSessionEvidence {
                        session_ref: "source".into(),
                        method: "passkey".into(),
                        issued_at_ms: now.saturating_sub(1000),
                        expires_at_ms: now + 2 * OUTAGE_MS,
                    },
                    now,
                ),
            ),
        )
        .unwrap();
    let mut admissions = crate::home_admission::HomeAdmissionStore::new();
    let token = admissions.open_office(&home, &lease).unwrap();
    let standing = admissions.office_standing(&lease, &token).unwrap();
    let context = leases
        .action_context(&store, lease.reference(), standing)
        .unwrap();
    (store, leases, admissions, context)
}
fn authority(context: &AuthenticatedActionContext) -> &OfficeStaffActionAuthority {
    let ActorAuthentication::OfficeStaff { authority } = context.authentication() else {
        panic!("not office staff")
    };
    authority
}

#[test]
fn office_action_identity_needs_no_local_account_session_and_never_changes_actor() {
    let (store, leases, _admissions, context) = fixture();
    assert_eq!(context.actor().as_str(), "alice");
    assert_eq!(
        context.claims(),
        &gaugedesk_core::abac::AuthorityAttributes::default()
    );
    assert!(crate::account_session::durable_evidence(
        &store,
        "source",
        "alice",
        crate::account::session_now_ms()
    )
    .unwrap()
    .is_none());
    let deadline = revalidate_action_context(&store, &leases.home, &context)
        .unwrap()
        .unwrap();
    assert_eq!(deadline, authority(&context).0.deadline_ms);
    assert!(revalidate_action_context(&store, &HomeId::new("another-home"), &context).is_err());
    assert!(authority(&context)
        .revalidate(&store, &leases.home, &AuthorityId::new("bob"))
        .is_err());
}

#[test]
fn only_the_exact_office_admission_can_construct_an_action_context() {
    let (store, leases, mut admissions, context) = fixture();
    let actor = context.actor().clone();
    let home = leases.home.clone();
    let reference = authority(&context).0.reference.clone();
    let generic = admissions.open(home.clone(), actor.clone());
    assert!(leases
        .action_context(
            &store,
            &reference,
            admissions.standing(&home, &actor, &generic).unwrap()
        )
        .is_err());
    assert!(revalidate_action_context(&store, &home, &context).is_ok());
    assert!(admissions.revoke(&home, &actor));
    assert!(revalidate_action_context(&store, &home, &context).is_err());
}

#[test]
fn captured_work_stops_when_home_admission_or_lease_issuer_disappears() {
    for stop_lease_issuer in [false, true] {
        let (mut store, leases, mut admissions, context) = fixture();
        let (_, basis) = store.read_for_dispatch(&["target"], |_| Ok(())).unwrap();
        let basis = authority(&context).bind_basis(&store, basis, None).unwrap();
        let home = leases.home.clone();
        if stop_lease_issuer {
            drop(leases);
        } else {
            admissions.revoke(&home, context.actor());
        }
        let mut invoked = false;
        assert!(store
            .with_dispatch_basis(&basis, || {
                invoked = true;
            })
            .is_err());
        assert!(!invoked);
        assert!(revalidate_action_context(&store, &home, &context).is_err());
    }
}

#[test]
fn captured_work_fences_office_membership_even_when_resource_basis_omits_it() {
    let (mut store, leases, _admissions, context) = fixture();
    let (_, basis) = store.read_for_dispatch(&["target"], |_| Ok(())).unwrap();
    let basis = authority(&context).bind_basis(&store, basis, None).unwrap();
    super::super::tests::member(
        &mut store,
        "alice",
        crate::org::MembershipStatus::Deprovisioned,
    );
    let mut invoked = false;
    assert!(store
        .with_dispatch_basis(&basis, || {
            invoked = true;
        })
        .is_err());
    assert!(!invoked);
    assert!(revalidate_action_context(&store, &leases.home, &context).is_err());
}

#[test]
fn captured_work_stops_on_exact_source_revocation_before_durable_publication() {
    let (mut store, mut leases, _admissions, context) = fixture();
    let (_, basis) = store.read_for_dispatch(&["target"], |_| Ok(())).unwrap();
    let basis = authority(&context).bind_basis(&store, basis, None).unwrap();
    // Simulate the first, in-memory half of revoke, before a failing publisher.
    // A store scope head has not moved: the process standing itself must stop it.
    leases
        .live
        .get_mut(&authority(&context).0.reference)
        .unwrap()
        .active
        .store(false, Ordering::Release);
    let mut invoked = false;
    assert!(store
        .with_dispatch_basis(&basis, || {
            invoked = true;
        })
        .is_err());
    assert!(!invoked);
    assert!(revalidate_action_context(&store, &leases.home, &context).is_err());
}

#[test]
fn monotonic_action_expiry_refuses_even_with_a_future_wall_deadline() {
    let (store, leases, _admissions, context) = fixture();
    let mut authority = authority(&context).clone();
    drop(context);
    Arc::get_mut(&mut authority.0).unwrap().monotonic_end = Instant::now();
    assert!(authority.0.deadline_ms > crate::account::session_now_ms());
    assert!(authority
        .revalidate(&store, &leases.home, authority.actor())
        .is_err());
}

#[test]
fn older_captured_context_and_basis_cannot_run_after_live_database_rollback() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("office.sqlite");
    let (mut store, mut leases, _admissions, context) =
        fixture_with_store(Store::open(path.to_str().unwrap()).unwrap());
    let (_, basis) = store.read_for_dispatch(&["target"], |_| Ok(())).unwrap();
    let basis = authority(&context).bind_basis(&store, basis, None).unwrap();
    let reference = authority(&context).0.reference.clone();
    leases.touch(&mut store, &reference).unwrap();
    // Revert the lease event head to the one captured before admitted activity.
    // The old resource basis can match again; its process revision must refuse.
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute(
            "DELETE FROM events WHERE scope_id = ?1 AND position > 0",
            [&reference],
        )
        .unwrap();
    assert!(revalidate_action_context(&store, &leases.home, &context).is_err());
    let mut invoked = false;
    assert!(store
        .with_dispatch_basis(&basis, || {
            invoked = true;
        })
        .is_err());
    assert!(!invoked);
}

#[test]
fn queued_grant_ceiling_uses_the_source_clock_floor_even_before_wall_expiry() {
    let (store, _leases, _admissions, context) = fixture();
    let ceiling = crate::account::session_now_ms() + 5000;
    let mut authority = authority(&context).clone();
    drop(context);
    // Represent the clock floor already learned by a running Home, followed
    // by a wall clock behind it. Fresh source authority cannot widen an older
    // queued grant's admitted ceiling.
    Arc::get_mut(&mut authority.0).unwrap().started_at_ms += 10_000;
    assert!(ceiling > crate::account::session_now_ms());
    let (_, basis) = store.read_for_dispatch(&["target"], |_| Ok(())).unwrap();
    assert!(authority.bind_basis(&store, basis, Some(ceiling)).is_err());
    let (_, basis) = store.read_for_dispatch(&["target"], |_| Ok(())).unwrap();
    assert!(authority.bind_basis(&store, basis, None).is_ok());
}
