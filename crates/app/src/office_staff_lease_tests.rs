use super::super::source::VerifiedSourceSession;
use super::*;
use crate::account_session::AccountSessionEvidence;

const NOW: u64 = 1_800_000_000_000;
const ISSUER: &str = "https://auth.example/account/identity";
const SOURCE: &str = "synthetic-session-digest";

pub(super) fn member(store: &mut Store, account: &str, status: crate::org::MembershipStatus) {
    let record = crate::org::MembershipRecord {
        id: account.into(),
        op: crate::org::RecordOp::Upsert,
        org_id: crate::org::ORG_ID.into(),
        authority: account.into(),
        email: String::new(),
        role: "member".into(),
        status,
        managed_by_scim: false,
        team: None,
    };
    store
        .append_record(
            crate::org::ORG_SCOPE,
            "membership",
            &serde_json::to_string(&record).unwrap(),
        )
        .unwrap();
}
fn policy(store: &mut Store, absolute_ms: u64, idle_ms: u64) {
    let record = crate::org::SecurityPolicyRecord {
        id: "security".into(),
        session_lifetime_secs: absolute_ms / 1000,
        idle_timeout_secs: idle_ms / 1000,
        ..Default::default()
    };
    store
        .append_record(
            crate::org::ORG_SCOPE,
            "security",
            &serde_json::to_string(&record).unwrap(),
        )
        .unwrap();
}
fn proof(account: &str, source: &str, now: u64, expiry: u64) -> SourceCheck {
    SourceCheck::Verified(VerifiedSourceSession::for_test(
        ISSUER,
        account,
        AccountSessionEvidence {
            session_ref: source.into(),
            method: "passkey".into(),
            issued_at_ms: NOW - 1000,
            expires_at_ms: expiry,
        },
        now,
    ))
}
fn manager() -> OfficeStaffLeases {
    let mut leases = OfficeStaffLeases::new(HomeId::new("office-home"));
    leases.started_at_ms = NOW;
    leases
}
fn fixture() -> (Store, OfficeStaffLeases, OfficeStaffLease) {
    let mut store = Store::open_in_memory().unwrap();
    member(&mut store, "alice", crate::org::MembershipStatus::Active);
    let mut leases = manager();
    let lease = leases
        .observe_at(
            &mut store,
            ISSUER,
            SOURCE,
            proof("alice", SOURCE, NOW, NOW + 2 * OUTAGE_MS),
            NOW,
            0,
        )
        .unwrap();
    (store, leases, lease)
}

#[test]
fn admitted_activity_cannot_cross_its_captured_deadline_to_extend_idle_time() {
    let (mut store, mut leases, alice) = fixture();
    let before = store.retained_events(alice.reference()).unwrap();
    let (_, basis) = store
        .read_for_dispatch(&["admitted-command"], |_| Ok(()))
        .unwrap();
    let basis = basis.with_deadline(std::time::UNIX_EPOCH);
    assert!(leases
        .touch_admitted(&mut store, alice.reference(), basis)
        .is_err());
    assert_eq!(store.retained_events(alice.reference()).unwrap(), before);
}

#[test]
fn independent_staff_survive_only_within_their_own_proved_outage_bounds() {
    let (mut store, mut leases, alice) = fixture();
    member(&mut store, "bob", crate::org::MembershipStatus::Active);
    let bob = leases
        .observe_at(
            &mut store,
            ISSUER,
            "bob-source",
            proof("bob", "bob-source", NOW + 1000, NOW + 2 * OUTAGE_MS),
            NOW + 1000,
            1000,
        )
        .unwrap();
    assert_eq!(alice.deadline_ms(), NOW + OUTAGE_MS);
    assert_eq!(bob.deadline_ms(), NOW + OUTAGE_MS + 1000);
    assert_ne!(alice.reference(), bob.reference());
    for time in [1000, OUTAGE_MS - 1] {
        let continued = leases
            .observe_at(
                &mut store,
                ISSUER,
                SOURCE,
                SourceCheck::Unavailable,
                NOW + time,
                time.into(),
            )
            .unwrap();
        assert_eq!(continued.deadline_ms(), alice.deadline_ms());
    }
    assert!(leases
        .observe_at(
            &mut store,
            ISSUER,
            SOURCE,
            SourceCheck::Unavailable,
            NOW + OUTAGE_MS,
            OUTAGE_MS.into()
        )
        .is_err());
    assert!(leases
        .current_at(&store, bob.reference(), NOW + OUTAGE_MS, OUTAGE_MS.into())
        .is_ok());
    assert!(leases
        .observe_at(
            &mut store,
            ISSUER,
            "unknown-source",
            SourceCheck::Unavailable,
            NOW,
            0
        )
        .is_err());
    assert!(leases
        .observe_at(
            &mut store,
            ISSUER,
            "outsider-source",
            proof("outsider", "outsider-source", NOW, NOW + OUTAGE_MS),
            NOW,
            0
        )
        .is_err());
}

#[test]
fn explicit_refusal_and_local_revocation_are_durable_terminal_and_independent() {
    for local in [false, true] {
        let (mut store, mut leases, alice) = fixture();
        member(&mut store, "bob", crate::org::MembershipStatus::Active);
        let bob = leases
            .observe_at(
                &mut store,
                ISSUER,
                "bob-source",
                proof("bob", "bob-source", NOW, NOW + OUTAGE_MS),
                NOW,
                0,
            )
            .unwrap();
        if local {
            leases
                .revoke_at(&mut store, alice.reference(), NOW + 1)
                .unwrap();
        } else {
            assert!(leases
                .observe_at(&mut store, ISSUER, SOURCE, SourceCheck::Refused, NOW + 1, 1)
                .is_err());
        }
        assert!(leases
            .current_at(&store, alice.reference(), NOW + 1, 1)
            .is_err());
        assert!(leases
            .current_at(&store, bob.reference(), NOW + 1, 1)
            .is_ok());
        assert!(leases
            .observe_at(
                &mut store,
                ISSUER,
                SOURCE,
                proof("alice", SOURCE, NOW + 2, NOW + OUTAGE_MS),
                NOW + 2,
                2
            )
            .is_err());
        let mut restarted = manager();
        assert!(restarted
            .observe_at(
                &mut store,
                ISSUER,
                SOURCE,
                proof("alice", SOURCE, NOW + 2, NOW + OUTAGE_MS),
                NOW + 2,
                2
            )
            .is_err());
        assert!(load(&store, alice.reference()).unwrap().unwrap().revoked);
    }
}

#[test]
fn membership_removal_is_immediate_and_source_proof_cannot_replace_local_standing() {
    let (mut store, mut leases, alice) = fixture();
    member(
        &mut store,
        "alice",
        crate::org::MembershipStatus::Deprovisioned,
    );
    assert!(leases
        .current_at(&store, alice.reference(), NOW + 1, 1)
        .is_err());
    assert!(leases
        .observe_at(
            &mut store,
            ISSUER,
            SOURCE,
            proof("alice", SOURCE, NOW + 1, NOW + OUTAGE_MS),
            NOW + 1,
            1
        )
        .is_err());
}

#[test]
fn verification_advances_only_the_outage_clock_and_activity_does_not_renew_source() {
    let (mut store, mut leases, alice) = fixture();
    policy(&mut store, 90 * 60 * 1000, 20 * 60 * 1000);
    let time = 10 * 60 * 1000;
    let refreshed = leases
        .observe_at(
            &mut store,
            ISSUER,
            SOURCE,
            proof("alice", SOURCE, NOW + time, NOW + 2 * OUTAGE_MS),
            NOW + time,
            time.into(),
        )
        .unwrap();
    assert_eq!(refreshed.deadline_ms(), NOW + 20 * 60 * 1000);
    let recorded = load(&store, alice.reference()).unwrap().unwrap();
    assert_eq!(recorded.office_started_ms, NOW);
    assert_eq!(recorded.last_activity_ms, NOW);
    assert_eq!(recorded.source_mint_ms, NOW - 1000);
    let touched = leases
        .touch_at(&mut store, alice.reference(), NOW + time, time.into())
        .unwrap();
    assert_eq!(touched.deadline_ms(), NOW + 30 * 60 * 1000);
    let latest = load(&store, alice.reference()).unwrap().unwrap();
    assert_eq!(latest.last_verified_ms, NOW + time);
    // Tightening and then loosening policy cannot reset or expand the original clocks.
    policy(&mut store, 15 * 60 * 1000, 5 * 60 * 1000);
    leases
        .touch_at(
            &mut store,
            alice.reference(),
            NOW + time + 1000,
            (time + 1000).into(),
        )
        .unwrap();
    policy(&mut store, 5 * OUTAGE_MS, OUTAGE_MS);
    assert_eq!(
        leases
            .current_at(
                &store,
                alice.reference(),
                NOW + time + 1000,
                (time + 1000).into()
            )
            .unwrap()
            .deadline_ms(),
        NOW + 15 * 60 * 1000
    );
    assert!(leases
        .current_at(
            &store,
            alice.reference(),
            NOW + 15 * 60 * 1000,
            (15 * 60 * 1000u64).into()
        )
        .is_err());
}

#[test]
fn source_expiry_can_end_work_before_an_hour_and_idle_expiry_cannot_be_refreshed() {
    let (mut store, mut leases, alice) = fixture();
    let early = NOW + 1000;
    let bound = leases
        .observe_at(
            &mut store,
            ISSUER,
            SOURCE,
            proof("alice", SOURCE, NOW + 1, early),
            NOW + 1,
            1,
        )
        .unwrap();
    assert_eq!(bound.deadline_ms(), early);
    assert!(leases
        .current_at(&store, alice.reference(), early, 1000)
        .is_err());
    let (mut store, mut leases, alice) = fixture();
    policy(&mut store, 0, 1000);
    leases
        .touch_at(&mut store, alice.reference(), NOW + 1, 1)
        .unwrap();
    assert!(leases
        .observe_at(
            &mut store,
            ISSUER,
            SOURCE,
            proof("alice", SOURCE, NOW + 1001, NOW + OUTAGE_MS),
            NOW + 1001,
            1001
        )
        .is_err());
}

#[test]
fn restart_requires_fresh_proof_without_resetting_durable_office_clocks() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("office.sqlite");
    let mut store = Store::open(path.to_str().unwrap()).unwrap();
    member(&mut store, "alice", crate::org::MembershipStatus::Active);
    policy(&mut store, OUTAGE_MS + 1000, 0);
    let mut leases = manager();
    let alice = leases
        .observe_at(
            &mut store,
            ISSUER,
            SOURCE,
            proof("alice", SOURCE, NOW, NOW + 2 * OUTAGE_MS),
            NOW,
            0,
        )
        .unwrap();
    drop(leases);
    drop(store);
    let mut store = Store::open(path.to_str().unwrap()).unwrap();
    let mut restarted = manager();
    restarted.started_at_ms = NOW + 1000;
    assert!(restarted
        .observe_at(
            &mut store,
            ISSUER,
            SOURCE,
            SourceCheck::Unavailable,
            NOW + 1000,
            0
        )
        .is_err());
    assert!(restarted
        .observe_at(
            &mut store,
            ISSUER,
            SOURCE,
            proof("alice", SOURCE, NOW, NOW + 2 * OUTAGE_MS),
            NOW + 1000,
            0
        )
        .is_err());
    let renewed = restarted
        .observe_at(
            &mut store,
            ISSUER,
            SOURCE,
            proof("alice", SOURCE, NOW + 1000, NOW + 2 * OUTAGE_MS),
            NOW + 1000,
            0,
        )
        .unwrap();
    assert_eq!(renewed.reference(), alice.reference());
    assert_eq!(renewed.deadline_ms(), NOW + OUTAGE_MS + 1000);
    assert_eq!(
        load(&store, alice.reference())
            .unwrap()
            .unwrap()
            .office_started_ms,
        NOW
    );
}

#[test]
fn backward_wall_clock_and_exhausted_monotonic_time_refuse() {
    let (mut store, mut leases, alice) = fixture();
    leases
        .touch_at(&mut store, alice.reference(), NOW + 1000, 1000)
        .unwrap();
    assert!(leases
        .current_at(&store, alice.reference(), NOW + 999, 1001)
        .is_err());
    assert!(leases
        .current_at(&store, alice.reference(), NOW + 1000, OUTAGE_MS.into())
        .is_err());
    assert!(leases
        .observe_at(
            &mut store,
            ISSUER,
            SOURCE,
            proof("alice", SOURCE, NOW + 999, NOW + OUTAGE_MS),
            NOW + 999,
            1001
        )
        .is_err());
}

#[test]
fn altered_account_method_or_source_mint_terminates_the_exact_parent() {
    for changed in 0..3 {
        let (mut store, mut leases, alice) = fixture();
        member(&mut store, "bob", crate::org::MembershipStatus::Active);
        let mut session = AccountSessionEvidence {
            session_ref: SOURCE.into(),
            method: "passkey".into(),
            issued_at_ms: NOW - 1000,
            expires_at_ms: NOW + OUTAGE_MS,
        };
        let account = if changed == 0 { "bob" } else { "alice" };
        if changed == 1 {
            session.method = "oidc".into();
        }
        if changed == 2 {
            session.issued_at_ms += 1;
        }
        let changed = SourceCheck::Verified(VerifiedSourceSession::for_test(
            ISSUER,
            account,
            session,
            NOW + 1,
        ));
        assert!(leases
            .observe_at(&mut store, ISSUER, SOURCE, changed, NOW + 1, 1)
            .is_err());
        assert!(leases
            .current_at(&store, alice.reference(), NOW + 1, 1)
            .is_err());
        assert!(load(&store, alice.reference()).unwrap().unwrap().revoked);
    }
}

#[test]
fn uncommitted_records_and_unreadable_revocation_never_expose_an_older_lease() {
    let (mut store, mut leases, alice) = fixture();
    leases
        .revoke_at(&mut store, alice.reference(), NOW + 1)
        .unwrap();
    struct HideRevocation;
    impl gaugedesk_store::ContentCodec for HideRevocation {
        fn encode(&self, _: &str, _: &str, payload: &str) -> Result<String, String> {
            Ok(payload.into())
        }
        fn decode(&self, _: &str, _: &str, payload: &str) -> Option<String> {
            (!payload.contains("\"revoked\":true")).then(|| payload.into())
        }
    }
    let store = store.with_codec(std::sync::Arc::new(HideRevocation));
    assert!(load(&store, alice.reference()).is_err());
    let (mut store, leases, alice) = fixture();
    let mut record = load(&store, alice.reference()).unwrap().unwrap();
    record.revision += 1;
    store
        .append_record(
            alice.reference(),
            LEASE_KIND,
            &serde_json::to_string(&record).unwrap(),
        )
        .unwrap();
    assert!(leases
        .current_at(&store, alice.reference(), NOW + 1, 1)
        .is_err());
}

#[test]
fn failed_admission_never_creates_process_local_offline_authority() {
    let mut store = Store::open_in_memory().unwrap();
    member(&mut store, "alice", crate::org::MembershipStatus::Active);
    // Codec failure reaches the actual evidence write, after proof/directory checks.
    struct FailLease;
    impl gaugedesk_store::ContentCodec for FailLease {
        fn encode(&self, _: &str, kind: &str, payload: &str) -> Result<String, String> {
            if kind == LEASE_KIND {
                Err("lease persistence unavailable".into())
            } else {
                Ok(payload.into())
            }
        }
        fn decode(&self, _: &str, _: &str, payload: &str) -> Option<String> {
            Some(payload.into())
        }
    }
    let mut store = store.with_codec(std::sync::Arc::new(FailLease));
    let mut leases = manager();
    assert!(leases
        .observe_at(
            &mut store,
            ISSUER,
            SOURCE,
            proof("alice", SOURCE, NOW, NOW + OUTAGE_MS),
            NOW,
            0
        )
        .is_err());
    assert!(leases.live.is_empty());
    assert!(load(&store, &scope(&leases.home, ISSUER, SOURCE))
        .unwrap()
        .is_none());
}

#[test]
fn restoring_an_older_live_snapshot_cannot_reset_known_revisions_or_revocation() {
    for revoked in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("office.sqlite");
        let mut store = Store::open(path.to_str().unwrap()).unwrap();
        member(&mut store, "alice", crate::org::MembershipStatus::Active);
        let mut leases = manager();
        let alice = leases
            .observe_at(
                &mut store,
                ISSUER,
                SOURCE,
                proof("alice", SOURCE, NOW, NOW + 2 * OUTAGE_MS),
                NOW,
                0,
            )
            .unwrap();
        if revoked {
            leases
                .revoke_at(&mut store, alice.reference(), NOW + 1)
                .unwrap();
        } else {
            leases
                .touch_at(&mut store, alice.reference(), NOW + 1, 1)
                .unwrap();
        }
        // Restore the older row set behind a still-running Home. Its live
        // revision/revocation witness must beat this apparently valid snapshot.
        let sql = rusqlite::Connection::open(&path).unwrap();
        sql.execute(
            "DELETE FROM events WHERE scope_id = ?1 AND position > 0",
            [alice.reference()],
        )
        .unwrap();
        assert!(leases
            .current_at(&store, alice.reference(), NOW + 2, 2)
            .is_err());
        assert!(leases
            .observe_at(
                &mut store,
                ISSUER,
                SOURCE,
                proof("alice", SOURCE, NOW + 2, NOW + 2 * OUTAGE_MS),
                NOW + 2,
                2
            )
            .is_err());
    }
}

#[test]
fn lease_evidence_is_encrypted_and_command_snapshots_hold_no_workforce_payload() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("office.sqlite");
    let vault = std::sync::Arc::new(crate::content_vault::ContentVault::new(
        dir.path().join("keys"),
        Box::new(crate::at_rest::LoopbackKeyWrap::new([7; 32])),
    ));
    let mut store = Store::open(path.to_str().unwrap())
        .unwrap()
        .with_codec(vault);
    member(&mut store, "alice", crate::org::MembershipStatus::Active);
    let mut leases = manager();
    let lease = leases
        .observe_at(
            &mut store,
            ISSUER,
            SOURCE,
            proof("alice", SOURCE, NOW, NOW + OUTAGE_MS),
            NOW,
            0,
        )
        .unwrap();
    let sql = rusqlite::Connection::open(&path).unwrap();
    let payload: String = sql
        .query_row(
            "SELECT payload FROM events WHERE scope_id = ?1",
            [lease.reference()],
            |row| row.get(0),
        )
        .unwrap();
    assert!(payload.starts_with("gwenc:1:"));
    for value in ["alice", SOURCE, ISSUER, "passkey"] {
        assert!(!payload.contains(value));
    }
    let snapshot: String = sql
        .query_row(
            "SELECT snapshot_json FROM commands WHERE scope_id = ?1",
            [lease.reference()],
            |row| row.get(0),
        )
        .unwrap();
    for value in ["alice", SOURCE, ISSUER, "passkey"] {
        assert!(!snapshot.contains(value));
    }
    assert_eq!(
        load(&store, lease.reference()).unwrap().unwrap().account,
        "alice"
    );
    assert!(leases
        .current_at(&store, lease.reference(), NOW + 1, 1)
        .is_ok());
}

#[test]
fn wrong_home_or_configured_issuer_never_shares_the_parent_lease() {
    let (mut store, leases, alice) = fixture();
    let mut other = manager();
    other.home = HomeId::new("another-home");
    assert!(other.current_at(&store, alice.reference(), NOW, 0).is_err());
    assert!(other
        .observe_at(
            &mut store,
            "https://other.example/account/identity",
            SOURCE,
            SourceCheck::Unavailable,
            NOW,
            0
        )
        .is_err());
    assert!(other
        .observe_at(
            &mut store,
            "https://other.example/account/identity",
            SOURCE,
            proof("alice", SOURCE, NOW, NOW + OUTAGE_MS),
            NOW,
            0
        )
        .is_err());
    assert!(leases.current_at(&store, alice.reference(), NOW, 0).is_ok());
}

#[test]
fn prepared_work_is_fenced_by_revocation_and_cannot_cross_a_process_restart() {
    let (mut store, mut leases, alice) = fixture();
    let (_, prepared) = leases.prepare(&store, alice.reference()).unwrap();
    assert_eq!(
        leases
            .with_prepared(&mut store, &prepared, || "authorized separately")
            .unwrap(),
        "authorized separately"
    );
    let restarted = manager();
    assert!(restarted
        .with_prepared(&mut store, &prepared, || panic!(
            "restarted prepared work ran"
        ))
        .is_err());
    leases
        .revoke_at(&mut store, alice.reference(), NOW + 10)
        .unwrap();
    assert!(leases
        .with_prepared(&mut store, &prepared, || panic!(
            "revoked prepared work ran"
        ))
        .is_err());
}

#[test]
fn prepared_work_obeys_monotonic_expiry_even_when_wall_clock_basis_is_in_the_future() {
    let (mut store, mut leases, alice) = fixture();
    let (_, prepared) = leases.prepare(&store, alice.reference()).unwrap();
    // Move the process clock forward without depending on a real sleep or the
    // workstation's wall clock. The captured wall-clock date remains unchanged.
    leases.started = Instant::now()
        .checked_sub(std::time::Duration::from_millis(OUTAGE_MS + 1))
        .unwrap();
    assert!(leases
        .with_prepared(&mut store, &prepared, || panic!(
            "expired prepared work ran"
        ))
        .is_err());
}

#[test]
fn native_verified_response_derives_a_local_lease_without_copying_a_hub_session() {
    let bearer = "synthetic-native-staff-bearer";
    let now = crate::account::session_now_ms();
    let identity = crate::account_identity::AccountIdentity {
        holds_email: None,
        account: "alice".into(),
        session: Some(AccountSessionEvidence {
            session_ref: crate::account_session::session_id(bearer),
            method: "passkey".into(),
            issued_at_ms: now - 1000,
            expires_at_ms: now + OUTAGE_MS,
        }),
    };
    let body = serde_json::to_string(&identity).unwrap();
    let (source, server) =
        super::super::source::tests::hub(200, "cache-control: no-store\r\n", body);
    let mut store = Store::open_in_memory().unwrap();
    member(&mut store, "alice", crate::org::MembershipStatus::Active);
    let mut leases = OfficeStaffLeases::new(HomeId::new("native-office-home"));
    let lease = leases
        .observe(
            &mut store,
            source.issuer(),
            &crate::account_session::session_id(bearer),
            source.check(bearer),
        )
        .unwrap();
    server.join().unwrap();
    assert_eq!(lease.account(), "alice");
    assert_eq!(lease.deadline_ms(), identity.session.unwrap().expires_at_ms);
    assert!(crate::account_auth::AccountAuth::rebuild(&store)
        .unwrap()
        .sessions
        .is_empty());
    let recorded = load(&store, lease.reference()).unwrap().unwrap();
    assert_eq!(
        recorded.source_ref,
        crate::account_session::session_id(bearer)
    );
    assert!(!serde_json::to_string(&recorded).unwrap().contains(bearer));
    assert!(leases.current(&store, lease.reference()).is_ok());
}

#[test]
fn exact_home_admission_revocation_reaches_the_engine_read_basis() {
    let (mut store, leases, alice) = fixture();
    let mut admissions = crate::home_admission::HomeAdmissionStore::new();
    let token = admissions.open_office(alice.home(), &alice).unwrap();
    let actor = gaugedesk_core::ids::AuthorityId::new(alice.account());
    let standing = admissions.standing(alice.home(), &actor, &token).unwrap();
    let (_, prepared) = leases.prepare(&store, alice.reference()).unwrap();
    let prepared = prepared.bind_home(standing).unwrap();
    store.with_dispatch_basis(&prepared.basis, || ()).unwrap();
    admissions.revoke(alice.home(), &actor);
    assert!(store
        .with_dispatch_basis(&prepared.basis, || panic!("revoked Home admission ran"))
        .is_err());
}

#[test]
fn another_source_for_the_same_person_cannot_reuse_the_home_credential() {
    let (mut store, mut leases, alice) = fixture();
    let other = leases
        .observe_at(
            &mut store,
            ISSUER,
            "another-alice-source",
            proof("alice", "another-alice-source", NOW, NOW + OUTAGE_MS),
            NOW,
            0,
        )
        .unwrap();
    let mut admissions = crate::home_admission::HomeAdmissionStore::new();
    let token = admissions.open_office(alice.home(), &alice).unwrap();
    let actor = gaugedesk_core::ids::AuthorityId::new(alice.account());
    let standing = admissions.standing(alice.home(), &actor, &token).unwrap();
    assert!(admissions.office_standing(&other, &token).is_err());
    assert!(admissions.office_standing(&alice, &token).is_ok());
    let (_, prepared) = leases.prepare(&store, other.reference()).unwrap();
    assert!(prepared.bind_home(standing).is_err());
    assert!(admissions
        .open_office(&HomeId::new("other-home"), &alice)
        .is_err());
}

#[test]
fn dropping_the_lease_service_invalidates_its_engine_read_basis() {
    let (mut store, leases, alice) = fixture();
    let (_, prepared) = leases.prepare(&store, alice.reference()).unwrap();
    store.with_dispatch_basis(&prepared.basis, || ()).unwrap();
    drop(leases);
    assert!(store
        .with_dispatch_basis(&prepared.basis, || panic!("dropped lease service ran"))
        .is_err());
}
