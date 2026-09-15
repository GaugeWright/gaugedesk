use super::*;

fn admit(
    store: &mut Store,
    key: &str,
    claim: &str,
    payload: &str,
) -> Result<MaterializedRecordAdmission, AdmitError> {
    store.admit_record_facts_with_claims(
        "reviews",
        key,
        payload,
        &[CommandRecordFact {
            scope_id: "organization".into(),
            kind: "approved".into(),
            payload: payload.into(),
        }],
        None,
        &[RecordCommandClaim {
            key: claim,
            snapshot: payload,
        }],
    )
}

#[test]
fn record_claims_bind_request_and_proposal_with_one_receipt_batch_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.sqlite");
    let mut store = Store::open(path.to_str().unwrap()).unwrap();
    assert!(
        !admit(&mut store, "request", "proposal", "approved")
            .unwrap()
            .replayed
    );
    drop(store);
    let mut store = Store::open(path.to_str().unwrap()).unwrap();
    assert!(
        admit(&mut store, "request", "proposal", "approved")
            .unwrap()
            .replayed
    );
    assert_eq!(
        store.records("organization", "approved").unwrap(),
        ["approved"]
    );
    assert!(matches!(
        admit(&mut store, "request", "proposal", "changed"),
        Err(AdmitError::Rejected(_))
    ));
    assert!(matches!(
        admit(&mut store, "request", "new-proposal", "approved"),
        Err(AdmitError::Rejected(_))
    ));
    assert!(store
        .command_for_key("reviews", "new-proposal")
        .unwrap()
        .is_none());
}

#[test]
fn record_claims_competing_reviewers_can_claim_one_proposal_only_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.sqlite");
    drop(Store::open(path.to_str().unwrap()).unwrap());
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let threads = (0..2)
        .map(|index| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut store = Store::open(path.to_str().unwrap()).unwrap();
                barrier.wait();
                admit(
                    &mut store,
                    &format!("review-{index}"),
                    "one-proposal",
                    "same requested change",
                )
            })
        })
        .collect::<Vec<_>>();
    let results = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(AdmitError::Rejected(_))))
            .count(),
        1
    );
    let store = Store::open(path.to_str().unwrap()).unwrap();
    assert_eq!(store.records("organization", "approved").unwrap().len(), 1);
    let loser = results.iter().position(Result::is_err).unwrap();
    assert!(
        store
            .command_for_key("reviews", &format!("review-{loser}"))
            .unwrap()
            .is_none(),
        "the losing primary claim rolls back too"
    );
}

#[test]
fn record_claims_cannot_borrow_another_requests_alias_even_with_the_same_payload() {
    let mut store = Store::open_in_memory().unwrap();
    store
        .admit_record_facts("reviews", "old-request", "same payload", &[])
        .unwrap();
    admit(&mut store, "new-request", "proposal", "same payload").unwrap();
    assert!(matches!(
        admit(&mut store, "old-request", "proposal", "same payload"),
        Err(AdmitError::Rejected(_))
    ));
    assert!(matches!(
        store.admit_record_facts("reviews", "proposal", "same payload", &[]),
        Err(AdmitError::Rejected(_))
    ));
}

#[test]
fn record_claims_roll_back_both_identities_when_the_fact_batch_fails() {
    let mut store = Store::open_in_memory().unwrap();
    store.conn.execute_batch("CREATE TRIGGER fail_fact BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT, 'fixture'); END;").unwrap();
    assert!(matches!(
        admit(&mut store, "request", "proposal", "approved"),
        Err(AdmitError::Db(_))
    ));
    assert!(store
        .command_for_key("reviews", "request")
        .unwrap()
        .is_none());
    assert!(store
        .command_for_key("reviews", "proposal")
        .unwrap()
        .is_none());
    store.conn.execute_batch("DROP TRIGGER fail_fact;").unwrap();
    assert!(
        !admit(&mut store, "request", "proposal", "approved")
            .unwrap()
            .replayed
    );
}

#[test]
fn record_claims_refuse_duplicate_or_primary_aliases_without_writes() {
    let mut store = Store::open_in_memory().unwrap();
    for keys in [
        ["request", "another"],
        ["duplicate", "duplicate"],
        ["", "another"],
    ] {
        let claims = keys.map(|key| RecordCommandClaim {
            key,
            snapshot: "approved",
        });
        assert!(matches!(
            store.admit_record_facts_with_claims(
                "reviews",
                "request",
                "approved",
                &[],
                None,
                &claims
            ),
            Err(AdmitError::Rejected(_))
        ));
        assert!(store
            .command_for_key("reviews", "request")
            .unwrap()
            .is_none());
    }
}
