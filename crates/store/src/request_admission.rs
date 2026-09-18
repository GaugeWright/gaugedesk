//! Stable caller intent and fresh server materialization are different things.
//! This is the HTTP-facing sibling of `admit_materialized`, not a new reducer.

use super::*;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestSnapshot {
    v: u8,
    kind: String,
    request: serde_json::Value,
    materialized: Option<serde_json::Value>,
}

impl Store {
    /// Recover the durable result for one exact request intent. A command row
    /// with another lifecycle, another body, an incomplete status, or a legacy
    /// receipt is not interchangeable recovery evidence.
    pub fn request_admission_status<L, I>(
        &self,
        scope: &str,
        key: &str,
        request: &I,
    ) -> Result<Option<RequestAdmissionStatus>, AdmitError>
    where
        L: Lifecycle,
        I: serde::Serialize,
    {
        let Some(command) = self.command_for_key(scope, key)? else {
            return Ok(None);
        };
        let snapshot: RequestSnapshot = serde_json::from_str(&command.snapshot_json)?;
        if snapshot.v != 1 {
            return Err(AdmitError::UnsupportedSchema(
                "command request snapshot".into(),
            ));
        }
        if snapshot.kind != L::KIND || snapshot.request != serde_json::to_value(request)? {
            return Err(AdmitError::Rejected(Rejection {
                reason: "request recovery identity does not match",
            }));
        }
        match command.status.as_str() {
            "applied" if snapshot.materialized.is_some() => {
                Ok(Some(RequestAdmissionStatus::Applied))
            }
            "rejected" => Ok(Some(RequestAdmissionStatus::Rejected)),
            _ => Ok(None),
        }
    }

    /// Admit stable, secret-free caller intent with freshly authenticated inputs
    /// (GAUGEAPP-6 / INV-19). Actor, authority, scope, expected basis and requested
    /// effect belong in `request`; raw credentials/session tokens never do.
    ///
    /// `authorize` runs on EVERY call, including receipt reads. `materialize`
    /// runs only for a new request, using the current fold inside the write
    /// transaction. Both callbacks must be pure: authenticate external facts and
    /// supply time/generated ids before calling. A fresh timestamp, auth epoch
    /// or generated id on retry therefore cannot change the original effect.
    ///
    /// Request binding, materialized command, events and successful receipt
    /// commit together. A domain rejection records its request with no events;
    /// a database/serialization failure rolls everything back. Existing APIs
    /// retain their exact-materialized-command semantics.
    pub fn admit_request<L, I>(
        &mut self,
        scope: &str,
        key: &str,
        request: &I,
        authorize: impl FnOnce(&L::State) -> Result<(), Rejection>,
        materialize: impl FnOnce(&L::State) -> Result<L::Command, Rejection>,
    ) -> Result<MaterializedAdmission<L::State>, AdmitError>
    where
        L: Lifecycle,
        L::Command: serde::Serialize,
        I: serde::Serialize,
    {
        let intent = serde_json::to_value(request)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut state = L::State::default();
        {
            let mut statement = tx.prepare_cached(
                "SELECT payload FROM events WHERE scope_id = ?1 AND kind = ?2 ORDER BY position",
            )?;
            let rows =
                statement.query_map(params![scope, L::KIND], |row| row.get::<_, String>(0))?;
            for row in rows {
                state = L::evolve(&state, serde_json::from_str(&row?)?);
            }
        }
        authorize(&state).map_err(AdmitError::Rejected)?;

        let previous = tx
            .prepare_cached(
                "SELECT command_id, scope_id, idempotency_key, status, snapshot_json
             FROM commands WHERE scope_id = ?1 AND idempotency_key = ?2",
            )?
            .query_row(params![scope, key], command_record_from_row)
            .optional()?;
        let receipt = tx
            .prepare_cached(
                "SELECT 1 FROM command_receipts WHERE scope_id = ?1 AND command_key = ?2",
            )?
            .query_row(params![scope, key], |_| Ok(()))
            .optional()?
            .is_some();
        if let Some(previous) = previous {
            let snapshot: RequestSnapshot = serde_json::from_str(&previous.snapshot_json)?;
            if snapshot.v != 1 {
                return Err(AdmitError::UnsupportedSchema(
                    "command request snapshot".into(),
                ));
            }
            if snapshot.kind != L::KIND || snapshot.request != intent {
                return Err(AdmitError::Rejected(Rejection {
                    reason: "idempotency key reused with different request",
                }));
            }
            if receipt && previous.status == "applied" && snapshot.materialized.is_some() {
                tx.commit()?;
                return Ok(MaterializedAdmission {
                    state,
                    replayed: true,
                });
            }
            return Err(AdmitError::Rejected(Rejection {
                reason: "request already rejected or incomplete; submit with a new key",
            }));
        }
        if receipt {
            return Err(AdmitError::Rejected(Rejection {
                reason: "receipt has no exact request binding",
            }));
        }

        let prepared = materialize(&state);
        let materialized = prepared
            .as_ref()
            .ok()
            .map(serde_json::to_value)
            .transpose()?;
        let decision = prepared.and_then(|command| L::decide(&state, command));
        let snapshot = serde_json::to_string(&RequestSnapshot {
            v: 1,
            kind: L::KIND.into(),
            request: intent,
            materialized,
        })?;
        let command_id = format!("request-command:{}:{scope}{key}", scope.len());
        tx.prepare_cached(
            "INSERT INTO commands (command_id, scope_id, idempotency_key, status, snapshot_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?
        .execute(params![
            command_id,
            scope,
            key,
            if decision.is_ok() {
                "applied"
            } else {
                "rejected"
            },
            snapshot
        ])?;
        let events = match decision {
            Ok(events) => events,
            Err(rejection) => {
                tx.commit()?;
                return Err(AdmitError::Rejected(rejection));
            }
        };
        let base: i64 = tx
            .prepare_cached(
                "SELECT COALESCE(MAX(position), -1) + 1 FROM events WHERE scope_id = ?1",
            )?
            .query_row([scope], |row| row.get(0))?;
        for (offset, event) in events.into_iter().enumerate() {
            tx.prepare_cached(
                "INSERT INTO events (scope_id, position, kind, payload) VALUES (?1, ?2, ?3, ?4)",
            )?
            .execute(params![
                scope,
                base + offset as i64,
                L::KIND,
                serde_json::to_string(&event)?
            ])?;
            state = L::evolve(&state, event);
        }
        tx.prepare_cached(
            "INSERT INTO command_receipts (scope_id, command_key, applied_at) VALUES (?1, ?2, ?3)",
        )?
        .execute(params![scope, key, base])?;
        tx.commit()?;
        Ok(MaterializedAdmission {
            state,
            replayed: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gaugedesk_core::run::{RunCommand, RunPhase, RunState};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Barrier,
    };

    fn intent(actor: &str) -> serde_json::Value {
        serde_json::json!({ "actor": actor, "authority": "owner", "scope": "scope", "basis": "0", "operation": "request" })
    }
    fn allow(_: &RunState) -> Result<(), Rejection> {
        Ok(())
    }

    #[test]
    fn fresh_materialization_is_not_repeated_and_authorization_is_never_skipped() {
        let mut store = Store::open_in_memory().unwrap();
        let first = store
            .admit_request::<RunState, _>("scope", "key", &intent("alice"), allow, |_| {
                Ok(RunCommand::RequestRun)
            })
            .unwrap();
        assert!(!first.replayed);
        store
            .admit::<RunState>("scope", RunCommand::AdmitRun)
            .unwrap();
        let authorized = AtomicUsize::new(0);
        let retry = store
            .admit_request::<RunState, _>(
                "scope",
                "key",
                &intent("alice"),
                |_| {
                    authorized.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
                |_| panic!("must not rematerialize a completed request"),
            )
            .unwrap();
        assert!(retry.replayed);
        assert_eq!(retry.state.phase, RunPhase::Admitted);
        assert_eq!(authorized.load(Ordering::SeqCst), 1);
        assert!(store
            .admit_request::<RunState, _>(
                "scope",
                "key",
                &intent("alice"),
                |_| Err(Rejection { reason: "revoked" }),
                |_| panic!("unauthorized")
            )
            .is_err());
        assert!(store
            .admit_request::<RunState, _>("scope", "key", &intent("bob"), allow, |_| panic!(
                "collision"
            ))
            .is_err());
        assert_eq!(store.records("scope", RunState::KIND).unwrap().len(), 2);
    }

    #[test]
    fn changed_request_is_refused_after_reopen_even_when_materialization_would_match() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("requests.sqlite");
        let mut store = Store::open(path.to_str().unwrap()).unwrap();
        store
            .admit_request::<RunState, _>("scope", "key", &intent("alice"), allow, |_| {
                Ok(RunCommand::RequestRun)
            })
            .unwrap();
        drop(store);
        let mut store = Store::open(path.to_str().unwrap()).unwrap();
        for field in ["actor", "authority", "scope", "basis", "operation"] {
            let mut changed = intent("alice");
            changed[field] = serde_json::Value::String("changed".into());
            assert!(store
                .admit_request::<RunState, _>("scope", "key", &changed, allow, |_| Ok(
                    RunCommand::RequestRun
                ))
                .is_err());
        }
        assert!(
            store
                .admit_request::<RunState, _>("scope", "key", &intent("alice"), allow, |_| panic!(
                    "no replay materialization"
                ))
                .unwrap()
                .replayed
        );
    }

    #[test]
    fn concurrent_identical_requests_prepare_and_append_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("requests.sqlite");
        drop(Store::open(path.to_str().unwrap()).unwrap());
        let barrier = Arc::new(Barrier::new(2));
        let prepares = Arc::new(AtomicUsize::new(0));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let path = path.clone();
                let barrier = barrier.clone();
                let prepares = prepares.clone();
                std::thread::spawn(move || {
                    let mut store = Store::open(path.to_str().unwrap()).unwrap();
                    barrier.wait();
                    store
                        .admit_request::<RunState, _>(
                            "scope",
                            "key",
                            &intent("alice"),
                            allow,
                            |_| {
                                prepares.fetch_add(1, Ordering::SeqCst);
                                Ok(RunCommand::RequestRun)
                            },
                        )
                        .unwrap()
                })
            })
            .collect();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.replayed).count(), 1);
        assert_eq!(prepares.load(Ordering::SeqCst), 1);
        assert_eq!(
            Store::open(path.to_str().unwrap())
                .unwrap()
                .records("scope", RunState::KIND)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn event_write_failure_rolls_back_request_and_receipt_with_the_effect() {
        let mut store = Store::open_in_memory().unwrap();
        store.conn.execute_batch("CREATE TEMP TRIGGER fail_event BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT, 'injected write failure'); END;").unwrap();
        assert!(store
            .admit_request::<RunState, _>("scope", "key", &intent("alice"), allow, |_| Ok(
                RunCommand::RequestRun
            ))
            .is_err());
        assert!(store.command_for_key("scope", "key").unwrap().is_none());
        assert!(store.records("scope", RunState::KIND).unwrap().is_empty());
        store
            .conn
            .execute_batch("DROP TRIGGER fail_event;")
            .unwrap();
        assert!(
            !store
                .admit_request::<RunState, _>("scope", "key", &intent("alice"), allow, |_| Ok(
                    RunCommand::RequestRun
                ))
                .unwrap()
                .replayed
        );
    }

    #[test]
    fn domain_rejection_is_durable_but_authentication_failure_cannot_claim_a_key() {
        let mut store = Store::open_in_memory().unwrap();
        assert!(store
            .admit_request::<RunState, _>(
                "scope",
                "denied",
                &intent("alice"),
                |_| Err(Rejection {
                    reason: "no access"
                }),
                |_| panic!("no authority")
            )
            .is_err());
        assert!(store.command_for_key("scope", "denied").unwrap().is_none());
        assert_eq!(
            store
                .request_admission_status::<RunState, _>("scope", "denied", &intent("alice"))
                .unwrap(),
            None
        );
        assert!(store
            .admit_request::<RunState, _>("scope", "bad", &intent("alice"), allow, |_| Ok(
                RunCommand::StartRun
            ))
            .is_err());
        assert_eq!(
            store
                .command_for_key("scope", "bad")
                .unwrap()
                .unwrap()
                .status,
            "rejected"
        );
        assert_eq!(
            store
                .request_admission_status::<RunState, _>("scope", "bad", &intent("alice"))
                .unwrap(),
            Some(RequestAdmissionStatus::Rejected)
        );
        assert!(store
            .request_admission_status::<RunState, _>("scope", "bad", &intent("bob"))
            .is_err());
        assert!(store
            .admit_request::<RunState, _>("scope", "bad", &intent("alice"), allow, |_| panic!(
                "no second decision"
            ))
            .is_err());
        assert!(store.records("scope", RunState::KIND).unwrap().is_empty());
    }

    #[test]
    fn an_unbound_legacy_receipt_cannot_be_claimed_by_a_new_request() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .admit_with_key::<RunState>("scope", "key", RunCommand::RequestRun)
            .unwrap();
        assert!(store
            .admit_request::<RunState, _>("scope", "key", &intent("alice"), allow, |_| panic!(
                "unknown binding"
            ))
            .is_err());
        assert!(store.command_for_key("scope", "key").unwrap().is_none());
    }
}
