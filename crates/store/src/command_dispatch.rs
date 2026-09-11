//! Atomic product admission and runtime outbox intent (ACTION-3 / ADR 0164).
//!
//! The runtime owns command bytes, protocol validation and effect outcomes.
//! This store retains references supplied by the authenticated product shell;
//! neither a reference nor a successful product admission grants execution.

use gaugedesk_core::{Lifecycle, Rejection};
use rusqlite::{params, OptionalExtension, TransactionBehavior};

use crate::{AdmitError, MaterializedAdmission, Store};

/// Process-local event-plane read basis. Only the store can capture one. It
/// conveys no permission and is never a replacement for current execution
/// authorization. Other storage planes need their own publication guards.
pub struct DispatchReadBasis {
    store_path: String,
    heads: std::collections::BTreeMap<String, Option<i64>>,
    deadline: Option<std::time::SystemTime>,
}

impl DispatchReadBasis {
    /// Add a validity ceiling from the captured authority. An existing ceiling
    /// can only be shortened; this observation still grants no authority.
    pub fn with_deadline(mut self, deadline: std::time::SystemTime) -> Self {
        self.deadline = Some(
            self.deadline
                .map_or(deadline, |existing| existing.min(deadline)),
        );
        self
    }

    pub fn deadline(&self) -> Option<std::time::SystemTime> {
        self.deadline
    }
}

/// One product commit while its current-authority writer transaction is held.
/// The evidence publisher consumes this inside its retention callback. Dropping
/// it rolls back; a successful commit remains durable if the callback then fails.
pub struct DispatchRecordAdmission<'tx> {
    tx: rusqlite::Transaction<'tx>,
    codec: Option<std::sync::Arc<dyn crate::ContentCodec>>,
}

impl DispatchRecordAdmission<'_> {
    /// Commit the exact command and its facts before releasing external evidence
    /// retention. This consumes the handle; it grants no external execution right.
    pub fn commit(
        self,
        command_scope: &str,
        idempotency_key: &str,
        snapshot_json: &str,
        facts: &[crate::CommandRecordFact],
    ) -> Result<crate::MaterializedRecordAdmission, AdmitError> {
        let stored = crate::record_admission::encode_facts(self.codec.as_ref(), facts)?;
        crate::record_admission::commit(
            self.tx,
            self.codec,
            command_scope,
            idempotency_key,
            snapshot_json,
            stored,
            None,
        )
    }
}

/// An append-only outbox fact in the same scope/order as the product admission.
pub const DISPATCH_KIND: &str = "runtime_command_dispatch_v1";

/// Exact, immutable references resolved by the owning runtime adapter. Payloads
/// and credentials belong behind their authorized content/transport boundaries.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandDispatch {
    pub runtime_ref: String,
    pub command_ref: String,
}

/// Causal link from an outbox event to the product command that admitted it.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchIntent {
    pub command_id: String,
    pub dispatch: CommandDispatch,
}

/// Original command and destination backed by a committed product receipt.
/// This is delivery data, not an authentication or execution grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedDispatch<Command> {
    pub command_id: String,
    pub command: Command,
    pub dispatch: CommandDispatch,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DispatchSnapshot<Command> {
    kind: String,
    command: Command,
    dispatch: CommandDispatch,
}

fn check_dispatch_basis(
    tx: &rusqlite::Transaction<'_>,
    store_path: &str,
    basis: &DispatchReadBasis,
) -> Result<(), AdmitError> {
    if basis
        .deadline
        .is_some_and(|deadline| std::time::SystemTime::now() >= deadline)
    {
        return Err(AdmitError::Rejected(Rejection {
            reason: "dispatch authorization expired while waiting",
        }));
    }
    if basis.store_path != store_path {
        return Err(AdmitError::Rejected(Rejection {
            reason: "dispatch authorization came from another store",
        }));
    }
    for (scope, expected) in &basis.heads {
        let current: Option<i64> = tx.query_row(
            "SELECT MAX(position) FROM events WHERE scope_id = ?1",
            params![scope],
            |row| row.get(0),
        )?;
        if &current != expected {
            return Err(AdmitError::Rejected(Rejection {
                reason: "dispatch authorization changed during preparation",
            }));
        }
    }
    Ok(())
}

impl Store {
    /// Fence current product standing before entering a bounded evidence
    /// publisher. Commit through the one-use handle inside that publisher's
    /// retention callback, so both exclusions span the product commit. No network
    /// work or external effect belongs in this callback. A callback error after
    /// commit does not undo the admission; retry the same exact command.
    ///
    /// The handle cannot escape this callback to become a deferred grant:
    /// ```compile_fail
    /// let mut store = gaugedesk_store::Store::open_in_memory().unwrap();
    /// let (_, basis) = store.read_for_dispatch(&["authority"], |_| Ok(())).unwrap();
    /// let escaped = store.with_dispatch_record_admission(&basis, |writer| writer);
    /// ```
    pub fn with_dispatch_record_admission<T>(
        &mut self,
        basis: &DispatchReadBasis,
        publish: impl for<'tx> FnOnce(DispatchRecordAdmission<'tx>) -> T,
    ) -> Result<T, AdmitError> {
        let codec = self.codec.clone();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_dispatch_basis(&tx, &self.path, basis)?;
        Ok(publish(DispatchRecordAdmission { tx, codec }))
    }

    /// Serialize a bounded native runtime operation with current product standing.
    /// The callback writes only separate runtime/target authorities; it must not write
    /// this product store, do network work, or return an escaping authority grant.
    /// Its error cannot undo a runtime admission which already committed.
    pub fn with_dispatch_basis<T>(
        &mut self,
        basis: &DispatchReadBasis,
        admit_runtime: impl FnOnce() -> T,
    ) -> Result<T, AdmitError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_dispatch_basis(&tx, &self.path, basis)?;
        let result = admit_runtime();
        tx.commit()?;
        Ok(result)
    }

    /// Fold the declared event scopes in one read snapshot. Callers must name
    /// every event scope on which their authorization depends; this does not
    /// fence the separate records/content tables or external authorities.
    pub fn read_for_dispatch<T>(
        &self,
        scopes: &[&str],
        read: impl FnOnce(&Store) -> Result<T, AdmitError>,
    ) -> Result<(T, DispatchReadBasis), AdmitError> {
        if scopes.is_empty() || scopes.iter().any(|scope| scope.trim().is_empty()) {
            return Err(AdmitError::Rejected(Rejection {
                reason: "dispatch authorization requires explicit event scopes",
            }));
        }
        let tx = self.conn.unchecked_transaction()?;
        let mut heads = std::collections::BTreeMap::new();
        for scope in scopes {
            let head: Option<i64> = tx.query_row(
                "SELECT MAX(position) FROM events WHERE scope_id = ?1",
                params![scope],
                |row| row.get(0),
            )?;
            heads.insert((*scope).to_owned(), head);
        }
        let value = read(self)?;
        tx.commit()?;
        Ok((
            value,
            DispatchReadBasis {
                store_path: self.path.clone(),
                heads,
                deadline: None,
            },
        ))
    }

    /// Refuse an intervening authorization-scope append before any command or
    /// outbox write. A stale retry must obtain a fresh authorized read too.
    pub fn admit_with_dispatch_against<L: Lifecycle>(
        &mut self,
        scope_id: &str,
        idempotency_key: &str,
        command: L::Command,
        dispatch: &CommandDispatch,
        basis: &DispatchReadBasis,
    ) -> Result<MaterializedAdmission<L::State>, AdmitError>
    where
        L::Command: serde::Serialize,
    {
        self.admit_with_dispatch_inner::<L>(
            scope_id,
            idempotency_key,
            command,
            dispatch,
            Some(basis),
        )
    }
    /// Read a delivery from one SQLite snapshot, without creating a command,
    /// repairing status, or advancing its lifecycle. A claimed command with no
    /// durable receipt is not deliverable. Legacy or inconsistent receipts
    /// cannot be promoted into outbox authority by this read.
    pub fn committed_dispatch<L: Lifecycle>(
        &mut self,
        scope_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<CommittedDispatch<L::Command>>, AdmitError>
    where
        L::Command: serde::de::DeserializeOwned,
    {
        if scope_id.trim().is_empty() || idempotency_key.trim().is_empty() {
            return Err(AdmitError::Rejected(Rejection {
                reason: "invalid product command dispatch identity",
            }));
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let receipted = tx
            .query_row(
                "SELECT 1 FROM command_receipts WHERE scope_id = ?1 AND command_key = ?2",
                params![scope_id, idempotency_key],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !receipted {
            return Ok(None);
        }
        let expected_id = format!("command:{}:{scope_id}{idempotency_key}", scope_id.len());
        let original: Option<(String, String)> = tx
            .query_row(
                "SELECT command_id, snapshot_json FROM commands WHERE scope_id = ?1 AND idempotency_key = ?2",
                params![scope_id, idempotency_key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((command_id, snapshot_json)) = original else {
            return Err(AdmitError::Rejected(Rejection {
                reason: "dispatch receipt has no original command",
            }));
        };
        let snapshot: DispatchSnapshot<L::Command> = serde_json::from_str(&snapshot_json)?;
        if command_id != expected_id
            || snapshot.kind != L::KIND
            || snapshot.dispatch.runtime_ref.trim().is_empty()
            || snapshot.dispatch.command_ref.trim().is_empty()
        {
            return Err(AdmitError::Rejected(Rejection {
                reason: "dispatch receipt does not match its original command",
            }));
        }
        let intent = DispatchIntent {
            command_id: command_id.clone(),
            dispatch: snapshot.dispatch.clone(),
        };
        let mut matches = 0;
        {
            let mut statement = tx.prepare(
                "SELECT payload FROM events WHERE scope_id = ?1 AND kind = ?2 ORDER BY position",
            )?;
            for row in statement.query_map(params![scope_id, DISPATCH_KIND], |row| {
                row.get::<_, String>(0)
            })? {
                let recorded: DispatchIntent = serde_json::from_str(&row?)?;
                if recorded.command_id == command_id {
                    if recorded != intent {
                        return Err(AdmitError::Rejected(Rejection {
                            reason: "dispatch receipt does not match its committed intent",
                        }));
                    }
                    matches += 1;
                }
            }
        }
        if matches != 1 {
            return Err(AdmitError::Rejected(Rejection {
                reason: "dispatch receipt has no unique committed intent",
            }));
        }
        tx.commit()?;
        Ok(Some(CommittedDispatch {
            command_id,
            command: snapshot.command,
            dispatch: snapshot.dispatch,
        }))
    }

    /// Commit the original product command, lifecycle events, outbox reference
    /// and product receipt in one transaction. A dispatcher reads only committed
    /// outbox facts and retries delivery under the referenced runtime identity.
    /// No network or file operation occurs in this transaction.
    ///
    /// Both command and dispatch reference bind the caller key. A changed
    /// reference refuses even if the lifecycle command happens to be identical.
    /// Replays return the current product fold and append nothing. `applied`
    /// refers to this product admission, never to execution by the runtime.
    /// Runtime acknowledgment/result admission are separate subsequent commands.
    ///
    /// Unlike the legacy heterogeneous-effect shell, no claim is committed
    /// ahead of pure admission: rollback leaves no unreceipted processing row
    /// for startup to expire. Existing legacy claims are still refused.
    pub fn admit_with_dispatch<L: Lifecycle>(
        &mut self,
        scope_id: &str,
        idempotency_key: &str,
        command: L::Command,
        dispatch: &CommandDispatch,
    ) -> Result<MaterializedAdmission<L::State>, AdmitError>
    where
        L::Command: serde::Serialize,
    {
        self.admit_with_dispatch_inner::<L>(scope_id, idempotency_key, command, dispatch, None)
    }

    fn admit_with_dispatch_inner<L: Lifecycle>(
        &mut self,
        scope_id: &str,
        idempotency_key: &str,
        command: L::Command,
        dispatch: &CommandDispatch,
        basis: Option<&DispatchReadBasis>,
    ) -> Result<MaterializedAdmission<L::State>, AdmitError>
    where
        L::Command: serde::Serialize,
    {
        if [
            scope_id,
            idempotency_key,
            &dispatch.runtime_ref,
            &dispatch.command_ref,
        ]
        .iter()
        .any(|value| value.trim().is_empty())
            || L::KIND == DISPATCH_KIND
        {
            return Err(AdmitError::Rejected(Rejection {
                reason: "invalid product command dispatch identity",
            }));
        }
        let snapshot = serde_json::to_string(&serde_json::json!({
            "kind": L::KIND,
            "command": &command,
            "dispatch": dispatch,
        }))?;
        let command_id = format!("command:{}:{scope_id}{idempotency_key}", scope_id.len());
        let intent = DispatchIntent {
            command_id: command_id.clone(),
            dispatch: dispatch.clone(),
        };
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(basis) = basis {
            check_dispatch_basis(&tx, &self.path, basis)?;
        }
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO commands
             (command_id, scope_id, idempotency_key, status, snapshot_json)
             VALUES (?1, ?2, ?3, 'received', ?4)",
            params![command_id, scope_id, idempotency_key, snapshot],
        )?;
        let (original, status): (String, String) = tx.query_row(
            "SELECT snapshot_json, status FROM commands WHERE scope_id = ?1 AND idempotency_key = ?2",
            params![scope_id, idempotency_key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if original != snapshot {
            return Err(AdmitError::Rejected(Rejection {
                reason: "idempotency key reused with different command or dispatch",
            }));
        }
        let replayed = tx
            .query_row(
                "SELECT 1 FROM command_receipts WHERE scope_id = ?1 AND command_key = ?2",
                params![scope_id, idempotency_key],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if replayed {
            // A legacy receipt without an original snapshot/outbox cannot be
            // upgraded into a successful dispatch admission on a retry.
            let mut statement = tx.prepare(
                "SELECT payload FROM events WHERE scope_id = ?1 AND kind = ?2 ORDER BY position",
            )?;
            let mut matches = 0;
            for row in statement.query_map(params![scope_id, DISPATCH_KIND], |row| {
                row.get::<_, String>(0)
            })? {
                let recorded: DispatchIntent = serde_json::from_str(&row?)?;
                if recorded.command_id == command_id {
                    if recorded != intent {
                        return Err(AdmitError::Rejected(Rejection {
                            reason: "dispatch receipt does not match its committed intent",
                        }));
                    }
                    matches += 1;
                }
            }
            if inserted != 0 || matches != 1 {
                return Err(AdmitError::Rejected(Rejection {
                    reason: "dispatch receipt has no unique committed intent",
                }));
            }
        }
        if !replayed && status != "received" {
            return Err(AdmitError::Rejected(Rejection {
                reason: "existing command has no replayable dispatch admission",
            }));
        }
        let mut state = L::State::default();
        {
            let mut statement = tx.prepare(
                "SELECT payload FROM events WHERE scope_id = ?1 AND kind = ?2 ORDER BY position",
            )?;
            for row in
                statement.query_map(params![scope_id, L::KIND], |row| row.get::<_, String>(0))?
            {
                state = L::evolve(&state, serde_json::from_str(&row?)?);
            }
        }
        if !replayed {
            let events = L::decide(&state, command).map_err(AdmitError::Rejected)?;
            let base: i64 = tx.query_row(
                "SELECT COALESCE(MAX(position), -1) + 1 FROM events WHERE scope_id = ?1",
                params![scope_id],
                |row| row.get(0),
            )?;
            let dispatch_position = base + events.len() as i64;
            for (offset, event) in events.into_iter().enumerate() {
                tx.execute(
                    "INSERT INTO events (scope_id, position, kind, payload) VALUES (?1, ?2, ?3, ?4)",
                    params![scope_id, base + offset as i64, L::KIND, serde_json::to_string(&event)?],
                )?;
                state = L::evolve(&state, event);
            }
            tx.execute(
                "INSERT INTO events (scope_id, position, kind, payload) VALUES (?1, ?2, ?3, ?4)",
                params![
                    scope_id,
                    dispatch_position,
                    DISPATCH_KIND,
                    serde_json::to_string(&intent)?
                ],
            )?;
            tx.execute(
                "INSERT INTO command_receipts (scope_id, command_key, applied_at) VALUES (?1, ?2, ?3)",
                params![scope_id, idempotency_key, base],
            )?;
        }
        tx.execute(
            "UPDATE commands SET status = 'applied', updated_at = CURRENT_TIMESTAMP
             WHERE scope_id = ?1 AND idempotency_key = ?2",
            params![scope_id, idempotency_key],
        )?;
        tx.commit()?;
        Ok(MaterializedAdmission { state, replayed })
    }
}

#[cfg(test)]
#[path = "command_dispatch_record_tests.rs"]
mod record_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use gaugedesk_core::run::{RunCommand, RunPhase, RunState};
    use std::sync::{Arc, Barrier};

    #[test]
    fn expired_authority_refuses_command_and_runtime_entry_without_changed_events() {
        let mut store = Store::open_in_memory().unwrap();
        let (_, basis) = store.read_for_dispatch(&["grants"], |_| Ok(())).unwrap();
        let expired = basis
            .with_deadline(std::time::UNIX_EPOCH)
            .with_deadline(std::time::SystemTime::now() + std::time::Duration::from_secs(3600));
        assert_eq!(expired.deadline(), Some(std::time::UNIX_EPOCH));
        assert!(store
            .with_dispatch_basis(&expired, || panic!("expired runtime entry"))
            .is_err());
        assert!(store
            .admit_with_dispatch_against::<RunState>(
                "scope",
                "key",
                RunCommand::RequestRun,
                &dispatch(),
                &expired
            )
            .is_err());
        assert!(store.command_for_key("scope", "key").unwrap().is_none());
        assert!(store.records("scope", DISPATCH_KIND).unwrap().is_empty());
    }

    #[test]
    fn runtime_admission_guard_excludes_changes_and_releases_after_lost_response() {
        let mut product = Store::open_in_memory().unwrap();
        let mut runtime = Store::open_in_memory().unwrap();
        let competing = rusqlite::Connection::open(product.path()).unwrap();
        competing.busy_timeout(std::time::Duration::ZERO).unwrap();
        let (_, stale) = product.read_for_dispatch(&["grants"], |_| Ok(())).unwrap();
        product.append_record("grants", "grant", "changed").unwrap();
        assert!(product
            .with_dispatch_basis(&stale, || panic!("stale callback entered"))
            .is_err());
        let (_, basis) = product.read_for_dispatch(&["grants"], |_| Ok(())).unwrap();
        let result = product
            .with_dispatch_basis(&basis, || {
                assert!(competing.execute_batch("BEGIN IMMEDIATE").is_err());
                runtime
                    .append_record("action", "admission", "exact command")
                    .unwrap();
                Err::<(), _>("lost runtime response")
            })
            .unwrap();
        assert!(result.is_err());
        assert_eq!(
            runtime.records("action", "admission").unwrap(),
            ["exact command"]
        );
        competing
            .execute_batch("BEGIN IMMEDIATE; ROLLBACK")
            .unwrap();
        let mut foreign = Store::open_in_memory().unwrap();
        assert!(foreign
            .with_dispatch_basis(&basis, || panic!("foreign callback entered"))
            .is_err());
    }

    #[test]
    fn authorization_read_is_consistent_and_changed_grants_publish_nothing() {
        let mut store = Store::open_in_memory().unwrap();
        store.append_record("grants", "grant", "active").unwrap();
        let mut other = store.sibling().unwrap();
        let (observed, basis) = store
            .read_for_dispatch(&["grants"], |snapshot| {
                other.append_record("grants", "grant", "revoked")?;
                snapshot.records("grants", "grant")
            })
            .unwrap();
        assert_eq!(observed, ["active"]);
        let rejected = store.admit_with_dispatch_against::<RunState>(
            "scope",
            "key",
            RunCommand::RequestRun,
            &dispatch(),
            &basis,
        );
        assert!(matches!(
            rejected,
            Err(AdmitError::Rejected(Rejection {
                reason: "dispatch authorization changed during preparation"
            }))
        ));
        assert!(store.command_for_key("scope", "key").unwrap().is_none());
        assert!(store.records("scope", DISPATCH_KIND).unwrap().is_empty());
    }

    #[test]
    fn fenced_admission_replays_with_fresh_authority_and_rejects_a_different_store() {
        let mut store = Store::open_in_memory().unwrap();
        let (_, basis) = store.read_for_dispatch(&["grants"], |_| Ok(())).unwrap();
        store.append_record("unrelated", "fact", "change").unwrap();
        let admitted = store
            .admit_with_dispatch_against::<RunState>(
                "scope",
                "key",
                RunCommand::RequestRun,
                &dispatch(),
                &basis,
            )
            .unwrap();
        assert!(!admitted.replayed);
        assert!(
            store
                .admit_with_dispatch_against::<RunState>(
                    "scope",
                    "key",
                    RunCommand::RequestRun,
                    &dispatch(),
                    &basis
                )
                .unwrap()
                .replayed
        );
        store.append_record("grants", "grant", "changed").unwrap();
        assert!(store
            .admit_with_dispatch_against::<RunState>(
                "scope",
                "key",
                RunCommand::RequestRun,
                &dispatch(),
                &basis
            )
            .is_err());
        let (_, current) = store.read_for_dispatch(&["grants"], |_| Ok(())).unwrap();
        assert!(
            store
                .admit_with_dispatch_against::<RunState>(
                    "scope",
                    "key",
                    RunCommand::RequestRun,
                    &dispatch(),
                    &current
                )
                .unwrap()
                .replayed
        );
        let mut other = Store::open_in_memory().unwrap();
        other.append_record("grants", "grant", "changed").unwrap();
        assert!(other
            .admit_with_dispatch_against::<RunState>(
                "scope",
                "key",
                RunCommand::RequestRun,
                &dispatch(),
                &current
            )
            .is_err());
        assert_eq!(store.records("scope", DISPATCH_KIND).unwrap().len(), 1);
        assert!(other.records("scope", DISPATCH_KIND).unwrap().is_empty());
        assert!(store.read_for_dispatch(&[], |_| Ok(())).is_err());
    }

    fn dispatch() -> CommandDispatch {
        CommandDispatch {
            runtime_ref: "home-runtime:alice".into(),
            command_ref: "admitted-command:immutable-1".into(),
        }
    }

    #[test]
    fn delivery_read_keeps_the_original_command_without_repairing_status() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .admit_with_dispatch::<RunState>("scope", "key", RunCommand::RequestRun, &dispatch())
            .unwrap();
        store
            .admit::<RunState>("scope", RunCommand::AdmitRun)
            .unwrap();
        store
            .conn
            .execute("UPDATE commands SET status = 'received'", [])
            .unwrap();
        let mut reopened = store.sibling().unwrap();
        drop(store);
        let changes = reopened.conn.total_changes();
        let delivery = reopened
            .committed_dispatch::<RunState>("scope", "key")
            .unwrap()
            .unwrap();
        assert_eq!(delivery.command, RunCommand::RequestRun);
        assert_eq!(delivery.dispatch, dispatch());
        assert_eq!(
            delivery.command_id,
            reopened
                .command_for_key("scope", "key")
                .unwrap()
                .unwrap()
                .command_id
        );
        assert_eq!(
            reopened.fold::<RunState>("scope").unwrap().phase,
            RunPhase::Admitted
        );
        assert_eq!(
            reopened
                .command_for_key("scope", "key")
                .unwrap()
                .unwrap()
                .status,
            "received"
        );
        assert_eq!(
            reopened.conn.total_changes(),
            changes,
            "delivery reads cannot write or repair status"
        );
        assert!(reopened
            .committed_dispatch::<RunState>("different-scope", "key")
            .unwrap()
            .is_none());
        assert!(reopened
            .committed_dispatch::<RunState>("scope", "different-key")
            .unwrap()
            .is_none());
    }

    #[test]
    fn delivery_requires_a_receipt_even_when_status_and_outbox_claim_admission() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .admit_with_dispatch::<RunState>("scope", "key", RunCommand::RequestRun, &dispatch())
            .unwrap();
        store
            .conn
            .execute("DELETE FROM command_receipts", [])
            .unwrap();
        assert_eq!(
            store
                .command_for_key("scope", "key")
                .unwrap()
                .unwrap()
                .status,
            "applied"
        );
        let changes = store.conn.total_changes();
        assert!(store
            .committed_dispatch::<RunState>("scope", "key")
            .unwrap()
            .is_none());
        assert_eq!(store.conn.total_changes(), changes);
    }

    #[test]
    fn delivery_refuses_missing_duplicate_or_changed_intents() {
        for corruption in [
            "missing",
            "duplicate",
            "destination",
            "command-ref",
            "command-id",
        ] {
            let mut store = Store::open_in_memory().unwrap();
            store
                .admit_with_dispatch::<RunState>(
                    "scope",
                    "key",
                    RunCommand::RequestRun,
                    &dispatch(),
                )
                .unwrap();
            let payload = store.records("scope", DISPATCH_KIND).unwrap().remove(0);
            let mut intent: DispatchIntent = serde_json::from_str(&payload).unwrap();
            match corruption {
                "missing" => {
                    store
                        .conn
                        .execute("DELETE FROM events WHERE kind = ?1", [DISPATCH_KIND])
                        .unwrap();
                }
                "duplicate" => {
                    store.conn.execute("INSERT INTO events (scope_id, position, kind, payload) VALUES ('scope', 2, ?1, ?2)", params![DISPATCH_KIND, payload]).unwrap();
                }
                other => {
                    match other {
                        "destination" => intent.dispatch.runtime_ref.push_str(":other"),
                        "command-ref" => intent.dispatch.command_ref.push_str(":other"),
                        "command-id" => intent.command_id.push_str(":other"),
                        _ => unreachable!(),
                    }
                    store
                        .conn
                        .execute(
                            "UPDATE events SET payload = ?1 WHERE kind = ?2",
                            params![serde_json::to_string(&intent).unwrap(), DISPATCH_KIND],
                        )
                        .unwrap();
                }
            }
            let changes = store.conn.total_changes();
            assert!(
                store
                    .committed_dispatch::<RunState>("scope", "key")
                    .is_err(),
                "{corruption}"
            );
            assert_eq!(store.conn.total_changes(), changes);
        }
    }

    #[test]
    fn delivery_refuses_missing_or_reclassified_original_commands() {
        for corruption in [
            "missing",
            "command-id",
            "kind",
            "empty-destination",
            "empty-command-ref",
        ] {
            let mut store = Store::open_in_memory().unwrap();
            store
                .admit_with_dispatch::<RunState>(
                    "scope",
                    "key",
                    RunCommand::RequestRun,
                    &dispatch(),
                )
                .unwrap();
            let record = store.command_for_key("scope", "key").unwrap().unwrap();
            match corruption {
                "missing" => {
                    store.conn.execute("DELETE FROM commands", []).unwrap();
                }
                "command-id" => {
                    store
                        .conn
                        .execute("UPDATE commands SET command_id = 'other'", [])
                        .unwrap();
                }
                other => {
                    let mut snapshot: serde_json::Value =
                        serde_json::from_str(&record.snapshot_json).unwrap();
                    match other {
                        "kind" => snapshot["kind"] = "other-lifecycle".into(),
                        "empty-destination" => snapshot["dispatch"]["runtime_ref"] = " ".into(),
                        "empty-command-ref" => snapshot["dispatch"]["command_ref"] = "".into(),
                        _ => unreachable!(),
                    }
                    store
                        .conn
                        .execute(
                            "UPDATE commands SET snapshot_json = ?1",
                            [snapshot.to_string()],
                        )
                        .unwrap();
                }
            }
            assert!(
                store
                    .committed_dispatch::<RunState>("scope", "key")
                    .is_err(),
                "{corruption}"
            );
        }
        let mut store = Store::open_in_memory().unwrap();
        assert!(store.committed_dispatch::<RunState>(" ", "key").is_err());
        assert!(store.committed_dispatch::<RunState>("scope", "").is_err());
    }

    #[test]
    fn restart_keeps_one_command_and_outbox_under_the_original_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("commands.sqlite");
        {
            let mut store = Store::open(path.to_str().unwrap()).unwrap();
            let first = store
                .admit_with_dispatch::<RunState>(
                    "scope",
                    "key",
                    RunCommand::RequestRun,
                    &dispatch(),
                )
                .unwrap();
            assert!(!first.replayed);
            assert_eq!(first.state.phase, RunPhase::Requested);
            let record = store.command_for_key("scope", "key").unwrap().unwrap();
            let intent: DispatchIntent =
                serde_json::from_str(&store.records("scope", DISPATCH_KIND).unwrap()[0]).unwrap();
            assert_eq!(intent.command_id, record.command_id);
            assert_eq!(intent.dispatch, dispatch());
            assert_eq!(record.status, "applied");
        }
        let mut store = Store::open(path.to_str().unwrap()).unwrap();
        assert_eq!(store.reconcile_commands().unwrap(), (0, 0));
        store
            .admit::<RunState>("scope", RunCommand::AdmitRun)
            .unwrap();
        let replay = store
            .admit_with_dispatch::<RunState>("scope", "key", RunCommand::RequestRun, &dispatch())
            .unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.state.phase, RunPhase::Admitted);
        assert_eq!(store.records("scope", DISPATCH_KIND).unwrap().len(), 1);
        assert_eq!(store.records("scope", RunState::KIND).unwrap().len(), 2);
    }

    #[test]
    fn changed_command_or_either_dispatch_reference_refuses_without_appending() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .admit_with_dispatch::<RunState>("scope", "key", RunCommand::RequestRun, &dispatch())
            .unwrap();
        let original = store
            .command_for_key("scope", "key")
            .unwrap()
            .unwrap()
            .snapshot_json;
        let mut another_runtime = dispatch();
        another_runtime.runtime_ref = "home-runtime:bob".into();
        let mut another_command = dispatch();
        another_command.command_ref = "admitted-command:immutable-2".into();
        for (command, candidate) in [
            (RunCommand::AdmitRun, dispatch()),
            (RunCommand::RequestRun, another_runtime),
            (RunCommand::RequestRun, another_command),
        ] {
            assert!(matches!(
                store.admit_with_dispatch::<RunState>("scope", "key", command, &candidate),
                Err(AdmitError::Rejected(_))
            ));
        }
        assert_eq!(
            store
                .command_for_key("scope", "key")
                .unwrap()
                .unwrap()
                .snapshot_json,
            original
        );
        assert_eq!(store.records("scope", DISPATCH_KIND).unwrap().len(), 1);
        assert_eq!(store.records("scope", RunState::KIND).unwrap().len(), 1);
    }

    #[test]
    fn independent_connections_racing_one_key_commit_one_outbox_intent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("race.sqlite");
        let first = Store::open(path.to_str().unwrap()).unwrap();
        let second = Store::open(path.to_str().unwrap()).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = [first, second]
            .into_iter()
            .map(|mut store| {
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    store
                        .admit_with_dispatch::<RunState>(
                            "scope",
                            "key",
                            RunCommand::RequestRun,
                            &dispatch(),
                        )
                        .unwrap()
                        .replayed
                })
            })
            .collect();
        let mut replayed: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        replayed.sort();
        assert_eq!(replayed, [false, true]);
        let store = Store::open(path.to_str().unwrap()).unwrap();
        assert_eq!(store.records("scope", DISPATCH_KIND).unwrap().len(), 1);
        assert_eq!(store.records("scope", RunState::KIND).unwrap().len(), 1);
    }

    #[test]
    fn every_write_boundary_rolls_back_command_events_outbox_and_receipt() {
        for clause in [
            "BEFORE INSERT ON commands",
            "BEFORE INSERT ON events WHEN NEW.kind = 'run'",
            "BEFORE INSERT ON events WHEN NEW.kind = 'runtime_command_dispatch_v1'",
            "BEFORE INSERT ON command_receipts",
            "BEFORE UPDATE ON commands",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("failure.sqlite");
            {
                let mut store = Store::open(path.to_str().unwrap()).unwrap();
                store.conn.execute_batch(&format!("CREATE TRIGGER fail_dispatch {clause} BEGIN SELECT RAISE(ABORT, 'injected admission failure'); END;")).unwrap();
                assert!(
                    matches!(
                        store.admit_with_dispatch::<RunState>(
                            "scope",
                            "key",
                            RunCommand::RequestRun,
                            &dispatch()
                        ),
                        Err(AdmitError::Db(_))
                    ),
                    "{clause}"
                );
            }
            let mut store = Store::open(path.to_str().unwrap()).unwrap();
            for table in ["events", "commands", "command_receipts"] {
                let count: i64 = store
                    .conn
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                        row.get(0)
                    })
                    .unwrap();
                assert_eq!(count, 0, "{clause}: partial {table}");
            }
            assert_eq!(store.reconcile_commands().unwrap(), (0, 0));
            store
                .conn
                .execute_batch("DROP TRIGGER fail_dispatch")
                .unwrap();
            assert!(
                !store
                    .admit_with_dispatch::<RunState>(
                        "scope",
                        "key",
                        RunCommand::RequestRun,
                        &dispatch()
                    )
                    .unwrap()
                    .replayed
            );
        }
    }

    #[test]
    fn a_rejected_pure_command_creates_no_delivery_intent_or_claim() {
        let mut store = Store::open_in_memory().unwrap();
        assert!(matches!(
            store.admit_with_dispatch::<RunState>(
                "scope",
                "key",
                RunCommand::AdmitRun,
                &dispatch()
            ),
            Err(AdmitError::Rejected(_))
        ));
        assert!(store.records("scope", DISPATCH_KIND).unwrap().is_empty());
        assert!(store.command_for_key("scope", "key").unwrap().is_none());
        assert!(
            !store
                .admit_with_dispatch::<RunState>(
                    "scope",
                    "key",
                    RunCommand::RequestRun,
                    &dispatch()
                )
                .unwrap()
                .replayed
        );
    }

    #[test]
    fn legacy_receipt_cannot_be_upgraded_into_an_outbox_acknowledgment() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .admit_with_key::<RunState>("scope", "key", RunCommand::RequestRun)
            .unwrap();
        assert!(matches!(
            store.admit_with_dispatch::<RunState>(
                "scope",
                "key",
                RunCommand::RequestRun,
                &dispatch()
            ),
            Err(AdmitError::Rejected(_))
        ));
        assert!(store.command_for_key("scope", "key").unwrap().is_none());
        assert!(store.records("scope", DISPATCH_KIND).unwrap().is_empty());
    }

    #[test]
    fn duplicate_intent_refuses_replay_instead_of_hiding_inconsistent_history() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .admit_with_dispatch::<RunState>("scope", "key", RunCommand::RequestRun, &dispatch())
            .unwrap();
        let intent = store
            .records("scope", DISPATCH_KIND)
            .unwrap()
            .pop()
            .unwrap();
        store
            .append_record("scope", DISPATCH_KIND, &intent)
            .unwrap();
        assert!(matches!(
            store.admit_with_dispatch::<RunState>(
                "scope",
                "key",
                RunCommand::RequestRun,
                &dispatch()
            ),
            Err(AdmitError::Rejected(_))
        ));
        assert_eq!(store.records("scope", DISPATCH_KIND).unwrap().len(), 2);
    }
}
