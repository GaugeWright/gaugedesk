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
    process_guards: Vec<std::sync::Arc<dyn Fn() -> bool + Send + Sync>>,
}

impl DispatchReadBasis {
    /// Add a process-local authentication condition checked under the final
    /// writer fence. Guards must inspect only clocks/atomic standing: no I/O,
    /// store reads, locks or side effects. They grant no product permission.
    pub fn with_process_guard(mut self, guard: impl Fn() -> bool + Send + Sync + 'static) -> Self {
        self.process_guards.push(std::sync::Arc::new(guard));
        self
    }

    /// Add a validity ceiling from the captured authority. An existing ceiling
    /// can only be shortened; this observation still grants no authority.
    pub fn with_deadline(mut self, deadline: std::time::SystemTime) -> Self {
        self.deadline = Some(
            self.deadline
                .map_or(deadline, |existing| existing.min(deadline)),
        );
        self
    }

    /// Combine independently captured resource observations for one admission.
    /// Overlapping scopes must agree; all heads and the earliest deadline are
    /// checked again under the final writer transaction. This grants no access.
    pub fn combine(mut self, other: Self) -> Result<Self, AdmitError> {
        if self.store_path != other.store_path
            || other.heads.iter().any(|(scope, head)| {
                self.heads
                    .get(scope)
                    .is_some_and(|existing| existing != head)
            })
        {
            return Err(AdmitError::Rejected(Rejection {
                reason: "resource observations have incompatible dispatch bases",
            }));
        }
        self.heads.extend(other.heads);
        self.process_guards.extend(other.process_guards);
        if let Some(deadline) = other.deadline {
            self = self.with_deadline(deadline);
        }
        Ok(self)
    }

    pub fn deadline(&self) -> Option<std::time::SystemTime> {
        self.deadline
    }
}

/// A borrowed check of the original authority while its product writer fence
/// is held. Native adapters invoke it at each effect/commit boundary; neither
/// a successful check nor a runtime receipt grants authority for later work.
/// A refusal is terminal for this invocation, even if a caller later repairs a
/// process flag. This check cannot be cloned or returned from the callback.
pub struct NativeDispatchCheck<'a> {
    _authority_transaction: &'a rusqlite::Transaction<'a>,
    deadline: Option<std::time::SystemTime>,
    process_guards: &'a [std::sync::Arc<dyn Fn() -> bool + Send + Sync>],
    ended: &'a std::cell::Cell<bool>,
}

impl NativeDispatchCheck<'_> {
    /// Inspect only the original clocks and atomic standing. Product authority
    /// writers are excluded by the held transaction; this performs no I/O,
    /// takes no locks and does not refresh or reconstruct authority.
    pub fn check_current(&self) -> Result<(), AdmitError> {
        check_latched_validity(self.deadline, self.process_guards, self.ended)
    }
}

/// Pending typed commands folded and decided under the actual product writer.
/// This is data, with no authority and no precomputed lifecycle events.
pub struct LifecycleBatch<L: Lifecycle> {
    pub scope: String,
    pub commands: Vec<L::Command>,
}

/// An original phase's positions, in typed-event then caller-fact order.
/// Unlike an ordinary completion replay, a prefix replay returns its original
/// positions so callers keep the same transcript/run anchors. This is retained
/// evidence, never a fresh execution or publication grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializedCommandPrefix {
    pub positions: Vec<i64>,
    pub replayed: bool,
}

/// One product commit while its current-authority writer transaction is held.
/// The evidence publisher consumes this inside its retention callback. Dropping
/// it rolls back; a successful commit remains durable if the callback then fails.
pub struct DispatchRecordAdmission<'tx> {
    tx: rusqlite::Transaction<'tx>,
    codec: Option<std::sync::Arc<dyn crate::ContentCodec>>,
    store_path: String,
    deadline: Option<std::time::SystemTime>,
    process_guards: Vec<std::sync::Arc<dyn Fn() -> bool + Send + Sync>>,
    native_ended: std::cell::Cell<bool>,
}

impl DispatchRecordAdmission<'_> {
    /// Run bounded native work under this same product publication fence.
    /// The check borrows the handle and cannot escape; after native work returns,
    /// the handle can be consumed inside the native evidence retention callback.
    /// A refused check remains terminal for every later use of this handle.
    /// No product writes, network work or lock-reacquiring check belong here.
    ///
    /// ```compile_fail
    /// use gaugedesk_store::Store;
    /// let mut store = Store::open_in_memory().unwrap();
    /// let (_, basis) = store.read_for_dispatch(&["authority"], |_| Ok(())).unwrap();
    /// store.with_dispatch_record_admission(&basis, |writer| {
    ///     writer.with_native_check(|check| check)
    /// });
    /// ```
    pub fn with_native_check<T>(
        &self,
        native: impl for<'check> FnOnce(&NativeDispatchCheck<'check>) -> T,
    ) -> Result<T, AdmitError> {
        let check = NativeDispatchCheck {
            _authority_transaction: &self.tx,
            deadline: self.deadline,
            process_guards: &self.process_guards,
            ended: &self.native_ended,
        };
        check.check_current()?;
        let result = native(&check);
        check.check_current()?;
        Ok(result)
    }

    /// Require the exact original pending intent under the held writer before
    /// any native effect. A refusal ends this handle even if a caller attempts
    /// to repair intent inside it. This check grants no later execution right.
    pub fn require_pending_claim(
        &self,
        command_id: &str,
        scope: &str,
        key: &str,
        snapshot: &str,
    ) -> Result<(), AdmitError> {
        let result =
            check_latched_validity(self.deadline, &self.process_guards, &self.native_ended)
                .and_then(|()| {
                    crate::record_admission::pending_command_matches(
                        &self.tx, command_id, scope, key, snapshot,
                    )
                })
                .and_then(|pending| {
                    if pending {
                        Ok(())
                    } else {
                        Err(AdmitError::Rejected(Rejection {
                            reason: "native work has no exact pending original command",
                        }))
                    }
                });
        if result.is_err() {
            self.native_ended.set(true);
        }
        result
    }

    /// Stage caller-selected original commands, events and receipts in this
    /// admission's transaction. Nothing is committed until the returned handle
    /// is committed; dropping it rolls the import back with the admission.
    ///
    /// This consumes the handle so an import error rolls back the transaction
    /// rather than leaving a partially imported archive a caller could commit.
    /// Exact existing state is a replay; conflicting state is never overwritten.
    /// Scope selection and current authority remain the caller's responsibility.
    pub fn import_command_scopes(
        self,
        archive: &crate::command_scope_archive::CommandScopeArchive,
        allowed: impl Fn(&str) -> bool,
    ) -> Result<Self, AdmitError> {
        crate::command_scope_archive::import_into(&self.tx, self.codec.as_ref(), archive, allowed)?;
        Ok(self)
    }

    /// Commit a lifecycle command and its runtime outbox while external input
    /// and base retention are held inside this product-first writer boundary.
    /// The handle is consumed; a failed publisher before this call rolls back.
    pub fn commit_dispatch<L: Lifecycle>(
        self,
        scope_id: &str,
        idempotency_key: &str,
        command: L::Command,
        dispatch: &CommandDispatch,
    ) -> Result<MaterializedAdmission<L::State>, AdmitError>
    where
        L::Command: serde::Serialize,
    {
        let prepared = PreparedDispatch::<L>::new(scope_id, idempotency_key, command, dispatch)?;
        check_latched_validity(self.deadline, &self.process_guards, &self.native_ended)?;
        commit_dispatch::<L>(self.tx, self.codec.as_ref(), prepared, || {
            check_latched_validity(self.deadline, &self.process_guards, &self.native_ended)
        })
    }

    /// Consume the held source fence to publish normal lifecycle admission and
    /// its outbox while external input/evidence retention still holds. Check the
    /// separately captured destination standing inside this same transaction.
    /// This reuses ordinary dispatch admission, including exact replay/rollback.
    pub fn admit_with_dispatch_against<L: Lifecycle>(
        self,
        scope_id: &str,
        idempotency_key: &str,
        command: L::Command,
        dispatch: &CommandDispatch,
        basis: &DispatchReadBasis,
    ) -> Result<MaterializedAdmission<L::State>, AdmitError>
    where
        L::Command: serde::Serialize,
    {
        let prepared = PreparedDispatch::<L>::new(scope_id, idempotency_key, command, dispatch)?;
        check_dispatch_basis(&self.tx, &self.store_path, basis)?;
        check_latched_validity(self.deadline, &self.process_guards, &self.native_ended)?;
        commit_dispatch::<L>(self.tx, self.codec.as_ref(), prepared, || {
            check_latched_validity(self.deadline, &self.process_guards, &self.native_ended)?;
            check_validity(basis.deadline, &basis.process_guards)
        })
    }

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
        check_latched_validity(self.deadline, &self.process_guards, &self.native_ended)?;
        crate::record_admission::commit(
            self.tx,
            self.codec,
            command_scope,
            idempotency_key,
            snapshot_json,
            stored,
            None,
            None,
            || check_latched_validity(self.deadline, &self.process_guards, &self.native_ended),
        )
    }

    /// Record one exact startup phase without finishing its pending parent.
    /// This phase has its own durable receipt and never grants later authority.
    /// Replay returns the original event positions after verifying their retained
    /// bytes; it does not decide commands against a later lifecycle state.
    /// A facts-only phase can bind a declaration to an earlier phase's assigned
    /// position without fabricating a lifecycle event. An empty phase refuses.
    #[allow(clippy::too_many_arguments)] // Original parent, named phase and typed facts.
    pub fn commit_claimed_lifecycle_prefix<L: Lifecycle>(
        self,
        command_id: &str,
        command_scope: &str,
        idempotency_key: &str,
        snapshot_json: &str,
        phase: &str,
        batch: LifecycleBatch<L>,
        facts: &[crate::CommandRecordFact],
    ) -> Result<MaterializedCommandPrefix, AdmitError>
    where
        L::Command: serde::Serialize,
    {
        check_latched_validity(self.deadline, &self.process_guards, &self.native_ended)?;
        crate::record_admission_prefix::commit(
            self.tx,
            self.codec,
            command_id,
            command_scope,
            idempotency_key,
            snapshot_json,
            phase,
            batch,
            facts,
            || check_latched_validity(self.deadline, &self.process_guards, &self.native_ended),
        )
    }

    /// Verify an existing exact original phase without consuming this writer.
    /// This stages/repairs nothing and returns only original positions. The
    /// same original authority and retained key must govern subsequent use;
    /// every refusal terminally ends this handle for native work and commit.
    #[allow(clippy::too_many_arguments)] // Same original pending parent and full phase meaning.
    pub fn require_claimed_lifecycle_prefix<L: Lifecycle>(
        &self,
        command_id: &str,
        command_scope: &str,
        idempotency_key: &str,
        snapshot_json: &str,
        phase: &str,
        batch: &LifecycleBatch<L>,
        facts: &[crate::CommandRecordFact],
    ) -> Result<Vec<i64>, AdmitError>
    where
        L::Command: serde::Serialize,
    {
        let result = (|| {
            check_latched_validity(self.deadline, &self.process_guards, &self.native_ended)?;
            let positions = crate::record_admission_prefix::verify(
                &self.tx,
                self.codec.as_ref(),
                command_id,
                command_scope,
                idempotency_key,
                snapshot_json,
                phase,
                batch,
                facts,
            )?;
            check_latched_validity(self.deadline, &self.process_guards, &self.native_ended)?;
            Ok(positions)
        })();
        if result.is_err() {
            self.native_ended.set(true);
        }
        result
    }

    /// Verify an original pre-result phase under this current reader's writer.
    /// Rechecks the exact recorded pair and phase bytes without pending task
    /// authority, reducers or repair. Positions grant no recipient access.
    /// Every refusal ends this handle for subsequent native work or commit.
    #[allow(clippy::too_many_arguments)]
    pub fn require_recorded_lifecycle_prefix<P: Lifecycle, L: Lifecycle, M: Lifecycle>(
        &self,
        command_id: &str,
        command_scope: &str,
        key: &str,
        snapshot: &str,
        phase: &str,
        batch: &LifecycleBatch<P>,
        facts: &[crate::CommandRecordFact],
    ) -> Result<Vec<i64>, AdmitError>
    where
        P::Command: serde::Serialize,
    {
        let result = (|| {
            check_latched_validity(self.deadline, &self.process_guards, &self.native_ended)?;
            let positions = crate::record_admission_prefix::verify_recorded::<P, L, M>(
                &self.tx,
                self.codec.as_ref(),
                command_id,
                command_scope,
                key,
                snapshot,
                phase,
                batch,
                facts,
            )?;
            check_latched_validity(self.deadline, &self.process_guards, &self.native_ended)?;
            Ok(positions)
        })();
        if result.is_err() {
            self.native_ended.set(true);
        }
        result
    }

    /// Finish the exact original claim with typed lifecycle decisions, retained
    /// result-reference facts and one durable receipt under this writer fence.
    /// Any rejected decision or final authority refusal rolls the entire batch
    /// back. A committed retry never applies the lifecycle commands again.
    pub fn commit_claimed_lifecycle<L: Lifecycle>(
        self,
        command_id: &str,
        command_scope: &str,
        idempotency_key: &str,
        snapshot_json: &str,
        batch: LifecycleBatch<L>,
        facts: &[crate::CommandRecordFact],
    ) -> Result<crate::MaterializedRecordAdmission, AdmitError> {
        let stored = crate::record_admission::encode_facts(self.codec.as_ref(), facts)?;
        check_latched_validity(self.deadline, &self.process_guards, &self.native_ended)?;
        crate::record_admission::commit_lifecycle(
            self.tx,
            self.codec,
            command_id,
            command_scope,
            idempotency_key,
            snapshot_json,
            batch,
            stored,
            || check_latched_validity(self.deadline, &self.process_guards, &self.native_ended),
        )
    }

    /// Finish two distinct lifecycles in one scope with the original receipt.
    /// The pure fact builder receives the first available position AFTER both
    /// typed batches are decided and staged under this writer. It must perform
    /// no I/O, acquire no locks and return only facts in that same scope. This
    /// lets transcript/boundary references use actual assigned positions.
    /// A rejected decision, builder/codec error or final authority refusal rolls
    /// everything back. Committed replay never calls the builder or reducers.
    #[allow(clippy::too_many_arguments)] // Exact original claim plus two typed intents.
    pub fn commit_claimed_lifecycle_pair<L: Lifecycle, M: Lifecycle>(
        self,
        command_id: &str,
        command_scope: &str,
        idempotency_key: &str,
        snapshot_json: &str,
        first: LifecycleBatch<L>,
        second: LifecycleBatch<M>,
        facts: impl FnOnce(i64) -> Result<Vec<crate::CommandRecordFact>, AdmitError>,
    ) -> Result<crate::MaterializedRecordAdmission, AdmitError> {
        check_latched_validity(self.deadline, &self.process_guards, &self.native_ended)?;
        crate::record_admission::commit_lifecycle_pair(
            self.tx,
            self.codec,
            command_id,
            command_scope,
            idempotency_key,
            snapshot_json,
            first,
            second,
            facts,
            || check_latched_validity(self.deadline, &self.process_guards, &self.native_ended),
        )
    }

    /// Publish a new exact paired result with independently verifiable provenance.
    /// Both typed batches, facts, owner marker and parent receipt commit atomically.
    /// Replay verifies original intents and retained rows without invoking the builder.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_recorded_claimed_lifecycle_pair<L: Lifecycle, M: Lifecycle>(
        self,
        command_id: &str,
        command_scope: &str,
        key: &str,
        snapshot: &str,
        first: LifecycleBatch<L>,
        second: LifecycleBatch<M>,
        facts: impl FnOnce(i64) -> Result<Vec<crate::CommandRecordFact>, AdmitError>,
    ) -> Result<crate::MaterializedRecordAdmission, AdmitError>
    where
        L::Command: serde::Serialize,
        M::Command: serde::Serialize,
    {
        check_latched_validity(self.deadline, &self.process_guards, &self.native_ended)?;
        crate::record_admission_pair::commit(
            self.tx,
            self.codec,
            command_id,
            command_scope,
            key,
            snapshot,
            first,
            second,
            facts,
            || check_latched_validity(self.deadline, &self.process_guards, &self.native_ended),
        )
    }

    /// Verify original committed pair rows under this current reader's writer.
    /// No reducer, repair, write or pending-task authority is supplied. Any
    /// refusal terminally ends this writer for subsequent work or publication.
    pub fn require_recorded_claimed_lifecycle_pair<L: Lifecycle, M: Lifecycle>(
        &self,
        command_id: &str,
        command_scope: &str,
        key: &str,
        snapshot: &str,
        result_scope: &str,
    ) -> Result<crate::RecordedLifecyclePair<L, M>, AdmitError> {
        let result = (|| {
            check_latched_validity(self.deadline, &self.process_guards, &self.native_ended)?;
            let original = crate::record_admission_pair::verify::<L, M>(
                &self.tx,
                self.codec.as_ref(),
                command_id,
                command_scope,
                key,
                snapshot,
                result_scope,
            )?;
            check_latched_validity(self.deadline, &self.process_guards, &self.native_ended)?;
            Ok(original)
        })();
        if result.is_err() {
            self.native_ended.set(true);
        }
        result
    }

    /// Finish an already claimed exact command together with its facts and
    /// durable receipt. The claim is not an execution grant: the original
    /// captured basis is checked at this transaction's final commit.
    pub fn commit_claimed(
        self,
        command_id: &str,
        command_scope: &str,
        idempotency_key: &str,
        snapshot_json: &str,
        facts: &[crate::CommandRecordFact],
    ) -> Result<crate::MaterializedRecordAdmission, AdmitError> {
        let stored = crate::record_admission::encode_facts(self.codec.as_ref(), facts)?;
        check_latched_validity(self.deadline, &self.process_guards, &self.native_ended)?;
        crate::record_admission::commit(
            self.tx,
            self.codec,
            command_scope,
            idempotency_key,
            snapshot_json,
            stored,
            None,
            Some(command_id),
            || check_latched_validity(self.deadline, &self.process_guards, &self.native_ended),
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

fn check_latched_validity(
    deadline: Option<std::time::SystemTime>,
    guards: &[std::sync::Arc<dyn Fn() -> bool + Send + Sync>],
    ended: &std::cell::Cell<bool>,
) -> Result<(), AdmitError> {
    if ended.get() {
        return Err(AdmitError::Rejected(Rejection {
            reason: "native dispatch authority ended",
        }));
    }
    let result = check_validity(deadline, guards);
    if result.is_err() {
        ended.set(true);
    }
    result
}

fn check_validity(
    deadline: Option<std::time::SystemTime>,
    guards: &[std::sync::Arc<dyn Fn() -> bool + Send + Sync>],
) -> Result<(), AdmitError> {
    if deadline.is_some_and(|end| std::time::SystemTime::now() >= end) {
        return Err(AdmitError::Rejected(Rejection {
            reason: "dispatch authorization expired while waiting",
        }));
    }
    if guards.iter().any(|guard| !guard()) {
        return Err(AdmitError::Rejected(Rejection {
            reason: "dispatch authentication is no longer active",
        }));
    }
    Ok(())
}

pub(super) fn check_dispatch_basis(
    tx: &rusqlite::Transaction<'_>,
    store_path: &str,
    basis: &DispatchReadBasis,
) -> Result<(), AdmitError> {
    check_validity(basis.deadline, &basis.process_guards)?;
    if basis.store_path != store_path {
        return Err(AdmitError::Rejected(Rejection {
            reason: "dispatch authorization came from another store",
        }));
    }
    for (scope, expected) in &basis.heads {
        let current: Option<i64> = tx
            .prepare_cached("SELECT MAX(position) FROM events WHERE scope_id = ?1")?
            .query_row(params![scope], |row| row.get(0))?;
        if &current != expected {
            return Err(AdmitError::Rejected(Rejection {
                reason: "dispatch authorization changed during preparation",
            }));
        }
    }
    Ok(())
}

impl Store {
    /// Serialize internal record preparation before taking external retention
    /// locks. This grants no product authority; a caller whose admission relies
    /// on current product standing must use `with_dispatch_record_admission`.
    pub fn with_record_admission<T>(
        &mut self,
        publish: impl for<'tx> FnOnce(DispatchRecordAdmission<'tx>) -> T,
    ) -> Result<T, AdmitError> {
        let codec = self.codec.clone();
        let store_path = self.path.clone();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        Ok(publish(DispatchRecordAdmission {
            tx,
            codec,
            store_path,
            deadline: None,
            process_guards: Vec::new(),
            native_ended: std::cell::Cell::new(false),
        }))
    }

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
        let store_path = self.path.clone();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_dispatch_basis(&tx, &self.path, basis)?;
        Ok(publish(DispatchRecordAdmission {
            tx,
            codec,
            store_path,
            deadline: basis.deadline,
            process_guards: basis.process_guards.clone(),
            native_ended: std::cell::Cell::new(false),
        }))
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

    /// Run bounded native work with the original authority check available at
    /// its actual effect/commit boundaries. No product writes or network work
    /// belong in this callback. Native effects that committed before refusal
    /// remain facts; this boundary cannot promise rollback in another authority.
    ///
    /// The check cannot escape to become a later execution grant:
    /// ```compile_fail
    /// use gaugedesk_store::Store;
    /// let mut store = Store::open_in_memory().unwrap();
    /// let (_, basis) = store.read_for_dispatch(&["authority"], |_| Ok(())).unwrap();
    /// let escaped = store.with_checked_dispatch_basis(&basis, |check| check);
    /// ```
    pub fn with_checked_dispatch_basis<T>(
        &mut self,
        basis: &DispatchReadBasis,
        admit_runtime: impl for<'check> FnOnce(&NativeDispatchCheck<'check>) -> T,
    ) -> Result<T, AdmitError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_dispatch_basis(&tx, &self.path, basis)?;
        let ended = std::cell::Cell::new(false);
        let result = {
            let check = NativeDispatchCheck {
                _authority_transaction: &tx,
                deadline: basis.deadline,
                process_guards: &basis.process_guards,
                ended: &ended,
            };
            let result = admit_runtime(&check);
            check.check_current()?;
            result
        };
        tx.commit()?;
        Ok(result)
    }

    /// The scope to include when observing a subordinate original phase.
    /// This locator conveys no command or publication authority.
    pub fn claimed_lifecycle_prefix_scope(command_id: &str, phase: &str) -> String {
        crate::record_admission_prefix::prefix_scope(command_id, phase)
    }

    /// Observe consistent phase-marker/receipt presence. Exact replay and retained
    /// content still require commit_claimed_lifecycle_prefix under its writer.
    pub fn claimed_lifecycle_prefix_recorded(
        &self,
        command_id: &str,
        phase: &str,
    ) -> Result<bool, AdmitError> {
        crate::record_admission_prefix::recorded(self, command_id, phase)
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
            let head: Option<i64> = tx
                .prepare_cached("SELECT MAX(position) FROM events WHERE scope_id = ?1")?
                .query_row(params![scope], |row| row.get(0))?;
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
                process_guards: Vec::new(),
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
            .prepare_cached(
                "SELECT 1 FROM command_receipts WHERE scope_id = ?1 AND command_key = ?2",
            )?
            .query_row(params![scope_id, idempotency_key], |_| Ok(()))
            .optional()?
            .is_some();
        if !receipted {
            return Ok(None);
        }
        let expected_id = format!("command:{}:{scope_id}{idempotency_key}", scope_id.len());
        let original: Option<(String, String)> = tx
            .prepare_cached("SELECT command_id, snapshot_json FROM commands WHERE scope_id = ?1 AND idempotency_key = ?2")?.query_row(
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
            for plain in
                crate::retained_kind_payloads(&tx, self.codec.as_ref(), scope_id, DISPATCH_KIND)?
            {
                let recorded: DispatchIntent = serde_json::from_str(&plain)?;
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
        let prepared = PreparedDispatch::<L>::new(scope_id, idempotency_key, command, dispatch)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(basis) = basis {
            check_dispatch_basis(&tx, &self.path, basis)?;
        }
        commit_dispatch::<L>(tx, self.codec.as_ref(), prepared, || match basis {
            Some(basis) => check_validity(basis.deadline, &basis.process_guards),
            None => Ok(()),
        })
    }
}

/// The same identity and pure lifecycle admission are used by ordinary and
/// externally retained publication. Preparing this value writes no state.
struct PreparedDispatch<'a, L: Lifecycle> {
    scope_id: &'a str,
    idempotency_key: &'a str,
    command: L::Command,
    snapshot: String,
    command_id: String,
    intent: DispatchIntent,
}

impl<'a, L: Lifecycle> PreparedDispatch<'a, L>
where
    L::Command: serde::Serialize,
{
    fn new(
        scope_id: &'a str,
        idempotency_key: &'a str,
        command: L::Command,
        dispatch: &CommandDispatch,
    ) -> Result<Self, AdmitError> {
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
        Ok(Self {
            scope_id,
            idempotency_key,
            command,
            snapshot,
            command_id,
            intent,
        })
    }
}

fn commit_dispatch<L: Lifecycle>(
    tx: rusqlite::Transaction<'_>,
    codec: Option<&std::sync::Arc<dyn crate::ContentCodec>>,
    prepared: PreparedDispatch<'_, L>,
    final_check: impl FnOnce() -> Result<(), AdmitError>,
) -> Result<MaterializedAdmission<L::State>, AdmitError>
where
    L::Command: serde::Serialize,
{
    let PreparedDispatch {
        scope_id,
        idempotency_key,
        command,
        snapshot,
        command_id,
        intent,
    } = prepared;
    let inserted = tx
        .prepare_cached(
            "INSERT OR IGNORE INTO commands
             (command_id, scope_id, idempotency_key, status, snapshot_json)
             VALUES (?1, ?2, ?3, 'received', ?4)",
        )?
        .execute(params![command_id, scope_id, idempotency_key, snapshot])?;
    let (original, status): (String, String) = tx.prepare_cached("SELECT snapshot_json, status FROM commands WHERE scope_id = ?1 AND idempotency_key = ?2")?.query_row(
        params![scope_id, idempotency_key],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if original != snapshot {
        return Err(AdmitError::Rejected(Rejection {
            reason: "idempotency key reused with different command or dispatch",
        }));
    }
    let replayed = tx
        .prepare_cached("SELECT 1 FROM command_receipts WHERE scope_id = ?1 AND command_key = ?2")?
        .query_row(params![scope_id, idempotency_key], |_| Ok(()))
        .optional()?
        .is_some();
    if replayed {
        // A legacy receipt without an original snapshot/outbox cannot be
        // upgraded into a successful dispatch admission on a retry.
        let mut matches = 0;
        for plain in crate::retained_kind_payloads(&tx, codec, scope_id, DISPATCH_KIND)? {
            let recorded: DispatchIntent = serde_json::from_str(&plain)?;
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
    let mut state = crate::fold_retained::<L>(&tx, codec, scope_id)?;
    if !replayed {
        let events = L::decide(&state, command).map_err(AdmitError::Rejected)?;
        let base: i64 = tx
            .prepare_cached(
                "SELECT COALESCE(MAX(position), -1) + 1 FROM events WHERE scope_id = ?1",
            )?
            .query_row(params![scope_id], |row| row.get(0))?;
        let dispatch_position = base + events.len() as i64;
        for (offset, event) in events.into_iter().enumerate() {
            tx.prepare_cached(
                "INSERT INTO events (scope_id, position, kind, payload) VALUES (?1, ?2, ?3, ?4)",
            )?
            .execute(params![
                scope_id,
                base + offset as i64,
                L::KIND,
                crate::encode_payload(codec, scope_id, L::KIND, &serde_json::to_string(&event)?)?
            ])?;
            state = L::evolve(&state, event);
        }
        tx.prepare_cached(
            "INSERT INTO events (scope_id, position, kind, payload) VALUES (?1, ?2, ?3, ?4)",
        )?
        .execute(params![
            scope_id,
            dispatch_position,
            DISPATCH_KIND,
            crate::encode_payload(
                codec,
                scope_id,
                DISPATCH_KIND,
                &serde_json::to_string(&intent)?
            )?
        ])?;
        tx.prepare_cached(
            "INSERT INTO command_receipts (scope_id, command_key, applied_at) VALUES (?1, ?2, ?3)",
        )?
        .execute(params![scope_id, idempotency_key, base])?;
    }
    tx.prepare_cached(
        "UPDATE commands SET status = 'applied', updated_at = CURRENT_TIMESTAMP
             WHERE scope_id = ?1 AND idempotency_key = ?2",
    )?
    .execute(params![scope_id, idempotency_key])?;
    final_check()?;
    tx.commit()?;
    Ok(MaterializedAdmission { state, replayed })
}

#[cfg(test)]
#[path = "command_dispatch_record_tests.rs"]
mod record_tests;

#[cfg(test)]
#[path = "command_dispatch_retained_tests.rs"]
mod retained_tests;

#[cfg(test)]
#[path = "command_dispatch_process_guard_tests.rs"]
mod process_guard_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use gaugedesk_core::run::{RunCommand, RunPhase, RunState};
    use std::sync::{Arc, Barrier};

    #[test]
    fn combining_resource_bases_preserves_all_heads_and_the_shortest_deadline() {
        let mut store = Store::open_in_memory().unwrap();
        let (_, left) = store
            .read_for_dispatch(&["left", "shared"], |_| Ok(()))
            .unwrap();
        let (_, right) = store
            .read_for_dispatch(&["right", "shared"], |_| Ok(()))
            .unwrap();
        let sooner = std::time::SystemTime::now() + std::time::Duration::from_secs(60);
        let basis = left
            .with_deadline(sooner)
            .combine(right.with_deadline(sooner + std::time::Duration::from_secs(60)))
            .unwrap();
        assert_eq!(basis.deadline(), Some(sooner));
        store.with_dispatch_basis(&basis, || ()).unwrap();
        store.append_record("right", "grant", "changed").unwrap();
        assert!(store
            .with_dispatch_basis(&basis, || panic!("stale combined basis"))
            .is_err());
        let (_, before) = store.read_for_dispatch(&["shared"], |_| Ok(())).unwrap();
        store.append_record("shared", "grant", "changed").unwrap();
        let (_, after) = store.read_for_dispatch(&["shared"], |_| Ok(())).unwrap();
        assert!(before.combine(after).is_err());
        let other = Store::open_in_memory().unwrap();
        let (_, here) = store.read_for_dispatch(&["shared"], |_| Ok(())).unwrap();
        let (_, there) = other.read_for_dispatch(&["shared"], |_| Ok(())).unwrap();
        assert!(here.combine(there).is_err());
    }

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
    fn record_admission_native_check_shares_fence_and_finishes_original_claim() {
        let mut product = Store::open_in_memory().unwrap();
        product
            .claim_command("upload", "chat", "key", "exact bytes")
            .unwrap();
        let competing = rusqlite::Connection::open(product.path()).unwrap();
        competing.busy_timeout(std::time::Duration::ZERO).unwrap();
        let (_, basis) = product
            .read_for_dispatch(&["authority"], |_| Ok(()))
            .unwrap();
        let facts = [crate::CommandRecordFact {
            scope_id: "chat".into(),
            kind: "resource".into(),
            payload: "exact native binding".into(),
        }];
        let admitted = product
            .with_dispatch_record_admission(&basis, |writer| {
                writer
                    .with_native_check(|check| {
                        check.check_current().unwrap();
                        assert!(competing.execute_batch("BEGIN IMMEDIATE").is_err());
                        // Returning read evidence does not release the product fence.
                        "retained native evidence"
                    })
                    .unwrap();
                assert!(competing.execute_batch("BEGIN IMMEDIATE").is_err());
                writer.commit_claimed("upload", "chat", "key", "exact bytes", &facts)
            })
            .unwrap()
            .unwrap();
        assert!(!admitted.replayed);
        assert_eq!(
            product.records("chat", "resource").unwrap(),
            ["exact native binding"]
        );
        assert_eq!(
            product
                .command_for_key("chat", "key")
                .unwrap()
                .unwrap()
                .command_id,
            "upload"
        );
        assert_eq!(
            product
                .command_for_key("chat", "key")
                .unwrap()
                .unwrap()
                .status,
            "applied"
        );
        competing
            .execute_batch("BEGIN IMMEDIATE; ROLLBACK")
            .unwrap();
    }

    #[test]
    fn record_admission_native_refusal_cannot_be_repaired_before_any_product_commit() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        for claimed in [false, true] {
            let mut product = Store::open_in_memory().unwrap();
            let mut native = Store::open_in_memory().unwrap();
            if claimed {
                product
                    .claim_command("upload", "chat", "key", "exact bytes")
                    .unwrap();
            }
            let current = Arc::new(AtomicBool::new(true));
            let live = current.clone();
            let (_, basis) = product
                .read_for_dispatch(&["authority"], |_| Ok(()))
                .unwrap();
            let basis = basis.with_process_guard(move || live.load(Ordering::SeqCst));
            let facts = [crate::CommandRecordFact {
                scope_id: "chat".into(),
                kind: "resource".into(),
                payload: "must not publish".into(),
            }];
            let result = product
                .with_dispatch_record_admission(&basis, |writer| {
                    assert!(writer
                        .with_native_check(|check| {
                            check.check_current().unwrap();
                            native
                                .append_record("runtime", "outcome", "already committed")
                                .unwrap();
                            current.store(false, Ordering::SeqCst);
                            assert!(check.check_current().is_err());
                            current.store(true, Ordering::SeqCst);
                        })
                        .is_err());
                    assert!(writer
                        .with_native_check(|_| panic!("ended admission reentered"))
                        .is_err());
                    // Even a caller that discards the error cannot revive publication.
                    if claimed {
                        writer.commit_claimed("upload", "chat", "key", "exact bytes", &facts)
                    } else {
                        writer.commit("chat", "key", "exact bytes", &facts)
                    }
                })
                .unwrap();
            assert!(result.is_err());
            assert!(product.records("chat", "resource").unwrap().is_empty());
            assert_eq!(
                native.records("runtime", "outcome").unwrap(),
                ["already committed"]
            );
            if claimed {
                assert_eq!(
                    product
                        .command_for_key("chat", "key")
                        .unwrap()
                        .unwrap()
                        .status,
                    "processing"
                );
            } else {
                assert!(product.command_for_key("chat", "key").unwrap().is_none());
            }
        }
    }

    #[test]
    fn native_dispatch_check_holds_writer_and_original_ceiling_and_latches_refusal() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        let mut product = Store::open_in_memory().unwrap();
        let competing = rusqlite::Connection::open(product.path()).unwrap();
        competing.busy_timeout(std::time::Duration::ZERO).unwrap();
        let current = Arc::new(AtomicBool::new(true));
        let live = current.clone();
        let (_, basis) = product
            .read_for_dispatch(&["authority"], |_| Ok(()))
            .unwrap();
        let ceiling = std::time::SystemTime::now() + std::time::Duration::from_secs(30);
        let basis = basis
            .with_process_guard(move || live.load(Ordering::SeqCst))
            .with_deadline(ceiling);
        let mut refused_inside = false;
        assert!(product
            .with_checked_dispatch_basis(&basis, |check| {
                assert!(competing.execute_batch("BEGIN IMMEDIATE").is_err());
                check.check_current().unwrap();
                current.store(false, Ordering::SeqCst);
                assert!(check.check_current().is_err());
                refused_inside = true;
                current.store(true, Ordering::SeqCst);
                assert!(
                    check.check_current().is_err(),
                    "repair cannot revive this invocation"
                );
            })
            .is_err());
        assert!(refused_inside);
        assert_eq!(basis.deadline(), Some(ceiling));
        competing
            .execute_batch("BEGIN IMMEDIATE; ROLLBACK")
            .unwrap();
        let expired = basis.with_deadline(std::time::SystemTime::UNIX_EPOCH);
        assert!(product
            .with_checked_dispatch_basis(&expired, |_| panic!("expired native work entered"))
            .is_err());
        let (_, stale) = product
            .read_for_dispatch(&["authority"], |_| Ok(()))
            .unwrap();
        product
            .append_record("authority", "grant", "removed")
            .unwrap();
        assert!(product
            .with_checked_dispatch_basis(&stale, |_| panic!("stale native work entered"))
            .is_err());
    }

    #[test]
    fn native_dispatch_final_check_refuses_unobserved_process_loss_and_preserves_prior_native_facts(
    ) {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        let mut product = Store::open_in_memory().unwrap();
        let mut native = Store::open_in_memory().unwrap();
        let current = Arc::new(AtomicBool::new(true));
        let live = current.clone();
        let (_, basis) = product
            .read_for_dispatch(&["authority"], |_| Ok(()))
            .unwrap();
        let basis = basis.with_process_guard(move || live.load(Ordering::SeqCst));
        assert!(product
            .with_checked_dispatch_basis(&basis, |check| {
                check.check_current().unwrap();
                native
                    .append_record("runtime", "outcome", "already committed")
                    .unwrap();
                current.store(false, Ordering::SeqCst);
            })
            .is_err());
        assert_eq!(
            native.records("runtime", "outcome").unwrap(),
            ["already committed"]
        );
        assert!(product.records("authority", "grant").unwrap().is_empty());
        let mut foreign = Store::open_in_memory().unwrap();
        assert!(foreign
            .with_checked_dispatch_basis(&basis, |_| panic!("foreign authority entered"))
            .is_err());
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
