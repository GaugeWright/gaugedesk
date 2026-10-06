//! One original office result: native evidence, typed completion and task receipt.
use super::{
    office_turn_payload::{PreparedFile, ResultPayloadPlan},
    office_turn_startup::{self, OfficeTurnContext, OfficeTurnStartup},
    EngineError, MergeCommand, MergePhase, MergeState, RunCommand, RunPhase, RunState, ServerEvent,
    TaskResult, TurnBoundaryRecord, TurnForkSnapshot, TurnOutcome,
};
use crate::LockUnpoisoned;
use gaugedesk_store::{command_dispatch::LifecycleBatch, AdmitError, CommandRecordFact};
use gaugedesk_workspace::{
    NativeHistoricalSettledTurn, NativeReviewedTurn, NativeSettledTurn, NativeTurnFileWitness,
    NativeWitnessedTurn, WorkspaceError,
};
use whipplescript_kernel::host_protocol::{
    RuntimeEvidencePointer, TurnReceipt, TurnStatus, HOST_PROTOCOL,
};
use whipplescript_store::vcs::recorded_review::RecordedMergeOutcome;

pub(crate) const CREATION_KIND: &str = "office_turn_creation";

/// Complete sealed original creation coordinates. This is provenance only;
/// a reader must independently retain current recipient/release/key authority.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OfficeCreationRecord {
    pub(crate) revision: String,
    pub(crate) command: String,
    pub(crate) actor: String,
    pub(crate) chat: String,
    pub(crate) input_position: i64,
    pub(crate) base_cut: String,
    pub(crate) lineage: whipplescript_store::branches::BranchRow,
    pub(crate) runtime_start: gaugedesk_harness::RuntimePosition,
    pub(crate) runtime_terminal: gaugedesk_harness::RuntimePosition,
    pub(crate) runtime_cut: String,
    pub(crate) result_cut: String,
    pub(crate) ordered_writes: Vec<PreparedFile>,
    pub(crate) evidence: whipplescript_store::branches::write_evidence::WriteEvidenceRef,
}

enum OfficeNativeResult {
    Reviewed(Box<NativeReviewedTurn>),
    Settled(Box<NativeSettledTurn>),
    Historical(Box<NativeHistoricalSettledTurn>),
}

#[derive(Clone, Copy)]
enum OfficeSettlement<'a> {
    Applied(
        &'a whipplescript_store::branches::CutRow,
        &'a whipplescript_store::branches::OpRow,
    ),
    Historical(
        &'a whipplescript_store::branches::CutRow,
        &'a whipplescript_store::branches::OpRow,
    ),
}
impl OfficeSettlement<'_> {
    fn coordinates(
        &self,
    ) -> (
        &whipplescript_store::branches::CutRow,
        &whipplescript_store::branches::OpRow,
    ) {
        match self {
            Self::Applied(cut, op) | Self::Historical(cut, op) => (cut, op),
        }
    }
    fn kind(&self) -> &'static str {
        match self {
            Self::Applied(..) => "current-applied",
            Self::Historical(..) => "original-history",
        }
    }
}

impl OfficeNativeResult {
    fn prepare(
        native: NativeWitnessedTurn,
        check: &mut dyn FnMut() -> Result<(), WorkspaceError>,
    ) -> Result<Self, WorkspaceError> {
        match native.recover_historical_settlement_guarded(check)? {
            Ok(history) => Ok(Self::Historical(Box::new(history))),
            Err(native) => {
                let reviewed = native.prepare_recorded_review_guarded(check)?;
                if matches!(
                    reviewed.review().outcome,
                    RecordedMergeOutcome::Conflicted { .. }
                ) {
                    Ok(Self::Reviewed(Box::new(reviewed)))
                } else {
                    Ok(Self::Settled(Box::new(reviewed.settle_guarded(check)?)))
                }
            }
        }
    }

    fn diff(&self) -> Result<String, WorkspaceError> {
        match self {
            Self::Reviewed(reviewed) => Ok(reviewed.review_diff()),
            Self::Settled(settled) => settled.review_diff(),
            Self::Historical(history) => history.review_diff(),
        }
    }

    fn publish<T>(
        &self,
        publish: impl FnOnce(
            &NativeWitnessedTurn,
            Option<OfficeSettlement<'_>>,
        ) -> whipplescript_store::StoreResult<T>,
    ) -> whipplescript_store::StoreResult<T> {
        match self {
            Self::Reviewed(reviewed) => {
                reviewed.publish_retained(|_, native| publish(native, None))
            }
            Self::Settled(settled) => settled.publish_retained(|native, cut, op| {
                publish(native, Some(OfficeSettlement::Applied(cut, op)))
            }),
            Self::Historical(history) => history.publish_retained(|native, cut, op| {
                publish(native, Some(OfficeSettlement::Historical(cut, op)))
            }),
        }
    }
}

fn refused(reason: &str) -> EngineError {
    EngineError::Message(reason.into())
}
fn native_error(error: AdmitError) -> whipplescript_store::StoreError {
    whipplescript_store::StoreError::Conflict(format!("office result refused: {error:?}"))
}
fn fact(scope: &str, kind: &str, payload: String) -> CommandRecordFact {
    CommandRecordFact {
        scope_id: scope.into(),
        kind: kind.into(),
        payload,
    }
}

fn settlement_fact(
    scope: &str,
    command_id: &str,
    result_cut: &str,
    settlement: OfficeSettlement<'_>,
) -> whipplescript_store::StoreResult<CommandRecordFact> {
    let (cut, operation) = settlement.coordinates();
    let payload = serde_json::to_string(&serde_json::json!({
        "revision": "office-native-settlement/v1", "command_id": command_id,
        "result_cut": result_cut, "settlement_cut": cut, "operation": operation,
        "evidence_kind": settlement.kind(),
    }))
    .map_err(|error| native_error(AdmitError::Json(error)))?;
    Ok(fact(scope, "office_native_settlement", payload))
}

/// Parse through the owner's published receipt schema. Neutral harness data is
/// original evidence carriage only; an absent witness is never an empty result.
fn original_receipt(
    office: &OfficeTurnContext<'_>,
    outcome: &TurnOutcome,
) -> Result<TurnReceipt, EngineError> {
    let witness = outcome
        .runtime_workspace_witness
        .as_ref()
        .ok_or_else(|| refused("office result has no original runtime workspace witness"))?;
    let receipt: TurnReceipt =
        serde_json::from_str(&witness.receipt_json).map_err(AdmitError::Json)?;
    let before = outcome
        .runtime_start_position
        .as_ref()
        .ok_or_else(|| refused("office result has no original runtime start"))?;
    let after = outcome
        .runtime_terminal_position
        .as_ref()
        .ok_or_else(|| refused("office result has no original runtime terminal"))?;
    if receipt.protocol != HOST_PROTOCOL
        || receipt.command_id != office.original.command_id()
        || receipt.instance_ref.is_empty()
        || receipt.run_ref.is_empty()
        || receipt.usage_ref.trim().is_empty()
        || receipt.guarantee_report_ref.trim().is_empty()
        || receipt.terminal_position.sequence == 0
        || receipt
            .workspace_cut_ref
            .as_deref()
            .is_none_or(str::is_empty)
        || before.instance_ref != receipt.instance_ref
        || after.instance_ref != receipt.instance_ref
        || receipt.terminal_position.instance_ref != receipt.instance_ref
        || after.sequence != receipt.terminal_position.sequence
        || before.sequence > after.sequence
        || (receipt.status == TurnStatus::Completed) != outcome.error.is_none()
    {
        return Err(refused(
            "office result differs from original runtime receipt",
        ));
    }
    let mut original_pointer = false;
    for pointer in &outcome.runtime_evidence_pointers {
        let pointer: RuntimeEvidencePointer =
            serde_json::from_str(pointer).map_err(AdmitError::Json)?;
        match pointer {
            RuntimeEvidencePointer::TurnReceipt(pointer) => {
                if pointer != receipt {
                    return Err(refused("office runtime receipt pointer differs"));
                }
                original_pointer = true;
            }
            RuntimeEvidencePointer::Event(event) => {
                if event.protocol != HOST_PROTOCOL
                    || event.command_id != receipt.command_id
                    || event.policy != receipt.policy
                    || event.position.instance_ref != receipt.instance_ref
                    || event.position.sequence < before.sequence
                    || event.position.sequence > after.sequence
                {
                    return Err(refused("office runtime event pointer differs"));
                }
            }
        }
    }
    if !original_pointer {
        return Err(refused("office result has no original receipt pointer"));
    }
    Ok(receipt)
}

pub(crate) fn admit_result(
    office: &OfficeTurnContext<'_>,
    startup: OfficeTurnStartup,
    scope: &str,
    outcome: TurnOutcome,
    fork_snapshot: Option<TurnForkSnapshot>,
) -> Result<TaskResult, EngineError> {
    if scope != office.authority.chat() {
        return Err(refused("office result differs from original chat"));
    }
    let receipt = original_receipt(office, &outcome)?;
    let witness = outcome
        .runtime_workspace_witness
        .as_ref()
        .expect("qualified original witness");
    let writes: Vec<_> = witness
        .writes
        .iter()
        .map(|write| NativeTurnFileWitness {
            path: write.path.clone(),
            kind: write.kind.clone(),
            sha256: write.content_hash.clone(),
            bytes: write.bytes,
        })
        .collect();
    let run_phase = if outcome.error.is_none() {
        RunPhase::Completed
    } else {
        RunPhase::Failed
    };
    let preparation =
        office_turn_startup::recorded_runtime(office, &startup, fork_snapshot.as_ref())?;
    let descriptors: Vec<_> = writes
        .iter()
        .map(|file| PreparedFile {
            path: file.path.clone(),
            kind: file.kind.clone(),
            sha256: file.sha256.clone(),
            bytes: file.bytes,
        })
        .collect();
    let payload_plan = ResultPayloadPlan::new(office, &startup, &preparation, &descriptors)?;
    let payload_scopes = payload_plan.scopes();
    let payload_scopes: Vec<_> = payload_scopes.iter().map(String::as_str).collect();
    let mut wb = office.wb.lock_unpoisoned();
    let authority = office.authority.prepare_basis(&wb)?;
    let key = wb
        .content_vault
        .as_ref()
        .ok_or_else(|| refused("original office result key unavailable"))?
        .prepare_scope_key(scope)
        .map_err(|_| refused("original office result key unavailable"))?;
    let owner = gaugedesk_core::determine_scope_authority(scope);
    let ((output, certified_reads, payloads), observed) =
        wb.store_ref()
            .read_for_dispatch(&payload_scopes, |reader| {
                reader.retained_events(scope)?;
                let output = crate::resource_store::prepare_office_output(
                    reader,
                    scope,
                    owner.as_str(),
                    &outcome.output_flow_signature,
                )?;
                let certified_reads =
                    crate::turn_summary::join_certified_reads(reader, scope, &output.reads)?;
                Ok((output, certified_reads, payload_plan.observe(reader)?))
            })?;
    let basis = authority.combine(observed)?;
    let original = office.original;
    let before_cut = startup.native_base.base_cut().to_owned();
    let original_lineage = startup.native_base.original_lineage()?.clone();
    let ((cut, diff, merge_phase), _) = wb.store_mut().with_dispatch_record_admission(&basis, |writer| {
        payloads.consume(writer, &key, original, |writer, bodies| {
        writer.require_pending_claim(original.command_id(), original.scope(), original.key(), original.snapshot())?;
        let reviewed = writer.with_native_check(|check| {
            let mut current = || check.check_current().map_err(|error| WorkspaceError { message: format!("{error:?}") });
            let native = startup.native_base.import_saved_result_guarded(
                &writes, receipt.workspace_cut_ref.as_deref().expect("qualified workspace cut"),
                office.authority.actor(), original.command_id(), &bodies, &mut current,
            )?;
            OfficeNativeResult::prepare(native, &mut current)
        })??;
        let diff = reviewed.diff()?;
        reviewed.publish(|native, settlement| {
            let cut = native.cut().to_owned();
            let (merge_commands, merge_phase) = if settlement.is_some() {
                (vec![MergeCommand::StartMerge, MergeCommand::WorkspaceClean, MergeCommand::PolicyAdmit, MergeCommand::AdvanceStandingRef], MergePhase::Advanced)
            } else {
                (vec![MergeCommand::StartMerge, MergeCommand::WorkspaceConflict], MergePhase::Rejected)
            };
            let mut records = output.facts_at(&cut).map_err(native_error)?;
            let creation = OfficeCreationRecord {
                revision: "office-result-creation/v1".into(),
                command: original.command_id().into(),
                actor: office.authority.actor().into(),
                chat: scope.into(),
                input_position: startup.user_entry_id,
                base_cut: before_cut.clone(),
                lineage: original_lineage,
                runtime_start: outcome.runtime_start_position.clone().expect("qualified start"),
                runtime_terminal: outcome.runtime_terminal_position.clone().expect("qualified terminal"),
                runtime_cut: receipt.workspace_cut_ref.clone().expect("qualified runtime cut"),
                result_cut: cut.clone(),
                // Preserve owner order and repeated paths. The final-file map
                // is a projection and cannot reconstruct the creation subject.
                ordered_writes: descriptors.clone(),
                evidence: native.result_evidence().cloned().ok_or_else(||
                    whipplescript_store::StoreError::Conflict("office original creation evidence unavailable".into()))?,
            };
            records.push(fact(scope, CREATION_KIND, serde_json::to_string(&creation)
                .map_err(|error| native_error(AdmitError::Json(error)))?));
            records.push(fact(scope, "office_runtime_receipt", witness.receipt_json.clone()));
            records.push(fact(scope, "workspace_result", cut.clone()));
            if let Some(settlement) = settlement {
                records.push(settlement_fact(scope, original.command_id(), &cut, settlement)?);
            }
            records.push(fact(scope, "office_turn_settlement_gap", serde_json::to_string(&serde_json::json!({
                "revision": "office-turn-settlement-gap/v1", "command_id": original.command_id(),
                "result_cut": cut, "reason": if settlement.is_some() { "original_office_projection_and_sibling_reconciliation_not_qualified" } else { "original_office_conflicted_candidate_isolated" },
            })).map_err(|error| native_error(AdmitError::Json(error)))?));
            records.push(fact(scope, "workspace_local_result", serde_json::to_string(&serde_json::json!({
                "revision": "office-workspace-local-result/v1", "runtime_reads": witness.reads,
                "runtime_workspace_cut": receipt.workspace_cut_ref,
                "pending_questions": outcome.asked_questions,
                "evidence": native.result_evidence(), "files": native.local_files(), "removed": native.local_removed(),
            })).map_err(|error| native_error(AdmitError::Json(error)))?));
            let mut pointers = std::collections::BTreeSet::new();
            for pointer in &outcome.runtime_evidence_pointers {
                if pointers.insert(pointer) {
                    let payload = serde_json::to_string(&super::RuntimeEvidenceCrossing {
                        runtime: "whipplescript", pointer,
                        workspace_cut_ref: Some(super::WorkspaceCutRef { substrate: "whipplescript", revision: &cut }),
                    }).map_err(|error| native_error(AdmitError::Json(error)))?;
                    records.push(fact(scope, super::RUNTIME_EVIDENCE_POINTER_KIND, payload));
                }
            }
            if let Some(reading) = &outcome.context_reading {
                records.push(fact(scope, super::CONTEXT_READING_KIND, serde_json::to_string(reading).map_err(|error| native_error(AdmitError::Json(error)))?));
            }
            // Metering remains evidence under office custody; no hosted billing
            // scope or reservation is written by this local result publication.
            if let Some(usage) = &outcome.managed_usage {
                records.push(fact(scope, "office_model_usage", serde_json::to_string(usage).map_err(|error| native_error(AdmitError::Json(error)))?));
            }
            let changed_paths = crate::advancement::TurnFacts::changed_paths_of(&diff);
            let summary = crate::turn_summary::TurnSummary {
                user_entry_id: startup.user_entry_id,
                receipt_status: if run_phase == RunPhase::Completed { crate::turn_summary::ReceiptStatus::Completed } else { crate::turn_summary::ReceiptStatus::Failed },
                error: outcome.error.clone(), changed_count: changed_paths.len(), changed_paths,
                policy_diff_direction: crate::turn_summary::policy_diff_direction(&diff), certified_reads,
            };
            let mut commands = vec![RunCommand::RecordObservation; outcome.observations.len()];
            commands.push(if run_phase == RunPhase::Completed { RunCommand::CompleteRun } else { RunCommand::FailRun });
            let settled_at_unix_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).ok()
                .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok());
            let result = writer.commit_recorded_claimed_lifecycle_pair(
                original.command_id(), original.scope(), original.key(), original.snapshot(),
                LifecycleBatch::<RunState> { scope: scope.into(), commands },
                LifecycleBatch::<MergeState> { scope: scope.into(), commands: merge_commands },
                |next| {
                    let mut assistant = None;
                    for observation in &outcome.observations {
                        let event = match observation.kind {
                            "assistant" => {
                                assistant = Some(next + records.len() as i64);
                                Some(ServerEvent::Assistant { text: observation.detail.clone(), settled_at_unix_ms })
                            },
                            "egress" | "egress_staged" | "tool_result" | "egress_blocked" => Some(ServerEvent::from_observation(observation)),
                            _ => None,
                        };
                        if let Some(event) = event { records.push(fact(scope, "transcript", event.to_json())); }
                    }
                    let assistant_entry_id = assistant.unwrap_or_else(|| {
                        let position = next + records.len() as i64;
                        records.push(fact(scope, "transcript", ServerEvent::Assistant { text: outcome.assistant_text.clone(), settled_at_unix_ms }.to_json()));
                        position
                    });
                    let fork_snapshot = fork_snapshot.map(|mut snapshot| {
                        snapshot.before_collaboration_cut = before_cut.clone(); snapshot.after_collaboration_cut = cut.clone();
                        snapshot.after_taint_evidence_digest = super::taint_evidence_digest(&output.reads_after);
                        snapshot
                    });
                    let boundary = TurnBoundaryRecord {
                        user_entry_id: startup.user_entry_id, assistant_entry_id,
                        before_workspace_cut: before_cut, after_workspace_cut: cut.clone(),
                        runtime_before: outcome.runtime_start_position.clone().expect("qualified start"),
                        runtime_after: outcome.runtime_terminal_position.clone().expect("qualified terminal"),
                        reads_before: startup.reads_before, reads_after: output.reads_after, fork_snapshot,
                    };
                    records.push(fact(scope, super::TURN_BOUNDARY_KIND, serde_json::to_string(&boundary)?));
                    if let Some(reason) = &outcome.error {
                        records.push(fact(scope, "transcript", ServerEvent::Error { reason: reason.clone(), code: None }.to_json()));
                    }
                    records.push(fact(scope, "transcript", ServerEvent::Admitted { kind: "run".into(), text: format!("run → {run_phase:?}") }.to_json()));
                    records.push(fact(scope, crate::turn_summary::TURN_SUMMARY_KIND, serde_json::to_string(&summary)?));
                    Ok(records)
                },
            ).map_err(native_error)?;
            Ok(((cut, diff, merge_phase), result))
        }).map_err(WorkspaceError::from).map_err(EngineError::Workspace)
        })
    })??;
    Ok(TaskResult {
        run_phase,
        assistant_text: outcome.assistant_text,
        diff,
        guarantee_outcomes: outcome.guarantee_outcomes,
        usage_observation: outcome.managed_usage,
        commit: Some(cut),
        merge_phase,
        mediated_tool_calls: outcome.mediated_tool_calls,
        blocked_effects: outcome
            .observations
            .iter()
            .filter(|observation| observation.kind == "egress_blocked")
            .map(|observation| observation.detail.clone())
            .collect(),
        pending_approvals: outcome.pending_approvals,
        // Retained above for guarded delivery; do not hand these to the
        // unqualified legacy recipient/bookkeeping writer.
        asked_questions: Vec::new(),
        error: outcome.error,
        auto_title: None,
    })
}

#[cfg(test)]
#[path = "office_turn_history_tests.rs"]
mod history_tests;
