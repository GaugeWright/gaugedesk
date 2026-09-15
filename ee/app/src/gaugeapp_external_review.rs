//! Durable approval before a separately authoritative management effect
//! (GAUGEAPP-1/6). Recovery retains the exact approved request, not a refreshed
//! payload with a newer expected basis. An unknown external outcome is never a
//! discarded proposal or evidence that it is safe to allocate another operation.

use super::*;

const INTENT_KIND: &str = "gaugeapp_external_review";

pub(super) fn claim_key(change_id: &str) -> String {
    format!("external-review:{change_id}")
}

fn completion_scope(headers: &HeaderMap) -> String {
    format!("{}:external-results", command_scope(headers))
}

/// Minted only after the authenticated route has accepted a human review and
/// persisted it. Private fields prevent an extension from confusing a browser
/// command with an admitted approval; deserialization is private store replay.
#[derive(Clone, Debug, serde::Serialize)]
pub struct ApprovedAdministrationChange {
    change_id: String,
    actor: String,
    command: GaugeAppCommandEnvelope,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredApproval {
    change_id: String,
    actor: String,
    command: GaugeAppCommandEnvelope,
}

impl ApprovedAdministrationChange {
    pub fn operation_key(&self) -> &str {
        &self.change_id
    }
    pub fn actor(&self) -> &str {
        &self.actor
    }
    pub fn command(&self) -> &GaugeAppCommandEnvelope {
        &self.command
    }
}

/// Read the exact durable approval at its owning Store. This is not an
/// authorization function: an authenticated service adapter must recheck the
/// current actor's organization capability before disclosing or using it.
/// Unapproved, discarded, conflicted or inconsistent records cannot become
/// service commands simply by presenting their change id.
pub fn stored_administration_approval(
    store: &gaugedesk_store::Store,
    store_scope: &str,
    change_id: &str,
) -> Result<Option<ApprovedAdministrationChange>, AdmitError> {
    let Some(change) = fold_gaugeapp_changes(store, store_scope)?.remove(change_id) else {
        return Ok(None);
    };
    if change.app != GaugeAppKind::Administration
        || !matches!(
            change.status,
            GaugeAppChangeStatus::Applying | GaugeAppChangeStatus::Applied
        )
    {
        return Ok(None);
    }
    let mut selected = None;
    for row in store.records(store_scope, INTENT_KIND)? {
        let value: StoredApproval = serde_json::from_str(&row)?;
        if value.change_id != change_id {
            continue;
        }
        if selected.is_some()
            || change.reviewed_by.as_deref() != Some(value.actor.as_str())
            || change.app != value.command.app
            || change.scope != value.command.scope
            || change.page_id != value.command.page_id
            || change.command_id != value.command.command_id
            || change.expected_basis != value.command.expected_basis
            || change.payload != value.command.payload
            || value.command.client == GaugeAppClient::Agent
        {
            return Err(AdmitError::Rejected(gaugedesk_core::Rejection {
                reason: "stored approval does not match its change",
            }));
        }
        selected = Some(ApprovedAdministrationChange {
            change_id: value.change_id,
            actor: value.actor,
            command: value.command,
        });
    }
    Ok(selected)
}

pub enum ExternalReviewOutcome {
    Applied(AdministrationMutationPlan),
    Pending,
    /// A terminal refusal from the owning authority, not an HTTP timeout or a
    /// temporarily absent result. It must fence that operation against later use.
    Rejected,
}

pub(super) struct ReviewJob {
    session: GaugeAppSession,
    approved: ApprovedAdministrationChange,
    extension: AdministrationGaugeAppExtensionHandle,
    task: ReviewTask,
}

enum ReviewTask {
    Apply(MutationPlan),
    Recover,
}

type PreparedReview = Result<ReviewJob, Response>;

fn unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({ "error": "approved change recovery is unavailable" })),
    )
        .into_response()
}

fn pending(
    session: &GaugeAppSession,
    approved: &ApprovedAdministrationChange,
    change: &GaugeAppChangeRecord,
) -> Response {
    (
        StatusCode::ACCEPTED,
        Json(json!({
            "receipt": gaugeapp_receipt(session, &approved.command, "applying"),
            "proposal": change,
        })),
    )
        .into_response()
}

#[allow(clippy::too_many_arguments)]
pub(super) fn begin(
    wb: &mut Workbench,
    headers: &HeaderMap,
    session: &GaugeAppSession,
    command: &GaugeAppCommandEnvelope,
    key: &str,
    change: &GaugeAppChangeRecord,
    extension: &AdministrationGaugeAppExtensionHandle,
    plan: MutationPlan,
) -> PreparedReview {
    if command.client == GaugeAppClient::Agent {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "an agent cannot approve a management change" })),
        )
            .into_response());
    }
    let approved = ApprovedAdministrationChange {
        change_id: change.id.clone(),
        actor: session.actor.clone(),
        command: command.clone(),
    };
    if approved.command.idempotency_key != key {
        return Err(unavailable());
    }
    let mut applying = change.clone();
    applying.status = GaugeAppChangeStatus::Applying;
    applying.reviewed_by = Some(session.actor.clone());
    let scope = req_scope(headers);
    let facts = match (
        fact(&scope, INTENT_KIND, &approved),
        fact(&scope, GAUGEAPP_CHANGE_KIND, &applying),
    ) {
        (Ok(intent), Ok(change)) => vec![intent, change],
        _ => return Err(unavailable()),
    };
    let audit_scope = gaugedesk_app::audit::scope_for(&scope);
    let audit = gaugedesk_app::audit::link(&session.actor, "gaugeapp.review.accepted", &change.id);
    // A review key may be retried, but one proposal cannot acquire two different
    // approval intents even across independently opened Store instances.
    let approval_snapshot =
        serde_json::to_string(&approved).expect("secret-free approval serializes");
    let claim_key = claim_key(&change.id);
    let result = wb.store_mut().admit_record_facts_with_claims(
        &command_scope(headers),
        key,
        &snapshot(command),
        &facts,
        Some(gaugedesk_app::audit::chained_in(&audit_scope, &audit)),
        &[gaugedesk_store::RecordCommandClaim {
            key: &claim_key,
            snapshot: &approval_snapshot,
        }],
    );
    let result = match result {
        Ok(result) => result,
        Err(error) => return Err(store_error(error)),
    };
    if let Some(entry) = gaugedesk_app::audit::committed_entry(result.chained_payload.as_deref()) {
        gaugedesk_app::audit::finish_committed_in(wb, &scope, &entry);
    }
    if result.replayed {
        return Err(pending(session, &approved, &applying));
    }
    Ok(ReviewJob {
        session: session.clone(),
        approved,
        extension: extension.clone(),
        task: ReviewTask::Apply(plan),
    })
}

pub(super) fn recover_if_approved(
    wb: &mut Workbench,
    headers: &HeaderMap,
    session: &GaugeAppSession,
    change: &GaugeAppChangeRecord,
    body: &ReviewBody,
    extension: Option<&AdministrationGaugeAppExtensionHandle>,
) -> Option<PreparedReview> {
    if matches!(
        change.status,
        GaugeAppChangeStatus::Proposed | GaugeAppChangeStatus::Rejected
    ) {
        return None;
    }
    let Some(extension) =
        extension.filter(|extension| extension.requires_external_review(&change.command_id))
    else {
        return (change.status == GaugeAppChangeStatus::Applying).then(|| Err(unavailable()));
    };
    let scope = req_scope(headers);
    let rows = match wb.store_ref().records(&scope, INTENT_KIND) {
        Ok(rows) => rows,
        Err(_) => return Some(Err(unavailable())),
    };
    let mut approved = None;
    for row in rows {
        let record: StoredApproval = match serde_json::from_str(&row) {
            Ok(value) => value,
            Err(_) => return Some(Err(unavailable())),
        };
        let value = ApprovedAdministrationChange {
            change_id: record.change_id,
            actor: record.actor,
            command: record.command,
        };
        if value.change_id == change.id {
            if approved.is_some() {
                return Some(Err(unavailable()));
            }
            approved = Some(value);
        }
    }
    let Some(approved) = approved else {
        return (change.status == GaugeAppChangeStatus::Applying).then(|| Err(unavailable()));
    };
    Some(prepare_recovery(session, change, body, extension, approved))
}

fn prepare_recovery(
    session: &GaugeAppSession,
    change: &GaugeAppChangeRecord,
    body: &ReviewBody,
    extension: &AdministrationGaugeAppExtensionHandle,
    approved: ApprovedAdministrationChange,
) -> PreparedReview {
    if body.client == GaugeAppClient::Agent || body.decision != "accept" {
        return Err((StatusCode::CONFLICT, Json(json!({ "error": "this change is already approved; check its service outcome instead of discarding or approving it again" }))).into_response());
    }
    authorize_observation(session, change, &approved)?;
    if let Some(response) = terminal(session, change, &approved) {
        return Err(response);
    }
    Ok(ReviewJob {
        session: session.clone(),
        approved,
        extension: extension.clone(),
        task: ReviewTask::Recover,
    })
}

fn authorize_observation(
    session: &GaugeAppSession,
    change: &GaugeAppChangeRecord,
    approved: &ApprovedAdministrationChange,
) -> Result<(), Response> {
    if approved.actor != session.actor
        || change.reviewed_by.as_deref() != Some(approved.actor())
        || approved.command.app != session.app
        || approved.command.scope != session.scope
        || change.app != session.app
        || change.scope != session.scope
        || approved.command.page_id != change.page_id
        || approved.command.command_id != change.command_id
        || approved.command.payload != change.payload
        || approved.command.expected_basis != change.expected_basis
    {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "approved change does not match the current actor and scope" })),
        )
            .into_response());
    }
    // This check authorizes recovery, NOT a new command. Only its session and
    // page-basis correlation are refreshed. The extension receives the original
    // approved request and must query/resume that exact identity at its owner.
    let mut authorization = approved.command.clone();
    authorization.session_id = session.id.clone();
    authorization.generation = session.generation.clone();
    if let Some(page) = session
        .pages
        .iter()
        .find(|page| page.id == authorization.page_id)
    {
        authorization.expected_basis = page.resource_basis.clone();
    }
    decide_reviewed_gaugeapp_command(session, &authorization).map_err(reject_gaugeapp)?;
    Ok(())
}

fn terminal(
    session: &GaugeAppSession,
    change: &GaugeAppChangeRecord,
    approved: &ApprovedAdministrationChange,
) -> Option<Response> {
    if matches!(
        change.status,
        GaugeAppChangeStatus::Applied | GaugeAppChangeStatus::Conflict
    ) {
        let applied = change.status == GaugeAppChangeStatus::Applied;
        return Some((if applied { StatusCode::OK } else { StatusCode::CONFLICT }, Json(json!({
            "receipt": gaugeapp_receipt(session, &approved.command, if applied { "applied" } else { "conflict" }), "proposal": change,
        }))).into_response());
    }
    None
}

/// Network work never borrows Workbench. The owning service may call back to
/// the management authority for fresh authorization while other Desk requests
/// continue. A task panic/lost response remains unknown, not safe to repeat.
pub(super) async fn execute(wb: SharedWorkbench, headers: HeaderMap, job: ReviewJob) -> Response {
    let ReviewJob {
        session,
        approved,
        extension,
        task,
    } = job;
    let call_approval = approved.clone();
    let tenant = tenant_id(&headers);
    let scope = req_scope(&headers);
    let call_scope = scope.clone();
    let call_extension = extension.clone();
    let outcome = tokio::task::spawn_blocking(move || match task {
        ReviewTask::Apply(plan) => {
            call_extension.apply_external_review(&tenant, &call_scope, &call_approval, plan)
        }
        ReviewTask::Recover => {
            call_extension.recover_external_review(&tenant, &call_scope, &call_approval)
        }
    })
    .await;
    let mut guard = wb.lock_unpoisoned();
    let change = match fold_gaugeapp_changes(guard.store_ref(), &scope)
        .ok()
        .and_then(|mut changes| changes.remove(approved.operation_key()))
    {
        Some(change) => change,
        None => return unavailable(),
    };
    // A concurrent recovery may already have completed. Its durable terminal
    // state wins over this call's late pending response; never append Applying.
    let response = if let Some(response) = terminal(&session, &change, &approved) {
        response
    } else if change.status != GaugeAppChangeStatus::Applying {
        return unavailable();
    } else {
        match outcome {
            Ok(Ok(ExternalReviewOutcome::Applied(plan))) => {
                finish_command_in(
                    &mut guard,
                    &headers,
                    &session,
                    &approved.command,
                    &approved.command.idempotency_key,
                    Some(change.clone()),
                    plan,
                    &completion_scope(&headers),
                )
                .0
            }
            Ok(Ok(ExternalReviewOutcome::Rejected)) => {
                rejected(&mut guard, &headers, &session, &approved, &change)
            }
            _ => pending(&session, &approved, &change),
        }
    };
    // Confirmation belongs in history even if this viewer lost access while
    // the service was working. Rebuild authorization before disclosing it.
    let current = match build_session(&guard, &headers, Some(&extension)) {
        Ok((session, _)) => session,
        Err(response) => return response,
    };
    if let Err(response) = authorize_observation(&current, &change, &approved) {
        return response;
    }
    response
}

fn rejected(
    wb: &mut Workbench,
    headers: &HeaderMap,
    session: &GaugeAppSession,
    approved: &ApprovedAdministrationChange,
    change: &GaugeAppChangeRecord,
) -> Response {
    let mut rejected = change.clone();
    rejected.status = GaugeAppChangeStatus::Conflict;
    let scope = req_scope(headers);
    let fact = match fact(&scope, GAUGEAPP_CHANGE_KIND, &rejected) {
        Ok(fact) => fact,
        Err(response) => return response,
    };
    let audit_scope = gaugedesk_app::audit::scope_for(&scope);
    let audit =
        gaugedesk_app::audit::link(&approved.actor, "gaugeapp.external.refused", &change.id);
    let result = wb.store_mut().admit_record_facts_chained(
        &completion_scope(headers),
        &approved.command.idempotency_key,
        &snapshot(&approved.command),
        &[fact],
        Some(gaugedesk_app::audit::chained_in(&audit_scope, &audit)),
    );
    match result {
        Ok(result) => {
            if let Some(entry) =
                gaugedesk_app::audit::committed_entry(result.chained_payload.as_deref())
            {
                gaugedesk_app::audit::finish_committed_in(wb, &scope, &entry);
            }
            (StatusCode::CONFLICT, Json(json!({ "receipt": gaugeapp_receipt(session, &approved.command, "conflict"), "proposal": rejected, "error": "the service refused this approved change" }))).into_response()
        }
        Err(error) => store_error(error),
    }
}
