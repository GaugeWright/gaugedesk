//! Original office task filing and retained native/product phase publication.
use super::{office_turn_startup::OfficeTurnContext, RunState};
use crate::LockUnpoisoned;
use gaugedesk_store::{command_dispatch::LifecycleBatch, AdmitError, CommandRecordFact};
use gaugedesk_workspace::WorkflowProtection;
use whipplescript_store::tracker_filing::TrackerFiling;

fn refused() -> AdmitError {
    AdmitError::Rejected(gaugedesk_core::Rejection {
        reason: "original office task filing refused",
    })
}

pub(crate) fn recipients(office: &OfficeTurnContext<'_>) -> Vec<(String, String)> {
    let disclose = || -> Result<Vec<(String, String)>, AdmitError> {
        let mut wb = office.wb.lock_unpoisoned();
        let original = office.original;
        let authority = office.authority.prepare_basis(&wb)?;
        let (_, _, choices, observed) = wb.prepare_project_tracker_recipients(
            office.authority.context(),
            office.authority.project(),
            crate::project_tracker::PROJECT_TASKS,
        )?;
        let basis = authority.combine(observed)?;
        wb.store_mut()
            .with_dispatch_record_admission(&basis, |writer| {
                writer.require_pending_claim(
                    original.command_id(),
                    original.scope(),
                    original.key(),
                    original.snapshot(),
                )?;
                writer.with_native_check(|check| check.check_current())??;
                Ok(choices.into_iter().collect())
            })?
    };
    disclose().unwrap_or_default()
}

pub(crate) fn file(
    office: &OfficeTurnContext<'_>,
    call_key: &str,
    content: &str,
    assigned_to: Option<&str>,
) -> Result<String, String> {
    let content = content.trim();
    if call_key.trim().is_empty() || content.is_empty() || content.len() > 16 * 1024 {
        return Err("office task input is invalid".into());
    }
    let (title, body) = content
        .split_once('\n')
        .map_or((content, ""), |(title, body)| (title.trim(), body.trim()));
    if title.is_empty() || title.len() > 512 {
        return Err("office task title is invalid".into());
    }
    let mut wb = office.wb.lock_unpoisoned();
    let original = office.original;
    let authority = office
        .authority
        .prepare_basis(&wb)
        .map_err(|_| "original office task authority ended")?;
    original
        .verify_pending(wb.store_ref())
        .map_err(|_| "original office task is not pending")?;
    let project = office.authority.project();
    let chat = office.authority.chat();
    let (tracker, eligible, choices, observed) = wb
        .prepare_project_tracker_recipients(
            office.authority.context(),
            project,
            crate::project_tracker::PROJECT_TASKS,
        )
        .map_err(|_| "office task tracker is not currently accessible")?;
    let recipient = match assigned_to.map(str::trim) {
        None => None,
        Some("me" | "myself") => Some(office.authority.actor().to_owned()),
        Some("") => return Err("office task assignee is empty".into()),
        Some(requested) if eligible.contains(requested) => Some(requested.to_owned()),
        Some(requested) => {
            let mut matches = choices
                .iter()
                .filter(|(_, display)| display.as_str() == requested);
            let recipient = matches
                .next()
                .ok_or("office task assignee is not eligible")?
                .0;
            if matches.next().is_some() {
                return Err("office task assignee is ambiguous".into());
            }
            Some(recipient.clone())
        }
    };
    if recipient
        .as_ref()
        .is_some_and(|recipient| !eligible.contains(recipient))
    {
        return Err("office task assignee is not a current tracker reader".into());
    }
    let basis = authority
        .combine(observed)
        .map_err(|_| "office task access basis differs")?;
    crate::federation::require_project_writes_available(wb.store_ref(), project)
        .map_err(|_| "office project writes are unavailable")?;
    // Only explicit enrollment may initialize storage or create this key.
    let key = wb.workflow_key(project, &tracker.workspace_id, false)?;
    let protection = WorkflowProtection::new(&tracker.workspace_id, key.clone())
        .map_err(|_| "office workflow protection is unavailable")?;
    let storage = wb.workflow_storage(&tracker.workspace_id)?;
    let identity = serde_json::to_vec(&(original.command_id(), call_key))
        .map_err(|_| "office task identity is invalid")?;
    let phase = format!(
        "office-task-filing:{}",
        crate::command_idempotency::digest(&identity)
    );
    let filing = TrackerFiling {
        operation_id: phase.clone(),
        instance_id: format!("project-agent-chat:{chat}"),
        effect_id: phase.clone(),
        actor: office.authority.actor().to_owned(),
        queue: tracker.queue,
        title: title.to_owned(),
        body: body.to_owned(),
        labels: Vec::new(),
        metadata: serde_json::json!({"source": "agent"}),
        assigned_to: recipient,
    };
    let item_id = key.retain(|| -> std::io::Result<String> {
        let mut stores = storage.open_existing_protected(&protection).map_err(|_| std::io::Error::other("existing protected office workflow unavailable"))?;
        wb.store_mut().with_dispatch_record_admission(&basis, |writer| -> Result<String, AdmitError> {
            writer.require_pending_claim(original.command_id(), original.scope(), original.key(), original.snapshot())?;
            let receipt = writer.with_native_check(|check| {
                stores.runtime.items.file_issue_once_guarded(&filing, &mut || {
                    check.check_current().map_err(|_| whipplescript_store::StoreError::Conflict("original office task authority ended".into()))
                })
            })?.map_err(|_| refused())?;
            let facts = [CommandRecordFact {
                scope_id: chat.into(), kind: "office_task_filing".into(),
                payload: serde_json::to_string(&serde_json::json!({
                    "revision": "office-task-filing/v1", "command_id": original.command_id(),
                    "request": filing, "receipt": receipt,
                }))?,
            }];
            stores.runtime.items.publish_filing_receipt(&filing, &receipt, |_| {
                writer.commit_claimed_lifecycle_prefix(
                    original.command_id(), original.scope(), original.key(), original.snapshot(), &phase,
                    LifecycleBatch::<RunState> { scope: chat.into(), commands: vec![] }, &facts,
                ).map_err(|_| whipplescript_store::StoreError::Conflict("original office filing phase refused".into()))
            }).map_err(|_| refused())?;
            Ok(receipt.item_id)
        }).map_err(|_| std::io::Error::other("office task filing refused"))?
          .map_err(|_| std::io::Error::other("office task filing refused"))
    }).map_err(|error| error.to_string())?;
    wb.notify_library_changed("project_tracker", project, "upsert");
    Ok(item_id)
}
