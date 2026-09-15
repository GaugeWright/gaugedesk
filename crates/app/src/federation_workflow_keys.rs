//! Native workflow custody on the actual handoff carriage.
use super::*;
use crate::content_vault::{PreparedScopeKey, PreparedScopeTransfer, ScopeKeyCapsule};
use gaugedesk_workspace::{WorkflowProtectionMode, PROTECTED_EXPORT_FORMAT};

pub(super) fn check_recipient(
    wb: &Workbench,
    peer: &str,
    recipient: &PublicKey,
) -> std::io::Result<()> {
    wb.federation_ref()
        .and_then(|fed| fed.grant_for(peer))
        .filter(|grant| {
            grant.is_valid(now_secs()) && &grant.source_authority_root_pubkey == recipient
        })
        .ok_or_else(|| {
            std::io::Error::other("current workflow recipient pairing is unavailable")
        })?;
    Ok(())
}

pub(super) fn prepare(
    wb: &Workbench,
    project: &str,
    peer: &str,
    recipient: &PublicKey,
) -> std::io::Result<Option<(String, PreparedScopeTransfer)>> {
    check_recipient(wb, peer, recipient)?;
    let project_record = wb
        .library
        .projects
        .get(project)
        .filter(|record| &record.home_id == wb.home_id())
        .ok_or_else(|| std::io::Error::other("workflow source is not this project's Home"))?;
    let Some(record) = wb.library.project_collaboration_workspaces.get(project) else {
        return Ok(None);
    };
    if record.home_id != project_record.home_id {
        return Err(std::io::Error::other(
            "workflow source Home bindings disagree",
        ));
    }
    let workspace = wb
        .collaboration_workspaces
        .get(&record.workspace_id)
        .ok_or_else(|| std::io::Error::other("project workflow workspace is not open"))?;
    let storage = workspace
        .native_workflow_storage()
        .map_err(std::io::Error::other)?;
    if storage
        .protection_mode(&record.workspace_id)
        .map_err(std::io::Error::other)?
        != Some(WorkflowProtectionMode::Protected)
    {
        return Ok(None);
    }
    let vault = wb
        .content_vault
        .as_ref()
        .ok_or_else(|| std::io::Error::other("protected workflow custody is not configured"))?;
    let scope = crate::project_workflow::content_scope(project)?;
    Ok(Some((
        record.workspace_id.clone(),
        vault.prepare_scope_transfer(&scope, recipient)?,
    )))
}

pub(super) fn validate(wire: &HandoffWire) -> Result<(), &'static str> {
    let mut protected = 0;
    for bundle in &wire.content {
        let protected_format = bundle.format == PROTECTED_EXPORT_FORMAT;
        if protected_format || bundle.workflow_key.is_some() {
            if wire.kind != HandoffMsgKind::OfferWithWorkflowKeys
                || !bundle.collaboration
                || !protected_format
                || bundle.workflow_key.is_none()
            {
                return Err("protected collaboration workflow requires its recipient key carriage");
            }
            protected += 1;
        }
    }
    if wire.kind == HandoffMsgKind::OfferWithWorkflowKeys && protected != 1 {
        return Err("workflow key offer must carry one protected collaboration workspace");
    }
    Ok(())
}

pub(super) fn receive(
    wb: &Workbench,
    wire: &HandoffWire,
) -> std::io::Result<Option<Arc<PreparedScopeKey>>> {
    let Some(capsule) = wire
        .content
        .iter()
        .find_map(|bundle| bundle.workflow_key.as_ref())
    else {
        return Ok(None);
    };
    let vault = wb
        .content_vault
        .as_ref()
        .ok_or_else(|| std::io::Error::other("receiving workflow custody is not configured"))?;
    let expected_scope = crate::project_workflow::content_scope(&wire.project)?;
    // Binding/recipient/ledger checks and rewrapping precede product locking.
    // The caller retains this prepared key inside its product transaction.
    vault
        .receive_scope_key(&expected_scope, &federation_root_signing_key(wb), capsule)
        .map(|key| Some(Arc::new(key)))
}

pub(super) type RetainedCustody<'a> = Option<(&'a Arc<PreparedScopeKey>, &'a ScopeKeyCapsule)>;
