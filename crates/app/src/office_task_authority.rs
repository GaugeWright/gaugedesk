//! Captured office work authority at task startup and upload reception boundaries.
use crate::{
    identity::{ActorAuthentication, AuthenticatedActionContext},
    LockUnpoisoned, SharedWorkbench,
};
use gaugedesk_core::ids::AuthorityId;
use gaugedesk_store::AdmitError;

#[derive(Clone)]
pub(crate) struct OfficeTaskAuthority {
    context: AuthenticatedActionContext,
    chat: String,
    project: String,
    client: crate::client_admission::ClientBuild,
    standing: OriginalOfficeStanding,
}

/// Original local parents survive neither removal nor replacement. Compare
/// retained denial history so revoke-and-restore between checkpoints is visible.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginalOfficeStanding {
    member_id: String,
    privileged: bool,
    grant_ids: std::collections::BTreeSet<String>,
    revocations: Vec<String>,
}

/// Sealed comparison recipe only. It cannot reconstruct live authentication.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OriginalOfficeTaskBinding {
    actor: String,
    chat: String,
    project: String,
    client: crate::client_admission::ClientBuild,
    standing: OriginalOfficeStanding,
    source_reference: String,
    process_epoch: String,
    admission_reference: String,
    deadline_ms: u64,
}

impl OriginalOfficeStanding {
    fn capture(
        store: &gaugedesk_store::Store,
        actor: &str,
        project: &str,
    ) -> Result<Self, AdmitError> {
        let org = crate::org::Org::rebuild(store)?;
        if !org.can_access_project(actor, project) {
            return Err(refused());
        }
        let member = org
            .members
            .values()
            .find(|member| {
                member.authority == actor && member.status == crate::org::MembershipStatus::Active
            })
            .ok_or_else(refused)?;
        let privileged = crate::org::is_privileged_role(&member.role);
        let mut standing = Self {
            member_id: member.id.clone(),
            privileged,
            grant_ids: if privileged {
                Default::default()
            } else {
                org.grants
                    .values()
                    .filter(|grant| grant.authority == actor && grant.project_id == project)
                    .map(|grant| grant.id.clone())
                    .collect()
            },
            revocations: Vec::new(),
        };
        standing.revocations = standing.observe_revocations(store, actor, project)?;
        Ok(standing)
    }

    fn observe_revocations(
        &self,
        store: &gaugedesk_store::Store,
        actor: &str,
        project: &str,
    ) -> Result<Vec<String>, AdmitError> {
        let mut denied = Vec::new();
        for row in store.records(crate::org::ORG_SCOPE, "membership")? {
            let record: crate::org::MembershipRecord = serde_json::from_str(&row)?;
            if record.id == self.member_id
                && (record.op == crate::library::RecordOp::Tombstone
                    || record.status != crate::org::MembershipStatus::Active
                    || record.authority != actor
                    || (self.privileged && !crate::org::is_privileged_role(&record.role)))
            {
                denied.push(format!("membership:{row}"));
            }
        }
        for row in store.records(crate::org::ORG_SCOPE, "member_grant")? {
            let record: crate::org::MemberGrantRecord = serde_json::from_str(&row)?;
            if self.grant_ids.contains(&record.id)
                && (record.op == crate::library::RecordOp::Tombstone
                    || record.authority != actor
                    || record.project_id != project)
            {
                denied.push(format!("grant:{row}"));
            }
        }
        Ok(denied)
    }

    fn check(
        &self,
        store: &gaugedesk_store::Store,
        actor: &str,
        project: &str,
    ) -> Result<(), AdmitError> {
        if self.observe_revocations(store, actor, project)? != self.revocations {
            return Err(refused());
        }
        Ok(())
    }
}

fn refused() -> AdmitError {
    AdmitError::Rejected(gaugedesk_core::Rejection {
        reason: "office task authority ended",
    })
}

impl OfficeTaskAuthority {
    pub(crate) fn original_binding(&self) -> Result<OriginalOfficeTaskBinding, AdmitError> {
        let ActorAuthentication::OfficeStaff { authority } = self.context.authentication() else {
            return Err(refused());
        };
        Ok(OriginalOfficeTaskBinding {
            actor: self.actor().into(),
            chat: self.chat.clone(),
            project: self.project.clone(),
            client: self.client.clone(),
            standing: self.standing.clone(),
            source_reference: authority.source_reference().into(),
            process_epoch: authority.process_epoch().into(),
            admission_reference: authority.admission_reference().into(),
            deadline_ms: authority.original_deadline_ms(),
        })
    }

    pub(crate) fn context(&self) -> &AuthenticatedActionContext {
        &self.context
    }

    pub(crate) fn chat(&self) -> &str {
        &self.chat
    }

    pub(crate) fn project(&self) -> &str {
        &self.project
    }

    pub(crate) fn actor(&self) -> &str {
        self.context.actor().as_str()
    }

    pub(crate) fn for_turn(
        wb: &SharedWorkbench,
        chat: &str,
        context: Option<&AuthenticatedActionContext>,
        client: Option<&crate::client_admission::ClientBuild>,
        actor: Option<&AuthorityId>,
        bearer: Option<&str>,
    ) -> Result<Option<Self>, AdmitError> {
        let guard = wb.lock_unpoisoned();
        let office = context.filter(|context| {
            matches!(
                context.authentication(),
                ActorAuthentication::OfficeStaff { .. }
            )
        });
        if bearer.is_some_and(|bearer| guard.has_office_staff_source(bearer)) && office.is_none() {
            return Err(refused());
        }
        let Some(context) = office else {
            return Ok(None);
        };
        if actor.is_some_and(|actor| actor != context.actor()) {
            return Err(refused());
        }
        guard
            .store_ref()
            .retained_events(crate::library::LIBRARY_SCOPE)?;
        let lib = crate::library::Library::rebuild(guard.store_ref())?;
        let project = lib.project_of_chat(chat).ok_or_else(refused)?;
        let standing =
            OriginalOfficeStanding::capture(guard.store_ref(), context.actor().as_str(), project)?;
        let authority = Self {
            context: context.clone(),
            chat: chat.into(),
            project: project.into(),
            client: client.ok_or_else(refused)?.clone(),
            standing,
        };
        drop(guard);
        authority.checkpoint(wb)?;
        Ok(Some(authority))
    }

    pub(crate) fn same_parent(&self, other: &Self) -> bool {
        let (
            ActorAuthentication::OfficeStaff { authority: left },
            ActorAuthentication::OfficeStaff { authority: right },
        ) = (
            self.context.authentication(),
            other.context.authentication(),
        )
        else {
            return false;
        };
        self.standing == other.standing
            && self.chat == other.chat
            && self.project == other.project
            && self.context.actor() == other.context.actor()
            && left.source_reference() == right.source_reference()
            && left.process_epoch() == right.process_epoch()
            && left.admission_reference() == right.admission_reference()
    }

    /// Uses the original observation and its ceiling. A source recheck or fresh
    /// login cannot lengthen this already submitted work's captured authority.
    /// This is a checkpoint, not an escaping runtime or publication grant.
    pub(crate) fn checkpoint(&self, wb: &SharedWorkbench) -> Result<(), AdmitError> {
        self.with_current(wb, || ())
    }

    /// Produce a bounded response inside the current writer fence. The callback
    /// must not acquire the Workbench lock, await or return authority for later use.
    pub(crate) fn with_current<T>(
        &self,
        wb: &SharedWorkbench,
        respond: impl FnOnce() -> T,
    ) -> Result<T, AdmitError> {
        let mut wb = wb.lock_unpoisoned();
        let basis = self.prepare_basis(&wb)?;
        wb.store_mut()
            .with_checked_dispatch_basis(&basis, |_| respond())
    }

    pub(crate) fn claim_upload_command(
        &self,
        wb: &SharedWorkbench,
        command_id: &str,
        scope_key: (&str, &str),
        legacy: (&str, &str),
        snapshot: &str,
    ) -> Result<(gaugedesk_store::CommandRecord, bool), AdmitError> {
        let (scope, key) = scope_key;
        let mut wb = wb.lock_unpoisoned();
        let basis = self.prepare_basis(&wb)?;
        let mut excluded = vec![legacy];
        if legacy.0 != scope {
            excluded.push((legacy.0, key));
        }
        wb.store_mut().claim_command_excluding(
            command_id,
            (scope, key),
            snapshot,
            Some(&basis),
            &excluded,
        )
    }

    pub(crate) fn prepare_basis(
        &self,
        wb: &crate::Workbench,
    ) -> Result<gaugedesk_store::command_dispatch::DispatchReadBasis, AdmitError> {
        let ActorAuthentication::OfficeStaff { authority } = self.context.authentication() else {
            return Err(refused());
        };
        if wb
            .office_staff_dispatch_context(
                authority.actor().as_str(),
                authority.source_reference(),
                authority.process_epoch(),
                authority.admission_reference(),
            )
            .is_none()
        {
            return Err(refused());
        }
        let handoff = crate::federation::handoff_scope(&self.project);
        let (_, basis) = wb.store_ref().read_for_dispatch(
            &[
                crate::library::LIBRARY_SCOPE,
                crate::org::ORG_SCOPE,
                &handoff,
            ],
            |reader| {
                reader.retained_events(crate::library::LIBRARY_SCOPE)?;
                reader.retained_events(crate::org::ORG_SCOPE)?;
                self.standing
                    .check(reader, self.context.actor().as_str(), &self.project)?;
                let lib = crate::library::Library::rebuild(reader)?;
                let org = crate::org::Org::rebuild(reader)?;
                if lib.project_of_chat(&self.chat) != Some(self.project.as_str())
                    || lib.project_home_id(&self.project) != Some(wb.home_id())
                    || !org.can_access_project(self.context.actor().as_str(), &self.project)
                {
                    return Err(refused());
                }
                crate::identity::revalidate_action_context(reader, wb.home_id(), &self.context)?;
                crate::federation::require_project_writes_available(reader, &self.project)?;
                if crate::client_admission::evaluate_client(
                    org.software_policy.as_ref(),
                    &self.client,
                    authority.now_ms(),
                )
                .status
                    == crate::client_admission::ClientAdmissionStatus::Blocked
                {
                    return Err(refused());
                }
                Ok(())
            },
        )?;
        authority.bind_basis(wb.store_ref(), basis, None)
    }
}

/// One submitted turn keeps its exact original parent, even in a reused harness.
/// Once refused, this binding remains ended if standing is later restored.
struct OfficeRuntimeAccess {
    wb: std::sync::Weak<std::sync::Mutex<crate::Workbench>>,
    original: OfficeTaskAuthority,
    parent: crate::command_idempotency::ClaimedHttpCommand,
    ended: std::sync::atomic::AtomicBool,
}

impl OfficeRuntimeAccess {
    fn current(&self) -> Result<(), AdmitError> {
        let wb = self.wb.upgrade().ok_or_else(refused)?;
        let mut wb = wb.lock_unpoisoned();
        let basis = self.original.prepare_basis(&wb)?;
        wb.store_mut()
            .with_dispatch_record_admission(&basis, |writer| {
                writer.require_pending_claim(
                    self.parent.command_id(),
                    self.parent.scope(),
                    self.parent.key(),
                    self.parent.snapshot(),
                )
            })??;
        Ok(())
    }
}

impl gaugedesk_harness::TurnAccess for OfficeRuntimeAccess {
    fn check_current(&self) -> Result<(), String> {
        use std::sync::atomic::Ordering;
        if self.ended.load(Ordering::Acquire) || self.current().is_err() {
            self.ended.store(true, Ordering::Release);
            return Err("office task authority ended".into());
        }
        Ok(())
    }
}

impl OfficeTaskAuthority {
    pub(crate) fn runtime_access(
        &self,
        wb: &SharedWorkbench,
        parent: &crate::command_idempotency::ClaimedHttpCommand,
    ) -> std::sync::Arc<dyn gaugedesk_harness::TurnAccess> {
        std::sync::Arc::new(OfficeRuntimeAccess {
            wb: std::sync::Arc::downgrade(wb),
            original: self.clone(),
            parent: parent.clone(),
            ended: std::sync::atomic::AtomicBool::new(false),
        })
    }
}
