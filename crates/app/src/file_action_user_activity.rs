//! Once-only office idle activity from a fresh committed user command.
use super::*;

/// No Clone/Deserialize or public constructor: a replay, observation, queued
/// step or restart cannot produce another fresh user-admission marker.
pub(super) struct NewOfficeUserActivity {
    context: AuthenticatedActionContext,
    command: HostActionCommand,
}

impl NewOfficeUserActivity {
    pub(super) fn from_admission(
        context: &AuthenticatedActionContext,
        command: &HostActionCommand,
    ) -> Option<Self> {
        matches!(
            context.authentication(),
            ActorAuthentication::OfficeStaff { .. }
        )
        .then(|| Self {
            context: context.clone(),
            command: command.clone(),
        })
    }
}

impl Workbench {
    /// Count a fresh admitted editor intent as user activity before authorizing
    /// its queue grant. The original intent stays committed if this fails; the
    /// caller reports unavailable dispatch and never substitutes a new command.
    /// Consuming the marker also on failure prevents late retries from reviving
    /// an idle lease. Existing grants keep their own original ceiling.
    pub(crate) fn record_editor_user_activity(
        &mut self,
        context: &AuthenticatedActionContext,
        inputs: &NativeActionInputCustody,
        admitted: &mut AdmittedEditorFileSave,
    ) -> Result<AuthenticatedActionContext, String> {
        let Some(activity) = admitted.user_activity.take() else {
            return Ok(context.clone());
        };
        if activity.context != *context || activity.command != admitted.command || admitted.replayed
        {
            return Err("office activity differs from its fresh user admission".into());
        }
        let ActorAuthentication::OfficeStaff { authority } = context.authentication() else {
            return Err("office activity requires its exact staff context".into());
        };
        // Re-prove the committed command, target and source immediately before
        // updating activity. The resulting basis carries exact Home cancellation
        // and the captured deadline into the activity publication transaction.
        let prepared = self.prepare_native_editor_action(
            context,
            inputs,
            &admitted.command,
            &admitted.command.policy,
        )?;
        self.record_office_admitted_activity(authority, prepared.basis)
    }
}
