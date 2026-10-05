//! Native fact signer metadata is separate from the original command issuer.
//! Public history verification grants neither current standing nor custody.
use super::*;
use gaugedesk_core::ids::{AuthorityId, PublicKey};
use serde::{Deserialize, Serialize};

const FRAME: &str = "gaugedesk.project-native-fact.v2";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProjectSignature {
    protocol: String,
    project: String,
    authority: String,
}

impl ProjectSignature {
    pub(super) fn new(project: &str, key: &SigningKey) -> Self {
        Self {
            protocol: FRAME.into(),
            project: project.into(),
            authority: crate::project_authority::authority(&key.public_key())
                .as_str()
                .into(),
        }
    }

    pub(super) fn authority(&self) -> &str {
        &self.authority
    }

    pub(super) fn signing_bytes(&self, body: &[u8]) -> Result<Vec<u8>, String> {
        // The complete legacy domain and body are inside the new signed frame.
        // Canonical tuple encoding separates every field without ambiguity.
        let payload = serde_json::to_value((self, body)).map_err(|e| e.to_string())?;
        let canonical = serde_json::to_string(
            &whipplescript_store::effect_recovery::canonical_value(&payload),
        )
        .map_err(|e| e.to_string())?;
        Ok(format!("{FRAME}\n{canonical}").into_bytes())
    }

    pub(super) fn root(
        &self,
        roots: &NativeHistoryRoots,
        store: &Store,
        command: &HostActionCommand,
    ) -> Result<GovernanceRootVerifier, String> {
        let project = command_project(command)?;
        if self.protocol != FRAME || self.project != project {
            return Err("native signature frame differs from the original project".into());
        }
        let root = roots.project_root(store, &project)?;
        if root.expected_signer().as_str() != self.authority {
            return Err("native signature frame has an unregistered authority".into());
        }
        Ok(root)
    }
}

pub(super) fn command_project(command: &HostActionCommand) -> Result<String, String> {
    let parts: Vec<String> =
        serde_json::from_str(&command.scope).map_err(|_| "invalid native project scope")?;
    match parts.as_slice() {
        [format, project, chat]
            if format == "gaugedesk.editor-file.v1" && !project.is_empty() && !chat.is_empty() =>
        {
            Ok(project.clone())
        }
        [format, project, chat, path]
            if format == "gaugedesk.editor-corrections.v1"
                && !project.is_empty()
                && !chat.is_empty()
                && !path.is_empty() =>
        {
            Ok(project.clone())
        }
        _ => Err("unsupported native project scope".into()),
    }
}

#[derive(Clone)]
pub(super) struct NativeHistoryRoots {
    legacy_issuer: AuthorityId,
    legacy_key: PublicKey,
}

impl NativeHistoryRoots {
    pub(super) fn open(wb: &Workbench) -> Result<Self, String> {
        Ok(Self {
            legacy_issuer: wb.authority().clone(),
            legacy_key: SigningKey::from_seed(&wb.governance_seed())
                .map_err(|e| e.reason)?
                .public_key(),
        })
    }

    fn project_root(&self, store: &Store, project: &str) -> Result<GovernanceRootVerifier, String> {
        let retained = store
            .project_authority_key(project)
            .map_err(|e| format!("{e:?}"))?
            .ok_or("original project authority is unavailable")?;
        let key = PublicKey::new(retained.public_key);
        let issuer = crate::project_authority::authority(&key);
        if issuer.as_str() != retained.authority_id
            || (retained.custody == "incoming-project-v1"
                && store
                    .committed_record_snapshot(
                        &crate::federation::handoff_scope(project),
                        "receive",
                    )
                    .map_err(|e| format!("{e:?}"))?
                    .is_none())
        {
            return Err("original project authority is invalid or unadmitted".into());
        }
        Ok(GovernanceRootVerifier::new(issuer, key))
    }

    pub(super) fn original_root(
        &self,
        store: &Store,
        command: &HostActionCommand,
    ) -> Result<GovernanceRootVerifier, String> {
        let project = command_project(command)?;
        self.policy_root(store, &project, &command.issuer)
    }

    pub(super) fn policy_root(
        &self,
        store: &Store,
        project: &str,
        issuer: &str,
    ) -> Result<GovernanceRootVerifier, String> {
        if issuer == self.legacy_issuer.as_str() {
            return Ok(GovernanceRootVerifier::new(
                self.legacy_issuer.clone(),
                self.legacy_key.clone(),
            ));
        }
        let root = self.project_root(store, project)?;
        if root.expected_signer().as_str() != issuer {
            return Err("original native issuer is untrusted".into());
        }
        Ok(root)
    }
}

impl Workbench {
    // Only call after current project access and write availability have been
    // observed. The caller must fence that basis before publishing any fact.
    pub(super) fn native_project_signer(
        &mut self,
        project: &str,
        basis: gaugedesk_store::command_dispatch::DispatchReadBasis,
    ) -> Result<
        (
            SigningKey,
            gaugedesk_store::command_dispatch::DispatchReadBasis,
        ),
        String,
    > {
        self.native_project_signer_access(project, basis, NativeActionAccess::Mutate)
    }

    pub(super) fn native_project_signer_access(
        &mut self,
        project: &str,
        basis: gaugedesk_store::command_dispatch::DispatchReadBasis,
        access: NativeActionAccess,
    ) -> Result<
        (
            SigningKey,
            gaugedesk_store::command_dispatch::DispatchReadBasis,
        ),
        String,
    > {
        let scope = crate::federation::handoff_scope(project);
        let (_, handoff) = self
            .store_ref()
            .read_for_dispatch(&[LIBRARY_SCOPE, &scope], |store| {
                access.require_available(store, project)
            })
            .map_err(|e| format!("project signer authority paused: {e:?}"))?;
        let basis = basis
            .combine(handoff)
            .map_err(|e| format!("project signer authority changed: {e:?}"))?;
        if matches!(access, NativeActionAccess::Mutate) {
            self.initialize_project_authority_against(project, &basis)
                .map_err(|e| e.to_string())?;
        }
        Ok((
            self.project_signing_key(project)
                .map_err(|e| e.to_string())?,
            basis,
        ))
    }

    pub(super) fn prepare_native_metadata_policy(
        &mut self,
        original: &HostActionCommand,
        scope: &str,
        request_id: &str,
        policy: &HostGovernancePolicy,
        key: &SigningKey,
        basis: gaugedesk_store::command_dispatch::DispatchReadBasis,
    ) -> Result<
        (
            ActionPolicyIdentity,
            crate::action_policy::RetainedActionPolicy,
            gaugedesk_store::command_dispatch::DispatchReadBasis,
        ),
        String,
    > {
        let mut identity = ActionPolicyIdentity {
            issuer: original.issuer.clone(),
            scope: scope.into(),
            request_id: request_id.into(),
        };
        let root = NativeHistoryRoots::open(self)?.original_root(self.store_ref(), original)?;
        if let Some(previous) = crate::action_policy::prepared_action_policy(
            self.store_ref(),
            &identity,
            policy,
            &root,
        )? {
            return Ok((identity, previous, basis));
        }
        identity.issuer = crate::project_authority::authority(&key.public_key())
            .as_str()
            .into();
        let project = command_project(original)?;
        let handoff_scope = crate::federation::handoff_scope(&project);
        let (_, current) = self
            .store_ref()
            .read_for_dispatch(&[LIBRARY_SCOPE, &handoff_scope], |store| {
                crate::federation::require_project_writes_available(store, &project)
            })
            .map_err(|e| format!("native metadata policy publication paused: {e:?}"))?;
        let basis = basis
            .combine(current)
            .map_err(|e| format!("native metadata policy authority changed: {e:?}"))?;
        let retained = crate::action_policy::prepare_action_policy_against(
            self.store_mut(),
            &identity,
            policy,
            key,
            &basis,
        )?;
        Ok((identity, retained, basis))
    }
}
