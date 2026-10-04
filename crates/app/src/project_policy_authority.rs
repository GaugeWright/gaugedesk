//! Trusted public roots for original project policy facts (WS-673).
//! This resolves historical signatures; it grants no current membership,
//! action admission or signing custody. Each caller separately fences standing.

use crate::Workbench;
use gaugedesk_core::signature::SigningKey;
use gaugedesk_whip_runtime::GovernanceRootVerifier;

/// Public roots for local native history in one already admitted project.
/// This is neither signing custody nor a portable runtime or relocation grant.
pub(super) struct LocalProjectPolicyRoots {
    project: String,
    roots: Vec<GovernanceRootVerifier>,
}

impl LocalProjectPolicyRoots {
    #[cfg(test)]
    pub(super) fn fixture(project: &str, roots: Vec<GovernanceRootVerifier>) -> Self {
        Self {
            project: project.into(),
            roots,
        }
    }

    pub(super) fn project(&self) -> &str {
        &self.project
    }

    pub(super) fn root(&self, issuer: &str) -> Result<&GovernanceRootVerifier, String> {
        self.roots
            .iter()
            .find(|root| root.expected_signer().as_str() == issuer)
            .ok_or_else(|| "original local project policy authority is unavailable".into())
    }
}

impl Workbench {
    /// Called after current project admission, before its final dispatch fence.
    /// Existing project registration is immutable; missing private custody must
    /// not erase the public meaning of historical signatures. No key is minted.
    pub(super) fn local_project_policy_roots(
        &self,
        project: &str,
    ) -> Result<LocalProjectPolicyRoots, String> {
        if project.trim().is_empty() || !self.owns_project(project) {
            return Err("local project policy authority is unavailable".into());
        }
        let legacy = SigningKey::from_seed(&self.governance_seed()).map_err(|e| e.reason)?;
        let mut roots = vec![GovernanceRootVerifier::new(
            self.authority().clone(),
            legacy.public_key(),
        )];
        if self
            .store_ref()
            .project_authority_key(project)
            .map_err(|error| format!("{error:?}"))?
            .is_some()
        {
            let (issuer, key) = self
                .project_authority_identity(project)
                .map_err(|error| error.to_string())?;
            roots.push(GovernanceRootVerifier::new(issuer, key));
        }
        Ok(LocalProjectPolicyRoots {
            project: project.into(),
            roots,
        })
    }

    /// Resolve the original issuer from retained project identity or admitted
    /// relocation pins, preserving legacy host roots and pairing deadlines.
    /// Current signing custody is obtained separately from project_authority.
    pub(super) fn project_policy_root(
        &self,
        project: &str,
        issuer: &str,
    ) -> Result<
        (
            GovernanceRootVerifier,
            gaugedesk_store::command_dispatch::DispatchReadBasis,
        ),
        String,
    > {
        use crate::federation::{BridgeRecord, BRIDGE_SCOPE};
        let pins = crate::federation::workflow_signers_scope(project);
        let ((key, expiry), basis) = self
            .store_ref()
            .read_for_dispatch(&[BRIDGE_SCOPE, &pins], |store| {
                if let Some(project_key) = store.project_authority_key(project).map_err(|_| {
                    gaugedesk_store::AdmitError::Rejected(gaugedesk_core::Rejection {
                        reason: "project workflow signing root is unavailable",
                    })
                })? {
                    if project_key.authority_id == issuer {
                        return Ok((
                            gaugedesk_core::ids::PublicKey::new(project_key.public_key),
                            None,
                        ));
                    }
                }
                // Original pre-project-key policies retain their original
                // issuer. New launch policies below always use the project key.
                if issuer == self.authority().as_str() {
                    let key = SigningKey::from_seed(&self.governance_seed()).map_err(|_| {
                        gaugedesk_store::AdmitError::Rejected(gaugedesk_core::Rejection {
                            reason: "local workflow signing root is unavailable",
                        })
                    })?;
                    return Ok((key.public_key(), None));
                }
                store.retained_events(&pins)?;
                let mut pinned = None;
                for row in store.records(&pins, crate::federation::WORKFLOW_SIGNER_PIN_KIND)? {
                    let pin: crate::federation::WorkflowSignerPin = serde_json::from_str(&row)?;
                    if pin.issuer == issuer {
                        pinned = Some(pin.governance_pubkey);
                    }
                }
                if let Some(key) = pinned {
                    return Ok((gaugedesk_core::ids::PublicKey::new(key), None));
                }
                // Read the authoritative roster, including tombstones and revokes.
                // A cached pairing or a key carried by the offer is not this evidence.
                store.retained_events(BRIDGE_SCOPE)?;
                let mut current = None;
                for row in store.records(BRIDGE_SCOPE, "bridge")? {
                    let record: BridgeRecord = serde_json::from_str(&row)?;
                    if record.id == issuer {
                        current = Some(record);
                    }
                }
                let record = current
                    .filter(|record| {
                        record.op == crate::library::RecordOp::Upsert
                            && record.active
                            && record.ticket.authority == issuer
                            && record.ticket.expiry > crate::account::session_now_ms() / 1000
                    })
                    .ok_or(gaugedesk_store::AdmitError::Rejected(
                        gaugedesk_core::Rejection {
                            reason: "original workflow signing authority is not currently trusted",
                        },
                    ))?;
                Ok((
                    gaugedesk_core::ids::PublicKey::new(record.ticket.governance_pubkey),
                    Some(record.ticket.expiry),
                ))
            })
            .map_err(|error| format!("{error:?}"))?;
        let basis = match expiry {
            Some(expiry) => basis.with_deadline(
                std::time::UNIX_EPOCH
                    .checked_add(std::time::Duration::from_secs(expiry))
                    .ok_or("workflow signing trust deadline is invalid")?,
            ),
            None => basis,
        };
        Ok((
            GovernanceRootVerifier::new(gaugedesk_core::ids::AuthorityId::new(issuer), key),
            basis,
        ))
    }
}
