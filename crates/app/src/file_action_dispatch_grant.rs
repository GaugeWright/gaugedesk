//! Explicit, revocable product authority for background use of one native save.
//! References identify a grant; every use authenticates its retained history and
//! current source/target standing inside the ordinary dispatch read basis.
use super::project_signature::{NativeHistoryRoots, ProjectSignature};
use super::*;
use gaugedesk_core::{
    ids::{AuthorityId, HomeId, PublicKey},
    signature::{verify_signature, Signature},
};
use gaugedesk_store::CommandRecordFact;
use gaugedesk_whip_runtime::PolicyEpochRef;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use whipplescript_kernel::gov::canonicalize;

pub(super) const GRANT_KIND: &str = "native_editor_dispatch_grant_v1";
const REVOKE_KIND: &str = "native_editor_dispatch_revocation_v1";
const PROTOCOL: &str = "gaugedesk.native-editor-dispatch-grant.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum Source {
    AccountSession {
        session_ref: String,
    },
    MachineController {
        grant_ref: String,
    },
    OfficeStaff {
        lease_ref: String,
        process_epoch: String,
        admission_ref: String,
    },
}

impl Source {
    fn from_request(context: &AuthenticatedActionContext) -> Result<Self, String> {
        match context.authentication() {
            ActorAuthentication::LocalPersonalTracker => {
                Err("local tracker authority cannot authorize file dispatch".into())
            }
            ActorAuthentication::AccountSession { session_ref } => Ok(Self::AccountSession {
                session_ref: session_ref.clone(),
            }),
            ActorAuthentication::MachineController { grant_ref } => Ok(Self::MachineController {
                grant_ref: grant_ref.clone(),
            }),
            ActorAuthentication::OfficeStaff { authority } => Ok(Self::OfficeStaff {
                lease_ref: authority.source_reference().into(),
                process_epoch: authority.process_epoch().into(),
                admission_ref: authority.admission_reference().into(),
            }),
            ActorAuthentication::IdentityProvider => Err(
                "identity provider has no durable revocable background authentication reference"
                    .into(),
            ),
            ActorAuthentication::NativeEditorDispatchGrant { .. } => {
                Err("a dispatch grant cannot authorize or renew dispatch authority".into())
            }
            ActorAuthentication::ProjectWorkflowInvocation { .. } => {
                Err("workflow authority cannot authorize dispatch authority".into())
            }
        }
    }

    fn current_context(
        &self,
        store: &Store,
        actor: &str,
        live_office: Option<&AuthenticatedActionContext>,
    ) -> Result<AuthenticatedActionContext, AdmitError> {
        match self {
            Self::OfficeStaff { .. } => {
                let context = live_office
                    .filter(|context| context.actor().as_str() == actor)
                    .ok_or_else(|| {
                        invalid("dispatch office source has no exact live Home admission")
                    })?;
                if &Self::from_request(context)
                    .map_err(|_| invalid("invalid live office source"))?
                    != self
                {
                    return Err(invalid(
                        "dispatch office source differs from its live admission",
                    ));
                }
                Ok(context.clone())
            }
            Self::AccountSession { session_ref } => {
                Ok(AuthenticatedActionContext::account_session(
                    AuthorityId::new(actor),
                    session_ref.clone(),
                ))
            }
            Self::MachineController { grant_ref } => {
                let grant = crate::mobile_machine_session::current_action_grant(store, grant_ref)?
                    .ok_or_else(|| invalid("dispatch controller source is not active"))?;
                if grant.device.as_str() != actor {
                    return Err(invalid(
                        "dispatch controller source belongs to another actor",
                    ));
                }
                Ok(AuthenticatedActionContext::machine_controller(&grant))
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProductAdmissionCause {
    scope: String,
    command_id: String,
    fingerprint: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    protocol: String,
    issuer: String,
    home_id: String,
    request_id: String,
    actor: String,
    origin: String,
    policy: PolicyEpochRef,
    original_admission: ProductAdmissionCause,
    source: Source,
    expires_at_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Revocation {
    protocol: String,
    grant_ref: String,
    grant_signature: Signature,
    actor: String,
    origin: String,
    source: Source,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Signed<T> {
    body: T,
    signature: Signature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    project_signature: Option<ProjectSignature>,
}

fn signing_bytes<T: Serialize>(body: &T) -> Result<Vec<u8>, AdmitError> {
    let json =
        serde_json::to_string(body).map_err(|_| invalid("dispatch grant encoding failed"))?;
    let canonical =
        canonicalize(&json).map_err(|_| invalid("dispatch grant canonicalization failed"))?;
    Ok(format!("{PROTOCOL}\n{canonical}").into_bytes())
}

fn sign<T: Serialize>(body: T, key: &SigningKey, project: &str) -> Result<Signed<T>, AdmitError> {
    let frame = ProjectSignature::new(project, key);
    let bytes = frame
        .signing_bytes(&signing_bytes(&body)?)
        .map_err(|_| invalid("native signature frame encoding failed"))?;
    let signature = key.sign(&bytes);
    Ok(Signed {
        body,
        signature,
        project_signature: Some(frame),
    })
}

fn verify<T: Serialize>(value: &Signed<T>, key: &PublicKey) -> Result<(), AdmitError> {
    let bytes = signing_bytes(&value.body)?;
    let bytes = match &value.project_signature {
        Some(frame) => frame
            .signing_bytes(&bytes)
            .map_err(|_| invalid("native signature frame encoding failed"))?,
        None => bytes,
    };
    if !verify_signature(&bytes, &value.signature, key).unwrap_or(false) {
        return Err(invalid("dispatch authority signature is invalid"));
    }
    Ok(())
}

fn fact_root<T>(
    value: &Signed<T>,
    roots: &NativeHistoryRoots,
    store: &Store,
    command: &HostActionCommand,
) -> Result<GovernanceRootVerifier, AdmitError> {
    match &value.project_signature {
        Some(frame) => frame.root(roots, store, command),
        None => roots.original_root(store, command),
    }
    .map_err(|_| invalid("original native fact signer is unavailable"))
}

fn grant_scope(
    home: &HomeId,
    command: &HostActionCommand,
    request_id: &str,
) -> Result<String, AdmitError> {
    if request_id.trim().is_empty() {
        return Err(invalid("dispatch grant request identity is missing"));
    }
    let instance = command
        .instance_ref()
        .map_err(|_| invalid("invalid dispatch command"))?;
    let address = serde_json::to_string(&(home.as_str(), instance, request_id))
        .map_err(|_| invalid("invalid dispatch grant address"))?;
    Ok(format!("native-editor-dispatch:{address}"))
}

/// Signed history plus receipt, not mutable command status or a bare record.
/// A grant namespace holds exactly its grant and optional forward revocation.
fn load_grant(
    store: &Store,
    home: &HomeId,
    command: &HostActionCommand,
    grant_ref: &str,
    roots: &NativeHistoryRoots,
) -> Result<Option<(Signed<Grant>, bool)>, AdmitError> {
    let history = store.retained_events(grant_ref)?;
    let original = store.committed_record_snapshot(grant_ref, "authorize")?;
    let revoked = store.committed_record_snapshot(grant_ref, "revoke")?;
    if history.is_empty() && original.is_none() && revoked.is_none() {
        return Ok(None);
    }
    let original = original.ok_or_else(|| invalid("dispatch grant has no committed receipt"))?;
    let grant: Signed<Grant> = serde_json::from_str(&original)
        .map_err(|_| invalid("dispatch grant snapshot is invalid"))?;
    verify(
        &grant,
        fact_root(&grant, roots, store, command)?.expected_key(),
    )?;
    let data = &grant.body;
    let command_id = store
        .command_for_key(&data.original_admission.scope, &command.request_id)?
        .ok_or_else(|| invalid("dispatch grant has no original product command"))?
        .command_id;
    if data.protocol != PROTOCOL
        || data.origin != "editor.save.dispatch.authorize"
        || data.issuer != command.issuer
        || data.home_id != home.as_str()
        || data.actor != command.provenance.initiator
        || data.actor != command.provenance.executor
        || data.policy != command.policy
        || data.original_admission.scope
            != command
                .instance_ref()
                .map_err(|_| invalid("invalid dispatch command"))?
        || data.original_admission.fingerprint
            != command
                .fingerprint()
                .map_err(|_| invalid("invalid dispatch command"))?
        || data.original_admission.command_id != command_id
        || grant_scope(home, command, &data.request_id)? != grant_ref
        || matches!(
            data.source,
            Source::AccountSession { .. } | Source::OfficeStaff { .. }
        ) != data.expires_at_ms.is_some()
        || history.first() != Some(&(0, GRANT_KIND.into(), original))
    {
        return Err(invalid("dispatch grant differs from its exact admission"));
    }
    match (history.as_slice(), revoked) {
        ([_], None) => Ok(Some((grant, false))),
        ([_, (1, kind, payload)], Some(snapshot))
            if kind == REVOKE_KIND && payload == &snapshot =>
        {
            let revocation: Signed<Revocation> = serde_json::from_str(&snapshot)
                .map_err(|_| invalid("dispatch revocation snapshot is invalid"))?;
            verify(
                &revocation,
                fact_root(&revocation, roots, store, command)?.expected_key(),
            )?;
            let data = &revocation.body;
            if data.protocol != PROTOCOL
                || data.origin != "editor.save.dispatch.revoke"
                || data.grant_ref != grant_ref
                || data.grant_signature != grant.signature
                || data.actor != grant.body.actor
            {
                return Err(invalid("dispatch revocation differs from its grant"));
            }
            Ok(Some((grant, true)))
        }
        _ => Err(invalid(
            "dispatch grant history is incomplete or contradictory",
        )),
    }
}

pub(super) struct GrantedAuthentication<'a> {
    pub context: &'a AuthenticatedActionContext,
    pub live_office: Option<&'a AuthenticatedActionContext>,
}

/// Inspect only a verified grant to discover its process-local office parent.
/// Current grant/source standing is checked again in the fenced read below.
/// Missing live authority never becomes a reconstructed account session.
pub(super) fn live_office_source(
    wb: &Workbench,
    command: &HostActionCommand,
    grant_ref: &str,
    roots: &NativeHistoryRoots,
) -> Result<Option<AuthenticatedActionContext>, AdmitError> {
    let (grant, revoked) = load_grant(wb.store_ref(), wb.home_id(), command, grant_ref, roots)?
        .ok_or_else(|| invalid("dispatch grant is not admitted"))?;
    if revoked {
        return Err(invalid("dispatch grant is revoked"));
    }
    match &grant.body.source {
        Source::OfficeStaff {
            lease_ref,
            process_epoch,
            admission_ref,
        } => wb
            .office_staff_dispatch_context(
                &grant.body.actor,
                lease_ref,
                process_epoch,
                admission_ref,
            )
            .map(Some)
            .ok_or_else(|| invalid("dispatch office source has no exact live Home admission")),
        _ => Ok(None),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn current_granted_authority(
    store: &Store,
    home: &HomeId,
    owners: &crate::project_owner::ProjectOwnerResolver,
    authentication: GrantedAuthentication<'_>,
    grant_ref: &str,
    command: &HostActionCommand,
    request: &EditorFileSave<'_>,
    roots: &NativeHistoryRoots,
) -> Result<(FileAuthority, ActionCause), AdmitError> {
    let (grant, revoked) = load_grant(store, home, command, grant_ref, roots)?
        .ok_or_else(|| invalid("dispatch grant is not admitted"))?;
    if revoked || authentication.context.actor().as_str() != grant.body.actor {
        return Err(invalid(
            "dispatch grant is revoked or belongs to another actor",
        ));
    }
    let source =
        grant
            .body
            .source
            .current_context(store, &grant.body.actor, authentication.live_office)?;
    let mut authority = current_authority(store, home, owners, &source, request)?;
    if let Some(ceiling) = grant.body.expires_at_ms {
        if ceiling <= crate::account::session_now_ms() {
            return Err(invalid("dispatch grant has expired"));
        }
        authority.valid_until_ms = Some(
            authority
                .valid_until_ms
                .map_or(ceiling, |live| live.min(ceiling)),
        );
    }
    Ok((authority, grant_cause(&grant)?))
}

/// The original grant admission is immutable; later revocation does not change
/// its digest or the cause an earlier operation recorded.
fn grant_cause(grant: &Signed<Grant>) -> Result<ActionCause, AdmitError> {
    let data = &grant.body;
    let scope = format!(
        "native-editor-dispatch:{}",
        serde_json::to_string(&(
            &data.home_id,
            &data.original_admission.scope,
            &data.request_id,
        ))
        .map_err(|_| invalid("invalid grant cause"))?
    );
    let serialized = serde_json::to_string(grant).map_err(|_| invalid("invalid grant cause"))?;
    let canonical = canonicalize(&serialized).map_err(|_| invalid("invalid grant cause"))?;
    let mut bytes = b"gaugedesk:native-editor-dispatch-grant:evidence:v1\0".to_vec();
    bytes.extend_from_slice(canonical.as_bytes());
    Ok(ActionCause {
        authority: grant
            .project_signature
            .as_ref()
            .map_or_else(|| data.issuer.clone(), |frame| frame.authority().into()),
        record_ref: serde_json::to_string(&(PROTOCOL, scope, "authorize"))
            .map_err(|_| invalid("invalid grant cause"))?,
        digest: Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    })
}

pub(super) fn with_grant_cause(
    mut original: ActionProvenance,
    cause: Option<&ActionCause>,
) -> ActionProvenance {
    if let Some(cause) = cause {
        original.causes.push(cause.clone());
    }
    original
}

/// A sibling of the actual product store for bounded reads under its writer
/// fence. This proves past causes, never present permission to execute. Grant
/// revocation/expiration does not rewrite a historical operation's authorship.
pub(super) struct NativeDispatchHistory {
    pub(super) store: Store,
    home: HomeId,
    pub(super) roots: NativeHistoryRoots,
}

impl NativeDispatchHistory {
    pub(super) fn open(wb: &Workbench) -> Result<Self, String> {
        Ok(Self {
            store: wb.store_ref().sibling().map_err(|e| format!("{e:?}"))?,
            home: wb.home_id().clone(),
            roots: NativeHistoryRoots::open(wb)?,
        })
    }

    pub(super) fn verify(
        &self,
        command: &HostActionCommand,
        actual: &ActionProvenance,
        original: &ActionProvenance,
    ) -> Result<(), AdmitError> {
        if actual == original {
            return Ok(());
        }
        let cause = actual
            .causes
            .last()
            .ok_or_else(|| invalid("missing historical dispatch cause"))?;
        if actual != &with_grant_cause(original.clone(), Some(cause)) {
            return Err(invalid(
                "historical dispatch provenance differs from the original actor or causes",
            ));
        }
        let (protocol, scope, act): (String, String, String) =
            serde_json::from_str(&cause.record_ref)
                .map_err(|_| invalid("invalid historical dispatch cause"))?;
        if protocol != PROTOCOL || act != "authorize" {
            return Err(invalid("unsupported historical dispatch cause"));
        }
        let (grant, _) = load_grant(&self.store, &self.home, command, &scope, &self.roots)?
            .ok_or_else(|| invalid("historical dispatch grant is unavailable"))?;
        if cause != &grant_cause(&grant)? {
            return Err(invalid(
                "historical dispatch cause differs from its signed grant",
            ));
        }
        Ok(())
    }
}

/// Durable address returned by grant admission; it carries no credential.
#[derive(Debug, PartialEq, Eq)]
pub struct NativeEditorDispatchGrant {
    pub grant_ref: String,
    pub replayed: bool,
}

/// Scoped observation for a native driver. No public authenticated-context
/// accessor: callers cannot turn background authority into command admission.
/// Every native operation revalidates it; retaining this value grants nothing.
/// ```compile_fail
/// use gaugedesk_app::{file_action_factory::NativeEditorDispatchAuthority,
///     identity::AuthenticatedActionContext};
/// fn extract(authority: NativeEditorDispatchAuthority) -> AuthenticatedActionContext {
///     authority.context
/// }
/// ```
pub struct NativeEditorDispatchAuthority {
    pub(super) context: AuthenticatedActionContext,
}

impl Workbench {
    /// Resolve a discovery hint against its signed grant and committed outbox.
    /// Current execution standing is still checked separately by the driver.
    pub(super) fn discover_editor_file_save_dispatch(
        &mut self,
        grant_ref: &str,
    ) -> Result<Option<HostActionCommand>, String> {
        let resolve = || -> Result<_, AdmitError> {
            let snapshot = self
                .store_ref()
                .committed_record_snapshot(grant_ref, "authorize")?
                .ok_or_else(|| invalid("discovered dispatch grant has no committed receipt"))?;
            let grant: Signed<Grant> = serde_json::from_str(&snapshot)?;
            let record = self
                .store_ref()
                .command(&grant.body.original_admission.command_id)?
                .ok_or_else(|| invalid("discovered dispatch grant has no original command"))?;
            Ok(record)
        };
        let record = resolve().map_err(|e| format!("{e:?}"))?;
        let delivery = self
            .store_mut()
            .committed_dispatch::<ProductActionAdmission>(&record.scope_id, &record.idempotency_key)
            .map_err(|e| format!("{e:?}"))?
            .ok_or("discovered dispatch grant has no committed outbox")?;
        let (_, revoked) = load_grant(
            self.store_ref(),
            self.home_id(),
            &delivery.command,
            grant_ref,
            &NativeHistoryRoots::open(self)?,
        )
        .map_err(|e| format!("{e:?}"))?
        .ok_or("discovered dispatch grant is unavailable")?;
        Ok((!revoked).then_some(delivery.command))
    }

    /// A new product act by the original authenticated actor. This neither
    /// delivers nor executes the command. A different authentication source or
    /// renewed grant requires a new stable grant request identity.
    pub fn authorize_editor_file_save_dispatch(
        &mut self,
        context: &AuthenticatedActionContext,
        inputs: &NativeActionInputCustody,
        command: &HostActionCommand,
        request_id: &str,
    ) -> Result<NativeEditorDispatchGrant, String> {
        let source = Source::from_request(context)?;
        let scope =
            grant_scope(self.home_id(), command, request_id).map_err(|e| format!("{e:?}"))?;
        let mut prepared = self.prepare_native_editor_action_scoped(
            context,
            inputs,
            command,
            &command.policy,
            &[&scope],
            NativeActionAccess::Mutate,
        )?;
        let previous = load_grant(
            self.store_ref(),
            self.home_id(),
            command,
            &scope,
            &NativeHistoryRoots::open(self)?,
        )
        .map_err(|e| format!("{e:?}"))?;
        if previous.as_ref().is_some_and(|(_, revoked)| *revoked) {
            return Err(
                "dispatch grant was revoked; a fresh authenticated grant request is required"
                    .into(),
            );
        }
        let expires_at_ms = prepared
            .basis
            .deadline()
            .map(|time| {
                time.duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| "invalid dispatch deadline".to_owned())
                    .and_then(|duration| {
                        u64::try_from(duration.as_millis())
                            .map_err(|_| "invalid dispatch deadline".to_owned())
                    })
            })
            .transpose()?;
        // A retry retains the originally admitted ceiling even if the same
        // authentication record now allows a longer session. It cannot renew
        // an expired grant, and a shorter current ceiling still wins.
        let expires_at_ms = previous
            .as_ref()
            .map_or(expires_at_ms, |(old, _)| old.body.expires_at_ms);
        if let Some(ceiling) = expires_at_ms {
            let deadline = std::time::UNIX_EPOCH
                .checked_add(std::time::Duration::from_millis(ceiling))
                .ok_or("dispatch grant deadline is out of range")?;
            prepared.basis = prepared.basis.with_deadline(deadline);
        }
        let body = Grant {
            protocol: PROTOCOL.into(),
            issuer: command.issuer.clone(),
            home_id: self.home_id().as_str().into(),
            request_id: request_id.into(),
            actor: context.actor().as_str().into(),
            origin: "editor.save.dispatch.authorize".into(),
            policy: command.policy.clone(),
            original_admission: ProductAdmissionCause {
                scope: prepared.scope,
                command_id: prepared.delivery.command_id,
                fingerprint: command.fingerprint().map_err(|e| format!("{e:?}"))?,
            },
            source,
            expires_at_ms,
        };
        let grant = match previous {
            Some((old, _)) if old.body == body => old,
            Some(_) => {
                return Err(
                    "dispatch grant request identity was reused with changed meaning".into(),
                )
            }
            None => sign(body, &prepared.key, &prepared.authority.project_id)
                .map_err(|e| format!("{e:?}"))?,
        };
        let payload = serde_json::to_string(&grant).map_err(|e| e.to_string())?;
        let receipt = self
            .store_mut()
            .with_dispatch_record_admission(&prepared.basis, |writer| {
                writer.commit(
                    &scope,
                    "authorize",
                    &payload,
                    &[CommandRecordFact {
                        scope_id: scope.clone(),
                        kind: GRANT_KIND.into(),
                        payload: payload.clone(),
                    }],
                )
            })
            .map_err(|e| format!("{e:?}"))?
            .map_err(|e| format!("{e:?}"))?;
        let _ = self.native_editor_dispatch_changed.send(scope.clone());
        Ok(NativeEditorDispatchGrant {
            grant_ref: scope,
            replayed: receipt.replayed,
        })
    }

    /// Forward-only revocation by a fresh authenticated context for the same
    /// original actor. A scoped background context cannot perform this ceremony.
    pub fn revoke_editor_file_save_dispatch(
        &mut self,
        context: &AuthenticatedActionContext,
        inputs: &NativeActionInputCustody,
        command: &HostActionCommand,
        grant_ref: &str,
    ) -> Result<(), String> {
        let source = Source::from_request(context)?;
        let prepared = self.prepare_native_editor_action_scoped(
            context,
            inputs,
            command,
            &command.policy,
            &[grant_ref],
            NativeActionAccess::Inspect,
        )?;
        let (grant, revoked) = load_grant(
            self.store_ref(),
            self.home_id(),
            command,
            grant_ref,
            &NativeHistoryRoots::open(self)?,
        )
        .map_err(|e| format!("{e:?}"))?
        .ok_or("dispatch grant is not admitted")?;
        if revoked {
            self.store_mut()
                .with_dispatch_basis(&prepared.basis, || ())
                .map_err(|e| format!("{e:?}"))?;
            let _ = self.native_editor_dispatch_changed.send(grant_ref.into());
            return Ok(());
        }
        let record = sign(
            Revocation {
                protocol: PROTOCOL.into(),
                grant_ref: grant_ref.into(),
                grant_signature: grant.signature,
                actor: context.actor().as_str().into(),
                origin: "editor.save.dispatch.revoke".into(),
                source,
            },
            &prepared.key,
            &prepared.authority.project_id,
        )
        .map_err(|e| format!("{e:?}"))?;
        let payload = serde_json::to_string(&record).map_err(|e| e.to_string())?;
        self.store_mut()
            .with_dispatch_record_admission(&prepared.basis, |writer| {
                writer.commit(
                    grant_ref,
                    "revoke",
                    &payload,
                    &[CommandRecordFact {
                        scope_id: grant_ref.into(),
                        kind: REVOKE_KIND.into(),
                        payload: payload.clone(),
                    }],
                )
            })
            .map_err(|e| format!("{e:?}"))?
            .map_err(|e| format!("{e:?}"))?;
        let _ = self.native_editor_dispatch_changed.send(grant_ref.into());
        Ok(())
    }

    /// Resolve a retained address after restart. This observes current authority
    /// but grants no interval of unchecked execution; the driver must pass this
    /// scoped context through native preparation for every subsequent operation.
    /// An office source additionally requires the original running Home epoch
    /// and exact live admission; its stored address cannot recreate either.
    pub fn load_editor_file_save_dispatch_authority(
        &mut self,
        inputs: &NativeActionInputCustody,
        command: &HostActionCommand,
        grant_ref: &str,
    ) -> Result<NativeEditorDispatchAuthority, String> {
        let authority = NativeEditorDispatchAuthority {
            context: AuthenticatedActionContext::native_editor_dispatch_grant(
                AuthorityId::new(&command.provenance.initiator),
                grant_ref.into(),
            ),
        };
        let prepared = self.prepare_native_editor_action(
            &authority.context,
            inputs,
            command,
            &command.policy,
        )?;
        self.store_mut()
            .with_dispatch_basis(&prepared.basis, || ())
            .map_err(|e| format!("{e:?}"))?;
        Ok(authority)
    }
}

#[cfg(test)]
#[path = "file_action_dispatch_grant_tests.rs"]
mod tests;
