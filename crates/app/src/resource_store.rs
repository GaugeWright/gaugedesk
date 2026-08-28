//! Durable, engagement-scoped resource-metadata records (`data.md`).
//!
//! A [`ResourceRecord`] is a declarative fact, not lifecycle state: we persist it
//! as an append-only record (`kind = "resource"`) in the **engagement's** scope —
//! taint is engagement-scoped (ADR 0026), so a context resource opened into an
//! engagement is an engagement-scoped fact — and fold it **latest-wins by
//! `ResourceId`** into the current view, exactly as [`crate::library`] folds the
//! library. A newer write for the same id supersedes the older (a rename, a
//! re-ingest, or a [`tombstone`] all fall out of "append a newer record"); the full
//! history is preserved in the log (`INV-6`).
//!
//! Unlike the library's `Tombstone` op, a resource tombstone does **not** remove
//! the record: per [[content-erasure]] the handle, metadata, and history remain
//! while future payload resolution is blocked (`INV-18`). So the tombstone is a
//! `tombstoned: true` revision, still listed.

use std::collections::{BTreeMap, BTreeSet};

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use gaugedesk_core::abac::{
    permitted_with_policy, Action, AuthorityAttributes, Context, Decision, Policy,
    ResourceAttributes,
};
use gaugedesk_core::attestation::{AttestationEvidence, CodeMeasurement};
use gaugedesk_core::boundary::Authority;
use gaugedesk_core::content_erasure::{
    ErasureCommand, ErasurePhase, ErasureState, OWNER as ERASURE_OWNER,
};
use gaugedesk_core::key_release::{
    EntitlementProof, EntitlementVerdict, KeyReleaseDecision, KeyReleaseRequest,
};
use gaugedesk_core::resource::{
    ContentLocator, Resource, ResourceId, ResourceKind, ResourceRecord,
};
use gaugedesk_core::resource_access::{AccessCommand, AccessPhase, AccessState};
use gaugedesk_core::resource_export::{ExportCommand, ExportPhase, ExportState};
use gaugedesk_core::review::{ReviewCommand, ReviewPhase, ReviewState};
use gaugedesk_core::taint::EngagementReads;
use gaugedesk_store::{AdmitError, Store};
use serde::Deserialize;

use crate::boundary_keeper::SealedKeyReleaseService;
use crate::stream::ServerEvent;
use crate::{
    command_idempotency::caller_idempotency_key, err_response, library::Library, net_http,
    LockUnpoisoned, SharedWorkbench, Workbench,
};

/// The record kind under which resource metadata is stored in an engagement scope.
const RESOURCE_KIND: &str = "resource";

fn is_target_payload_path(path: &str) -> bool {
    path != gaugedesk_boundary::definition::CONFIG_PATH
        && path != gaugedesk_boundary::definition::RUNTIME_MOUNT_ROOT
        && !path.starts_with(&format!(
            "{}/",
            gaugedesk_boundary::definition::RUNTIME_MOUNT_ROOT
        ))
}
/// The record kind under which a turn's resource **reads** are durably accumulated
/// (engagement-scoped taint, `taint::EngagementReads`).
const READ_KIND: &str = "read";
/// The record kind under which sealed-key **release grants** are durably recorded
/// (engagement-scoped, ATTEST-6): the audit fact that a sealed key was released to
/// an attested host, never the key bytes themselves.
const KEY_RELEASE_KIND: &str = "key-release-grant";
const ATTESTED_RUN_METER_KIND: &str = "attested-run-meter";

/// The deterministic, **URL-safe** handle for a context folder: re-ingesting the
/// same folder updates the same resource (latest-wins) rather than minting a
/// duplicate, and the handle rides a `:rid` route segment unescaped. Non-alphanumeric
/// path characters collapse to `-` (distinct real folders stay distinct).
pub fn context_id(path: &str) -> ResourceId {
    let slug: String = path
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    ResourceId::new(format!("ctx-{}", slug.trim_matches('-')))
}

/// The per-resource scope holding that resource's access lifecycle. A scope is one
/// lifecycle instance (ADR 0006), so each resource's [[resource-access]] gets its
/// own scope — distinct from the engagement scope that holds the resource records.
pub fn access_scope(engagement: &str, id: &ResourceId) -> String {
    format!("{engagement}::access::{}", id.as_str())
}

/// The per-resource scope holding that resource's [[content-erasure]] lifecycle.
pub fn erasure_scope(engagement: &str, id: &ResourceId) -> String {
    format!("{engagement}::erasure::{}", id.as_str())
}

/// The internal per-resource scope holding that resource's
/// [[resource-export]] lifecycle. Product callers address the resource, never
/// this coordinator-owned scope id.
pub fn export_scope(engagement: &str, id: &ResourceId) -> String {
    format!("{engagement}-export-{}", id.as_str())
}

/// The internal per-resource scope holding that resource's [[review]] lifecycle.
pub fn review_scope(engagement: &str, id: &ResourceId) -> String {
    format!("{engagement}-review-{}", id.as_str())
}

/// Caller-selectable review decisions on a concrete resource. Identity is
/// deliberately absent: the admission shell materializes it from the request.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ResourceReviewAction {
    Consent,
    Reject,
    Revoke,
    Release,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResourceReviewCommandBody {
    action: ResourceReviewAction,
}

/// Caller-selectable source decisions on a concrete resource export. Target
/// admission and the final `Export` fact belong to the actual egress handler.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ResourceExportAction {
    Consent,
    Reject,
    Revoke,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResourceExportCommandBody {
    action: ResourceExportAction,
}

/// The engagement's derived **output** resource handle (one per engagement,
/// refreshed each turn).
pub fn output_id(engagement: &str) -> ResourceId {
    ResourceId::new(format!("out-{engagement}"))
}

/// Persist a resource record (a new latest-wins revision for its `ResourceId`).
pub fn put(store: &mut Store, scope: &str, record: &ResourceRecord) -> Result<(), AdmitError> {
    let payload = serde_json::to_string(record)?;
    store.append_record(scope, RESOURCE_KIND, &payload)?;
    Ok(())
}

/// Every resource in a scope at its current revision, latest-wins by `ResourceId`.
/// Tombstoned records are included (the handle persists; see module docs).
pub fn list(store: &Store, scope: &str) -> Result<Vec<ResourceRecord>, AdmitError> {
    let mut latest: BTreeMap<String, ResourceRecord> = BTreeMap::new();
    for row in store.records(scope, RESOURCE_KIND)? {
        let rec: ResourceRecord = serde_json::from_str(&row)?;
        // records() is position-ordered (oldest→newest), so a later insert wins.
        latest.insert(rec.resource.id.as_str().to_string(), rec);
    }
    Ok(latest.into_values().collect())
}

/// The current revision of one resource by handle, if present.
pub fn get(
    store: &Store,
    scope: &str,
    id: &ResourceId,
) -> Result<Option<ResourceRecord>, AdmitError> {
    Ok(list(store, scope)?
        .into_iter()
        .find(|r| &r.resource.id == id))
}

/// Mint a durable `context` resource for an opened folder and **auto-grant** access
/// (trust-by-default, `context.md`): in the single-user collapse the local owner
/// both requires and approves the access, so its [[resource-access]] lifecycle
/// reaches `Granted`. Persists the record in the engagement scope and the access
/// events in the per-resource access scope. Returns the record.
pub fn mint_context(
    store: &mut Store,
    engagement: &str,
    owner: &str,
    path: &str,
    commit: &str,
) -> Result<ResourceRecord, AdmitError> {
    mint_context_with(
        store,
        engagement,
        owner,
        path,
        commit,
        ResourceAttributes::default(),
    )
}

/// As [`mint_context`] but stamping the resource's ABAC [`ResourceAttributes`] at
/// ingest (`SECAUD-5`, SOC 2 Confidentiality C1.1): the classification / data-residency
/// region the operator labels the source with. The ABAC floor ([`abac_permits`]) then
/// enforces those attributes on egress (e.g. `Pii` ⇒ attested-same-region for export).
/// `mint_context` is this with the fail-closed default (`Regulated`, no region).
pub fn mint_context_with(
    store: &mut Store,
    engagement: &str,
    owner: &str,
    path: &str,
    commit: &str,
    attributes: ResourceAttributes,
) -> Result<ResourceRecord, AdmitError> {
    let id = context_id(path);
    let res = Resource::input(id.clone(), ResourceKind::context(), Authority::from(owner));
    let rec = ResourceRecord::new(
        res,
        ContentLocator::Workspace {
            path: path.to_string(),
            commit: commit.to_string(),
        },
        |_| Authority::from(owner),
    )
    .with_attributes(attributes);
    put(store, engagement, &rec)?;

    // Trust-by-default grant: the single local owner requires and approves itself.
    // Idempotent — re-ingesting the same folder updates the record but leaves the
    // already-granted access untouched (a fresh request would be rejected).
    let scope = access_scope(engagement, &id);
    if store.fold::<AccessState>(&scope)?.phase == AccessPhase::Init {
        let required: BTreeSet<Authority> = BTreeSet::from([Authority::from(owner)]);
        store.admit::<AccessState>(&scope, AccessCommand::RequestAccess { required })?;
        store.admit::<AccessState>(&scope, AccessCommand::Approve(Authority::from(owner)))?;
    }
    Ok(rec)
}

/// The current access phase of a resource, folded from its access scope.
pub fn access_phase(
    store: &Store,
    engagement: &str,
    id: &ResourceId,
) -> Result<AccessPhase, AdmitError> {
    Ok(store
        .fold::<AccessState>(&access_scope(engagement, id))?
        .phase)
}

/// **Explicitly request** access to a resource (`CORE-3`): the `required` authorities must
/// each approve before the payload is accessible (`INV-13`). This is the **multi-party** path
/// — the single-user collapse uses the trust-by-default auto-grant in [`mint_context`].
/// Returns the resulting phase. Drives the [`resource-access`] reducer in the per-resource
/// access scope, so the `(decide, evolve)` gating (only `Init` may request) is authoritative.
pub fn request_access(
    store: &mut Store,
    engagement: &str,
    id: &ResourceId,
    required: BTreeSet<Authority>,
) -> Result<AccessPhase, AdmitError> {
    let scope = access_scope(engagement, id);
    store.admit::<AccessState>(&scope, AccessCommand::RequestAccess { required })?;
    Ok(store.fold::<AccessState>(&scope)?.phase)
}

/// **Approve** a pending access request as `approver` (`CORE-3`): once every required
/// authority has approved, the reducer emits `Granted` and the payload becomes accessible.
pub fn approve_access(
    store: &mut Store,
    engagement: &str,
    id: &ResourceId,
    approver: Authority,
) -> Result<AccessPhase, AdmitError> {
    let scope = access_scope(engagement, id);
    store.admit::<AccessState>(&scope, AccessCommand::Approve(approver))?;
    Ok(store.fold::<AccessState>(&scope)?.phase)
}

/// **Revoke** a granted access (`CORE-3`/`INV-18`): future-only — the grant stops admitting,
/// but already-released payloads are not recalled. Returns the resulting phase.
pub fn revoke_access(
    store: &mut Store,
    engagement: &str,
    id: &ResourceId,
) -> Result<AccessPhase, AdmitError> {
    let scope = access_scope(engagement, id);
    store.admit::<AccessState>(&scope, AccessCommand::Revoke)?;
    Ok(store.fold::<AccessState>(&scope)?.phase)
}

/// The context resources a turn may read right now: `context`-kind, granted, and
/// not tombstoned. The engine records these as the turn's reads.
pub fn granted_context(store: &Store, engagement: &str) -> Result<Vec<ResourceId>, AdmitError> {
    let mut out = Vec::new();
    for r in list(store, engagement)? {
        if r.resource.kind == ResourceKind::context()
            && !r.tombstoned
            && access_phase(store, engagement, &r.resource.id)? == AccessPhase::Granted
        {
            out.push(r.resource.id);
        }
    }
    Ok(out)
}

/// Translate WhippleScript's certified host-output flow signature back into
/// GaugeDesk resource identities. `project` is the admitted workspace view and
/// therefore expands to the currently granted context records; command, human,
/// and turn-image capabilities are runtime inputs but not GaugeDesk data records.
pub fn certified_output_reads(
    store: &Store,
    engagement: &str,
    signature: &[gaugedesk_harness::OutputFieldFlow],
) -> Result<Vec<ResourceId>, AdmitError> {
    let mut reads = BTreeSet::new();
    let granted = granted_context(store, engagement)?;
    for handle in signature.iter().flat_map(|field| field.read_handles.iter()) {
        match handle.as_str() {
            "project" => reads.extend(granted.iter().cloned()),
            "command" | "human" | "turn_images" => {}
            handle if handle.starts_with("resource:") => {
                let id = ResourceId::new(handle.trim_start_matches("resource:"));
                if granted.contains(&id) {
                    reads.insert(id);
                }
            }
            // A future WhippleScript data-bearing handle must never silently
            // under-taint an output before GaugeDesk learns its product mapping.
            // Conservatively inherit every granted context (fail closed).
            _ => reads.extend(granted.iter().cloned()),
        }
    }
    Ok(reads.into_iter().collect())
}

/// Durably record a turn's reads (engagement-scoped, `taint::EngagementReads`):
/// each id is appended under the `read` kind. Folding dedups, so a re-read is
/// harmless; the accumulation **survives** a later revoke/tombstone of the read
/// resource — a past read still taints (the per-run-taint tooth would leak here).
pub fn record_reads(
    store: &mut Store,
    engagement: &str,
    ids: &[ResourceId],
) -> Result<(), AdmitError> {
    for id in ids {
        store.append_record(engagement, READ_KIND, id.as_str())?;
    }
    Ok(())
}

/// The engagement's accumulated read-set, folded into the verified
/// [`EngagementReads`] across every turn.
pub fn engagement_reads(store: &Store, engagement: &str) -> Result<EngagementReads, AdmitError> {
    let mut reads = EngagementReads::new();
    for id in store.records(engagement, READ_KIND)? {
        reads.read(id);
    }
    Ok(reads)
}

/// The stakeholders of everything the engagement has read, **beyond `owner`** —
/// the read-side taint guard the advancement policy consults (ATTN-3, ADR 0082
/// §4). Non-empty means the turn's outputs carry someone else's stake and must
/// never auto-advance. Fail-closed: a read whose owner can't be resolved (a
/// tombstoned or unknown record) surfaces as `"<unresolved>"` rather than
/// disappearing.
pub fn external_read_stakeholders(
    store: &Store,
    engagement: &str,
    owner: &str,
) -> Result<Vec<String>, AdmitError> {
    let reads = engagement_reads(store, engagement)?;
    let owners: BTreeMap<String, Authority> = list(store, engagement)?
        .into_iter()
        .map(|r| (r.resource.id.as_str().to_string(), r.resource.owner))
        .collect();
    Ok(reads
        .taint(|item| {
            owners
                .get(item)
                .map(|a| a.as_str().to_string())
                .unwrap_or_else(|| "<unresolved>".to_string())
        })
        .into_iter()
        .filter(|a| a != owner)
        .collect())
}

/// Mint/refresh the engagement's derived **output** resource from the durable,
/// engagement-scoped read-set: its provenance is everything the engagement has
/// **read** (across all turns), and its stakeholders are the owners of those reads
/// (`taint::EngagementReads::taint`). Because owners are resolved from the persisted
/// records — which survive revoke/tombstone — a context read in an earlier turn
/// still taints an output produced later (engagement-scoped soundness, ADR 0026).
pub fn mint_output(
    store: &mut Store,
    engagement: &str,
    owner: &str,
    commit: &str,
) -> Result<ResourceRecord, AdmitError> {
    let reads = engagement_reads(store, engagement)?;
    // Owner lookup over every persisted record (tombstoned ones included), so a
    // past read still resolves to its owner after the resource is revoked/erased.
    let owners: BTreeMap<String, Authority> = list(store, engagement)?
        .into_iter()
        .map(|r| (r.resource.id.as_str().to_string(), r.resource.owner))
        .collect();
    // `EngagementReads::taint` is String-keyed; bridge its result into the typed
    // authority set the boundary expects (the owner oracle yields the owner's id string).
    let stakeholders: BTreeSet<Authority> = reads
        .taint(|item| {
            owners
                .get(item)
                .map(|a| a.as_str().to_string())
                .unwrap_or_default()
        })
        .into_iter()
        .map(Authority::from)
        .collect();
    let provenance: BTreeSet<ResourceId> = reads
        .items()
        .iter()
        .map(|s| ResourceId::new(s.clone()))
        .collect();
    let resource = Resource::derived(output_id(engagement), Authority::from(owner), provenance);
    let rec = ResourceRecord {
        resource,
        stakeholders,
        locator: ContentLocator::Workspace {
            path: String::new(),
            commit: commit.to_string(),
        },
        tombstoned: false,
        // A derived output inherits the fail-closed default classification; a real
        // declassification/labeling step (review) would set tighter attributes.
        attributes: ResourceAttributes::default(),
    };
    put(store, engagement, &rec)?;
    Ok(rec)
}

/// Tombstone a resource's payload via the [[content-erasure]] lifecycle: drive it
/// to `Tombstoned` (request → owner-approve → tombstone) in the per-resource
/// erasure scope, then append a `tombstoned: true` record revision. The
/// record/handle/history remain; only future payload resolution is blocked
/// (`INV-18`/`INV-6`). Returns `false` if no such resource exists. Idempotent: a
/// second call leaves the already-tombstoned erasure lifecycle untouched.
pub fn tombstone(store: &mut Store, engagement: &str, id: &ResourceId) -> Result<bool, AdmitError> {
    let Some(mut rec) = get(store, engagement, id)? else {
        return Ok(false);
    };
    let scope = erasure_scope(engagement, id);
    if store.fold::<ErasureState>(&scope)?.phase != ErasurePhase::Tombstoned {
        store.admit::<ErasureState>(&scope, ErasureCommand::RequestErasure)?;
        store.admit::<ErasureState>(
            &scope,
            ErasureCommand::Approve(Authority::from(ERASURE_OWNER)),
        )?;
        store.admit::<ErasureState>(&scope, ErasureCommand::Tombstone)?;
    }
    rec.tombstoned = true;
    put(store, engagement, &rec)?;
    Ok(true)
}

impl Workbench {
    /// Count pending output reviews for one authority without returning any
    /// engagement, resource, review, or content metadata. The Console uses this
    /// only after target-Home admission, then discards that admission.
    pub(crate) fn review_notification_count(
        &self,
        actor: &gaugedesk_core::ids::AuthorityId,
    ) -> Result<usize, AdmitError> {
        let actor = Authority::from(actor.as_str());
        let library = Library::rebuild(self.store_ref())?;
        let mut count = 0;
        for chat_id in library.chats.keys() {
            for (record, _) in self.list_resource_contexts(chat_id)? {
                if record.tombstoned || record.resource.kind != ResourceKind::output() {
                    continue;
                }
                let review = self.review_state(&review_scope(chat_id, &record.resource.id))?;
                if review.phase == ReviewPhase::Proposed
                    && review.required.contains(&actor)
                    && !review.consented.contains(&actor)
                {
                    count += 1;
                }
            }
        }
        Ok(count)
    }

    /// Mint/refresh a context resource inside this workbench's durable store.
    pub fn mint_resource_context(
        &mut self,
        chat_id: &str,
        owner: &str,
        path: &str,
        commit: &str,
        attributes: ResourceAttributes,
    ) -> Result<ResourceRecord, AdmitError> {
        mint_context_with(self.store_mut(), chat_id, owner, path, commit, attributes)
    }

    /// Current resource records with their folded access phase.
    pub fn list_resource_contexts(
        &self,
        chat_id: &str,
    ) -> Result<Vec<(ResourceRecord, AccessPhase)>, AdmitError> {
        let store = self.store_ref();
        list(store, chat_id)?
            .into_iter()
            .map(|record| {
                let phase =
                    access_phase(store, chat_id, &record.resource.id).unwrap_or(AccessPhase::Init);
                Ok((record, phase))
            })
            .collect()
    }

    /// Current revision of one resource handle.
    pub fn resource_context(
        &self,
        chat_id: &str,
        resource_id: &ResourceId,
    ) -> Result<Option<ResourceRecord>, AdmitError> {
        get(self.store_ref(), chat_id, resource_id)
    }

    /// Folded access phase for one resource handle.
    pub fn resource_access_phase(
        &self,
        chat_id: &str,
        resource_id: &ResourceId,
    ) -> Result<AccessPhase, AdmitError> {
        access_phase(self.store_ref(), chat_id, resource_id)
    }

    /// Tombstone a resource payload while preserving its handle/history.
    pub fn tombstone_resource_context(
        &mut self,
        chat_id: &str,
        resource_id: &ResourceId,
    ) -> Result<bool, AdmitError> {
        tombstone(self.store_mut(), chat_id, resource_id)
    }

    /// Drive the explicit resource-access request reducer.
    pub fn request_resource_access(
        &mut self,
        chat_id: &str,
        resource_id: &ResourceId,
    ) -> Result<Option<AccessPhase>, AdmitError> {
        let Some(record) = self.resource_context(chat_id, resource_id)? else {
            return Ok(None);
        };
        let required = record.stakeholders;
        request_access(self.store_mut(), chat_id, resource_id, required).map(Some)
    }

    /// Approve a pending resource-access request.
    pub fn approve_resource_access(
        &mut self,
        chat_id: &str,
        resource_id: &ResourceId,
        approver: Authority,
    ) -> Result<AccessPhase, AdmitError> {
        approve_access(self.store_mut(), chat_id, resource_id, approver)
    }

    /// Revoke a granted resource-access request.
    pub fn revoke_resource_access(
        &mut self,
        chat_id: &str,
        resource_id: &ResourceId,
    ) -> Result<AccessPhase, AdmitError> {
        revoke_access(self.store_mut(), chat_id, resource_id)
    }

    /// Propose a resource export and return its reducer scope plus folded state.
    pub fn admit_resource_export(
        &mut self,
        chat_id: &str,
        resource_id: &ResourceId,
    ) -> Result<Option<(String, ExportState)>, AdmitError> {
        let Some(rec) = get(self.store_ref(), chat_id, resource_id)? else {
            return Ok(None);
        };
        let scope = export_scope(chat_id, resource_id);
        let source_required = rec.stakeholders.iter().map(|a| a.as_str().into()).collect();
        let state = self
            .store_mut()
            .admit::<ExportState>(&scope, ExportCommand::ProposeExport { source_required })?;
        Ok(Some((scope, state)))
    }

    /// Fold the resource-export state for one handle.
    pub fn resource_export_state(
        &self,
        chat_id: &str,
        resource_id: &ResourceId,
    ) -> Result<ExportState, AdmitError> {
        self.store_ref()
            .fold::<ExportState>(&export_scope(chat_id, resource_id))
    }

    /// Persist the audit fact that an admitted resource export wrote bytes to disk.
    pub fn record_resource_export_to_disk(
        &mut self,
        chat_id: &str,
        payload: &serde_json::Value,
    ) -> Result<i64, AdmitError> {
        self.store_mut()
            .append_record(chat_id, "export_to_disk", &payload.to_string())
    }

    /// Propose a resource review and return its reducer scope plus folded state.
    pub fn admit_resource_review(
        &mut self,
        chat_id: &str,
        resource_id: &ResourceId,
    ) -> Result<Option<(String, ReviewState)>, AdmitError> {
        let Some(rec) = get(self.store_ref(), chat_id, resource_id)? else {
            return Ok(None);
        };
        let scope = review_scope(chat_id, resource_id);
        let required = rec.stakeholders.iter().map(|a| a.as_str().into()).collect();
        let state = self
            .store_mut()
            .admit::<ReviewState>(&scope, ReviewCommand::Propose { required })?;
        Ok(Some((scope, state)))
    }
}

#[derive(Deserialize)]
pub(crate) struct ContextBody {
    /// Absolute path to a **folder** or a **single file** (UX-1) of context to open into
    /// the engagement.
    path: String,
    /// Required when a work chat has more than one writable target. Context is
    /// candidate content and therefore must resolve to one exact target authority.
    #[serde(default)]
    target_id: Option<String>,
    /// **SECAUD-5**: optional data classification for the ingested source
    /// (`public` | `internal` | `pii` | `regulated`). Unknown / omitted => the
    /// fail-closed default `regulated`, so a missing or typo'd label never *under*-protects.
    #[serde(default)]
    classification: Option<String>,
    /// **SECAUD-5**: optional data-residency region tag (e.g. `eu`, `us`) the ABAC floor
    /// enforces for `pii` egress.
    #[serde(default)]
    region: Option<String>,
}

/// Map the ingest body's optional classification/region labels onto fail-closed ABAC
/// [`ResourceAttributes`] (`SECAUD-5`). An unrecognized or absent classification
/// resolves to the most-protected `Regulated`.
pub(crate) fn context_attributes(
    classification: Option<&str>,
    region: Option<&str>,
) -> ResourceAttributes {
    use gaugedesk_core::abac::{Classification, Region};
    let classification = match classification
        .map(|s| s.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("public") => Classification::Public,
        Some("internal") => Classification::Internal,
        Some("pii") => Classification::Pii,
        _ => Classification::Regulated, // unknown / "regulated" / None => fail-closed
    };
    ResourceAttributes {
        classification,
        region: region
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(Region::new),
        purpose: Default::default(),
    }
}

/// Context ingestion ("open a folder or attach a file"): copy an existing folder of
/// documents/code, or a single file (UX-1), into the engagement worktree so the agent
/// can work against it.
pub(crate) async fn post_context(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    actor: Option<axum::extract::Extension<crate::identity::AuthenticatedActor>>,
    Json(body): Json<ContextBody>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    // ENTSEC-5: in enterprise mode the control plane is remote — a server-local *path* ingest
    // would read the SERVER's filesystem at a client's request (a confused-deputy /
    // info-disclosure risk), so it is disabled; the client uploads its files instead
    // (`POST /chats/:id/context/upload`). Solo keeps it (the disk is the operator's own).
    if wb.has_idp() {
        return (
            StatusCode::FORBIDDEN,
            "server-path context ingest is disabled in enterprise mode; upload the files instead \
             (POST /chats/:id/context/upload)",
        )
            .into_response();
    }
    let (n, commit) = match wb.ingest_context_into_engagement(
        &id,
        std::path::Path::new(&body.path),
        body.target_id.as_deref(),
    ) {
        Some(Ok(out)) => out,
        None => return (StatusCode::NOT_FOUND, "no such engagement").into_response(),
        Some(Err(e)) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    // A minted context must be owned by the authority the agent will act-for,
    // or the information-flow envelope denies the very read this ingest exists
    // to enable. `engine.rs` resolves that principal as
    // `authenticated_actor.unwrap_or_else(|| authority())`, so this mirrors it
    // exactly. Solo is unchanged — with no IdP both sides collapse to the
    // instance authority — while an IdP deployment now agrees instead of
    // minting under the instance and acting-for the signed-in person.
    let owner = actor
        .map(|axum::extract::Extension(actor)| actor.0.as_str().to_owned())
        .unwrap_or_else(|| wb.authority().as_str().to_string());
    let attributes = context_attributes(body.classification.as_deref(), body.region.as_deref());
    let rec = match wb.mint_resource_context(&id, &owner, &body.path, &commit, attributes) {
        Ok(r) => r,
        Err(e) => return err_response(e),
    };
    let handle = rec.resource.id.as_str().to_string();
    wb.publish(
        &id,
        ServerEvent::Admitted {
            kind: "context".into(),
            text: format!("ingested {n} file(s) -> {handle}"),
        },
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({ "ingested": n, "resource": handle })),
    )
        .into_response()
}

/// One uploaded context file (`ENTSEC-5`): a name + its text content.
#[derive(serde::Deserialize)]
pub(crate) struct UploadedFile {
    name: String,
    content: String,
}

#[derive(serde::Deserialize)]
pub(crate) struct ContextUploadBody {
    /// The uploaded files (name + text content) to open into the engagement.
    files: Vec<UploadedFile>,
    /// Required when a work chat has more than one writable target.
    #[serde(default)]
    target_id: Option<String>,
    /// SECAUD-5: optional data classification for the ingested source.
    #[serde(default)]
    classification: Option<String>,
    /// SECAUD-5: optional data-residency region tag.
    #[serde(default)]
    region: Option<String>,
}

/// `POST /chats/:id/context/upload` (`ENTSEC-5`): ingest context from an **upload** rather
/// than a server-local path — the enterprise thin-client's context-in (its files are not on
/// the server's disk). Path-confined per file (basename only); the minted resource carries
/// the same classification/region attributes and access gating as the path ingest. Works in
/// both modes (solo may upload too); enterprise *requires* it since the path ingest is
/// disabled there.
pub(crate) async fn post_context_upload(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    actor: Option<axum::extract::Extension<crate::identity::AuthenticatedActor>>,
    Json(body): Json<ContextUploadBody>,
) -> impl IntoResponse {
    if body.files.is_empty() {
        return (StatusCode::BAD_REQUEST, "no files uploaded").into_response();
    }
    let mut wb = wb.lock_unpoisoned();
    let files: Vec<(String, String)> = body
        .files
        .into_iter()
        .map(|f| (f.name, f.content))
        .collect();
    let (n, commit) = match wb.ingest_upload_into_engagement(&id, &files, body.target_id.as_deref())
    {
        Some(Ok(out)) => out,
        None => return (StatusCode::NOT_FOUND, "no such engagement").into_response(),
        Some(Err(e)) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    // A minted context must be owned by the authority the agent will act-for,
    // or the information-flow envelope denies the very read this ingest exists
    // to enable. `engine.rs` resolves that principal as
    // `authenticated_actor.unwrap_or_else(|| authority())`, so this mirrors it
    // exactly. Solo is unchanged — with no IdP both sides collapse to the
    // instance authority — while an IdP deployment now agrees instead of
    // minting under the instance and acting-for the signed-in person.
    let owner = actor
        .map(|axum::extract::Extension(actor)| actor.0.as_str().to_owned())
        .unwrap_or_else(|| wb.authority().as_str().to_string());
    let attributes = context_attributes(body.classification.as_deref(), body.region.as_deref());
    let label = format!("uploaded: {n} file(s)");
    let rec = match wb.mint_resource_context(&id, &owner, &label, &commit, attributes) {
        Ok(r) => r,
        Err(e) => return err_response(e),
    };
    let handle = rec.resource.id.as_str().to_string();
    wb.publish(
        &id,
        ServerEvent::Admitted {
            kind: "context".into(),
            text: format!("uploaded {n} file(s) -> {handle}"),
        },
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({ "ingested": n, "resource": handle })),
    )
        .into_response()
}

/// The context list / output catalog projection (`data.md`): the engagement's
/// durable resources, rendered as handles and metadata only. Resolving payload
/// requires the content route and a granted basis (`INV-10`).
pub(crate) async fn get_resources(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    let recs = match wb.list_resource_contexts(&id) {
        Ok(r) => r,
        Err(e) => return err_response(e),
    };
    let views: Vec<serde_json::Value> = recs
        .iter()
        .map(|(r, access)| {
            serde_json::json!({
                "id": r.resource.id.as_str(),
                "kind": r.resource.kind.as_str(),
                "owner": r.resource.owner,
                "stakeholders": r.stakeholders,
                "access": format!("{access:?}"),
                "tombstoned": r.tombstoned,
            })
        })
        .collect();
    (StatusCode::OK, Json(views)).into_response()
}

/// `?path=` for resource content resolution. Absent means return the content manifest.
#[derive(Deserialize)]
pub(crate) struct ContentQuery {
    #[serde(default)]
    path: String,
}

/// Resolve the protected payload behind a resource handle. A handle conveys no
/// payload access; resolution is gated by granted access and tombstone state.
pub(crate) async fn get_resource_content(
    State(wb): State<SharedWorkbench>,
    Path((id, rid)): Path<(String, String)>,
    Query(q): Query<ContentQuery>,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    let res_id = ResourceId::new(rid);
    let rec = match wb.resource_context(&id, &res_id) {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "no such resource").into_response(),
        Err(e) => return err_response(e),
    };
    if rec.tombstoned {
        return (StatusCode::GONE, "resource payload tombstoned").into_response();
    }
    match wb.resource_access_phase(&id, &res_id) {
        Ok(AccessPhase::Granted) => {}
        Ok(_) => return (StatusCode::FORBIDDEN, "access not granted (INV-10)").into_response(),
        Err(e) => return err_response(e),
    }
    if q.path.is_empty() {
        match wb.engagement_tree(&id) {
            None => (StatusCode::NOT_FOUND, "no such engagement").into_response(),
            Some(Ok(entries)) => {
                let manifest = entries
                    .into_iter()
                    .filter(|e| !e.is_dir && is_target_payload_path(&e.path))
                    .map(|e| e.path)
                    .collect::<Vec<_>>()
                    .join("\n");
                (StatusCode::OK, manifest).into_response()
            }
            Some(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")).into_response(),
        }
    } else {
        match wb.read_engagement_file(&id, &q.path) {
            None => (StatusCode::NOT_FOUND, "no such engagement").into_response(),
            Some(Ok(content)) => (StatusCode::OK, content).into_response(),
            Some(Err(e)) => (StatusCode::BAD_REQUEST, format!("{e}")).into_response(),
        }
    }
}

/// Tombstone a resource's payload via the content-erasure lifecycle: future
/// resolution is blocked while the handle/record/history remain.
pub(crate) async fn post_resource_tombstone(
    State(wb): State<SharedWorkbench>,
    Path((id, rid)): Path<(String, String)>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    let res_id = ResourceId::new(rid);
    match wb.tombstone_resource_context(&id, &res_id) {
        Ok(true) => {
            wb.publish(
                &id,
                ServerEvent::Admitted {
                    kind: "erasure".into(),
                    text: format!("tombstoned {}", res_id.as_str()),
                },
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({ "tombstoned": res_id.as_str() })),
            )
                .into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, "no such resource").into_response(),
        Err(e) => err_response(e),
    }
}

/// The access phase of a resource (`CORE-3`): `Init`/`Requested`/`Granted`/`Revoked`/`Denied`.
pub(crate) async fn get_resource_access(
    State(wb): State<SharedWorkbench>,
    Path((id, rid)): Path<(String, String)>,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    let res_id = ResourceId::new(rid);
    match wb.resource_access_phase(&id, &res_id) {
        Ok(phase) => (StatusCode::OK, Json(serde_json::json!({ "phase": phase }))).into_response(),
        Err(e) => err_response(e),
    }
}

/// Explicitly request access to a resource (`CORE-3`). The immutable resource
/// record, not caller input, supplies the required stakeholder set (`INV-13`).
pub(crate) async fn post_resource_access_request(
    State(wb): State<SharedWorkbench>,
    Path((id, rid)): Path<(String, String)>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    let res_id = ResourceId::new(rid);
    match wb.request_resource_access(&id, &res_id) {
        Ok(Some(phase)) => {
            (StatusCode::OK, Json(serde_json::json!({ "phase": phase }))).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "no such resource").into_response(),
        Err(AdmitError::Rejected(rejection)) => {
            (StatusCode::CONFLICT, rejection.reason).into_response()
        }
        Err(e) => err_response(e),
    }
}

/// Approve a pending access request as the authenticated actor (`CORE-3`);
/// grants once all required stakeholders have approved. Caller-supplied identity
/// is deliberately absent: a bearer must never consent as somebody else.
pub(crate) async fn post_resource_access_approve(
    State(wb): State<SharedWorkbench>,
    Path((id, rid)): Path<(String, String)>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    let res_id = ResourceId::new(rid);
    // CORE-6: the resource-attribute ABAC floor gates the grant — a pii/regulated resource at
    // an unattested ceiling is refused access even where the consent reducer would allow it
    // (restrict-only, fail-closed). No-op in solo / no-policy.
    let bearer = net_http::bearer(&headers);
    if let Err((code, msg)) = wb.authorize_resource_access_in(
        bearer,
        &id,
        &res_id,
        &crate::workbench_auth::req_scope(&headers),
    ) {
        return (code, msg).into_response();
    }
    let approver = Authority::from(wb.actor(bearer));
    match wb.approve_resource_access(&id, &res_id, approver) {
        Ok(phase) => (StatusCode::OK, Json(serde_json::json!({ "phase": phase }))).into_response(),
        Err(AdmitError::Rejected(rejection)) => {
            (StatusCode::FORBIDDEN, rejection.reason).into_response()
        }
        Err(e) => err_response(e),
    }
}

/// Revoke a granted access (`CORE-3`/`INV-18`, future-only).
pub(crate) async fn post_resource_access_revoke(
    State(wb): State<SharedWorkbench>,
    Path((id, rid)): Path<(String, String)>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    let res_id = ResourceId::new(rid);
    match wb.revoke_resource_access(&id, &res_id) {
        Ok(phase) => (StatusCode::OK, Json(serde_json::json!({ "phase": phase }))).into_response(),
        Err(e) => err_response(e),
    }
}

/// Propose exporting a resource across the boundary edge. The required source
/// consenters are derived from the resource's stakeholders.
pub(crate) async fn post_resource_export(
    State(wb): State<SharedWorkbench>,
    Path((id, rid)): Path<(String, String)>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    let res_id = ResourceId::new(rid);
    if let Err((code, msg)) = wb.authorize_resource_export_in(
        net_http::bearer(&headers),
        &id,
        &res_id,
        &crate::workbench_auth::req_scope(&headers),
    ) {
        return (code, msg).into_response();
    }
    match wb.admit_resource_export(&id, &res_id) {
        Ok(Some((scope, state))) => {
            wb.publish(
                &id,
                ServerEvent::Admitted {
                    kind: "export".into(),
                    text: format!("export proposed for {}", res_id.as_str()),
                },
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({ "scope": scope, "state": state })),
            )
                .into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "no such resource").into_response(),
        Err(AdmitError::Rejected(r)) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "rejected": r.reason })),
        )
            .into_response(),
        Err(e) => err_response(e),
    }
}

/// Read one resource's export lifecycle through the resource that owns it. This
/// replaces the raw scope projection so a caller cannot probe an unrelated
/// lifecycle by guessing its scope id.
pub(crate) async fn get_resource_export(
    State(wb): State<SharedWorkbench>,
    Path((id, rid)): Path<(String, String)>,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    let res_id = ResourceId::new(rid);
    match wb.resource_context(&id, &res_id) {
        Ok(Some(_)) => match wb.resource_export_state(&id, &res_id) {
            Ok(state) => (StatusCode::OK, Json(state)).into_response(),
            Err(error) => err_response(error),
        },
        Ok(None) => (StatusCode::NOT_FOUND, "no such resource").into_response(),
        Err(error) => err_response(error),
    }
}

/// Admit a source-stakeholder decision for one concrete resource export. The
/// body carries only the action; the authority is resolved from the production
/// bearer and checked against the resource's authoritative stakeholders.
pub(crate) async fn post_resource_export_command(
    State(wb): State<SharedWorkbench>,
    Path((id, rid)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<ResourceExportCommandBody>,
) -> impl IntoResponse {
    let key = match caller_idempotency_key(&headers) {
        Ok(key) => key,
        Err(response) => return response,
    };
    let bearer = net_http::bearer(&headers);
    let mut wb = wb.lock_unpoisoned();
    let res_id = ResourceId::new(rid);
    let record = match wb.resource_context(&id, &res_id) {
        Ok(Some(record)) => record,
        Ok(None) => return (StatusCode::NOT_FOUND, "no such resource").into_response(),
        Err(error) => return err_response(error),
    };
    if let Err((code, message)) = wb.authorize_resource_export_in(
        bearer,
        &id,
        &res_id,
        &crate::workbench_auth::req_scope(&headers),
    ) {
        return (code, message).into_response();
    }
    let actor = match wb.authenticate_identity(bearer) {
        Ok(actor) => Authority::from(actor.as_str()),
        Err((code, message)) => return (code, message).into_response(),
    };
    if !record.stakeholders.contains(&actor) {
        return (
            StatusCode::FORBIDDEN,
            "only a resource stakeholder may decide source export consent",
        )
            .into_response();
    }
    let command = match body.action {
        ResourceExportAction::Consent => ExportCommand::SourceConsent(actor),
        ResourceExportAction::Reject => ExportCommand::Reject(actor),
        ResourceExportAction::Revoke => ExportCommand::Revoke(actor),
    };
    let scope = export_scope(&id, &res_id);
    match wb.admit_export_command(&scope, &key, command) {
        Ok(admission) => (StatusCode::OK, Json(admission.state)).into_response(),
        Err(AdmitError::Rejected(rejection)) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "rejected": rejection.reason })),
        )
            .into_response(),
        Err(error) => err_response(error),
    }
}

/// The destination of an export-to-disk: the directory bytes leave to.
#[derive(Deserialize)]
pub(crate) struct ExportToDiskBody {
    /// Absolute destination directory the deliverable is written into.
    dest: String,
    /// Optional single file (relative path within the resource) to export; absent
    /// means the whole resolved file set.
    #[serde(default)]
    path: Option<String>,
}

/// Materialize an admitted export to disk: turn an `Exported` `resource-export`
/// into bytes actually leaving the boundary edge.
pub(crate) async fn post_resource_export_to_disk(
    State(wb): State<SharedWorkbench>,
    Path((id, rid)): Path<(String, String)>,
    Json(body): Json<ExportToDiskBody>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    if wb.has_idp() {
        return (
            StatusCode::FORBIDDEN,
            "export-to-disk is disabled in enterprise mode (it would write to your endpoint); \
             use the server-side export",
        )
            .into_response();
    }
    let res_id = ResourceId::new(rid);

    let rec = match wb.resource_context(&id, &res_id) {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "no such resource").into_response(),
        Err(e) => return err_response(e),
    };
    if rec.tombstoned {
        return (StatusCode::GONE, "resource payload tombstoned").into_response();
    }

    let needs_target_admission = match wb.resource_export_state(&id, &res_id) {
        Ok(state)
            if state.phase == ExportPhase::Requested
                && state.source_required == state.source_consented
                && !state.target_admitted =>
        {
            true
        }
        Ok(state) if state.phase == ExportPhase::Cleared => false,
        Ok(state) => {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "export still needs source consent before target admission",
                    "phase": format!("{:?}", state.phase),
                })),
            )
                .into_response()
        }
        Err(e) => return err_response(e),
    };

    let dest = std::path::PathBuf::from(&body.dest);
    if !dest.is_absolute() {
        return (StatusCode::BAD_REQUEST, "dest must be an absolute path").into_response();
    }
    if !dest.is_dir() {
        return (
            StatusCode::BAD_REQUEST,
            "dest must be an existing directory",
        )
            .into_response();
    }

    let files: Vec<String> = match &body.path {
        Some(p) => vec![p.clone()],
        None => match wb.engagement_tree(&id) {
            None => return (StatusCode::NOT_FOUND, "no such engagement").into_response(),
            Some(Ok(entries)) => entries
                .into_iter()
                .filter(|e| !e.is_dir && is_target_payload_path(&e.path))
                .map(|e| e.path)
                .collect(),
            Some(Err(e)) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")).into_response()
            }
        },
    };
    if needs_target_admission {
        // A valid, user-selected local directory is the target's admission.
        // Keep that fact adjacent to actual egress instead of exposing a raw
        // command that any authenticated source could self-assert.
        let scope = export_scope(&id, &res_id);
        if let Err(error) = wb.admit_export_command(
            &scope,
            "resource-export-to-disk-target",
            ExportCommand::TargetAdmit,
        ) {
            return err_response(error);
        }
    }
    let mut written = Vec::new();
    for rel in &files {
        let content = match wb.read_engagement_file(&id, rel) {
            None => return (StatusCode::NOT_FOUND, "no such engagement").into_response(),
            Some(Ok(c)) => c,
            Some(Err(e)) => {
                return (StatusCode::BAD_REQUEST, format!("{rel}: {e}")).into_response()
            }
        };
        let out = dest.join(rel);
        if let Some(parent) = out.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("mkdir {rel}: {e}"),
                )
                    .into_response();
            }
        }
        if let Err(e) = std::fs::write(&out, content) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("write {rel}: {e}"),
            )
                .into_response();
        }
        written.push(rel.clone());
    }

    let egress = serde_json::json!({
        "resource": res_id.as_str(),
        "dest": body.dest,
        "files": written,
    });
    if let Err(e) = wb.record_resource_export_to_disk(&id, &egress) {
        return err_response(e);
    }
    let scope = export_scope(&id, &res_id);
    if let Err(error) = wb.admit_export_command(
        &scope,
        "resource-export-to-disk-crossed",
        ExportCommand::Export,
    ) {
        return err_response(error);
    }
    wb.publish(
        &id,
        ServerEvent::Admitted {
            kind: "export".into(),
            text: format!("exported {} file(s) to disk", written.len()),
        },
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({ "exported": written, "dest": body.dest })),
    )
        .into_response()
}

/// Propose review (declassification) of a resource. The required consenters are
/// derived from the resource's stakeholders, mirroring export.
pub(crate) async fn post_resource_review(
    State(wb): State<SharedWorkbench>,
    Path((id, rid)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    let res_id = ResourceId::new(rid);
    if let Err((code, message)) = wb.authorize_resource_export_in(
        net_http::bearer(&headers),
        &id,
        &res_id,
        &crate::workbench_auth::req_scope(&headers),
    ) {
        return (code, message).into_response();
    }
    match wb.admit_resource_review(&id, &res_id) {
        Ok(Some((scope, state))) => {
            wb.publish(
                &id,
                ServerEvent::Admitted {
                    kind: "review".into(),
                    text: format!("review proposed for {}", res_id.as_str()),
                },
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({ "scope": scope, "state": state })),
            )
                .into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "no such resource").into_response(),
        Err(AdmitError::Rejected(r)) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "rejected": r.reason })),
        )
            .into_response(),
        Err(e) => err_response(e),
    }
}

/// Read one resource's declassification lifecycle without exposing its raw
/// coordinator scope as a product route.
pub(crate) async fn get_resource_review(
    State(wb): State<SharedWorkbench>,
    Path((id, rid)): Path<(String, String)>,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    let res_id = ResourceId::new(rid);
    match wb.resource_context(&id, &res_id) {
        Ok(Some(_)) => match wb.review_state(&review_scope(&id, &res_id)) {
            Ok(state) => (StatusCode::OK, Json(state)).into_response(),
            Err(error) => err_response(error),
        },
        Ok(None) => (StatusCode::NOT_FOUND, "no such resource").into_response(),
        Err(error) => err_response(error),
    }
}

/// Admit an authenticated stakeholder's review decision for a concrete output.
/// The request cannot supply either a scope or an authority.
pub(crate) async fn post_resource_review_command(
    State(wb): State<SharedWorkbench>,
    Path((id, rid)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<ResourceReviewCommandBody>,
) -> impl IntoResponse {
    let key = match caller_idempotency_key(&headers) {
        Ok(key) => key,
        Err(response) => return response,
    };
    let bearer = net_http::bearer(&headers);
    let mut wb = wb.lock_unpoisoned();
    let res_id = ResourceId::new(rid);
    let record = match wb.resource_context(&id, &res_id) {
        Ok(Some(record)) => record,
        Ok(None) => return (StatusCode::NOT_FOUND, "no such resource").into_response(),
        Err(error) => return err_response(error),
    };
    if let Err((code, message)) = wb.authorize_resource_export_in(
        bearer,
        &id,
        &res_id,
        &crate::workbench_auth::req_scope(&headers),
    ) {
        return (code, message).into_response();
    }
    let actor = match wb.authenticate_identity(bearer) {
        Ok(actor) => Authority::from(actor.as_str()),
        Err((code, message)) => return (code, message).into_response(),
    };
    if !record.stakeholders.contains(&actor) {
        return (
            StatusCode::FORBIDDEN,
            "only a resource stakeholder may decide its review",
        )
            .into_response();
    }
    let command = match body.action {
        ResourceReviewAction::Consent => ReviewCommand::Consent(actor),
        ResourceReviewAction::Reject => ReviewCommand::Reject(actor),
        ResourceReviewAction::Revoke => ReviewCommand::Revoke(actor),
        ResourceReviewAction::Release => ReviewCommand::Release,
    };
    let scope = review_scope(&id, &res_id);
    match wb.admit_review_command(&scope, &key, command) {
        Ok(admission) => (StatusCode::OK, Json(admission.state)).into_response(),
        Err(AdmitError::Rejected(rejection)) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "rejected": rejection.reason })),
        )
            .into_response(),
        Err(error) => err_response(error),
    }
}

/// Whether a resource's payload may currently be resolved: it exists, its access is
/// `Granted`, and it is not tombstoned (handle ≠ access, `INV-10`; tombstone blocks
/// future resolution, `INV-18`).
pub fn is_resolvable(store: &Store, engagement: &str, id: &ResourceId) -> Result<bool, AdmitError> {
    match get(store, engagement, id)? {
        Some(rec) if !rec.tombstoned => {
            Ok(access_phase(store, engagement, id)? == AccessPhase::Granted)
        }
        _ => Ok(false),
    }
}

/// ABAC gate over a resource's egress/use (ADR 0032 step 4): compose the verified
/// floor's verdict (`floor_baseline` — conjunctive consent + ceiling, decided by the
/// existing protection path) with the enterprise `policy`, reading the resource's
/// persisted [`ResourceRecord::attributes`] and the actor's claims (resolved by the
/// [`crate::identity::IdentityProvider`]). The result is **restrict-only**
/// (`ABAC_MONOTONE`): it can only *deny* what the floor already allowed, never grant
/// — so calling it as a pre-check before an admission can never widen access. A
/// missing record denies (fail-closed, `INV-20`).
///
/// This is the mechanism; wiring it onto the live HTTP admission routes
/// (resource-access / export) is the remaining `CORE-6` step.
#[allow(clippy::too_many_arguments)]
pub fn abac_permits(
    store: &Store,
    engagement: &str,
    id: &ResourceId,
    actor: &AuthorityAttributes,
    action: Action,
    context: Context,
    policy: &Policy,
    floor_baseline: bool,
) -> Result<bool, AdmitError> {
    let Some(rec) = get(store, engagement, id)? else {
        return Ok(false);
    };
    let decision = Decision {
        actor: actor.clone(),
        resource: rec.attributes,
        action,
        context,
    };
    Ok(permitted_with_policy(floor_baseline, policy, &decision))
}

/// A durable, engagement-scoped audit fact that a sealed key was released to an
/// attested host (D-ATTEST / ADR 0040, ATTEST-6).
///
/// The [`boundary_keeper`](crate::boundary_keeper) gate (ATTEST-5) decides *whether*
/// to release a sealed key against trustworthy [`AttestationEvidence`]; this record
/// is what persists once it does — the fact of release, so an engagement keeps an
/// auditable trail of which keys were unsealed to which measurement under which
/// boundary. It is **never** the key bytes: per the content-behind-handles
/// discipline, sealed secrets never land inline in the engagement log — the bytes
/// flow to the caller from the [`KeyReleaseDecision`], while only this fact is
/// durable. Records fold latest-wins by `sealed_key_id` (a re-release supersedes
/// the prior grant) exactly like the resource records above.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KeyReleaseGrant {
    /// The sealed key that was released.
    pub sealed_key_id: String,
    /// The measurement the released key was sealed to (and the attested host proved).
    pub measurement: CodeMeasurement,
    /// The boundary scope under which the release was granted.
    pub boundary: String,
    /// The participant the key was released to.
    pub participant: String,
}

/// One billable attested run: a trustworthy, entitled key-release batch that
/// released at least one sealed key. This is deliberately distinct from the
/// per-key [`KeyReleaseGrant`] audit facts — one run may receive many keys but is
/// still one metered run (ADR 0048).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct AttestedRunMeterRecord {
    measurement: CodeMeasurement,
    boundary: String,
    participant: String,
    released_keys: usize,
}

impl KeyReleaseGrant {
    /// Record that `sealed_key_id` (sealed to `measurement`) was released to
    /// `participant` under `boundary`.
    pub fn new(
        sealed_key_id: impl Into<String>,
        measurement: CodeMeasurement,
        boundary: impl Into<String>,
        participant: impl Into<String>,
    ) -> Self {
        Self {
            sealed_key_id: sealed_key_id.into(),
            measurement,
            boundary: boundary.into(),
            participant: participant.into(),
        }
    }
}

/// Release every sealed key the attested `evidence` is entitled to and durably
/// record a [`KeyReleaseGrant`] for each one actually released (ATTEST-6).
///
/// This is the resource-store side of the attested key-release flow: where
/// [`boundary_keeper::accept_boundary_attested`](crate::boundary_keeper::accept_boundary_attested)
/// releases a single *named* key, an attested host proving a measurement is
/// entitled to **all** keys sealed to that measurement. We enumerate them via
/// [`SealedKeyReleaseService::sealed_key_ids_for_measurement`], drive the pure
/// [`KeyReleaseRequest::decide`] for each (so the trustworthiness check is never
/// bypassed), and persist a grant for every release that succeeds. Returns the
/// `(sealed_key_id, decision)` for each candidate so the caller can hand the
/// released bytes to the workload — only the *fact* of release is durable, never
/// the bytes.
///
/// Untrustworthy evidence enumerates no keys (the verdict carries no measurement),
/// so nothing is released and nothing is granted — a defence in depth alongside the
/// pure decision.
///
/// The `entitlement` verdict (ADR 0048) gates the release commercially: even a
/// trustworthy host attesting the sealed measurement releases nothing unless the
/// engagement is entitled. The verdict is the shell's, from
/// [`package_flow::attested_run_verdict`](crate::package_flow::attested_run_verdict);
/// each per-key request carries it, and the pure decision fails closed on anything
/// but `Active`. An unentitled engagement releases — and grants — nothing.
pub fn release_sealed_keys(
    store: &mut Store,
    engagement: &str,
    boundary: &str,
    participant: &str,
    evidence: &AttestationEvidence,
    entitlement: EntitlementVerdict,
    keys: &dyn SealedKeyReleaseService,
) -> Result<Vec<(String, KeyReleaseDecision)>, AdmitError> {
    let mut out = Vec::new();
    let mut released_keys = 0;
    // Only a trustworthy verdict yields a measurement to release against; untrusted
    // evidence releases nothing (and `decide` would deny each request anyway).
    let Some(measurement) = evidence.result.verified_measurement().cloned() else {
        return Ok(out);
    };
    for id in keys.sealed_key_ids_for_measurement(&measurement) {
        let decision = keys.release(&KeyReleaseRequest::new(
            id.clone(),
            evidence.clone(),
            EntitlementProof::new(engagement, entitlement),
        ));
        if decision.is_released() {
            released_keys += 1;
            let grant =
                KeyReleaseGrant::new(id.clone(), measurement.clone(), boundary, participant);
            let payload = serde_json::to_string(&grant)?;
            store.append_record(engagement, KEY_RELEASE_KIND, &payload)?;
        }
        out.push((id, decision));
    }
    if released_keys > 0 {
        let meter = AttestedRunMeterRecord {
            measurement,
            boundary: boundary.to_string(),
            participant: participant.to_string(),
            released_keys,
        };
        store.append_record(
            engagement,
            ATTESTED_RUN_METER_KIND,
            &serde_json::to_string(&meter)?,
        )?;
    }
    Ok(out)
}

/// Every sealed-key release grant recorded for `measurement` in an engagement, at
/// its current revision (latest-wins by `sealed_key_id`), ordered by key id
/// (ATTEST-6). The audit read over the durable grants `release_sealed_keys` wrote —
/// "which keys were unsealed to this attested measurement".
pub fn sealed_keys_for_measurement(
    store: &Store,
    engagement: &str,
    measurement: &CodeMeasurement,
) -> Result<Vec<KeyReleaseGrant>, AdmitError> {
    let mut latest: BTreeMap<String, KeyReleaseGrant> = BTreeMap::new();
    for row in store.records(engagement, KEY_RELEASE_KIND)? {
        let grant: KeyReleaseGrant = serde_json::from_str(&row)?;
        if &grant.measurement == measurement {
            // records() is position-ordered (oldest→newest), so a later grant wins.
            latest.insert(grant.sealed_key_id.clone(), grant);
        }
    }
    Ok(latest.into_values().collect())
}

/// The metered usage of attested key releases for an engagement (ADR 0048) — the
/// **billing signal**. A run is counted once per successful entitled release batch,
/// while the per-key grants remain available as audit detail. This prevents a run
/// receiving multiple sealed keys from being over-counted.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AttestedRunUsage {
    /// Billable attested runs — one per successful entitled key-release batch.
    pub attested_runs: u64,
    /// Total per-key release events. Audit detail, not the billing multiplier.
    pub release_events: usize,
    /// Distinct sealed keys released (folded latest-wins by id).
    pub distinct_keys: usize,
    /// The distinct attested measurements that earned a release, lower-case hex, sorted.
    pub measurements: Vec<String>,
}

/// Roll up an engagement's attested key-release grants into [`AttestedRunUsage`] — the
/// metered-compute reading the billing rail consumes (ADR 0048).
pub fn attested_run_usage(store: &Store, engagement: &str) -> Result<AttestedRunUsage, AdmitError> {
    let attested_runs = store
        .records(engagement, ATTESTED_RUN_METER_KIND)?
        .into_iter()
        .map(|row| serde_json::from_str::<AttestedRunMeterRecord>(&row))
        .collect::<Result<Vec<_>, _>>()?
        .len() as u64;
    let mut release_events = 0usize;
    let mut keys = BTreeSet::new();
    let mut measurements = BTreeSet::new();
    for row in store.records(engagement, KEY_RELEASE_KIND)? {
        let grant: KeyReleaseGrant = serde_json::from_str(&row)?;
        release_events += 1;
        keys.insert(grant.sealed_key_id);
        measurements.insert(grant.measurement.digest_hex().to_string());
    }
    Ok(AttestedRunUsage {
        attested_runs,
        release_events,
        distinct_keys: keys.len(),
        measurements: measurements.into_iter().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use gaugedesk_core::resource::{
        ContentLocator, Resource, ResourceId, ResourceKind, ResourceRecord,
    };

    fn ctx_record(id: &str, owner: &str, commit: &str) -> ResourceRecord {
        let res = Resource::input(ResourceId::new(id), ResourceKind::context(), owner.into());
        ResourceRecord::new(
            res,
            ContentLocator::Workspace {
                path: "docs".into(),
                commit: commit.into(),
            },
            |_| Authority::from(owner),
        )
    }

    #[test]
    fn round_trips_and_folds_latest_wins() {
        let mut store = Store::open_in_memory().unwrap();
        let scope = "engagement-1";
        put(&mut store, scope, &ctx_record("r1", "B", "c1")).unwrap();
        put(&mut store, scope, &ctx_record("r2", "A", "c1")).unwrap();
        // A newer revision of r1 (re-ingest at a new commit) supersedes the old.
        put(&mut store, scope, &ctx_record("r1", "B", "c2")).unwrap();

        let all = list(&store, scope).unwrap();
        assert_eq!(all.len(), 2, "two distinct handles");
        let r1 = get(&store, scope, &ResourceId::new("r1")).unwrap().unwrap();
        match r1.locator {
            ContentLocator::Workspace { commit, .. } => {
                assert_eq!(commit, "c2", "latest revision wins")
            }
            _ => panic!("expected workspace locator"),
        }
    }

    #[test]
    fn tombstone_blocks_resolution_but_record_remains() {
        let mut store = Store::open_in_memory().unwrap();
        let eng = "engagement-1";
        let rec = mint_context(&mut store, eng, "local-user", "docs", "c1").unwrap();
        let id = &rec.resource.id;
        // Granted + not tombstoned ⇒ resolvable.
        assert!(
            is_resolvable(&store, eng, id).unwrap(),
            "granted context resolves"
        );

        assert!(tombstone(&mut store, eng, id).unwrap());
        // INV-18: future payload resolution is blocked…
        assert!(
            !is_resolvable(&store, eng, id).unwrap(),
            "tombstoned ⇒ unresolvable"
        );
        // …via the real content-erasure lifecycle…
        assert_eq!(
            store
                .fold::<ErasureState>(&erasure_scope(eng, id))
                .unwrap()
                .phase,
            ErasurePhase::Tombstoned
        );
        // …while the handle/record/history are preserved (INV-6).
        let r = get(&store, eng, id).unwrap().unwrap();
        assert!(r.tombstoned, "current revision tombstoned");
        assert_eq!(list(&store, eng).unwrap().len(), 1, "record still present");
        // Tombstoning a missing handle is a no-op; a repeat tombstone is idempotent.
        assert!(!tombstone(&mut store, eng, &ResourceId::new("nope")).unwrap());
        assert!(
            tombstone(&mut store, eng, id).unwrap(),
            "second tombstone idempotent"
        );
    }

    #[test]
    fn mint_context_persists_and_auto_grants() {
        let mut store = Store::open_in_memory().unwrap();
        let eng = "engagement-1";
        let rec = mint_context(&mut store, eng, "local-user", "docs", "c1").unwrap();
        assert_eq!(rec.resource.kind, ResourceKind::context());
        assert_eq!(
            rec.stakeholders,
            BTreeSet::from([Authority::from("local-user")])
        );
        // the record is listed under the engagement scope…
        assert_eq!(list(&store, eng).unwrap().len(), 1);
        // …and access is auto-granted in the per-resource access scope (trust-by-default).
        assert_eq!(
            access_phase(&store, eng, &rec.resource.id).unwrap(),
            AccessPhase::Granted
        );
        // re-ingesting the same folder updates the same handle, not a duplicate.
        mint_context(&mut store, eng, "local-user", "docs", "c2").unwrap();
        assert_eq!(
            list(&store, eng).unwrap().len(),
            1,
            "re-ingest is latest-wins"
        );
    }

    #[test]
    fn output_taint_is_engagement_scoped_and_survives_tombstone() {
        let mut store = Store::open_in_memory().unwrap();
        let eng = "engagement-1";
        mint_context(&mut store, eng, "local-user", "docs", "c1").unwrap();
        mint_context(&mut store, eng, "client", "client-data", "c1").unwrap();

        // a turn reads both granted contexts → both taint the output (INV-13).
        let reads = granted_context(&store, eng).unwrap();
        record_reads(&mut store, eng, &reads).unwrap();
        let out = mint_output(&mut store, eng, "local-user", "c2").unwrap();
        assert_eq!(out.resource.kind, ResourceKind::output());
        assert_eq!(
            out.stakeholders,
            BTreeSet::from([Authority::from("local-user"), Authority::from("client")])
        );

        // the client's context is tombstoned AFTER being read; a later turn only
        // re-reads what is still granted (docs)…
        tombstone(&mut store, eng, &context_id("client-data")).unwrap();
        let reads = granted_context(&store, eng).unwrap();
        record_reads(&mut store, eng, &reads).unwrap();
        let out = mint_output(&mut store, eng, "local-user", "c3").unwrap();
        // …but the earlier read of the client's context persists: still tainted
        // (engagement-scoped soundness — the per-run-taint tooth would leak here).
        assert_eq!(
            out.stakeholders,
            BTreeSet::from([Authority::from("local-user"), Authority::from("client")])
        );
    }

    #[test]
    fn certified_project_flow_expands_to_granted_product_resources() {
        let mut store = Store::open_in_memory().unwrap();
        let eng = "engagement-1";
        let context = mint_context(&mut store, eng, "client", "client-data", "c1").unwrap();
        let signature = vec![gaugedesk_harness::OutputFieldFlow {
            field: "assistant_text".to_owned(),
            read_handles: vec![
                "project".to_owned(),
                "command".to_owned(),
                "human".to_owned(),
            ],
        }];
        assert_eq!(
            certified_output_reads(&store, eng, &signature).unwrap(),
            vec![context.resource.id]
        );
    }

    #[test]
    fn an_unread_context_does_not_taint_the_output() {
        let mut store = Store::open_in_memory().unwrap();
        let eng = "engagement-1";
        mint_context(&mut store, eng, "client", "secret", "c1").unwrap();
        // nothing read → an output derived from nothing is untainted, freely egressable.
        let out = mint_output(&mut store, eng, "local-user", "c2").unwrap();
        assert!(
            out.stakeholders.is_empty(),
            "no reads ⇒ no stakeholders: {:?}",
            out.stakeholders
        );
        assert!(out.resource.provenance.is_empty());
    }

    #[test]
    fn scopes_are_isolated() {
        let mut store = Store::open_in_memory().unwrap();
        put(&mut store, "engagement-a", &ctx_record("r1", "B", "c1")).unwrap();
        assert!(list(&store, "engagement-b").unwrap().is_empty());
    }

    mod abac_gate {
        use super::*;
        use gaugedesk_core::abac::{Classification, Region, Role};

        fn pii_record(id: &str, owner: &str, region: &str) -> ResourceRecord {
            let res = Resource::input(ResourceId::new(id), ResourceKind::context(), owner.into());
            ResourceRecord::new(
                res,
                ContentLocator::Workspace {
                    path: "d".into(),
                    commit: "c".into(),
                },
                |_| Authority::from(owner),
            )
            .with_attributes(ResourceAttributes {
                classification: Classification::Pii,
                region: Some(Region::new(region)),
                purpose: Default::default(),
            })
        }

        fn actor(roles: &[Role], region: &str) -> AuthorityAttributes {
            AuthorityAttributes {
                roles: roles.iter().cloned().collect(),
                region: Some(Region::new(region)),
                ..Default::default()
            }
        }

        #[test]
        fn attributes_persist_through_put_and_get() {
            let mut store = Store::open_in_memory().unwrap();
            let rec = pii_record("r-pii", "client", "eu");
            put(&mut store, "eng", &rec).unwrap();
            let back = get(&store, "eng", &ResourceId::new("r-pii"))
                .unwrap()
                .unwrap();
            assert_eq!(back.attributes.classification, Classification::Pii);
            assert_eq!(back.attributes.region, Some(Region::new("eu")));
        }

        #[test]
        fn mint_context_with_stamps_classification_for_the_floor() {
            // SECAUD-5: a labeled ingest carries its classification/region through to the
            // ABAC floor, so a PII context ingested with a label is narrowed at an
            // unattested ceiling — proving capture-at-ingest reaches enforcement.
            let mut store = Store::open_in_memory().unwrap();
            let rec = mint_context_with(
                &mut store,
                "eng",
                "client",
                "client-data",
                "c1",
                ResourceAttributes {
                    classification: Classification::Pii,
                    region: Some(Region::new("eu")),
                    purpose: Default::default(),
                },
            )
            .unwrap();
            let back = get(&store, "eng", &rec.resource.id).unwrap().unwrap();
            assert_eq!(back.attributes.classification, Classification::Pii);
            assert_eq!(back.attributes.region, Some(Region::new("eu")));
            // The floor reads the stamped attributes: PII at an unattested ceiling is denied.
            assert!(!abac_permits(
                &store,
                "eng",
                &rec.resource.id,
                &actor(&[Role::member()], "eu"),
                Action::Run,
                Context {
                    ceiling_attested: false
                },
                &Policy::enterprise_example(),
                true,
            )
            .unwrap());
            // The default (unlabeled) mint stays the fail-closed Regulated default.
            let plain = mint_context(&mut store, "eng", "client", "plain", "c1").unwrap();
            assert_eq!(plain.attributes, ResourceAttributes::default());
        }

        #[test]
        fn pii_egress_blocked_at_unattested_ceiling_even_though_floor_allows() {
            let mut store = Store::open_in_memory().unwrap();
            let rec = pii_record("r-pii", "client", "eu");
            put(&mut store, "eng", &rec).unwrap();
            let policy = Policy::enterprise_example();
            let id = &rec.resource.id;
            // The floor allowed (baseline = true), but a pii resource at an
            // unattested ceiling is narrowed by policy.
            assert!(!abac_permits(
                &store,
                "eng",
                id,
                &actor(&[Role::member()], "eu"),
                Action::Run,
                Context {
                    ceiling_attested: false
                },
                &policy,
                true,
            )
            .unwrap());
            // Attested + same region ⇒ the floor's verdict stands.
            assert!(abac_permits(
                &store,
                "eng",
                id,
                &actor(&[Role::member()], "eu"),
                Action::Run,
                Context {
                    ceiling_attested: true
                },
                &policy,
                true,
            )
            .unwrap());
        }

        #[test]
        fn abac_never_grants_what_floor_denied() {
            // ABAC_MONOTONE end-to-end: floor denies ⇒ never permitted, whatever the
            // attributes, role, or ceiling.
            let mut store = Store::open_in_memory().unwrap();
            let rec = pii_record("r-pii", "client", "eu");
            put(&mut store, "eng", &rec).unwrap();
            assert!(!abac_permits(
                &store,
                "eng",
                &rec.resource.id,
                &actor(&[Role::admin()], "eu"),
                Action::Run,
                Context {
                    ceiling_attested: true
                },
                &Policy::enterprise_example(),
                false,
            )
            .unwrap());
        }

        #[test]
        fn missing_record_is_fail_closed() {
            let store = Store::open_in_memory().unwrap();
            assert!(!abac_permits(
                &store,
                "eng",
                &ResourceId::new("nope"),
                &actor(&[], "eu"),
                Action::Export,
                Context {
                    ceiling_attested: true
                },
                &Policy::enterprise_example(),
                true,
            )
            .unwrap());
        }

        #[test]
        fn record_without_attributes_field_deserializes_to_default() {
            // Back-compat (`#[serde(default)]`): a resource record serialized before
            // the `attributes` field round-trips as the fail-closed default, so
            // existing engagement logs replay unchanged (INV-20).
            let json = r#"{"resource":{"id":"r","kind":"context","owner":"A","provenance":[]},"stakeholders":["A"],"locator":{"Workspace":{"path":"d","commit":"c"}},"tombstoned":false}"#;
            let rec: ResourceRecord = serde_json::from_str(json).unwrap();
            assert_eq!(rec.attributes, ResourceAttributes::default());
        }
    }

    mod sealed_keys {
        use super::*;
        use crate::boundary_keeper::LoopbackKeyReleaseService;
        use gaugedesk_core::attestation::{
            AttestationQuote, QuoteRejection, QuoteVerificationResult,
        };
        use gaugedesk_core::key_release::{
            EntitlementIneligibility, KeyReleaseDenial, SealedKeyRecord,
        };

        fn measurement() -> CodeMeasurement {
            CodeMeasurement::new("a".repeat(64))
        }

        fn other_measurement() -> CodeMeasurement {
            CodeMeasurement::new("b".repeat(64))
        }

        fn quote(m: CodeMeasurement) -> AttestationQuote {
            AttestationQuote::new(m, "nonce-1", vec![1, 2, 3, 4])
        }

        fn trustworthy(m: CodeMeasurement) -> AttestationEvidence {
            AttestationEvidence::new(
                quote(m.clone()),
                QuoteVerificationResult::Verified { measurement: m },
            )
        }

        /// A service holding two keys sealed to `measurement()` and one sealed to a
        /// different measurement — to prove only the matching ones are released.
        fn key_service() -> LoopbackKeyReleaseService {
            LoopbackKeyReleaseService::with_keys([
                SealedKeyRecord::new("sealed-a", measurement(), vec![1]),
                SealedKeyRecord::new("sealed-b", measurement(), vec![2]),
                SealedKeyRecord::new("other", other_measurement(), vec![9]),
            ])
        }

        /// ADR 0048: an unentitled engagement releases — and grants — **no** key, even
        /// for a trustworthy host attesting the very sealed measurement. The keys are
        /// enumerated (the measurement matches), but each is denied `Unentitled`, so the
        /// audit trail stays empty: the meter gates the seal.
        #[test]
        fn unentitled_engagement_releases_and_grants_nothing() {
            let mut store = Store::open_in_memory().unwrap();
            let eng = "engagement-1";
            let released = release_sealed_keys(
                &mut store,
                eng,
                "boundary-1",
                "A",
                &trustworthy(measurement()),
                EntitlementVerdict::Ineligible {
                    reason: EntitlementIneligibility::Blocked,
                },
                &key_service(),
            )
            .unwrap();
            // Both keys sealed to the attested measurement were candidates, but each is
            // denied for want of an active entitlement — none released.
            assert_eq!(released.len(), 2);
            assert!(released.iter().all(|(_, d)| matches!(
                d,
                KeyReleaseDecision::Denied {
                    reason: KeyReleaseDenial::Unentitled { .. }
                }
            )));
            // And so no grant is recorded — nothing was actually unsealed.
            assert!(sealed_keys_for_measurement(&store, eng, &measurement())
                .unwrap()
                .is_empty());
            assert_eq!(
                attested_run_usage(&store, eng).unwrap(),
                AttestedRunUsage::default(),
                "a denied release batch is never billable"
            );
        }

        /// Trustworthy evidence releases exactly the keys sealed to its measurement,
        /// records one grant per release, and the grants read back by measurement.
        #[test]
        fn releases_and_records_grants_for_the_attested_measurement() {
            let mut store = Store::open_in_memory().unwrap();
            let eng = "engagement-1";
            let released = release_sealed_keys(
                &mut store,
                eng,
                "boundary-1",
                "A",
                &trustworthy(measurement()),
                EntitlementVerdict::Active,
                &key_service(),
            )
            .unwrap();

            // Both keys sealed to the attested measurement released; the third (other
            // measurement) was never even a candidate.
            assert_eq!(released.len(), 2);
            assert!(released.iter().all(|(_, d)| d.is_released()));
            assert_eq!(
                released
                    .iter()
                    .map(|(id, _)| id.as_str())
                    .collect::<Vec<_>>(),
                ["sealed-a", "sealed-b"]
            );

            let grants = sealed_keys_for_measurement(&store, eng, &measurement()).unwrap();
            assert_eq!(grants.len(), 2);
            assert_eq!(
                grants
                    .iter()
                    .map(|g| g.sealed_key_id.as_str())
                    .collect::<Vec<_>>(),
                ["sealed-a", "sealed-b"]
            );
            assert!(grants
                .iter()
                .all(|g| g.boundary == "boundary-1" && g.participant == "A"));
            // No grant was recorded for the unattested measurement.
            assert!(
                sealed_keys_for_measurement(&store, eng, &other_measurement())
                    .unwrap()
                    .is_empty()
            );
        }

        /// ADR 0048 metering: one successful entitled release batch is one billable
        /// attested run even when it releases multiple keys. Per-key release events
        /// remain audit detail; a later release batch counts as another run.
        #[test]
        fn usage_rolls_up_the_release_grants() {
            let mut store = Store::open_in_memory().unwrap();
            let eng = "engagement-1";
            assert_eq!(
                attested_run_usage(&store, eng).unwrap(),
                AttestedRunUsage::default(),
                "no releases ⇒ zero usage"
            );

            release_sealed_keys(
                &mut store,
                eng,
                "boundary-1",
                "A",
                &trustworthy(measurement()),
                EntitlementVerdict::Active,
                &key_service(),
            )
            .unwrap();

            let usage = attested_run_usage(&store, eng).unwrap();
            assert_eq!(usage.attested_runs, 1, "one release batch = one run");
            assert_eq!(
                usage.release_events, 2,
                "the two released keys remain visible as audit events"
            );
            assert_eq!(usage.distinct_keys, 2);
            assert_eq!(
                usage.measurements,
                vec![measurement().digest_hex().to_string()]
            );

            // A re-release (re-acceptance) is a fresh metered release: events grow,
            // distinct keys do not.
            release_sealed_keys(
                &mut store,
                eng,
                "boundary-2",
                "B",
                &trustworthy(measurement()),
                EntitlementVerdict::Active,
                &key_service(),
            )
            .unwrap();
            let usage = attested_run_usage(&store, eng).unwrap();
            assert_eq!(usage.attested_runs, 2, "a later batch is another run");
            assert_eq!(usage.release_events, 4, "re-release counts again");
            assert_eq!(usage.distinct_keys, 2, "still the same two keys");

            // Usage is per-engagement.
            assert_eq!(
                attested_run_usage(&store, "other-engagement").unwrap(),
                AttestedRunUsage::default()
            );
        }

        /// Untrustworthy evidence (a rejected verdict carries no measurement) releases
        /// nothing and records no grant — the audit trail stays empty.
        #[test]
        fn untrustworthy_evidence_releases_and_records_nothing() {
            let mut store = Store::open_in_memory().unwrap();
            let eng = "engagement-1";
            let evidence = AttestationEvidence::new(
                quote(measurement()),
                QuoteVerificationResult::Rejected {
                    reason: QuoteRejection::StaleNonce,
                },
            );
            let released = release_sealed_keys(
                &mut store,
                eng,
                "boundary-1",
                "A",
                &evidence,
                EntitlementVerdict::Active,
                &key_service(),
            )
            .unwrap();
            assert!(released.is_empty());
            assert!(sealed_keys_for_measurement(&store, eng, &measurement())
                .unwrap()
                .is_empty());
            assert_eq!(
                attested_run_usage(&store, eng).unwrap(),
                AttestedRunUsage::default()
            );
        }

        /// Trustworthy evidence whose measurement matches no held key releases nothing
        /// and records nothing — there is simply nothing sealed to it.
        #[test]
        fn no_keys_sealed_to_measurement_grants_nothing() {
            let mut store = Store::open_in_memory().unwrap();
            let eng = "engagement-1";
            let service = LoopbackKeyReleaseService::with_keys([SealedKeyRecord::new(
                "other",
                other_measurement(),
                vec![9],
            )]);
            let released = release_sealed_keys(
                &mut store,
                eng,
                "boundary-1",
                "A",
                &trustworthy(measurement()),
                EntitlementVerdict::Active,
                &service,
            )
            .unwrap();
            assert!(released.is_empty());
            assert!(sealed_keys_for_measurement(&store, eng, &measurement())
                .unwrap()
                .is_empty());
            assert_eq!(
                attested_run_usage(&store, eng).unwrap(),
                AttestedRunUsage::default()
            );
        }

        /// Release and grant stay in lock-step with the pure decision: a key sealed to a
        /// *different* measurement than the host attested is never enumerated for it, so
        /// it is neither released nor granted even though it sits in the same service.
        #[test]
        fn keys_for_a_different_measurement_are_left_sealed() {
            let mut store = Store::open_in_memory().unwrap();
            let eng = "engagement-1";
            let released = release_sealed_keys(
                &mut store,
                eng,
                "boundary-1",
                "A",
                &trustworthy(measurement()),
                EntitlementVerdict::Active,
                &key_service(),
            )
            .unwrap();
            // The "other" key (sealed to other_measurement) is never a candidate…
            assert!(released.iter().all(|(id, _)| id != "other"));
            assert!(released.iter().all(|(_, d)| !matches!(
                d,
                KeyReleaseDecision::Denied {
                    reason: KeyReleaseDenial::MeasurementMismatch
                }
            )));
            // …and so it leaves no grant under either measurement.
            assert!(
                sealed_keys_for_measurement(&store, eng, &other_measurement())
                    .unwrap()
                    .is_empty()
            );
        }

        /// A re-release of the same key (e.g. a re-acceptance) supersedes its prior
        /// grant latest-wins rather than duplicating it; grants are isolated per
        /// engagement.
        #[test]
        fn re_release_supersedes_and_engagements_are_isolated() {
            let mut store = Store::open_in_memory().unwrap();
            let eng = "engagement-1";
            release_sealed_keys(
                &mut store,
                eng,
                "boundary-1",
                "A",
                &trustworthy(measurement()),
                EntitlementVerdict::Active,
                &key_service(),
            )
            .unwrap();
            // Re-release under a different boundary/participant: latest-wins, not a dup.
            release_sealed_keys(
                &mut store,
                eng,
                "boundary-2",
                "B",
                &trustworthy(measurement()),
                EntitlementVerdict::Active,
                &key_service(),
            )
            .unwrap();
            let grants = sealed_keys_for_measurement(&store, eng, &measurement()).unwrap();
            assert_eq!(grants.len(), 2, "two keys, latest revision each");
            assert!(grants
                .iter()
                .all(|g| g.boundary == "boundary-2" && g.participant == "B"));

            // A different engagement sees none of engagement-1's grants.
            assert!(
                sealed_keys_for_measurement(&store, "engagement-2", &measurement())
                    .unwrap()
                    .is_empty()
            );
        }

        /// The grant is the audit *fact*, not the key bytes — it round-trips through
        /// serde and never carries secret material.
        #[test]
        fn grant_serde_round_trips_without_key_bytes() {
            let grant = KeyReleaseGrant::new("sealed-a", measurement(), "boundary-1", "A");
            let json = serde_json::to_string(&grant).unwrap();
            assert!(
                !json.contains("key_bytes"),
                "no sealed bytes in the durable grant"
            );
            let back: KeyReleaseGrant = serde_json::from_str(&json).unwrap();
            assert_eq!(back, grant);
        }
    }
}
