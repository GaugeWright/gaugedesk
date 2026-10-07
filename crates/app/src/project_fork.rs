//! Fork a project, and pull a fork's original into it
//! ([DR-0327](../../../specs/decisions/0327-a-project-can-be-forked-and-pull-its-original.md);
//! GaugeWright DR-0208).
//!
//! A fork is the export-and-import that transfers no standing. It is a new
//! project made by the ordinary project lifecycle, owned by the forking
//! account as its only member, whose collaboration Main receives the source's
//! managed files and whose placements re-place the source's work Agents at
//! their pinned versions. Nothing else crosses: no chat, tracker, workflow
//! state, credential, grant, deployment, inbox item, settlement or member.
//!
//! The source and the cut it was forked at are the fork's **upstream**. The
//! record grants nothing. A pull re-admits the puller on the original every
//! time, compares the original's files now against the basis the fork last
//! took, and lands what changed through an incoming line that the fork merges
//! into its own Main — the fork's admitted act, never a write by the original.
//! Both files and the basis compare by content identity, which is global.

use std::collections::{BTreeMap, BTreeSet};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use gaugedesk_workspace::MergeOutcome;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::library::{Admission, AgentKind, InstanceKind, PlacementKind, RecordOp};
use crate::{net_http, LockUnpoisoned, SharedWorkbench, Workbench};

/// The `ProjectRecord.extra` key naming a fork's upstream.
pub const UPSTREAM_EXTRA: &str = "upstream";

/// The record kind holding the basis a fork last took from its upstream.
const BASIS_KIND: &str = "project_upstream_basis";

/// The project scope a fork's basis is recorded in. It is the fork's own
/// scope, so a handoff of the fork carries it.
fn basis_scope(project_id: &str) -> String {
    format!("project::{project_id}::upstream")
}

/// A fork's upstream, as its project record carries it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Upstream {
    pub project_id: String,
    pub forked_by: String,
    /// The caller's idempotency key for the fork operation, so a retried fork
    /// returns the project it made instead of making a second one.
    pub operation: String,
}

/// What the fork last took from its upstream: the original's collaboration
/// Main cut and the content identity of every managed file there, by path
/// inside the managed partition.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct UpstreamBasis {
    source_project: String,
    source_cut: Option<String>,
    files: BTreeMap<String, String>,
    actor: String,
}

pub fn upstream_of(project: &crate::library::ProjectRecord) -> Option<Upstream> {
    project
        .extra
        .get(UPSTREAM_EXTRA)
        .and_then(|value| serde_json::from_value(value.clone()).ok())
}

/// The three-way comparison a pull makes for every managed path: the basis
/// last taken, the original now (`theirs`) and the fork now (`ours`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct PullPlan {
    /// Paths only the original changed: the fork takes the original's bytes.
    pub take: Vec<String>,
    /// Paths only the original removed: the fork removes them.
    pub remove: Vec<String>,
    /// Paths both changed differently since the basis.
    pub conflicts: Vec<String>,
}

impl PullPlan {
    pub fn is_empty(&self) -> bool {
        self.take.is_empty() && self.remove.is_empty() && self.conflicts.is_empty()
    }
}

pub fn plan_pull(
    base: &BTreeMap<String, String>,
    theirs: &BTreeMap<String, String>,
    ours: &BTreeMap<String, String>,
) -> PullPlan {
    let mut plan = PullPlan::default();
    let paths: BTreeSet<&String> = base
        .keys()
        .chain(theirs.keys())
        .chain(ours.keys())
        .collect();
    for path in paths {
        let (b, t, o) = (base.get(path), theirs.get(path), ours.get(path));
        // The original did not move this path, or the fork already holds
        // exactly what the original holds: nothing to bring.
        if t == b || o == t {
            continue;
        }
        if o == b {
            match t {
                Some(_) => plan.take.push(path.clone()),
                None => plan.remove.push(path.clone()),
            }
        } else {
            plan.conflicts.push(path.clone());
        }
    }
    plan
}

/// How a pull settles one conflicting path.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Resolution {
    /// Keep the fork's own version.
    Mine,
    /// Take the original's version, or its removal.
    Theirs,
}

#[derive(Debug)]
pub enum ForkError {
    NotFound,
    Refused(String),
    Conflict(String),
    Failed(String),
}

impl IntoResponse for ForkError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            ForkError::NotFound => (StatusCode::NOT_FOUND, "no such project".to_owned()),
            ForkError::Refused(message) => (StatusCode::FORBIDDEN, message),
            ForkError::Conflict(message) => (StatusCode::CONFLICT, message),
            ForkError::Failed(message) => (StatusCode::INTERNAL_SERVER_ERROR, message),
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}

impl Workbench {
    /// The collaboration workspace id and partition root of `project`'s
    /// managed target: the project's own files.
    fn managed_partition(&self, project_id: &str) -> Result<(String, String), String> {
        let workspace_id = self
            .library
            .project_collaboration_workspaces
            .get(project_id)
            .map(|record| record.workspace_id.clone())
            .ok_or_else(|| "project collaboration workspace is undeclared".to_owned())?;
        let target_id = crate::library_state::managed_project_target_id(project_id);
        if !self.library.work_targets.contains_key(&target_id) {
            return Err("project has no managed files".to_owned());
        }
        let root = format!("targets/{}", crate::library::target_id_path_v1(&target_id)?);
        Ok((workspace_id, root))
    }

    /// The managed files on `project`'s collaboration Main by path inside the
    /// partition, with the cut they were read at.
    fn managed_manifest(
        &mut self,
        project_id: &str,
    ) -> Result<(BTreeMap<String, String>, Option<String>), String> {
        self.ensure_project_collaboration_workspace(project_id)?;
        let (workspace_id, root) = self.managed_partition(project_id)?;
        let workspace = self
            .collaboration_workspaces
            .get(&workspace_id)
            .ok_or_else(|| "project collaboration workspace is not open".to_owned())?;
        let cut = workspace.current_main_cut().map_err(|e| e.to_string())?;
        let prefix = format!("{root}/");
        let files = workspace
            .main_manifest()
            .map_err(|e| e.to_string())?
            .into_iter()
            .filter_map(|(path, hash)| {
                let inner = path.strip_prefix(&prefix)?.to_owned();
                (!inner.starts_with(".gaugedesk-runtime/")).then_some((inner, hash))
            })
            .collect();
        Ok((files, cut))
    }

    fn read_managed_bytes(&self, project_id: &str, path: &str) -> Result<Vec<u8>, String> {
        let (workspace_id, root) = self.managed_partition(project_id)?;
        self.collaboration_workspaces
            .get(&workspace_id)
            .ok_or_else(|| "project collaboration workspace is not open".to_owned())?
            .read_main_file_bytes(&format!("{root}/{path}"))
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("`{path}` is no longer on the original's Main"))
    }

    /// Land `writes` and `removes` on `project`'s collaboration Main through
    /// one disposable incoming line, merged as the project's own act. The
    /// line is removed whatever the outcome; a conflicting merge leaves Main
    /// unchanged.
    fn land_on_managed_main(
        &mut self,
        project_id: &str,
        writes: &[(String, Vec<u8>)],
        removes: &[String],
        message: &str,
    ) -> Result<MergeOutcome, String> {
        let (workspace_id, root) = self.managed_partition(project_id)?;
        let workspace = self
            .collaboration_workspaces
            .get(&workspace_id)
            .ok_or_else(|| "project collaboration workspace is not open".to_owned())?;
        let line = crate::library::gen_id("upstream");
        let engagement = workspace
            .create_engagement(&line)
            .map_err(|e| e.to_string())?;
        let outcome = (|| {
            for (path, bytes) in writes {
                engagement
                    .write_file_bytes(&format!("{root}/{path}"), bytes)
                    .map_err(|e| e.to_string())?;
            }
            for path in removes {
                engagement
                    .remove_file(&format!("{root}/{path}"))
                    .map_err(|e| e.to_string())?;
            }
            engagement.commit_turn(message).map_err(|e| e.to_string())?;
            engagement.merge_into_main().map_err(|e| e.to_string())
        })();
        drop(engagement);
        let _ = workspace.remove_engagement(&line);
        outcome
    }

    fn record_basis(&mut self, fork_id: &str, basis: &UpstreamBasis) -> Result<(), String> {
        self.store_mut()
            .append_record(
                &basis_scope(fork_id),
                BASIS_KIND,
                &serde_json::to_string(basis).map_err(|e| e.to_string())?,
            )
            .map(|_| ())
            .map_err(|e| format!("{e:?}"))
    }

    fn current_basis(&self, fork_id: &str) -> Result<UpstreamBasis, String> {
        let records = self
            .store_ref()
            .records(&basis_scope(fork_id), BASIS_KIND)
            .map_err(|e| format!("{e:?}"))?;
        let last = records
            .last()
            .ok_or_else(|| "this fork has no recorded basis".to_owned())?;
        serde_json::from_str(last).map_err(|e| e.to_string())
    }

    /// Fork `source` into a new project owned by `actor`
    /// (GaugeWright DR-0208). `operation` makes a retry return the same fork.
    pub fn fork_project(
        &mut self,
        source_id: &str,
        requested_name: Option<&str>,
        actor: &str,
        operation: &str,
    ) -> Result<serde_json::Value, ForkError> {
        let source = self
            .library
            .projects
            .get(source_id)
            .cloned()
            .ok_or(ForkError::NotFound)?;
        if self.is_panel_preview_project_id(source_id) {
            return Err(ForkError::NotFound);
        }
        if crate::shipped_tutorials::is_tutorial_project(&source) {
            return Err(ForkError::Refused(
                "Tutorials is maintained by GaugeWright".into(),
            ));
        }
        if self.project_moving(source_id) {
            return Err(ForkError::Conflict(
                crate::federation::PAUSED_FOR_MOVE.into(),
            ));
        }
        if &source.home_id != self.home_id() {
            return Err(ForkError::Conflict(
                "fork a project through the Home that holds it".into(),
            ));
        }
        let upstream = Upstream {
            project_id: source_id.to_owned(),
            forked_by: actor.to_owned(),
            operation: operation.to_owned(),
        };
        let id = fork_project_id(source_id, actor, operation);
        if let Some(existing) = self.library.projects.get(&id) {
            return if upstream_of(existing).as_ref() == Some(&upstream) {
                Ok(self.fork_receipt(&id, Vec::new()))
            } else {
                Err(ForkError::Conflict(
                    "fork operation identity is already bound to another project".into(),
                ))
            };
        }
        let name = requested_name
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| fork_name(&source.name));

        let (theirs, source_cut) = self
            .managed_manifest(source_id)
            .map_err(ForkError::Failed)?;
        let mut writes = Vec::with_capacity(theirs.len());
        for path in theirs.keys() {
            writes.push((
                path.clone(),
                self.read_managed_bytes(source_id, path)
                    .map_err(ForkError::Failed)?,
            ));
        }

        // On a Home that holds the office-controlled profile, every project is
        // the enrolled organization's, and so is a fork of one: it inherits the
        // profile and never becomes an account's project outside it (WS-424;
        // DR-0371). The forking person keeps reaching it through a grant.
        let profile_organization = match self.office_profile() {
            Ok(None) => None,
            Ok(Some(profile)) => Some(
                self.project_organization(&source)
                    .map(str::to_owned)
                    .unwrap_or(profile.organization),
            ),
            Err(_) => {
                return Err(ForkError::Conflict(
                    "the office-controlled profile is unavailable; nothing was forked".into(),
                ))
            }
        };
        let mut extra = BTreeMap::new();
        match &profile_organization {
            Some(organization) => {
                extra.insert(
                    "organization".to_owned(),
                    serde_json::Value::String(organization.clone()),
                );
            }
            None => crate::project_owner::record_owner(&mut extra, actor),
        }
        extra.insert(
            UPSTREAM_EXTRA.to_owned(),
            serde_json::to_value(&upstream).map_err(|e| ForkError::Failed(e.to_string()))?,
        );
        crate::library_routes::create_project_lifecycle(self, &id, &name, extra, false)
            .map_err(ForkError::Failed)?;

        let populated = (|| {
            // A fork is never less protected than what it was made from.
            self.update_project_record(
                &id,
                None,
                Some(source.network_isolated),
                source.deployment_mode,
                Some(source.run_purpose.clone()),
            )
            .ok_or("fork vanished while it was being made")?;
            let (ours, _) = self.managed_manifest(&id)?;
            let changed: Vec<(String, Vec<u8>)> = writes
                .into_iter()
                .filter(|(path, _)| ours.get(path) != theirs.get(path))
                .collect();
            let removes: Vec<String> = ours
                .keys()
                .filter(|path| !theirs.contains_key(*path))
                .cloned()
                .collect();
            if !changed.is_empty() || !removes.is_empty() {
                let message = format!("Fork of {}", source.name);
                if self.land_on_managed_main(&id, &changed, &removes, &message)?
                    != MergeOutcome::Clean
                {
                    return Err("the fork's new Main refused its files".to_owned());
                }
            }
            self.record_basis(
                &id,
                &UpstreamBasis {
                    source_project: source_id.to_owned(),
                    source_cut,
                    files: theirs.clone(),
                    actor: actor.to_owned(),
                },
            )?;
            if profile_organization.is_some() {
                self.grant_fork_to_forker(&id, actor)?;
            }
            Ok::<_, String>(self.replace_agents(source_id, &id, actor))
        })();
        match populated {
            Ok(skipped) => Ok(self.fork_receipt(&id, skipped)),
            Err(error) => {
                self.delete_project_cascade(&id);
                Err(ForkError::Failed(error))
            }
        }
    }

    /// Grant the forking person the organization-owned fork they made inside
    /// the office-controlled profile. An administrator already reaches it.
    fn grant_fork_to_forker(&mut self, fork_id: &str, actor: &str) -> Result<(), String> {
        if actor.is_empty() || actor == "anonymous" {
            return Ok(());
        }
        let grant = crate::org::MemberGrantRecord {
            id: crate::org::MemberGrantRecord::make_id(actor, fork_id),
            op: RecordOp::Upsert,
            authority: actor.to_owned(),
            project_id: fork_id.to_owned(),
        };
        let raw = serde_json::to_string(&grant).map_err(|error| error.to_string())?;
        self.store_mut()
            .append_record(crate::org::ORG_SCOPE, "member_grant", &raw)
            .map(|_| ())
            .map_err(|error| format!("{error:?}"))
    }

    /// Re-place the source's active Agents on the fork at their pinned
    /// versions. A Panel agent is placed without any deployment. Returns the
    /// Agents that were not placed and why.
    fn replace_agents(
        &mut self,
        source_id: &str,
        fork_id: &str,
        actor: &str,
    ) -> Vec<serde_json::Value> {
        let placements: Vec<_> = self
            .library
            .using_instances_of(source_id)
            .into_iter()
            .filter(|placement| placement.admission == Admission::Active)
            .cloned()
            .collect();
        let source_general = crate::library_routes::general_placement_id(source_id);
        let fork_general = crate::library_routes::general_placement_id(fork_id);
        let mut skipped = Vec::new();
        for placement in placements {
            let Some(agent) = self.library.agents.get(&placement.agent_id).cloned() else {
                continue;
            };
            let skip = |reason: &str| json!({ "agent_id": agent.id, "name": agent.name, "reason": reason });
            let placed = if placement.id == source_general {
                self.library
                    .instances
                    .contains_key(&fork_general)
                    .then(|| fork_general.clone())
                    .ok_or_else(|| "the fork has no built-in Agent".to_owned())
            } else if self.desktop_account_mode() && !self.agent_placeable_by(&agent.id, actor) {
                skipped.push(skip("this Agent belongs to another account"));
                continue;
            } else if placement.placement_kind == PlacementKind::Panel {
                if placement.collection_recipient.is_some() {
                    skipped.push(skip(
                        "this Panel agent collects output and needs a recipient chosen in the fork",
                    ));
                    continue;
                }
                self.place_panel_agent_on_project(fork_id, &agent.id, Admission::Active, None)
            } else if agent.agent_kind == AgentKind::Panel {
                continue;
            } else {
                self.place_archetype_on_project(fork_id, &agent.id, Admission::Active)
            };
            match placed {
                Ok(fork_placement) => {
                    if let Some(mut record) = self.library.instances.get(&fork_placement).cloned() {
                        if record.agent_id == placement.agent_id
                            && record.kind == InstanceKind::Using
                            && record.version != placement.version
                        {
                            record.op = RecordOp::Upsert;
                            record.version = placement.version;
                            self.write_instance_record(record);
                        }
                    }
                }
                Err(reason) => skipped.push(skip(&reason)),
            }
        }
        skipped
    }

    fn fork_receipt(&self, id: &str, skipped_agents: Vec<serde_json::Value>) -> serde_json::Value {
        let project = self.library.projects.get(id);
        json!({
            "id": id,
            "name": project.map(|project| project.name.clone()),
            "home_id": self.home_id().as_str(),
            "upstream": project.and_then(upstream_of).map(|upstream| upstream.project_id),
            "skipped_agents": skipped_agents,
        })
    }

    /// What pulling `fork_id`'s upstream would do now.
    fn pull_preview(
        &mut self,
        fork_id: &str,
    ) -> Result<(Upstream, PullPlan, Option<String>), ForkError> {
        let fork = self
            .library
            .projects
            .get(fork_id)
            .cloned()
            .ok_or(ForkError::NotFound)?;
        let upstream = upstream_of(&fork)
            .ok_or_else(|| ForkError::Conflict("this project is not a fork".into()))?;
        let source = self
            .library
            .projects
            .get(&upstream.project_id)
            .cloned()
            .ok_or_else(|| ForkError::Conflict("the original no longer exists here".into()))?;
        if source.home_id != fork.home_id || &source.home_id != self.home_id() {
            return Err(ForkError::Conflict(
                "pulling from a project on another Project Host is not available yet".into(),
            ));
        }
        if self.project_moving(&upstream.project_id) || self.project_moving(fork_id) {
            return Err(ForkError::Conflict(
                crate::federation::PAUSED_FOR_MOVE.into(),
            ));
        }
        let basis = self.current_basis(fork_id).map_err(ForkError::Failed)?;
        let (theirs, source_cut) = self
            .managed_manifest(&upstream.project_id)
            .map_err(ForkError::Failed)?;
        let (ours, _) = self.managed_manifest(fork_id).map_err(ForkError::Failed)?;
        Ok((
            upstream,
            plan_pull(&basis.files, &theirs, &ours),
            source_cut,
        ))
    }

    /// Pull `fork_id`'s upstream into its Main. `expected_cut` is the
    /// original's cut the caller previewed; if the original moved since, the
    /// caller previews again rather than settling conflicts it never saw.
    pub fn pull_upstream(
        &mut self,
        fork_id: &str,
        actor: &str,
        expected_cut: Option<&str>,
        resolutions: &BTreeMap<String, Resolution>,
    ) -> Result<serde_json::Value, ForkError> {
        let (upstream, plan, source_cut) = self.pull_preview(fork_id)?;
        if let Some(expected) = expected_cut {
            if source_cut.as_deref() != Some(expected) {
                return Err(ForkError::Conflict(
                    "the original changed since this pull was previewed".into(),
                ));
            }
        }
        let unresolved: Vec<&String> = plan
            .conflicts
            .iter()
            .filter(|path| !resolutions.contains_key(*path))
            .collect();
        if !unresolved.is_empty() {
            return Err(ForkError::Conflict(format!(
                "choose a version for every conflicting file: {}",
                unresolved
                    .iter()
                    .map(|path| path.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
        let (theirs, _) = self
            .managed_manifest(&upstream.project_id)
            .map_err(ForkError::Failed)?;
        let mut take: Vec<String> = plan.take.clone();
        let mut remove: Vec<String> = plan.remove.clone();
        for path in &plan.conflicts {
            if resolutions.get(path) == Some(&Resolution::Theirs) {
                if theirs.contains_key(path) {
                    take.push(path.clone());
                } else {
                    remove.push(path.clone());
                }
            }
        }
        let mut writes = Vec::with_capacity(take.len());
        for path in &take {
            writes.push((
                path.clone(),
                self.read_managed_bytes(&upstream.project_id, path)
                    .map_err(ForkError::Failed)?,
            ));
        }
        let source_name = self
            .library
            .projects
            .get(&upstream.project_id)
            .map(|project| project.name.clone())
            .unwrap_or_default();
        if !writes.is_empty() || !remove.is_empty() {
            let outcome = self
                .land_on_managed_main(
                    fork_id,
                    &writes,
                    &remove,
                    &format!("Pull from {source_name}"),
                )
                .map_err(ForkError::Failed)?;
            if outcome != MergeOutcome::Clean {
                return Err(ForkError::Conflict(
                    "the fork's Main changed while pulling; nothing was changed, preview again"
                        .into(),
                ));
            }
        }
        self.record_basis(
            fork_id,
            &UpstreamBasis {
                source_project: upstream.project_id.clone(),
                source_cut: source_cut.clone(),
                files: theirs,
                actor: actor.to_owned(),
            },
        )
        .map_err(ForkError::Failed)?;
        Ok(json!({
            "pulled": take.len() + remove.len(),
            "taken": take,
            "removed": remove,
            "kept": plan.conflicts.iter().filter(|path| resolutions.get(*path) == Some(&Resolution::Mine)).collect::<Vec<_>>(),
            "source_cut": source_cut,
        }))
    }
}

/// A fork's id is derived from its source, its forking account and the
/// caller's operation key, so a retry lands on the same project.
fn fork_project_id(source_id: &str, actor: &str, operation: &str) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(format!("gaugedesk-fork:{source_id}:{actor}:{operation}"));
    format!("proj-fork-{}", hex::encode(&digest[..12]))
}

fn fork_name(source: &str) -> String {
    let suffix = " (fork)";
    let room = 120 - suffix.chars().count();
    let base: String = source.trim().chars().take(room).collect();
    format!("{base}{suffix}")
}

// ---- routes -----------------------------------------------------------------

/// Admit the request's actor to read `project`, the way the route boundary
/// admits a request naming it. Used for the *other* project a fork or pull
/// reads, which the path does not name.
#[allow(clippy::result_large_err)]
fn admit_reader(
    wb: &Workbench,
    headers: &HeaderMap,
    project: &str,
) -> Result<String, axum::response::Response> {
    let bearer = net_http::bearer(headers);
    let scope = crate::workbench_auth::req_scope(headers);
    let actor = wb
        .admit_data_request_with_client(
            bearer,
            Some(project),
            &scope,
            crate::client_admission::ClientBuild::from_headers(headers),
            false,
        )
        .map_err(IntoResponse::into_response)?;
    if !wb.project_visibility_in(bearer, &scope).allows(project) {
        return Err(ForkError::NotFound.into_response());
    }
    Ok(actor)
}

#[derive(Deserialize, Default)]
pub struct ForkProject {
    #[serde(default)]
    pub name: Option<String>,
    /// Idempotency key; a retry with the same key returns the same fork.
    #[serde(default)]
    pub operation_id: Option<String>,
}

pub async fn fork_project(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<ForkProject>,
) -> axum::response::Response {
    let mut wb = wb.lock_unpoisoned();
    let actor = match admit_reader(&wb, &headers, &id) {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    let operation = body
        .operation_id
        .filter(|operation| !operation.trim().is_empty())
        .unwrap_or_else(|| crate::library::gen_id("fork"));
    match wb.fork_project(&id, body.name.as_deref(), &actor, &operation) {
        Ok(receipt) => (StatusCode::CREATED, Json(receipt)).into_response(),
        Err(error) => error.into_response(),
    }
}

/// The fork's upstream and what a pull would bring now. The original is
/// re-admitted on every read: a person who can no longer open it learns only
/// that pulling is unavailable.
pub async fn get_upstream(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> axum::response::Response {
    let mut wb = wb.lock_unpoisoned();
    let Some(upstream) = wb.library.projects.get(&id).and_then(upstream_of) else {
        return (StatusCode::OK, Json(json!({ "upstream": null }))).into_response();
    };
    if admit_reader(&wb, &headers, &upstream.project_id).is_err() {
        return (
            StatusCode::OK,
            Json(json!({
                "upstream": { "available": false, "reason": "you can no longer open the original" }
            })),
        )
            .into_response();
    }
    let name = wb
        .library
        .projects
        .get(&upstream.project_id)
        .map(|project| project.name.clone());
    match wb.pull_preview(&id) {
        Ok((upstream, plan, source_cut)) => (
            StatusCode::OK,
            Json(json!({
                "upstream": {
                    "available": true,
                    "project_id": upstream.project_id,
                    "name": name,
                    "source_cut": source_cut,
                    "take": plan.take,
                    "remove": plan.remove,
                    "conflicts": plan.conflicts,
                }
            })),
        )
            .into_response(),
        Err(ForkError::Conflict(reason)) => (
            StatusCode::OK,
            Json(json!({
                "upstream": {
                    "available": false,
                    "project_id": upstream.project_id,
                    "name": name,
                    "reason": reason,
                }
            })),
        )
            .into_response(),
        Err(error) => error.into_response(),
    }
}

#[derive(Deserialize, Default)]
pub struct PullUpstream {
    /// The original's cut the caller previewed.
    #[serde(default)]
    pub source_cut: Option<String>,
    /// A version for every conflicting path.
    #[serde(default)]
    pub resolutions: BTreeMap<String, Resolution>,
}

pub async fn pull_upstream(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<PullUpstream>,
) -> axum::response::Response {
    let mut wb = wb.lock_unpoisoned();
    let Some(fork) = wb.library.projects.get(&id).cloned() else {
        return ForkError::NotFound.into_response();
    };
    let Some(upstream) = upstream_of(&fork) else {
        return ForkError::Conflict("this project is not a fork".into()).into_response();
    };
    let actor = match admit_reader(&wb, &headers, &upstream.project_id) {
        Ok(actor) => actor,
        Err(_) => {
            return ForkError::Refused("you can no longer open the original".into()).into_response()
        }
    };
    // Only the fork's owner takes its original's work into it.
    if crate::project_owner::recorded_owner(&fork).is_some_and(|owner| owner != actor) {
        return ForkError::Refused("only the fork's owner can pull its original".into())
            .into_response();
    }
    match wb.pull_upstream(&id, &actor, body.source_cut.as_deref(), &body.resolutions) {
        Ok(receipt) => (StatusCode::OK, Json(receipt)).into_response(),
        Err(error) => error.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(path, hash)| ((*path).to_owned(), (*hash).to_owned()))
            .collect()
    }

    #[test]
    fn a_pull_takes_only_what_the_original_changed_and_names_what_both_changed() {
        let base = manifest(&[
            ("same", "a"),
            ("theirs", "a"),
            ("ours", "a"),
            ("both", "a"),
            ("gone", "a"),
            ("agreed", "a"),
        ]);
        let theirs = manifest(&[
            ("same", "a"),
            ("theirs", "b"),
            ("ours", "a"),
            ("both", "b"),
            ("agreed", "c"),
            ("new", "n"),
        ]);
        let ours = manifest(&[
            ("same", "a"),
            ("theirs", "a"),
            ("ours", "b"),
            ("both", "c"),
            ("gone", "a"),
            ("agreed", "c"),
            ("mine", "m"),
        ]);
        let plan = plan_pull(&base, &theirs, &ours);
        assert_eq!(plan.take, vec!["new".to_owned(), "theirs".to_owned()]);
        assert_eq!(plan.remove, vec!["gone".to_owned()]);
        assert_eq!(plan.conflicts, vec!["both".to_owned()]);
    }

    #[test]
    fn a_path_the_fork_removed_but_the_original_changed_is_a_conflict() {
        let base = manifest(&[("f", "a")]);
        let plan = plan_pull(&base, &manifest(&[("f", "b")]), &manifest(&[]));
        assert_eq!(plan.conflicts, vec!["f".to_owned()]);
    }

    use crate::LockUnpoisoned;

    fn bytes(wb: &mut Workbench, project: &str) -> BTreeMap<String, Vec<u8>> {
        let (files, _) = wb.managed_manifest(project).unwrap();
        files
            .keys()
            .map(|path| (path.clone(), wb.read_managed_bytes(project, path).unwrap()))
            .collect()
    }

    fn land(wb: &mut Workbench, project: &str, writes: &[(&str, &[u8])], removes: &[&str]) {
        let writes: Vec<(String, Vec<u8>)> = writes
            .iter()
            .map(|(path, body)| ((*path).to_owned(), body.to_vec()))
            .collect();
        let removes: Vec<String> = removes.iter().map(|path| (*path).to_owned()).collect();
        assert_eq!(
            wb.land_on_managed_main(project, &writes, &removes, "test")
                .unwrap(),
            MergeOutcome::Clean
        );
    }

    fn forked() -> (tempfile::TempDir, crate::SharedWorkbench, String, String) {
        let root = tempfile::tempdir().unwrap();
        let shared = crate::workbench_state::open_lean_workbench(root.path()).unwrap();
        let fork_id = {
            let mut wb = shared.lock_unpoisoned();
            crate::library_routes::create_named_project(&mut wb, "proj-peach", "Peach").unwrap();
            land(
                &mut wb,
                "proj-peach",
                &[
                    ("notes.md", b"base notes"),
                    ("image.bin", b"\0\xff\x80picture"),
                ],
                &[],
            );
            let actor = wb.authority().as_str().to_owned();
            wb.fork_project("proj-peach", None, &actor, "op-1").unwrap()["id"]
                .as_str()
                .unwrap()
                .to_owned()
        };
        (root, shared, "proj-peach".to_owned(), fork_id)
    }

    #[test]
    fn a_fork_copies_the_managed_files_exactly_and_records_its_upstream() {
        let (_root, shared, source, fork) = forked();
        let mut wb = shared.lock_unpoisoned();
        assert_eq!(bytes(&mut wb, &fork), bytes(&mut wb, &source));
        assert_eq!(bytes(&mut wb, &fork)["image.bin"], b"\0\xff\x80picture");
        let record = wb.library.projects.get(&fork).unwrap().clone();
        assert_eq!(record.name, "Peach (fork)");
        assert!(!record.is_default);
        let actor = wb.authority().as_str().to_owned();
        assert_eq!(
            crate::project_owner::recorded_owner(&record),
            Some(actor.as_str())
        );
        assert_eq!(upstream_of(&record).unwrap().project_id, source);
        assert!(wb
            .library
            .chats
            .values()
            .all(|chat| { wb.library.project_of_chat(&chat.id) != Some(fork.as_str()) }));
    }

    #[test]
    fn a_retried_fork_returns_the_same_project() {
        let (_root, shared, source, fork) = forked();
        let mut wb = shared.lock_unpoisoned();
        let count = wb.library.projects.len();
        let actor = wb.authority().as_str().to_owned();
        let again = wb.fork_project(&source, None, &actor, "op-1").unwrap();
        assert_eq!(again["id"], fork.as_str());
        assert_eq!(wb.library.projects.len(), count);
        let other = wb
            .fork_project(&source, Some("Another"), &actor, "op-2")
            .unwrap();
        assert_ne!(other["id"], fork.as_str());
    }

    #[test]
    fn a_fork_inherits_its_originals_protective_posture() {
        let root = tempfile::tempdir().unwrap();
        let shared = crate::workbench_state::open_lean_workbench(root.path()).unwrap();
        let mut wb = shared.lock_unpoisoned();
        crate::library_routes::create_named_project(&mut wb, "proj-closed", "Closed").unwrap();
        wb.update_project_record(
            "proj-closed",
            None,
            Some(true),
            None,
            Some(Some("audit".into())),
        )
        .unwrap();
        let actor = wb.authority().as_str().to_owned();
        let fork = wb.fork_project("proj-closed", None, &actor, "op").unwrap();
        let record = wb
            .library
            .projects
            .get(fork["id"].as_str().unwrap())
            .unwrap();
        assert!(record.network_isolated);
        assert_eq!(record.run_purpose.as_deref(), Some("audit"));
    }

    #[test]
    fn a_pull_brings_the_originals_changes_and_keeps_the_forks_own() {
        let (_root, shared, source, fork) = forked();
        let mut wb = shared.lock_unpoisoned();
        land(
            &mut wb,
            &source,
            &[("notes.md", b"newer notes"), ("new.md", b"new")],
            &["image.bin"],
        );
        land(&mut wb, &fork, &[("mine.md", b"fork only")], &[]);
        let (_, plan, cut) = wb.pull_preview(&fork).unwrap();
        assert_eq!(plan.take, vec!["new.md".to_owned(), "notes.md".to_owned()]);
        assert_eq!(plan.remove, vec!["image.bin".to_owned()]);
        assert!(plan.conflicts.is_empty());
        let actor = wb.authority().as_str().to_owned();
        wb.pull_upstream(&fork, &actor, cut.as_deref(), &BTreeMap::new())
            .unwrap();
        let files = bytes(&mut wb, &fork);
        assert_eq!(files["notes.md"], b"newer notes");
        assert_eq!(files["new.md"], b"new");
        assert_eq!(files["mine.md"], b"fork only");
        assert!(!files.contains_key("image.bin"));
        assert!(wb.pull_preview(&fork).unwrap().1.is_empty());
        // The original is untouched by its fork's work.
        assert!(!bytes(&mut wb, &source).contains_key("mine.md"));
    }

    #[test]
    fn a_conflict_is_settled_only_by_an_explicit_choice() {
        let (_root, shared, source, fork) = forked();
        let mut wb = shared.lock_unpoisoned();
        land(&mut wb, &source, &[("notes.md", b"theirs")], &[]);
        land(&mut wb, &fork, &[("notes.md", b"mine")], &[]);
        let (_, plan, cut) = wb.pull_preview(&fork).unwrap();
        assert_eq!(plan.conflicts, vec!["notes.md".to_owned()]);
        let actor = wb.authority().as_str().to_owned();
        assert!(matches!(
            wb.pull_upstream(&fork, &actor, cut.as_deref(), &BTreeMap::new()),
            Err(ForkError::Conflict(_))
        ));
        assert_eq!(bytes(&mut wb, &fork)["notes.md"], b"mine");
        let keep = BTreeMap::from([("notes.md".to_owned(), Resolution::Mine)]);
        wb.pull_upstream(&fork, &actor, cut.as_deref(), &keep)
            .unwrap();
        assert_eq!(bytes(&mut wb, &fork)["notes.md"], b"mine");
        // Kept once, it is not asked about again until the original moves.
        assert!(wb.pull_preview(&fork).unwrap().1.is_empty());
        land(&mut wb, &source, &[("notes.md", b"theirs again")], &[]);
        let (_, plan, cut) = wb.pull_preview(&fork).unwrap();
        assert_eq!(plan.conflicts, vec!["notes.md".to_owned()]);
        let take = BTreeMap::from([("notes.md".to_owned(), Resolution::Theirs)]);
        wb.pull_upstream(&fork, &actor, cut.as_deref(), &take)
            .unwrap();
        assert_eq!(bytes(&mut wb, &fork)["notes.md"], b"theirs again");
    }

    #[test]
    fn a_pull_refuses_a_preview_the_original_has_moved_past() {
        let (_root, shared, source, fork) = forked();
        let mut wb = shared.lock_unpoisoned();
        let (_, _, cut) = wb.pull_preview(&fork).unwrap();
        land(&mut wb, &source, &[("notes.md", b"moved")], &[]);
        let actor = wb.authority().as_str().to_owned();
        assert!(matches!(
            wb.pull_upstream(&fork, &actor, cut.as_deref(), &BTreeMap::new()),
            Err(ForkError::Conflict(_))
        ));
        assert_eq!(bytes(&mut wb, &fork)["notes.md"], b"base notes");
    }

    #[test]
    fn deleting_the_original_leaves_the_fork_whole() {
        let (_root, shared, source, fork) = forked();
        let mut wb = shared.lock_unpoisoned();
        assert!(wb.delete_project_cascade(&source));
        assert!(matches!(
            wb.pull_preview(&fork),
            Err(ForkError::Conflict(_))
        ));
        assert_eq!(bytes(&mut wb, &fork)["notes.md"], b"base notes");
    }

    #[test]
    fn a_fork_places_the_originals_agents_at_their_pinned_versions() {
        let root = tempfile::tempdir().unwrap();
        let shared = crate::workbench_state::open_workbench(root.path()).unwrap();
        let mut wb = shared.lock_unpoisoned();
        crate::library_routes::create_named_project(&mut wb, "proj-apple", "Apple").unwrap();
        let general = crate::library_routes::general_placement_id("proj-apple");
        let mut pinned = wb
            .library
            .instances
            .get(&general)
            .expect("built-in Agent")
            .clone();
        pinned.op = RecordOp::Upsert;
        pinned.version = 1;
        wb.write_instance_record(pinned.clone());
        let actor = wb.authority().as_str().to_owned();
        let fork = wb.fork_project("proj-apple", None, &actor, "op").unwrap();
        let fork = fork["id"].as_str().unwrap();
        let forked = wb
            .library
            .instances
            .get(&crate::library_routes::general_placement_id(fork))
            .unwrap();
        assert_eq!(forked.agent_id, pinned.agent_id);
        assert_eq!(forked.version, 1);
        assert_eq!(
            wb.library.using_instances_of(fork).len(),
            wb.library.using_instances_of("proj-apple").len()
        );
    }

    #[test]
    fn a_fork_name_stays_within_the_project_name_limit() {
        assert_eq!(fork_name("Peach"), "Peach (fork)");
        assert_eq!(fork_name(&"x".repeat(200)).chars().count(), 120);
    }
}
