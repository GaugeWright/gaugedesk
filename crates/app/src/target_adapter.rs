//! Protected locator custody and external target attachment (ADR 0100).
//!
//! Locator paths are control-plane state stored outside the library projection.
//! Target records and clients carry only an opaque handle.

use std::path::{Path, PathBuf};

use axum::{
    extract::{Path as AxumPath, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use gaugewright_workspace::{ExternalTargetKind, ExternalWorkspace, Workspace};

use crate::library::{
    gen_id, PlacementTargetsRecord, RecordOp, TargetCapabilities, TargetVcsPosture, WorkTargetKind,
    WorkTargetOwner, WorkTargetRecord, WorkTargetStatus,
};
use crate::{LockUnpoisoned, SharedWorkbench, Workbench};

const TARGET_ACT_KIND: &str = "target_act";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TargetActKind {
    Read,
    Propose,
    Apply,
    Publish,
    Release,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TargetActStatus {
    Completed,
    Refused,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TargetActRecord {
    pub id: String,
    pub target_id: String,
    pub chat_id: Option<String>,
    pub act: TargetActKind,
    pub basis: String,
    pub candidate: Option<String>,
    pub checks: Vec<String>,
    pub resulting_revision: Option<String>,
    pub adapter: String,
    pub status: TargetActStatus,
    pub reason: Option<String>,
}

fn target_act_scope(target_id: &str) -> String {
    format!("target::{target_id}::acts")
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ProtectedLocator {
    handle: String,
    kind: WorkTargetKind,
    path: PathBuf,
}

#[derive(Debug, Deserialize)]
pub struct AttachTargetBody {
    pub name: String,
    pub kind: WorkTargetKind,
    pub path: PathBuf,
    #[serde(default = "whole_target_scope")]
    pub path_scope: Vec<String>,
}

fn whole_target_scope() -> Vec<String> {
    vec![".".to_owned()]
}

fn locator_root(targets_root: &Path) -> PathBuf {
    targets_root
        .parent()
        .unwrap_or(targets_root)
        .join("control")
        .join("target-locators")
}

fn locator_file(targets_root: &Path, handle: &str) -> PathBuf {
    locator_root(targets_root).join(format!("{}.json", hex::encode(handle.as_bytes())))
}

fn write_locator(targets_root: &Path, locator: &ProtectedLocator) -> Result<(), String> {
    let root = locator_root(targets_root);
    std::fs::create_dir_all(&root).map_err(|error| error.to_string())?;
    let final_path = locator_file(targets_root, &locator.handle);
    let temporary = final_path.with_extension("json.tmp");
    std::fs::write(
        &temporary,
        serde_json::to_vec(locator).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())?;
    }
    std::fs::rename(temporary, final_path).map_err(|error| error.to_string())
}

fn read_locator(targets_root: &Path, handle: &str) -> Result<ProtectedLocator, String> {
    let body = std::fs::read(locator_file(targets_root, handle))
        .map_err(|error| format!("protected locator {handle} is unavailable: {error}"))?;
    let locator: ProtectedLocator =
        serde_json::from_slice(&body).map_err(|error| error.to_string())?;
    if locator.handle != handle {
        return Err("protected locator handle does not match its record".to_owned());
    }
    Ok(locator)
}

pub(crate) fn open_external_workspace(
    targets_root: &Path,
    target: &WorkTargetRecord,
) -> Result<Box<dyn Workspace>, String> {
    let locator = read_locator(targets_root, &target.locator_handle)?;
    if locator.kind != target.kind {
        return Err(format!(
            "protected locator kind does not match target {}",
            target.id
        ));
    }
    let kind = match target.kind {
        WorkTargetKind::ExternalVcs => ExternalTargetKind::Git,
        WorkTargetKind::ExternalFolder => ExternalTargetKind::Folder,
        WorkTargetKind::Managed => {
            return Err("managed targets do not resolve through protected locators".to_owned())
        }
    };
    ExternalWorkspace::open(&locator.path, targets_root.join(&target.id), kind)
        .map(|workspace| Box::new(workspace) as Box<dyn Workspace>)
        .map_err(|error| error.to_string())
}

pub(crate) fn remove_locator(targets_root: &Path, handle: &str) {
    if !handle.starts_with("managed-target:") {
        let _ = std::fs::remove_file(locator_file(targets_root, handle));
    }
}

impl Workbench {
    // Each argument maps directly to a durable TargetActRecord field. Keeping
    // them explicit makes security-sensitive call sites auditable.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record_target_act(
        &mut self,
        chat_id: Option<&str>,
        target_id: &str,
        act: TargetActKind,
        candidate: Option<String>,
        checks: Vec<String>,
        resulting_revision: Option<String>,
        status: TargetActStatus,
        reason: Option<String>,
    ) -> Result<TargetActRecord, String> {
        let target = self
            .library
            .work_targets
            .get(target_id)
            .ok_or_else(|| "no such work target".to_owned())?;
        let basis = chat_id
            .and_then(|chat_id| self.library.chat_targets.get(chat_id))
            .map(|binding| binding.basis.clone())
            .or_else(|| target.current_basis.clone())
            .ok_or_else(|| "work target has no exact basis".to_owned())?;
        let record = TargetActRecord {
            id: gen_id("target-act"),
            target_id: target_id.to_owned(),
            chat_id: chat_id.map(str::to_owned),
            act,
            basis,
            candidate,
            checks,
            resulting_revision,
            adapter: target.adapter.clone(),
            status,
            reason,
        };
        self.store_mut()
            .append_record(
                &target_act_scope(target_id),
                TARGET_ACT_KIND,
                &serde_json::to_string(&record).map_err(|error| error.to_string())?,
            )
            .map_err(|error| format!("{error:?}"))?;
        Ok(record)
    }

    pub(crate) fn target_acts(&self, target_id: &str) -> Result<Vec<TargetActRecord>, String> {
        self.store_ref()
            .records(&target_act_scope(target_id), TARGET_ACT_KIND)
            .map_err(|error| format!("{error:?}"))?
            .into_iter()
            .map(|body| serde_json::from_str(&body).map_err(|error| error.to_string()))
            .collect()
    }

    pub(crate) fn available_target_acts(&self, chat_id: &str) -> Vec<TargetActKind> {
        let Some(binding) = self.library.chat_targets.get(chat_id) else {
            return Vec::new();
        };
        let mut acts = Vec::new();
        if binding.capabilities.read {
            acts.push(TargetActKind::Read);
        }
        if binding.capabilities.propose {
            acts.push(TargetActKind::Propose);
        }
        if binding.capabilities.apply {
            acts.push(TargetActKind::Apply);
        }
        if binding.capabilities.publish {
            acts.push(TargetActKind::Publish);
        }
        if binding.capabilities.release {
            acts.push(TargetActKind::Release);
        }
        acts
    }

    fn attach_external_target(
        &mut self,
        project_id: &str,
        body: AttachTargetBody,
    ) -> Result<WorkTargetRecord, String> {
        if body.name.trim().is_empty() {
            return Err("target name is required".to_owned());
        }
        if !matches!(
            body.kind,
            WorkTargetKind::ExternalVcs | WorkTargetKind::ExternalFolder
        ) {
            return Err("managed targets are created by GaugeDesk, not attached".to_owned());
        }
        if body.path_scope.is_empty()
            || body
                .path_scope
                .iter()
                .any(|path| path.trim().is_empty() || path.starts_with('/') || path.contains(".."))
        {
            return Err("target path scope must contain safe relative paths".to_owned());
        }
        let project = self
            .library
            .projects
            .get(project_id)
            .ok_or_else(|| "no such project".to_owned())?;
        if &project.home_id != self.home_id() {
            return Err("project belongs to another Home".to_owned());
        }
        let source = std::fs::canonicalize(&body.path).map_err(|error| error.to_string())?;
        if !source.is_dir() {
            return Err("target path is not a directory".to_owned());
        }
        let target_id = gen_id("target");
        let handle = gen_id("locator");
        let external_kind = match body.kind {
            WorkTargetKind::ExternalVcs => ExternalTargetKind::Git,
            WorkTargetKind::ExternalFolder => ExternalTargetKind::Folder,
            WorkTargetKind::Managed => unreachable!(),
        };
        let workspace =
            ExternalWorkspace::open(&source, self.targets_dir().join(&target_id), external_kind)
                .map_err(|error| error.to_string())?;
        let basis = workspace.exact_basis().map_err(|error| error.to_string())?;
        let can_publish = workspace.can_publish();
        write_locator(
            &self.targets_dir(),
            &ProtectedLocator {
                handle: handle.clone(),
                kind: body.kind,
                path: source,
            },
        )?;
        let (adapter, adapter_family, vcs_posture) = match body.kind {
            WorkTargetKind::ExternalVcs => (
                "git".to_owned(),
                "external-vcs:git-v1".to_owned(),
                TargetVcsPosture::ExternalVcs,
            ),
            WorkTargetKind::ExternalFolder => (
                "fingerprinted-folder".to_owned(),
                "external-folder:fingerprint-v1".to_owned(),
                TargetVcsPosture::Unversioned,
            ),
            WorkTargetKind::Managed => unreachable!(),
        };
        let target = WorkTargetRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: target_id.clone(),
            op: RecordOp::Upsert,
            name: body.name,
            owner: WorkTargetOwner::Project {
                project_id: project_id.to_owned(),
            },
            kind: body.kind,
            authority: self.home_id().as_str().to_owned(),
            parties: vec![self.home_id().as_str().to_owned()],
            locator_handle: handle,
            adapter,
            adapter_family,
            vcs_posture,
            current_basis: Some(basis),
            path_scope: body.path_scope,
            capabilities: TargetCapabilities {
                read: true,
                propose: true,
                apply: true,
                publish: can_publish,
                release: false,
            },
            status: WorkTargetStatus::Available,
        };
        self.targets.insert(target_id.clone(), Box::new(workspace));
        self.write_work_target_record(target.clone());
        let placement_ids = self
            .library
            .using_instances_of(project_id)
            .into_iter()
            .map(|placement| placement.id.clone())
            .collect::<Vec<_>>();
        for placement_id in placement_ids {
            let mut target_ids = self
                .library
                .placement_targets
                .get(&placement_id)
                .map(|record| record.target_ids.clone())
                .unwrap_or_default();
            if !target_ids.contains(&target_id) {
                target_ids.push(target_id.clone());
            }
            self.write_placement_targets_record(PlacementTargetsRecord {
                schema: crate::library::LIBRARY_RECORD_SCHEMA,
                extra: Default::default(),
                placement_id,
                op: RecordOp::Upsert,
                target_ids,
            });
        }
        Ok(target)
    }
}

pub async fn list_target_acts(
    State(workbench): State<SharedWorkbench>,
    AxumPath(target_id): AxumPath<String>,
) -> impl IntoResponse {
    let workbench = workbench.lock_unpoisoned();
    if !workbench.library.work_targets.contains_key(&target_id) {
        return (StatusCode::NOT_FOUND, "no such work target").into_response();
    }
    match workbench.target_acts(&target_id) {
        Ok(acts) => Json(json!({ "acts": acts })).into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error).into_response(),
    }
}

pub async fn request_terminal_target_act(
    State(workbench): State<SharedWorkbench>,
    AxumPath((chat_id, act)): AxumPath<(String, String)>,
) -> impl IntoResponse {
    let requested = match act.as_str() {
        "publish" => TargetActKind::Publish,
        "release" => TargetActKind::Release,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                "read, propose, and apply use their dedicated chat/file/merge commands",
            )
                .into_response()
        }
    };
    let mut workbench = workbench.lock_unpoisoned();
    let Some(binding) = workbench.library.chat_targets.get(&chat_id).cloned() else {
        return (StatusCode::NOT_FOUND, "no such target-bound chat").into_response();
    };
    let admitted = match requested {
        TargetActKind::Publish => binding.capabilities.publish,
        TargetActKind::Release => binding.capabilities.release,
        _ => false,
    };
    if admitted && requested == TargetActKind::Publish {
        let outcome = workbench
            .engagements
            .get(&chat_id)
            .ok_or_else(|| "chat candidate is unavailable".to_owned())
            .and_then(|candidate| candidate.publish().map_err(|error| error.to_string()));
        return match outcome {
            Ok(revision) => {
                let _ = workbench.record_target_act(
                    Some(&chat_id),
                    &binding.target_id,
                    requested,
                    None,
                    Vec::new(),
                    Some(revision.0),
                    TargetActStatus::Completed,
                    None,
                );
                (StatusCode::OK, Json(json!({ "published": true }))).into_response()
            }
            Err(reason) => {
                let record = workbench.record_target_act(
                    Some(&chat_id),
                    &binding.target_id,
                    requested,
                    None,
                    Vec::new(),
                    None,
                    TargetActStatus::Refused,
                    Some(reason),
                );
                (StatusCode::CONFLICT, Json(json!({ "act": record.ok() }))).into_response()
            }
        };
    }
    let reason = if admitted {
        "this adapter has no configured releaser capability"
    } else {
        "the chat target binding does not grant this act"
    };
    let record = workbench.record_target_act(
        Some(&chat_id),
        &binding.target_id,
        requested,
        None,
        Vec::new(),
        None,
        TargetActStatus::Refused,
        Some(reason.to_owned()),
    );
    match record {
        Ok(record) => (
            if admitted {
                StatusCode::NOT_IMPLEMENTED
            } else {
                StatusCode::FORBIDDEN
            },
            Json(json!({ "act": record })),
        )
            .into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error).into_response(),
    }
}

pub async fn attach_target(
    State(workbench): State<SharedWorkbench>,
    AxumPath(project_id): AxumPath<String>,
    Json(body): Json<AttachTargetBody>,
) -> impl IntoResponse {
    let mut workbench = workbench.lock_unpoisoned();
    match workbench.attach_external_target(&project_id, body) {
        Ok(target) => (
            StatusCode::CREATED,
            Json(Workbench::work_target_json(&target)),
        )
            .into_response(),
        Err(error) => {
            let status = if error == "no such project" {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::BAD_REQUEST
            };
            (status, Json(json!({ "error": error }))).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{open_workbench, DEFAULT_PLACEMENT, DEFAULT_PROJECT};

    #[test]
    fn folder_attach_keeps_locator_protected_and_refuses_stale_write() {
        let root = tempfile::tempdir().unwrap();
        let source = tempfile::tempdir().unwrap();
        std::fs::write(source.path().join("work.txt"), "basis\n").unwrap();
        let workbench = open_workbench(root.path()).unwrap();
        let (target_id, chat_id, handle) = {
            let mut workbench = workbench.lock_unpoisoned();
            let target = workbench
                .attach_external_target(
                    DEFAULT_PROJECT,
                    AttachTargetBody {
                        name: "Existing folder".to_owned(),
                        kind: WorkTargetKind::ExternalFolder,
                        path: source.path().to_path_buf(),
                        path_scope: whole_target_scope(),
                    },
                )
                .unwrap();
            let workspace_json = workbench.workspace_value().to_string();
            assert!(!workspace_json.contains(&source.path().display().to_string()));
            assert!(!workspace_json.contains(&target.locator_handle));
            let chat = workbench
                .create_chat_in_instance_on_target(
                    DEFAULT_PLACEMENT,
                    "folder work",
                    Some(&target.id),
                )
                .unwrap();
            let chat_id = chat["id"].as_str().unwrap().to_owned();
            let acts = workbench.target_acts(&target.id).unwrap();
            assert!(acts.iter().any(|act| {
                act.chat_id.as_deref() == Some(&chat_id)
                    && act.act == TargetActKind::Read
                    && act.status == TargetActStatus::Completed
            }));
            let candidate = workbench.engagements.get(&chat_id).unwrap();
            candidate.write_file("work.txt", "candidate\n").unwrap();
            candidate.commit_turn("candidate").unwrap();
            assert_eq!(
                std::fs::read_to_string(source.path().join("work.txt")).unwrap(),
                "basis\n"
            );
            std::fs::write(source.path().join("work.txt"), "concurrent\n").unwrap();
            assert_eq!(
                candidate.merge_into_main().unwrap(),
                gaugewright_workspace::MergeOutcome::Conflict
            );
            (target.id, chat_id, target.locator_handle)
        };
        assert!(locator_file(&root.path().join("targets"), &handle).is_file());
        drop(workbench);
        let reopened = open_workbench(root.path()).unwrap();
        let reopened = reopened.lock_unpoisoned();
        assert!(reopened.targets.contains_key(&target_id));
        assert!(reopened.engagements.contains_key(&chat_id));
        assert_eq!(
            std::fs::read_to_string(source.path().join("work.txt")).unwrap(),
            "concurrent\n"
        );
    }

    #[test]
    fn attaching_external_git_requires_a_clean_native_repository() {
        let root = tempfile::tempdir().unwrap();
        let source = tempfile::tempdir().unwrap();
        std::process::Command::new("git")
            .current_dir(source.path())
            .args(["init", "--quiet"])
            .status()
            .unwrap();
        std::fs::write(source.path().join("tracked.txt"), "basis\n").unwrap();
        std::process::Command::new("git")
            .current_dir(source.path())
            .args(["add", "tracked.txt"])
            .status()
            .unwrap();
        std::process::Command::new("git")
            .current_dir(source.path())
            .env("GIT_AUTHOR_NAME", "Test")
            .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
            .env("GIT_COMMITTER_NAME", "Test")
            .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
            .args(["commit", "--quiet", "-m", "basis"])
            .status()
            .unwrap();
        let workbench = open_workbench(root.path()).unwrap();
        let mut workbench = workbench.lock_unpoisoned();
        let target = workbench
            .attach_external_target(
                DEFAULT_PROJECT,
                AttachTargetBody {
                    name: "Native repository".to_owned(),
                    kind: WorkTargetKind::ExternalVcs,
                    path: source.path().to_path_buf(),
                    path_scope: whole_target_scope(),
                },
            )
            .unwrap();
        assert_eq!(target.vcs_posture, TargetVcsPosture::ExternalVcs);
        assert_eq!(target.adapter_family, "external-vcs:git-v1");

        std::fs::write(source.path().join("dirty.txt"), "not committed\n").unwrap();
        let error = workbench
            .attach_external_target(
                DEFAULT_PROJECT,
                AttachTargetBody {
                    name: "Dirty repository".to_owned(),
                    kind: WorkTargetKind::ExternalVcs,
                    path: source.path().to_path_buf(),
                    path_scope: whole_target_scope(),
                },
            )
            .unwrap_err();
        assert!(error.contains("must be clean"));
    }
}
