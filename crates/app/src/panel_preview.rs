//! Trying an Agent from the Workshop, run as a disposable work chat.
//!
//! A Panel agent's Preview (DR-0272 §3) and an Agent's "test in a chat"
//! (DR-0324) are the same thing: the author's draft, or for a Panel agent a
//! placement's pinned version, run with the provider, model, and funding the
//! author's work chats use by default. Every work-chat path assumes a placement
//! of an ordinary Agent on a project, so a preview is built from exactly those
//! parts and hidden:
//!
//! - a **hidden fork**, an ordinary Agent whose one preview version is the
//!   snapshot being tried — for a Panel agent narrowed to its public
//!   abilities, which is what a visitor's session may use;
//! - a **hidden project** holding one managed `workspace` target — seeded with
//!   a Panel agent's initial files, empty for an Agent — so nothing the preview
//!   writes reaches a real project, Personal, or an Inbox;
//! - one work placement and one chat.
//!
//! Funding is the author's own: the hidden project has no organization model
//! selection, so the engine resolves the provider, model, and credential the
//! way it does for any work chat. Ending the preview deletes the project and
//! the fork. The trade the founder accepted for a Panel agent is that Preview
//! exercises the agent, not the public runtime, its shared panels, or audience
//! admission; for an Agent, that a test sees no real project's files.
//!
//! The names here, and the `panel_preview` marker they persist, predate tests
//! of ordinary Agents and are kept because records already carry them.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::library::{
    self, Admission, AgentKind, ArchetypeVersionRecord, InstanceKind, PlacementKind,
    ProjectCollaborationWorkspaceRecord, ProjectRecord, RecordOp, LIBRARY_RECORD_SCHEMA,
};
use crate::library_state::{published_discipline_root, published_package_root};
use crate::Workbench;

/// The `extra` key marking a preview's hidden project and hidden Agent.
pub const PANEL_PREVIEW_EXTRA: &str = "panel_preview";

/// What a preview is of. Recorded on both hidden records so either one leads
/// back to the Agent it tries, and so a second preview of the same thing
/// replaces the first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PanelPreviewMarker {
    /// The Agent or Panel agent being tried.
    pub agent_id: String,
    /// The project placement whose pinned version is tried; absent for the
    /// Workshop draft.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement_id: Option<String>,
    /// The frozen version tried; absent for the draft.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u64>,
    /// The hidden project, written on the hidden Agent's marker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    /// The hidden Agent, written on the hidden project's marker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview_agent_id: Option<String>,
}

fn marker_of(
    extra: &std::collections::BTreeMap<String, serde_json::Value>,
) -> Option<PanelPreviewMarker> {
    extra
        .get(PANEL_PREVIEW_EXTRA)
        .and_then(|value| serde_json::from_value(value.clone()).ok())
}

/// What a preview's hidden project previews, if `project` is one.
pub fn preview_marker(project: &ProjectRecord) -> Option<PanelPreviewMarker> {
    marker_of(&project.extra)
}

/// Whether `project` is a preview's hidden project.
pub fn is_panel_preview_project(project: &ProjectRecord) -> bool {
    project.extra.contains_key(PANEL_PREVIEW_EXTRA)
}

/// Whether `agent` is a preview's hidden Agent.
pub fn is_panel_preview_agent(agent: &library::AgentRecord) -> bool {
    agent.extra.contains_key(PANEL_PREVIEW_EXTRA)
}

/// One live preview, as the Panel agent's projection lists it.
#[derive(Clone, Debug, Serialize)]
pub struct LivePanelPreview {
    pub chat_id: String,
    pub project_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placement_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u64>,
}

fn copy_tree(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let destination = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &destination)?;
        } else {
            std::fs::copy(entry.path(), destination)?;
        }
    }
    Ok(())
}

/// Every file under `root`, as a relative `/`-separated path and its bytes.
fn files_under(root: &Path) -> std::io::Result<Vec<(String, Vec<u8>)>> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) -> std::io::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                walk(root, &path, out)?;
            } else {
                let relative = path
                    .strip_prefix(root)
                    .map_err(std::io::Error::other)?
                    .components()
                    .map(|part| part.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                out.push((relative, std::fs::read(&path)?));
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(root, root, &mut out)?;
    out.sort();
    Ok(out)
}

/// Narrow a snapshot's package to the abilities a visitor's session may use.
fn narrow_abilities(package_root: &Path, public_abilities: &[String]) -> Result<(), String> {
    let manifest_path = package_root.join("package.json");
    let text = std::fs::read_to_string(&manifest_path).map_err(|error| error.to_string())?;
    let mut manifest: serde_json::Value =
        serde_json::from_str(&text).map_err(|error| error.to_string())?;
    let object = manifest
        .as_object_mut()
        .ok_or_else(|| "the Panel agent's package manifest is not an object".to_owned())?;
    object.insert(
        "agent_abilities".to_owned(),
        serde_json::Value::from(public_abilities.to_vec()),
    );
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
}

/// The one managed target a Panel preview's agent works in, which a work chat
/// shows as a folder of this name.
const PREVIEW_TARGET: &str = "workspace";

/// Tell a Panel preview's agent where a visitor's folders are.
///
/// A deployed session keeps `artifacts/`, `work/` and `outbox/` at its root,
/// and a Panel agent's instructions name them so (DR-0310). Preview runs as a
/// work chat, which shows its one target as the folder `workspace/`, so a
/// write to `outbox/survey.json` was refused as outside every folder and the
/// author's test failed on instructions that are right for a visitor. The note
/// goes into the preview's own copy of the instructions, never the Agent's.
fn note_preview_folders(package_root: &Path) -> Result<(), String> {
    let manifest_path = package_root.join("package.json");
    let text = std::fs::read_to_string(&manifest_path).map_err(|error| error.to_string())?;
    let mut manifest: serde_json::Value =
        serde_json::from_str(&text).map_err(|error| error.to_string())?;
    let context = match manifest
        .get("project_context")
        .and_then(|value| value.as_str())
    {
        Some(context) => context.to_owned(),
        None => {
            manifest["project_context"] = serde_json::Value::from("AGENTS.md");
            std::fs::write(
                &manifest_path,
                serde_json::to_string_pretty(&manifest).map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            "AGENTS.md".to_owned()
        }
    };
    let path = package_root.join(&context);
    let mut body = std::fs::read_to_string(&path).unwrap_or_default();
    body.push_str(&format!(
        "\n\n## This is the owner's preview\n\nIn a visitor's session the folders `artifacts/`, `work/` and `outbox/` are at the top level. In this preview they are inside `{PREVIEW_TARGET}/`: wherever these instructions name a path such as `outbox/survey.json`, use `{PREVIEW_TARGET}/outbox/survey.json`. Behave otherwise exactly as you would for a visitor.\n"
    ));
    std::fs::write(&path, body).map_err(|error| error.to_string())
}

impl Workbench {
    /// Every live preview of the Agent or Panel agent `agent_id`.
    pub(crate) fn panel_previews_of(&self, agent_id: &str) -> Vec<LivePanelPreview> {
        self.library
            .projects
            .values()
            .filter_map(|project| {
                let marker = marker_of(&project.extra)?;
                (marker.agent_id == agent_id).then_some((project, marker))
            })
            .filter_map(|(project, marker)| {
                let chat_id = self
                    .library
                    .chats
                    .values()
                    .find(|chat| {
                        self.library
                            .instances
                            .get(&chat.instance_id)
                            .and_then(|instance| instance.project_id.as_deref())
                            == Some(project.id.as_str())
                    })?
                    .id
                    .clone();
                Some(LivePanelPreview {
                    chat_id,
                    project_id: project.id.clone(),
                    placement_id: marker.placement_id,
                    version: marker.version,
                })
            })
            .collect()
    }

    /// The hidden project of the preview that `chat_id` belongs to, if any.
    pub(crate) fn panel_preview_project_of_chat(&self, chat_id: &str) -> Option<String> {
        let chat = self.library.chats.get(chat_id)?;
        let project_id = self
            .library
            .instances
            .get(&chat.instance_id)?
            .project_id
            .clone()?;
        self.library
            .projects
            .get(&project_id)
            .filter(|project| is_panel_preview_project(project))
            .map(|project| project.id.clone())
    }

    /// Whether `project_id` names a preview's hidden project.
    pub(crate) fn is_panel_preview_project_id(&self, project_id: &str) -> bool {
        self.library
            .projects
            .get(project_id)
            .is_some_and(is_panel_preview_project)
    }

    /// Whether `target` belongs to a preview: its hidden project's workspace or
    /// its hidden Agent's authoring target.
    pub(crate) fn is_panel_preview_target(&self, target: &library::WorkTargetRecord) -> bool {
        match &target.owner {
            library::WorkTargetOwner::Project { project_id } => {
                self.is_panel_preview_project_id(project_id)
            }
            library::WorkTargetOwner::Archetype { archetype_id } => self
                .library
                .agents
                .get(archetype_id)
                .is_some_and(is_panel_preview_agent),
        }
    }

    /// End one preview: its hidden project, chat, target, and Agent go.
    pub(crate) fn end_panel_preview(&mut self, project_id: &str) -> bool {
        let Some(marker) = self
            .library
            .projects
            .get(project_id)
            .and_then(|project| marker_of(&project.extra))
        else {
            return false;
        };
        let removed = self.delete_project_cascade(project_id);
        if let Some(preview_agent) = marker.preview_agent_id {
            let _ = self.delete_agent_cascade(&preview_agent);
        }
        removed
    }

    /// End every preview of the Agent or Panel agent `agent_id`.
    pub(crate) fn end_panel_previews_of(&mut self, agent_id: &str) {
        let projects = self
            .panel_previews_of(agent_id)
            .into_iter()
            .map(|preview| preview.project_id)
            .collect::<Vec<_>>();
        // A preview whose chat is already gone is still a hidden project.
        let orphaned = self
            .library
            .projects
            .values()
            .filter(|project| {
                marker_of(&project.extra).is_some_and(|marker| marker.agent_id == agent_id)
            })
            .map(|project| project.id.clone())
            .collect::<Vec<_>>();
        for project in projects.into_iter().chain(orphaned) {
            self.end_panel_preview(&project);
        }
    }

    /// Open a disposable work chat running `agent_id`: its draft, or for a
    /// Panel agent the version pinned by its project placement `placement_id`.
    ///
    /// A preview of the same thing that is already open is replaced, so trying
    /// a draft again picks up the edits made since. Returns the chat, as
    /// creating any chat does.
    pub(crate) fn start_panel_preview_chat(
        &mut self,
        agent_id: &str,
        placement_id: Option<&str>,
    ) -> Result<serde_json::Value, String> {
        let agent = self
            .library
            .agents
            .get(agent_id)
            .filter(|agent| !is_panel_preview_agent(agent))
            .cloned()
            .ok_or_else(|| "no such Agent to try".to_owned())?;
        let source_target = self
            .library
            .authoring_target_for(&agent.id)
            .map(|target| target.id.clone())
            .ok_or_else(|| "the Agent's authoring target is unavailable".to_owned())?;
        let panel = agent.agent_kind == AgentKind::Panel;
        let (version, profile) =
            match placement_id {
                // An Agent is tested on its draft, so the author can go back and
                // forth between editing and trying it (DR-0324).
                None if !panel => (None, None),
                Some(_) if !panel => {
                    return Err("a version preview requires a Panel agent's placement".to_owned())
                }
                Some(placement_id) => {
                    let placement = self
                        .library
                        .instances
                        .get(placement_id)
                        .filter(|placement| {
                            placement.kind == InstanceKind::Using
                                && placement.placement_kind == PlacementKind::Panel
                                && placement.agent_id == agent.id
                        })
                        .ok_or_else(|| {
                            "a version preview requires this Panel agent's placement".to_owned()
                        })?;
                    let profile = agent
                        .versions
                        .get(&placement.version)
                        .and_then(|version| version.panel_profile.clone())
                        .ok_or_else(|| {
                            "the placement's version has no frozen public profile".to_owned()
                        })?;
                    (Some(placement.version), Some(profile))
                }
                None => (
                    None,
                    Some(agent.panel_profile.clone().ok_or_else(|| {
                        "the Panel agent's draft has no public profile".to_owned()
                    })?),
                ),
            };

        // A second preview of the same thing replaces the first.
        let replaced = self
            .library
            .projects
            .values()
            .filter(|project| {
                marker_of(&project.extra).is_some_and(|marker| {
                    marker.agent_id == agent.id && marker.placement_id.as_deref() == placement_id
                })
            })
            .map(|project| project.id.clone())
            .collect::<Vec<_>>();
        for project in replaced {
            self.end_panel_preview(&project);
        }

        let project_id = library::gen_id("panel-preview");
        let marker = PanelPreviewMarker {
            agent_id: agent.id.clone(),
            placement_id: placement_id.map(str::to_owned),
            version,
            project_id: None,
            preview_agent_id: None,
        };
        let mut preview_agent_id: Option<String> = None;
        let built = (|| {
            let preview_agent = self.fork_panel_agent_for_preview(
                &agent.id,
                &source_target,
                version,
                profile.as_ref(),
                PanelPreviewMarker {
                    project_id: Some(project_id.clone()),
                    ..marker.clone()
                },
            )?;
            preview_agent_id = Some(preview_agent.clone());
            self.create_panel_preview_project(
                &project_id,
                &format!("{} preview", agent.name),
                profile.as_ref(),
                PanelPreviewMarker {
                    preview_agent_id: Some(preview_agent.clone()),
                    ..marker.clone()
                },
            )?;
            let placement =
                self.place_archetype_on_project(&project_id, &preview_agent, Admission::Active)?;
            let title = match version {
                Some(version) => format!("Preview of version {version}"),
                None if panel => "Preview of the draft".to_owned(),
                None => "Test of the draft".to_owned(),
            };
            self.create_chat_in_instance(&placement, &title)
        })();
        match built {
            Ok(chat) => Ok(chat),
            Err(error) => {
                if self.library.projects.contains_key(&project_id) {
                    self.delete_project_cascade(&project_id);
                }
                if let Some(preview_agent) = preview_agent_id {
                    let _ = self.delete_agent_cascade(&preview_agent);
                }
                Err(error)
            }
        }
    }

    /// Fork the Agent into a hidden ordinary Agent whose current version is
    /// the snapshot being tried, narrowed to a Panel agent's public abilities.
    fn fork_panel_agent_for_preview(
        &mut self,
        agent_id: &str,
        source_target: &str,
        version: Option<u64>,
        profile: Option<&library::PanelPublicProfile>,
        marker: PanelPreviewMarker,
    ) -> Result<String, String> {
        let created = self
            .fork_archetype(agent_id, None)
            .map_err(|error| match error {
                crate::library_state::ForkArchetypeError::NotFound => {
                    "the Agent does not exist".to_owned()
                }
                crate::library_state::ForkArchetypeError::SourceNotOpen => {
                    "the Agent's authoring target is not open".to_owned()
                }
                crate::library_state::ForkArchetypeError::Create(error) => error,
            })?;
        // A fork is installed in Personal; a preview's Agent is not.
        let personal = self
            .library
            .instances
            .values()
            .filter(|instance| {
                instance.kind == InstanceKind::Using && instance.agent_id == created.id
            })
            .map(|instance| instance.id.clone())
            .collect::<Vec<_>>();
        for placement in personal {
            self.destroy_instance(&placement);
        }
        let mut fork = self
            .library
            .agents
            .get(&created.id)
            .cloned()
            .ok_or_else(|| "the preview's Agent was not created".to_owned())?;
        let fork_target = self
            .library
            .authoring_target_for(&fork.id)
            .map(|target| target.id.clone())
            .ok_or_else(|| "the preview's authoring target was not created".to_owned())?;

        // Prepare the snapshot outside both repositories.
        let staging = self.targets_dir().join(&fork_target).join("panel-preview");
        let _ = std::fs::remove_dir_all(&staging);
        let package_staging = staging.join("package");
        let discipline_staging = staging.join("discipline");
        let prepared = (|| -> Result<(), String> {
            match version {
                Some(version) => {
                    copy_tree(
                        &published_package_root(&self.targets_dir(), source_target, version),
                        &package_staging,
                    )
                    .map_err(|error| error.to_string())?;
                    copy_tree(
                        &published_discipline_root(&self.targets_dir(), source_target, version),
                        &discipline_staging,
                    )
                    .map_err(|error| error.to_string())?;
                }
                None => {
                    let repo = self.targets_dir().join(source_target).join("repo");
                    let package =
                        crate::agent_release::snapshot_authored_package(&repo, &package_staging)
                            .map_err(|error| error.to_string())?;
                    crate::agent_release::snapshot_authored_discipline(
                        &repo,
                        &discipline_staging,
                        &package,
                    )
                    .map_err(|error| error.to_string())?;
                }
            }
            match profile {
                Some(profile) => {
                    let public = profile.public_abilities.iter().cloned().collect::<Vec<_>>();
                    narrow_abilities(&package_staging, &public)?;
                    note_preview_folders(&package_staging)
                }
                None => Ok(()),
            }
        })();
        let committed = prepared.and_then(|()| {
            self.commit_preview_version(
                &fork_target,
                fork.current_version + 1,
                &package_staging,
                &discipline_staging,
            )
        });
        let _ = std::fs::remove_dir_all(&staging);
        let record = committed?;

        let preview_version = fork.current_version + 1;
        fork.agent_kind = AgentKind::Work;
        fork.panel_profile = None;
        for frozen in fork.versions.values_mut() {
            frozen.panel_profile = None;
        }
        fork.versions.insert(preview_version, record);
        fork.current_version = preview_version;
        fork.auto_upgrade = false;
        fork.name = format!("{} (preview)", fork.name.trim_end_matches(" (fork)"));
        fork.extra.insert(
            PANEL_PREVIEW_EXTRA.to_owned(),
            serde_json::to_value(&marker).map_err(|error| error.to_string())?,
        );
        let authoring_instance = fork.instance_id.clone();
        self.write_agent_record(fork);
        if let Some(mut instance) = self.library.instances.get(&authoring_instance).cloned() {
            instance.placement_kind = PlacementKind::Work;
            self.write_instance_record(instance);
        }
        Ok(created.id)
    }

    /// Commit a prepared package and discipline as `version` of `target_id`,
    /// the way publishing freezes a draft.
    fn commit_preview_version(
        &mut self,
        target_id: &str,
        version: u64,
        package_root: &Path,
        discipline_root: &Path,
    ) -> Result<ArchetypeVersionRecord, String> {
        let package_files = files_under(package_root).map_err(|error| error.to_string())?;
        let discipline_files = files_under(discipline_root).map_err(|error| error.to_string())?;
        let engagement_id = library::gen_id("panel-preview-freeze");
        let workspace = self
            .targets
            .get(target_id)
            .ok_or_else(|| "the preview's authoring target is not open".to_owned())?;
        let engagement = workspace
            .create_engagement(&engagement_id)
            .map_err(|error| error.to_string())?;
        let package_target = gaugedesk_boundary::definition::version_root(version);
        let discipline_target = crate::discipline::discipline_version_root(version);
        let result = (|| {
            let files = package_files
                .iter()
                .map(|(path, body)| (format!("{package_target}/{path}"), body))
                .chain(
                    discipline_files
                        .iter()
                        .map(|(path, body)| (format!("{discipline_target}/{path}"), body)),
                );
            for (path, body) in files {
                let text = std::str::from_utf8(body)
                    .map_err(|_| format!("the preview snapshot file `{path}` is not text"))?;
                engagement
                    .write_file(&path, text)
                    .map_err(|error| error.to_string())?;
            }
            let package = gaugedesk_whip_runtime::AuthoredAgentPackage::load(
                engagement.path().join(&package_target),
            )?;
            let discipline = crate::discipline::load(
                &engagement.path().join(&discipline_target),
                package.capabilities().iter().cloned(),
            )?;
            engagement
                .commit_turn(&format!("panel preview version {version}"))
                .map_err(|error| error.to_string())?;
            match engagement
                .merge_into_main()
                .map_err(|error| error.to_string())?
            {
                gaugedesk_workspace::MergeOutcome::Clean => Ok(ArchetypeVersionRecord {
                    package_ref: package.version_ref().to_owned(),
                    discipline_ref: discipline.reference,
                    source_owner_authority: None,
                    panel_profile: None,
                }),
                gaugedesk_workspace::MergeOutcome::Conflict => {
                    Err("the preview's snapshot could not be committed".to_owned())
                }
            }
        })();
        let _ = workspace.remove_engagement(&engagement_id);
        result
    }

    /// The hidden project: one managed `workspace` target seeded with a Panel
    /// agent's initial files, and no tracker or default Agent.
    fn create_panel_preview_project(
        &mut self,
        project_id: &str,
        name: &str,
        profile: Option<&library::PanelPublicProfile>,
        marker: PanelPreviewMarker,
    ) -> Result<String, String> {
        let home_id = self.home_id().clone();
        let mut extra = std::collections::BTreeMap::new();
        extra.insert(
            PANEL_PREVIEW_EXTRA.to_owned(),
            serde_json::to_value(&marker).map_err(|error| error.to_string())?,
        );
        self.write_project_record(ProjectRecord {
            schema: LIBRARY_RECORD_SCHEMA,
            extra,
            id: project_id.to_owned(),
            op: RecordOp::Upsert,
            name: name.to_owned(),
            is_default: false,
            home_id: home_id.clone(),
            network_isolated: false,
            run_purpose: None,
            deployment_mode: None,
        });
        self.write_project_collaboration_workspace_record(ProjectCollaborationWorkspaceRecord {
            project_id: project_id.to_owned(),
            workspace_id: format!("project-workspace-{project_id}"),
            home_id,
            substrate: "whipplescript".to_owned(),
            host_contract_revision: crate::workstream_host_contract::REVISION.to_owned(),
            host_contract_digest: crate::workstream_host_contract::DIGEST.to_owned(),
            op: RecordOp::Upsert,
            schema: LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
        });
        self.ensure_project_collaboration_workspace(project_id)?;
        // A public session sees its initial files under `workspace/`, which the
        // public host strips when it seeds; the target is that workspace.
        let mut seeds = Vec::new();
        for file in profile
            .iter()
            .flat_map(|profile| &profile.initial_workspace)
        {
            let path = file
                .path
                .strip_prefix("workspace/")
                .unwrap_or(&file.path)
                .to_owned();
            let body = String::from_utf8(file.bytes.clone()).map_err(|_| {
                format!(
                    "Preview seeds text files only, and `{}` is not text",
                    file.path
                )
            })?;
            seeds.push((path, body));
        }
        self.create_managed_project_target_seeded(project_id, PREVIEW_TARGET.to_owned(), &seeds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_preview_tells_its_agent_where_the_visitor_folders_are() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"project_context":"AGENTS.md"}"#,
        )
        .unwrap();
        std::fs::write(dir.path().join("AGENTS.md"), "Write `outbox/survey.json`.").unwrap();
        note_preview_folders(dir.path()).unwrap();
        let body = std::fs::read_to_string(dir.path().join("AGENTS.md")).unwrap();
        assert!(body.starts_with("Write `outbox/survey.json`."), "{body}");
        assert!(body.contains("`workspace/outbox/survey.json`"), "{body}");

        // A package with no project instructions gets them.
        let bare = tempfile::tempdir().unwrap();
        std::fs::write(bare.path().join("package.json"), "{}").unwrap();
        note_preview_folders(bare.path()).unwrap();
        let manifest: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(bare.path().join("package.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest["project_context"], "AGENTS.md");
        assert!(std::fs::read_to_string(bare.path().join("AGENTS.md"))
            .unwrap()
            .contains("workspace/"));
    }

    #[test]
    fn narrowing_replaces_the_package_abilities_with_the_public_ones() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"schema":"x","agent_abilities":["workspace.read","command.run"],"capabilities":["workspace.read","command.run"]}"#,
        )
        .unwrap();
        narrow_abilities(dir.path(), &["workspace.read".to_owned()]).unwrap();
        let manifest: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("package.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            manifest["agent_abilities"],
            serde_json::json!(["workspace.read"])
        );
        assert_eq!(
            manifest["capabilities"],
            serde_json::json!(["workspace.read", "command.run"]),
            "the registry is left alone; only what the agent is granted narrows",
        );
    }

    #[test]
    fn a_marker_round_trips_through_record_extra() {
        let marker = PanelPreviewMarker {
            agent_id: "agent-a".to_owned(),
            placement_id: Some("inst-p".to_owned()),
            version: Some(3),
            project_id: None,
            preview_agent_id: Some("agent-b".to_owned()),
        };
        let mut extra = std::collections::BTreeMap::new();
        extra.insert(
            PANEL_PREVIEW_EXTRA.to_owned(),
            serde_json::to_value(&marker).unwrap(),
        );
        assert_eq!(marker_of(&extra), Some(marker));
    }
}
