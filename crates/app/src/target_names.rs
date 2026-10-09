//! Work-target names as a chat and its agent see them (DR-0248).
//!
//! The agent sees each selected target as a folder named after it, and the
//! name is versioned in the project's collaboration workspace: one file per
//! target at `.gaugedesk-names/<target-id-path-v1>`, beside the target's
//! partition and selected into every chat that selects the partition.
//! Collaboration Main's file holds the project's name, which the target
//! record's `name` projects; a chat branch's file is what that chat sees. A
//! rename is an ordinary change to that file on the chat's branch, so it
//! syncs, promotes and conflicts like any other change: two branches that
//! rename one target touch the same file. Two targets cannot reach one name
//! through separate branches, because a rename is admitted, under the
//! workbench lock, only when no name on Main or on any branch of the project
//! already has its key.

use std::collections::BTreeSet;

use crate::library::{
    target_id_path_v1, target_name_key, validate_project_target_name, validate_target_name,
    InstanceKind, RecordOp, TargetParticipationMode, WorkTargetOwner,
};
use crate::Workbench;

/// The collaboration-workspace directory that versions target names.
pub(crate) const TARGET_NAMES_ROOT: &str = ".gaugedesk-names";

/// Where a target's name is versioned.
pub(crate) fn target_name_path(target_id: &str) -> Result<String, String> {
    Ok(format!(
        "{TARGET_NAMES_ROOT}/{}",
        target_id_path_v1(target_id)?
    ))
}

/// Whether a workspace path is a target-name record rather than content.
pub(crate) fn is_target_name_path(path: &str) -> bool {
    path == TARGET_NAMES_ROOT || path.starts_with(&format!("{TARGET_NAMES_ROOT}/"))
}

/// A chat's selected roots for its targets: each target's partition and the
/// file that versions its name.
pub(crate) fn chat_target_roots<'a>(
    target_ids: impl IntoIterator<Item = &'a str>,
) -> Result<BTreeSet<String>, String> {
    let mut roots = BTreeSet::new();
    for target_id in target_ids {
        roots.insert(format!("targets/{}", target_id_path_v1(target_id)?));
        roots.insert(target_name_path(target_id)?);
    }
    Ok(roots)
}

fn decode_name(body: &str) -> Option<String> {
    let name = body.strip_suffix('\n').unwrap_or(body);
    validate_target_name(name).ok()?;
    Some(name.to_owned())
}

fn encode_name(name: &str) -> String {
    format!("{name}\n")
}

/// Make a stored name follow the folder rules and be unique among `taken`
/// keys, changing it as little as possible. Used for names recorded before
/// DR-0248, which only had to be non-empty.
pub(crate) fn sanitize_target_name(name: &str, taken: &BTreeSet<String>) -> String {
    let mut cleaned = name
        .chars()
        .map(|character| {
            if character == '/' || character == '\\' || character.is_control() {
                '-'
            } else {
                character
            }
        })
        .collect::<String>();
    cleaned = cleaned.trim_start_matches('.').to_owned();
    if cleaned.trim().is_empty() {
        cleaned = "files".to_owned();
    }
    let fit = |text: &str, limit: usize| {
        let mut end = text.len().min(limit);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text[..end].to_owned()
    };
    let base = fit(&cleaned, 255);
    if !taken.contains(&target_name_key(&base)) {
        return base;
    }
    for counter in 2.. {
        let suffix = format!(" {counter}");
        let candidate = format!("{}{suffix}", fit(&base, 255 - suffix.len()));
        if !taken.contains(&target_name_key(&candidate)) {
            return candidate;
        }
    }
    unreachable!("an unbounded counter always finds a free name")
}

/// A target whose name differs between a chat and the line it merges into,
/// as the chat's conflict surface offers it for settling (DR-0248).
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub(crate) struct TargetNameDisagreement {
    /// The target's stored root, `targets/<target-id-path-v1>`.
    pub(crate) root: String,
    pub(crate) chat_name: String,
    pub(crate) line_name: String,
}

impl Workbench {
    fn project_collaboration_workspace_id(&self, project_id: &str) -> Option<String> {
        self.library
            .project_collaboration_workspaces
            .get(project_id)
            .map(|record| record.workspace_id.clone())
    }

    fn project_target_ids(&self, project_id: &str) -> Vec<String> {
        self.library
            .work_targets
            .values()
            .filter(|target| {
                target.op != RecordOp::Tombstone
                    && matches!(
                        &target.owner,
                        WorkTargetOwner::Project { project_id: owner } if owner == project_id
                    )
            })
            .map(|target| target.id.clone())
            .collect()
    }

    /// The project's name for a target: collaboration Main's.
    pub(crate) fn main_target_name(&self, project_id: &str, target_id: &str) -> Option<String> {
        let workspace_id = self.project_collaboration_workspace_id(project_id)?;
        let workspace = self.collaboration_workspaces.get(&workspace_id)?;
        let body = workspace
            .read_main_file(&target_name_path(target_id).ok()?)
            .ok()??;
        decode_name(&body)
    }

    /// The name a chat sees for one of its targets: its branch's, and the
    /// project's until the branch has one.
    pub(crate) fn chat_target_name(&self, chat_id: &str, target_id: &str) -> String {
        self.chat_target_name_in(
            self.engagements
                .get(chat_id)
                .map(|engagement| engagement.as_ref()),
            target_id,
        )
    }

    /// The same name projection for an owned candidate that is not published yet.
    pub(crate) fn chat_target_name_in(
        &self,
        engagement: Option<&dyn gaugedesk_workspace::ChatWorkspace>,
        target_id: &str,
    ) -> String {
        let branch = engagement.and_then(|engagement| {
            engagement
                .read_file(&target_name_path(target_id).ok()?)
                .ok()
                .and_then(|body| decode_name(&body))
        });
        branch.unwrap_or_else(|| {
            self.library
                .work_targets
                .get(target_id)
                .map(|target| target.name.clone())
                .unwrap_or_default()
        })
    }

    /// Each of a chat's target roots, `targets/<target-id-path-v1>`, with the
    /// name the chat shows it under.
    pub(crate) fn chat_target_folder_names(&self, chat_id: &str) -> Vec<(String, String)> {
        let Some(set) = self.library.current_target_set(chat_id) else {
            return Vec::new();
        };
        set.members
            .iter()
            .filter_map(|member| {
                let encoded = target_id_path_v1(&member.target_id).ok()?;
                Some((
                    format!("targets/{encoded}"),
                    self.chat_target_name(chat_id, &member.target_id),
                ))
            })
            .collect()
    }

    /// The name the line a chat merges into holds for one of its targets.
    pub(crate) fn line_target_name(&self, chat_id: &str, target_id: &str) -> Option<String> {
        let body = self
            .engagements
            .get(chat_id)?
            .read_line_file(&target_name_path(target_id).ok()?)
            .ok()??;
        decode_name(&body)
    }

    /// The chat's targets whose names differ from its line's, for a chat in
    /// conflict to settle (DR-0248).
    pub(crate) fn target_name_disagreements(&self, chat_id: &str) -> Vec<TargetNameDisagreement> {
        let Some(set) = self.library.current_target_set(chat_id) else {
            return Vec::new();
        };
        set.members
            .iter()
            .filter_map(|member| {
                let line_name = self.line_target_name(chat_id, &member.target_id)?;
                let chat_name = self.chat_target_name(chat_id, &member.target_id);
                let root = format!("targets/{}", target_id_path_v1(&member.target_id).ok()?);
                (chat_name != line_name).then_some(TargetNameDisagreement {
                    root,
                    chat_name,
                    line_name,
                })
            })
            .collect()
    }

    /// Settle a target name that differs between a chat and its line by
    /// keeping the chat's name or taking the line's. A conflict on the name is
    /// resolved in the store, which then applies the choice to the next merge;
    /// the caller retries the merge. Returns the name the chat now has.
    pub(crate) fn settle_target_name(
        &mut self,
        chat_id: &str,
        target_id: &str,
        keep_chat: bool,
    ) -> Result<String, String> {
        let set = self
            .library
            .current_target_set(chat_id)
            .ok_or_else(|| "this chat has no targets".to_owned())?;
        let member = set
            .members
            .iter()
            .find(|member| member.target_id == target_id)
            .ok_or_else(|| "that folder is not one of this chat's targets".to_owned())?;
        if member.participation != TargetParticipationMode::Writable
            || !member.capability_ceiling.propose
        {
            return Err("this chat cannot change that folder's name".to_owned());
        }
        let path = target_name_path(target_id)?;
        let engagement = self
            .engagements
            .get(chat_id)
            .ok_or_else(|| "this chat's workspace is not open".to_owned())?;
        engagement
            .resolve_conflict_taking(&path, keep_chat)
            .map_err(|error| error.to_string())?;
        if !keep_chat {
            // Without a recorded conflict the chat may still hold a pending
            // rename of its own; taking the line's name then replaces it.
            if let Some(line_name) = self.line_target_name(chat_id, target_id) {
                if self.chat_target_name(chat_id, target_id) != line_name {
                    let engagement = self
                        .engagements
                        .get(chat_id)
                        .ok_or_else(|| "this chat's workspace is not open".to_owned())?;
                    engagement
                        .write_file_bytes(&path, encode_name(&line_name).as_bytes())
                        .map_err(|error| error.to_string())?;
                    engagement
                        .commit_turn(&format!("took the project's name {line_name}"))
                        .map_err(|error| error.to_string())?;
                }
            }
        }
        Ok(self.chat_target_name(chat_id, target_id))
    }

    /// Rename a project target on collaboration Main, where the project's
    /// names live, from outside any chat (DR-0248). Open chats on Main take
    /// the new name when they sync; a chat with its own pending rename of the
    /// target meets it as a name conflict it can settle.
    pub(crate) fn rename_project_target(
        &mut self,
        project_id: &str,
        target_id: &str,
        name: &str,
    ) -> Result<Vec<String>, String> {
        if !self
            .project_target_ids(project_id)
            .iter()
            .any(|id| id == target_id)
        {
            return Err("that target does not belong to this project".to_owned());
        }
        self.validate_new_target_name(project_id, Some(target_id), name)?;
        self.seed_main_target_name(project_id, target_id, name)?;
        self.project_main_target_names(project_id);
        let workspace_id = self
            .project_collaboration_workspace_id(project_id)
            .ok_or_else(|| "project collaboration workspace is undeclared".to_owned())?;
        Ok(self.sync_mainline_members(&workspace_id))
    }

    /// Every name a project's targets hold anywhere: on Main, and on each
    /// chat branch that selects them, pending renames included.
    fn project_name_claims(&self, project_id: &str) -> Vec<(String, String)> {
        let mut claims = self
            .project_target_ids(project_id)
            .into_iter()
            .filter_map(|target_id| {
                let name = self.main_target_name(project_id, &target_id).or_else(|| {
                    self.library
                        .work_targets
                        .get(&target_id)
                        .map(|target| target.name.clone())
                })?;
                Some((target_id, name))
            })
            .collect::<Vec<_>>();
        for (chat_id, chat) in &self.library.chats {
            if self.library.project_of_chat(chat_id) != Some(project_id) {
                continue;
            }
            let using = self
                .library
                .instances
                .get(&chat.instance_id)
                .is_some_and(|instance| instance.kind == InstanceKind::Using);
            let Some(set) = using
                .then(|| self.library.current_target_set(chat_id))
                .flatten()
            else {
                continue;
            };
            for member in &set.members {
                claims.push((
                    member.target_id.clone(),
                    self.chat_target_name(chat_id, &member.target_id),
                ));
            }
        }
        claims
    }

    /// Refuse a name that breaks the folder rules or that another target of
    /// the project holds anywhere.
    pub(crate) fn validate_new_target_name(
        &self,
        project_id: &str,
        target_id: Option<&str>,
        name: &str,
    ) -> Result<(), String> {
        let claims = self.project_name_claims(project_id);
        validate_project_target_name(
            name,
            target_id,
            claims
                .iter()
                .map(|(target_id, name)| (target_id.as_str(), name.as_str())),
        )
    }

    /// Rename one of a chat's targets on the chat's branch. The new name is
    /// written into the chat's checkout; the chat's next commit records it,
    /// which for an agent's `mv` is the end of the turn that made it.
    pub(crate) fn rename_chat_target(
        &mut self,
        chat_id: &str,
        target_id: &str,
        to: &str,
    ) -> Result<(), String> {
        let project_id = self
            .library
            .project_of_chat(chat_id)
            .ok_or_else(|| "this chat has no project".to_owned())?
            .to_owned();
        let set = self
            .library
            .current_target_set(chat_id)
            .ok_or_else(|| "this chat has no targets".to_owned())?;
        let member = set
            .members
            .iter()
            .find(|member| member.target_id == target_id)
            .ok_or_else(|| "that folder is not one of this chat's targets".to_owned())?;
        let from = self.chat_target_name(chat_id, target_id);
        if member.participation != TargetParticipationMode::Writable
            || !member.capability_ceiling.propose
        {
            return Err(format!("`{from}` is read-only in this chat"));
        }
        if to == from {
            return Ok(());
        }
        self.validate_new_target_name(&project_id, Some(target_id), to)?;
        let path = target_name_path(target_id)?;
        self.engagements
            .get(chat_id)
            .ok_or_else(|| "this chat's workspace is not open".to_owned())?
            .write_file_bytes(&path, encode_name(to).as_bytes())
            .map_err(|error| error.to_string())
    }

    /// Rename the target a chat's stored root belongs to, as an agent's `mv`
    /// of its folder names it.
    pub(crate) fn rename_chat_target_root(
        &mut self,
        chat_id: &str,
        root: &str,
        to: &str,
    ) -> Result<(), String> {
        let target_id = self
            .library
            .current_target_set(chat_id)
            .and_then(|set| {
                set.members.iter().find_map(|member| {
                    let encoded = target_id_path_v1(&member.target_id).ok()?;
                    (root == format!("targets/{encoded}")).then(|| member.target_id.clone())
                })
            })
            .ok_or_else(|| "that folder is not one of this chat's targets".to_owned())?;
        self.rename_chat_target(chat_id, &target_id, to)
    }

    /// Record a target's name on collaboration Main, where the project's names
    /// live: at creation, and for a target that predates DR-0248.
    pub(crate) fn seed_main_target_name(
        &mut self,
        project_id: &str,
        target_id: &str,
        name: &str,
    ) -> Result<(), String> {
        validate_target_name(name)?;
        let workspace_id = self
            .project_collaboration_workspace_id(project_id)
            .ok_or_else(|| "project collaboration workspace is undeclared".to_owned())?;
        let path = target_name_path(target_id)?;
        let body = encode_name(name);
        self.collaboration_workspaces
            .get(&workspace_id)
            .ok_or_else(|| "project collaboration workspace is not open".to_owned())?
            .seed_main(&[(path.as_str(), body.as_str())])
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    /// The keys of every name a project's targets hold anywhere.
    pub(crate) fn project_name_keys(&self, project_id: &str) -> BTreeSet<String> {
        self.project_name_claims(project_id)
            .iter()
            .map(|(_, name)| target_name_key(name))
            .collect()
    }

    /// A name for a new target of the project: `name` if it is free and
    /// follows the rules, otherwise the nearest one that does. For names
    /// GaugeDesk proposes, such as `<project> files`.
    pub(crate) fn free_target_name(&self, project_id: &str, name: &str) -> String {
        sanitize_target_name(name, &self.project_name_keys(project_id))
    }

    /// Record a project target's name on collaboration Main unless Main
    /// already has one, from its record, made valid and unique if it was
    /// recorded before DR-0248.
    pub(crate) fn ensure_main_target_name(
        &mut self,
        project_id: &str,
        target_id: &str,
    ) -> Result<(), String> {
        if self.main_target_name(project_id, target_id).is_some() {
            return Ok(());
        }
        let recorded = self
            .library
            .work_targets
            .get(target_id)
            .map(|target| target.name.clone())
            .ok_or_else(|| format!("target {target_id} is unavailable"))?;
        let mut taken = self
            .project_name_claims(project_id)
            .into_iter()
            .filter(|(owner, _)| owner != target_id)
            .map(|(_, name)| target_name_key(&name))
            .collect::<BTreeSet<_>>();
        taken.remove("");
        let name = sanitize_target_name(&recorded, &taken);
        self.seed_main_target_name(project_id, target_id, &name)?;
        self.project_main_target_names(project_id);
        Ok(())
    }

    /// Make each project target record's `name` what collaboration Main
    /// holds, after Main advances.
    pub(crate) fn project_main_target_names(&mut self, project_id: &str) {
        for target_id in self.project_target_ids(project_id) {
            let Some(name) = self.main_target_name(project_id, &target_id) else {
                continue;
            };
            let Some(record) = self.library.work_targets.get(&target_id) else {
                continue;
            };
            if record.name != name {
                let mut record = record.clone();
                record.name = name;
                self.write_work_target_record(record);
            }
        }
    }

    /// Project Main's names for the project a chat belongs to, after the chat
    /// may have advanced Main.
    pub(crate) fn project_chat_main_target_names(&mut self, chat_id: &str) {
        if let Some(project_id) = self.library.project_of_chat(chat_id).map(str::to_owned) {
            self.project_main_target_names(&project_id);
        }
    }

    /// Give every project target a name on collaboration Main that follows
    /// the folder rules and is unique in its project, then project Main's
    /// names onto the records. Names recorded before DR-0248 only had to be
    /// non-empty; one that breaks a rule is changed as little as possible.
    pub(crate) fn migrate_target_names(&mut self) {
        let projects = self
            .library
            .project_collaboration_workspaces
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        for project_id in projects {
            let Some(workspace_id) = self.project_collaboration_workspace_id(&project_id) else {
                continue;
            };
            if !self.collaboration_workspaces.contains_key(&workspace_id) {
                continue;
            }
            for target_id in self.project_target_ids(&project_id) {
                if let Err(error) = self.ensure_main_target_name(&project_id, &target_id) {
                    eprintln!("[target-names] cannot name {target_id} on Main: {error}");
                }
            }
            self.project_main_target_names(&project_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_legacy_name_is_changed_only_as_far_as_the_rules_need() {
        let taken = BTreeSet::from([target_name_key("api"), target_name_key("API 2")]);
        assert_eq!(sanitize_target_name("owner/repo", &taken), "owner-repo");
        assert_eq!(sanitize_target_name(".hidden", &taken), "hidden");
        assert_eq!(sanitize_target_name("Api", &taken), "Api 3");
        assert_eq!(sanitize_target_name("...", &taken), "files");
        assert_eq!(sanitize_target_name("tab\there", &taken), "tab-here");
        let long = "é".repeat(200);
        let fitted = sanitize_target_name(&long, &taken);
        assert!(fitted.len() <= 255 && validate_target_name(&fitted).is_ok());
    }

    #[test]
    fn a_chat_selects_each_partition_with_its_name() {
        let roots = chat_target_roots(["target-a"]).unwrap();
        let encoded = target_id_path_v1("target-a").unwrap();
        assert_eq!(
            roots,
            BTreeSet::from([
                format!("targets/{encoded}"),
                format!(".gaugedesk-names/{encoded}"),
            ])
        );
        assert!(is_target_name_path(&format!(".gaugedesk-names/{encoded}")));
        assert!(!is_target_name_path("targets/.gaugedesk-names"));
    }
}
