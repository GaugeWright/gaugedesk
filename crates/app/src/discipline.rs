//! Immutable archetype workspace-discipline bundles (ADR 0100 / TARGET-2).

use std::collections::BTreeSet;
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const DISCIPLINE_ROOT: &str = ".whipple/discipline";
pub const DISCIPLINE_DRAFT_ROOT: &str = ".whipple/discipline/draft";
pub const DISCIPLINE_MANIFEST: &str = "discipline.json";

pub fn discipline_version_root(version: u64) -> String {
    format!("{DISCIPLINE_ROOT}/versions/{version}")
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum DisciplineTreatment {
    Runtime,
    Check,
    Procedure,
    Template,
    Scaffold,
    Managed,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct DisciplineAsset {
    pub path: String,
    pub treatment: DisciplineTreatment,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DisciplineManifest {
    pub schema: String,
    /// Existing skill/package references. GaugeDesk deliberately defines no
    /// second skill payload format.
    pub skills: BTreeSet<String>,
    /// Must equal the immutable WhippleScript package capability registry.
    pub capabilities: BTreeSet<String>,
    pub assets: Vec<DisciplineAsset>,
    pub target_rules: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct DisciplineBundle {
    pub reference: String,
    pub manifest: DisciplineManifest,
    /// Manifest plus declared assets, relative to the discipline root.
    pub files: Vec<(String, String)>,
}

pub fn default_manifest(capabilities: impl IntoIterator<Item = String>) -> String {
    manifest(capabilities, BTreeSet::new(), Vec::new())
}

pub fn manifest(
    capabilities: impl IntoIterator<Item = String>,
    skills: BTreeSet<String>,
    assets: Vec<DisciplineAsset>,
) -> String {
    serde_json::to_string_pretty(&DisciplineManifest {
        schema: "gaugedesk.discipline.v1".to_owned(),
        skills,
        capabilities: capabilities.into_iter().collect(),
        assets,
        target_rules: Vec::new(),
    })
    .expect("discipline manifest serializes")
}

/// Project authored references and skills into the pinned discipline. The
/// generated copy belongs to the selected version; agent/ remains the source.
pub fn materialize_agent_definition(
    agent_root: &Path,
    discipline_root: &Path,
) -> Result<(), String> {
    let manifest_path = discipline_root.join(DISCIPLINE_MANIFEST);
    let mut manifest: DisciplineManifest = serde_json::from_str(
        &std::fs::read_to_string(&manifest_path).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    manifest.assets.retain(|asset| {
        !asset.path.starts_with("agent-skills/") && !asset.path.starts_with("agent-files/")
    });
    let destination = discipline_root.join("agent-skills");
    if destination.exists() {
        std::fs::remove_dir_all(&destination).map_err(|error| error.to_string())?;
    }
    let references = discipline_root.join("agent-files");
    if references.exists() {
        std::fs::remove_dir_all(&references).map_err(|error| error.to_string())?;
    }
    let skills_root = agent_root.join("skills");
    match std::fs::symlink_metadata(&skills_root) {
        Ok(metadata) => {
            if !metadata.file_type().is_dir() {
                return Err("agent/skills must be a real directory".to_owned());
            }
            let mut entries = std::fs::read_dir(&skills_root)
                .map_err(|error| error.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?;
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                let name = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| "Agent skill name is not UTF-8".to_owned())?;
                if name == ".gaugedesk-folder" {
                    continue;
                }
                if !entry
                    .file_type()
                    .map_err(|error| error.to_string())?
                    .is_dir()
                {
                    return Err(format!("agent/skills/{name} must be a skill directory"));
                }
                let skill_md = entry.path().join("SKILL.md");
                let body = std::fs::read_to_string(&skill_md)
                    .map_err(|error| format!("agent/skills/{name}/SKILL.md: {error}"))?;
                let frontmatter =
                    whipplescript_store::skill_frontmatter::parse_skill_frontmatter(&body)
                        .map_err(|error| format!("agent/skills/{name}/SKILL.md: {error}"))?;
                if frontmatter.name != name {
                    return Err(format!(
                        "skill name `{}` differs from directory `{name}`",
                        frontmatter.name
                    ));
                }
                copy_skill_files(
                    &entry.path(),
                    &destination.join(&name),
                    &format!("agent-skills/{name}"),
                    &mut manifest.assets,
                )?;
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    let mut authored = std::fs::read_dir(agent_root)
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    authored.sort_by_key(|entry| entry.file_name());
    for entry in authored {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "Agent file name is not UTF-8".to_owned())?;
        if matches!(
            name.as_str(),
            "AGENTS.md" | "HUMANS.md" | "SYSTEM.md" | "skills"
        ) {
            continue;
        }
        let path = format!("agent-files/{name}");
        if !valid_relative_path(&path) {
            return Err(format!("invalid Agent file path `{path}`"));
        }
        let kind = entry.file_type().map_err(|error| error.to_string())?;
        if kind.is_dir() {
            copy_skill_files(
                &entry.path(),
                &references.join(&name),
                &path,
                &mut manifest.assets,
            )?;
        } else if kind.is_file() {
            std::fs::create_dir_all(&references).map_err(|error| error.to_string())?;
            let body = std::fs::read_to_string(entry.path())
                .map_err(|error| format!("{path}: {error}"))?;
            std::fs::write(references.join(&name), body).map_err(|error| error.to_string())?;
            manifest.assets.push(DisciplineAsset {
                path,
                treatment: DisciplineTreatment::Runtime,
            });
        } else {
            return Err(format!("Agent file `{path}` must be a regular file"));
        }
    }
    std::fs::write(
        manifest_path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&manifest).map_err(|error| error.to_string())?
        ),
    )
    .map_err(|error| error.to_string())
}

fn copy_skill_files(
    source: &Path,
    destination: &Path,
    relative: &str,
    assets: &mut Vec<DisciplineAsset>,
) -> Result<(), String> {
    std::fs::create_dir_all(destination).map_err(|error| error.to_string())?;
    let mut entries = std::fs::read_dir(source)
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "Agent file name is not UTF-8".to_owned())?;
        let path = format!("{relative}/{name}");
        if !valid_relative_path(&path) {
            return Err(format!("invalid Agent skill path `{path}`"));
        }
        let file_type = entry.file_type().map_err(|error| error.to_string())?;
        if file_type.is_dir() {
            copy_skill_files(&entry.path(), &destination.join(&name), &path, assets)?;
        } else if file_type.is_file() {
            let body = std::fs::read_to_string(entry.path())
                .map_err(|error| format!("{path}: {error}"))?;
            std::fs::write(destination.join(&name), body).map_err(|error| error.to_string())?;
            assets.push(DisciplineAsset {
                path,
                treatment: DisciplineTreatment::Runtime,
            });
        } else {
            return Err(format!("Agent skill path `{path}` must be a regular file"));
        }
    }
    Ok(())
}

fn valid_relative_path(path: &str) -> bool {
    !path.is_empty()
        && Path::new(path)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

pub fn load(
    root: &Path,
    package_capabilities: impl IntoIterator<Item = String>,
) -> Result<DisciplineBundle, String> {
    let manifest_body = std::fs::read_to_string(root.join(DISCIPLINE_MANIFEST))
        .map_err(|error| format!("discipline manifest: {error}"))?;
    let mut manifest: DisciplineManifest = serde_json::from_str(&manifest_body)
        .map_err(|error| format!("discipline manifest: {error}"))?;
    if manifest.schema != "gaugedesk.discipline.v1" {
        return Err("discipline manifest has an unsupported schema".to_owned());
    }
    let package_capabilities: BTreeSet<String> = package_capabilities.into_iter().collect();
    if manifest.capabilities != package_capabilities {
        return Err(
            "discipline capabilities do not equal the WhippleScript package registry".to_owned(),
        );
    }
    manifest.assets.sort();
    if manifest
        .assets
        .windows(2)
        .any(|pair| pair[0].path == pair[1].path)
    {
        return Err("discipline declares the same asset more than once".to_owned());
    }
    let mut files = vec![(DISCIPLINE_MANIFEST.to_owned(), manifest_body)];
    for asset in &manifest.assets {
        if !valid_relative_path(&asset.path) || asset.path == DISCIPLINE_MANIFEST {
            return Err(format!(
                "discipline asset has an invalid path: {}",
                asset.path
            ));
        }
        let body = std::fs::read_to_string(root.join(&asset.path))
            .map_err(|error| format!("discipline asset {}: {error}", asset.path))?;
        files.push((asset.path.clone(), body));
    }
    for (path, body) in crate::official_skills::assets_for(&manifest.skills)? {
        if manifest.assets.iter().any(|asset| asset.path == path) {
            return Err(format!("official skill guide path is reserved: {path}"));
        }
        files.push((path, body));
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));

    let canonical_manifest = serde_json::to_vec(&manifest).map_err(|error| error.to_string())?;
    let mut digest = Sha256::new();
    digest.update((canonical_manifest.len() as u64).to_be_bytes());
    digest.update(&canonical_manifest);
    for (path, body) in files.iter().filter(|(path, _)| path != DISCIPLINE_MANIFEST) {
        digest.update((path.len() as u64).to_be_bytes());
        digest.update(path.as_bytes());
        digest.update((body.len() as u64).to_be_bytes());
        digest.update(body.as_bytes());
    }
    Ok(DisciplineBundle {
        reference: format!(
            "gaugedesk:discipline:sha256:{}",
            hex::encode(digest.finalize())
        ),
        manifest,
        files,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_is_content_addressed_and_rejects_capability_drift() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("check.sh"), "exit 0\n").unwrap();
        let manifest = DisciplineManifest {
            schema: "gaugedesk.discipline.v1".into(),
            skills: BTreeSet::from(["skill://review".into()]),
            capabilities: BTreeSet::from(["workspace.read".into()]),
            assets: vec![DisciplineAsset {
                path: "check.sh".into(),
                treatment: DisciplineTreatment::Check,
            }],
            target_rules: vec!["requires README.md".into()],
        };
        std::fs::write(
            dir.path().join(DISCIPLINE_MANIFEST),
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();
        let first = load(dir.path(), ["workspace.read".to_owned()]).unwrap();
        std::fs::write(dir.path().join("check.sh"), "exit 1\n").unwrap();
        let second = load(dir.path(), ["workspace.read".to_owned()]).unwrap();
        assert_ne!(first.reference, second.reference);
        assert!(load(dir.path(), ["workspace.write".to_owned()])
            .unwrap_err()
            .contains("capabilities"));
    }

    #[test]
    fn bundle_rejects_paths_outside_its_root() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = DisciplineManifest {
            schema: "gaugedesk.discipline.v1".into(),
            skills: BTreeSet::new(),
            capabilities: BTreeSet::new(),
            assets: vec![DisciplineAsset {
                path: "../secret".into(),
                treatment: DisciplineTreatment::Runtime,
            }],
            target_rules: Vec::new(),
        };
        std::fs::write(
            dir.path().join(DISCIPLINE_MANIFEST),
            serde_json::to_string(&manifest).unwrap(),
        )
        .unwrap();
        assert!(load(dir.path(), []).unwrap_err().contains("invalid path"));
    }

    #[test]
    fn official_skill_references_materialize_immutable_guides() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = DisciplineManifest {
            schema: "gaugedesk.discipline.v1".into(),
            skills: crate::official_skills::office_skill_references(),
            capabilities: BTreeSet::new(),
            assets: Vec::new(),
            target_rules: Vec::new(),
        };
        std::fs::write(
            dir.path().join(DISCIPLINE_MANIFEST),
            serde_json::to_string(&manifest).unwrap(),
        )
        .unwrap();
        let bundle = load(dir.path(), []).unwrap();
        for skill in crate::official_skills::catalog() {
            assert!(bundle.files.iter().any(|(path, guide)| path
                == &crate::official_skills::asset_path(skill)
                && guide == skill.guide));
        }
    }

    #[test]
    fn authored_skill_files_are_pinned_and_removed_with_the_draft() {
        let root = tempfile::tempdir().unwrap();
        let agent = root.path().join("agent");
        let discipline = root.path().join("discipline");
        std::fs::create_dir_all(agent.join("skills/triage/references")).unwrap();
        std::fs::create_dir_all(&discipline).unwrap();
        std::fs::write(
            discipline.join(DISCIPLINE_MANIFEST),
            default_manifest(Vec::<String>::new()),
        )
        .unwrap();
        std::fs::write(
            agent.join("skills/triage/SKILL.md"),
            "---\nname: triage\ndescription: Inspect reports\n---\nRead the report.\n",
        )
        .unwrap();
        std::fs::write(
            agent.join("skills/triage/references/guide.md"),
            "Guide v1\n",
        )
        .unwrap();
        std::fs::write(agent.join("reference.md"), "Reference v1\n").unwrap();
        materialize_agent_definition(&agent, &discipline).unwrap();
        let first = load(&discipline, []).unwrap();
        assert!(first.files.iter().any(|(path, body)| path
            == "agent-skills/triage/references/guide.md"
            && body == "Guide v1\n"));
        assert!(first
            .files
            .iter()
            .any(|(path, body)| path == "agent-files/reference.md" && body == "Reference v1\n"));
        std::fs::write(
            agent.join("skills/triage/references/guide.md"),
            "Guide v2\n",
        )
        .unwrap();
        materialize_agent_definition(&agent, &discipline).unwrap();
        let second = load(&discipline, []).unwrap();
        assert_ne!(first.reference, second.reference);
        std::fs::remove_dir_all(agent.join("skills/triage")).unwrap();
        std::fs::remove_file(agent.join("reference.md")).unwrap();
        materialize_agent_definition(&agent, &discipline).unwrap();
        let third = load(&discipline, []).unwrap();
        assert!(!third
            .files
            .iter()
            .any(|(path, _)| path.starts_with("agent-skills/")));
        assert!(!third
            .files
            .iter()
            .any(|(path, _)| path.starts_with("agent-files/")));
    }
}
