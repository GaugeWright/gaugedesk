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
}
