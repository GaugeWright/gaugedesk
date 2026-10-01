//! WhippleScript's own authoring skill, given to GaugeDesk's editor.
//!
//! An edit chat writes WhippleScript for the Agent it is editing, so it reads
//! the guide WhippleScript publishes for exactly that:
//! `skills/whipplescript-author/SKILL.md` and the documents and examples it
//! links to. The copies under `editor-skill/` are the bytes at the public
//! WhippleScript revision this repository runs, and
//! `contracts/whipplescript-author-skill-pin.json` holds their digests, so an
//! edit here or a re-pin that forgets them fails
//! `scripts/check-whipplescript-author-skill.mjs`.
//!
//! The files are written beneath the chat's runtime mount, keeping the layout
//! they have in WhippleScript so the skill's relative links resolve. The mount
//! is chat-local and read-only to the agent, and it is never part of the
//! Agent's draft.

use std::io;
use std::path::Path;

/// Where the editor's runtime material lives inside an edit chat's worktree.
pub(crate) const EDITOR_MOUNT: &str = ".gaugedesk-runtime/editor";
/// The skill registry source that marks a skill as GaugeDesk-shipped editor
/// material rather than anything the Agent being edited declares.
pub(crate) const EDITOR_SKILL_SOURCE: &str = "gaugedesk-editor";
/// The skill's path within the mount, as WhippleScript lays it out.
pub(crate) const SKILL_PATH: &str = "skills/whipplescript-author/SKILL.md";

macro_rules! vendored {
    ($($path:literal),* $(,)?) => {
        &[$(($path, include_str!(concat!("../editor-skill/", $path)))),*]
    };
}

/// Every vendored file, by its path in the WhippleScript repository. The pin
/// check requires this list and the pin's to name the same files.
pub const FILES: &[(&str, &str)] = vendored![
    "skills/whipplescript-author/SKILL.md",
    "docs/api-reference.md",
    "docs/concepts.md",
    "docs/current-state.md",
    "docs/diagnostics.md",
    "docs/examples.md",
    "docs/json-reference.md",
    "docs/language-reference.md",
    "docs/manual.md",
    "docs/providers.md",
    "docs/quickstart.md",
    "docs/runtime-operations.md",
    "docs/troubleshooting.md",
    "docs/tutorial.md",
    "examples/queue-worker-with-review.whip",
    "examples/revision-validation-approval.whip",
    "examples/scheduled-escalation.whip",
];

/// The skill body.
pub(crate) fn skill_body() -> &'static str {
    FILES
        .iter()
        .find(|(path, _)| *path == SKILL_PATH)
        .map(|(_, body)| *body)
        .expect("the vendored skill is in FILES")
}

/// The skill's location as the model is told it, relative to the worktree.
pub(crate) fn skill_location() -> String {
    format!("{EDITOR_MOUNT}/{SKILL_PATH}")
}

/// Replace the chat's editor mount with exactly the vendored files.
pub(crate) fn mount(worktree: &Path) -> io::Result<()> {
    let root = worktree.join(EDITOR_MOUNT);
    if root.exists() {
        std::fs::remove_dir_all(&root)?;
    }
    for (path, body) in FILES {
        let destination = root.join(path);
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(destination, body)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_relative_link_in_the_skill_is_vendored() {
        let body = skill_body();
        let mut checked = 0;
        for target in body
            .split("](")
            .skip(1)
            .filter_map(|rest| rest.split(')').next())
        {
            let target = target.split('#').next().unwrap_or_default();
            let Some(path) = target.strip_prefix("../../") else {
                continue;
            };
            assert!(
                FILES.iter().any(|(vendored, _)| *vendored == path),
                "the skill links {path}, which is not vendored"
            );
            checked += 1;
        }
        assert!(checked > 0, "the skill links nothing; the parser is stale");
    }

    #[test]
    fn the_mount_holds_exactly_the_vendored_files() {
        let worktree = tempfile::tempdir().unwrap();
        let stale = worktree.path().join(EDITOR_MOUNT).join("docs/retired.md");
        std::fs::create_dir_all(stale.parent().unwrap()).unwrap();
        std::fs::write(&stale, "retired").unwrap();
        mount(worktree.path()).unwrap();
        assert!(!stale.exists());
        for (path, body) in FILES {
            let written =
                std::fs::read_to_string(worktree.path().join(EDITOR_MOUNT).join(path)).unwrap();
            assert_eq!(&written, body, "{path}");
        }
        let skill = std::fs::read_to_string(worktree.path().join(skill_location())).unwrap();
        let frontmatter =
            whipplescript_store::skill_frontmatter::parse_skill_frontmatter(&skill).unwrap();
        assert_eq!(frontmatter.name, "whipplescript-author");
    }
}
