//! A project's whip programs, each with its structure and every instance of
//! it — what the Structure and Instances tabs on a `.whip` file draw, and what
//! the Project Home rolls up as "whips running".
//!
//! Two kinds of program run in a project. The inbound gate is a file the
//! project carries (`gates/inbound.whip`) and its instances live in the gate's
//! own runtime store; an agent package a chat runs is not a project file, and
//! its instances live in that chat's runtime store. Both are read the same
//! way, through WhippleScript's own instance projection, so the desk never
//! re-derives from a log what a log cannot carry: an effect a firing never
//! requested has no row anywhere, and only the program knows it was there.
//!
//! GaugeDesk holds pointers, not copies (ADR 0080). Nothing here is persisted;
//! every call reads the stores as they are, beside whatever is writing them.

use std::path::Path;

use serde_json::{json, Value};

use crate::Workbench;

pub const PROJECT_WHIPS_SCHEMA: &str = "gaugedesk.project_whips.v1";

impl Workbench {
    /// `None` when there is no such project. A project with nothing running
    /// still answers, with the gate's structure and an empty instance list:
    /// a program is a program before anything runs it.
    pub fn project_whips_value(&self, project_id: &str) -> Option<Value> {
        self.library.projects.get(project_id)?;
        let root = self.root_path();
        let mut whips = Vec::new();

        // The gate: the one program every project has, read off the project's
        // files target — what the author has, not what shipped (ADR 0110 §5).
        let target = crate::library_state::managed_project_target_id(project_id);
        let gate_source = self
            .targets_dir()
            .join(&target)
            .join("repo")
            .join(crate::gate::GATE_PROGRAM_PATH);
        // The path as the file nav shows it — `targets/<encoded target>/…` —
        // because that is what a reader selects, and a tab keyed on a path
        // the nav never produces is a tab that never opens. The bare in-repo
        // path is the fallback only if the target id cannot be encoded, which
        // the nav could not have shown either.
        let gate_path = crate::library::target_id_path_v1(&target)
            .map(|encoded| format!("targets/{encoded}/{}", crate::gate::GATE_PROGRAM_PATH))
            .unwrap_or_else(|_| crate::gate::GATE_PROGRAM_PATH.to_owned());
        let gate_structure = std::fs::read_to_string(&gate_source)
            .ok()
            .and_then(|source| gaugedesk_whip_runtime::program_structure(&source));
        let gate_store =
            crate::gate_service::gate_state_dir(&root, project_id).join("runtime.sqlite");
        let gate_instances = projected(&gate_store, Some("gate"));
        whips.push(json!({
            "path": gate_path,
            "program": "gate",
            "chat": Value::Null,
            "structure": gate_structure,
            "instances": gate_instances,
        }));

        // Every chat's package. A chat that has never run has no store, and a
        // store's instances group by the program that ran them.
        let runtime_root = root.join("whip-runtimes");
        for chat in self.library.project_chats(project_id) {
            let store = gaugedesk_whip_runtime::chat_runtime_database(&runtime_root, &chat.id);
            let mut by_program: std::collections::BTreeMap<String, Vec<Value>> = Default::default();
            for instance in read(&store) {
                by_program
                    .entry(instance.program)
                    .or_default()
                    .push(instance.view);
            }
            for (program, instances) in by_program {
                // The structure a program has is what its instances ran under;
                // with no instance there is nothing to read it from, and no
                // file to compile it from either.
                let structure = instances
                    .first()
                    .and_then(|view| view.get("structure").cloned())
                    .filter(|structure| structure.get("available") == Some(&Value::Bool(true)));
                whips.push(json!({
                    "path": Value::Null,
                    "program": program,
                    "chat": chat.id,
                    "structure": structure,
                    "instances": instances,
                }));
            }
        }

        Some(json!({
            "schema": PROJECT_WHIPS_SCHEMA,
            "project": project_id,
            "whips": whips,
        }))
    }
}

/// The instances in one runtime store, or none when the store is not there
/// yet — which is the ordinary state of a project nothing has run in.
fn read(store: &Path) -> Vec<gaugedesk_whip_runtime::ProjectedInstance> {
    if !store.exists() {
        return Vec::new();
    }
    match gaugedesk_whip_runtime::instance_views(store) {
        Ok(instances) => instances,
        Err(error) => {
            // A store that exists and cannot be read is worth a line in the
            // log, not a failed page: the other programs still draw.
            tracing::warn!(store = %store.display(), error = %error, "whip views: could not read a runtime store");
            Vec::new()
        }
    }
}

fn projected(store: &Path, program: Option<&str>) -> Vec<Value> {
    read(store)
        .into_iter()
        .filter(|instance| program.is_none_or(|name| instance.program == name))
        .map(|instance| instance.view)
        .collect()
}
