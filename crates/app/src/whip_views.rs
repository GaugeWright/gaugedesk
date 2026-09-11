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
        let (gate_instances, gate_unread) = projected(&gate_store, Some("gate"));
        whips.push(json!({
            "path": gate_path,
            "program": "gate",
            "chat": Value::Null,
            "structure": gate_structure,
            "instances": gate_instances,
            "unread": gate_unread,
        }));

        // Every chat's package. A chat that has never run has no store, and a
        // store's instances group by the program that ran them.
        let runtime_root = root.join("whip-runtimes");
        for chat in self.library.project_chats(project_id) {
            let store = gaugedesk_whip_runtime::chat_runtime_database(&runtime_root, &chat.id);
            let mut by_program: std::collections::BTreeMap<String, Vec<Value>> = Default::default();
            let chat_read = read(&store);
            for instance in chat_read.instances {
                by_program
                    .entry(instance.program)
                    .or_default()
                    .push(instance.view);
            }
            // A store that would not open has no programs to group, so without
            // this the whole chat vanishes from the view rather than appearing
            // as a chat whose runs could not be read.
            if let Some(unread) = chat_read.unread {
                whips.push(json!({
                    "path": Value::Null,
                    "program": Value::Null,
                    "chat": chat.id,
                    "structure": Value::Null,
                    "instances": [],
                    "unread": unread,
                }));
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
                    "unread": Value::Null,
                }));
            }
        }

        // One place a reader can look to learn the view is partial, so a
        // banner does not have to be derived by scanning every program.
        let complete = whips
            .iter()
            .all(|whip| whip.get("unread").is_none_or(Value::is_null));
        Some(json!({
            "schema": PROJECT_WHIPS_SCHEMA,
            "project": project_id,
            "complete": complete,
            "whips": whips,
        }))
    }
}

/// One store's instances, and what the read could not see (ACTION-7).
///
/// The distinction this type exists to keep is between **nothing to see** and
/// **could not see**. Both used to arrive as an empty vector, so a store that
/// was corrupt, locked, or on a disk that had gone away drew exactly like a
/// project nothing had ever run in — an investigator reading the Instances tab
/// was told "no runs" by a view that meant "no answer".
struct StoreRead {
    instances: Vec<gaugedesk_whip_runtime::ProjectedInstance>,
    /// `None` when the read is complete — *including* when the store does not
    /// exist, which is a complete answer: nothing has run. `Some(reason)` when
    /// the view is missing something it cannot enumerate.
    unread: Option<&'static str>,
}

/// The instances in one runtime store.
///
/// An absent store is not a gap. A store that exists and refuses to be read is,
/// and says so rather than answering with silence.
fn read(store: &Path) -> StoreRead {
    if !store.exists() {
        return StoreRead {
            instances: Vec::new(),
            unread: None,
        };
    }
    match gaugedesk_whip_runtime::instance_views(store) {
        Ok(instances) => StoreRead {
            instances,
            unread: None,
        },
        Err(error) => {
            // Still not a failed page — the other programs draw. What changes
            // is that this one no longer claims to have drawn.
            tracing::warn!(store = %store.display(), error = %error, "whip views: could not read a runtime store");
            StoreRead {
                instances: Vec::new(),
                unread: Some(UNREADABLE),
            }
        }
    }
}

/// The reason a read saw less than the whole store. One spelling, because the
/// client renders on it and a second would render as nothing.
///
/// `unauthorized` belongs in this set the moment these routes carry a caller
/// identity to refuse; today they do not, so inventing the value would be a
/// state nothing can produce.
pub const UNREADABLE: &str = "unreadable";

fn projected(store: &Path, program: Option<&str>) -> (Vec<Value>, Option<&'static str>) {
    let read = read(store);
    let views = read
        .instances
        .into_iter()
        .filter(|instance| program.is_none_or(|name| instance.program == name))
        .map(|instance| instance.view)
        .collect();
    (views, read.unread)
}
