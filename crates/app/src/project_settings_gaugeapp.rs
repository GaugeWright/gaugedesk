//! Project Settings, a GaugeApp served by [`crate::gaugeapp_host`]. Every
//! request is re-admitted at the serving Home and is scoped to one project,
//! person, and GaugeApp.
use axum::{http::HeaderMap, http::StatusCode, response::Response};
use gaugedesk_core::abac::Role;
use gaugedesk_store::CommandRecordFact;
use serde_json::{json, Value};

use crate::{
    client_admission::ClientBuild,
    gaugeapp_contract::{GaugeAppCommandEnvelope, GaugeAppKind},
    gaugeapp_host::{boxed_error, Admission, Applied, GaugeAppDefinition, Page},
    library::{WorkTargetOwner, LIBRARY_SCOPE},
    net_http,
    workbench_auth::req_scope,
    Workbench,
};

/// The project-owned management GaugeApp.
pub struct ProjectSettings;

const NAME_SET: &str = "project.name.set";
const ISOLATION_SET: &str = "project.network-isolation.set";
const TARGET_NAME_SET: &str = "project.target.name.set";

impl GaugeAppDefinition for ProjectSettings {
    type Services = ();

    const APP: GaugeAppKind = GaugeAppKind::ProjectSettings;
    const PATH: &'static str = "/projects/{id}/settings";
    const SCOPE: &'static str = "project";
    const LABEL: &'static str = "project settings";
    const CAPABILITY: &'static str = "project.manage";
    const COMMANDS: &'static [&'static str] = &[NAME_SET, ISOLATION_SET, TARGET_NAME_SET];

    fn admit(wb: &Workbench, headers: &HeaderMap, id: &str) -> Result<Admission, Box<Response>> {
        admit_project(wb, headers, id)
    }

    fn pages(wb: &Workbench, id: &str) -> Vec<Page> {
        let Some(project) = wb.library.projects.get(id) else {
            return Vec::new();
        };
        let page = |id: &'static str, model: Value, commands: &'static [&'static str]| Page {
            id,
            read_model: format!("project.settings.{id}"),
            model,
            commands,
        };
        vec![
            page(
                "overview",
                json!({
                    "id": project.id, "name": project.name,
                    "network_isolated": project.network_isolated,
                    "is_personal": project.is_default,
                    "run_purpose": project.run_purpose,
                    "home_id": project.home_id,
                    "guide": {
                        "page": "Overview: the project's name, whether it is the person's Personal project, and whether its Agents may use the network.",
                        "controls": {
                            "Name": "name; the person renames the project from the navigator or here",
                            "Network access: Isolate / Allow network": "network_isolated",
                        },
                        "commands": {
                            NAME_SET: { "does": "Renames the project.", "control": "Name", "payload": { "name": "Theo Studio" } },
                            ISOLATION_SET: isolation_guide(),
                        },
                    },
                }),
                &[NAME_SET, ISOLATION_SET],
            ),
            page(
                "people",
                json!({
                    "project": id,
                    "participants": crate::federation::participants_of(wb.store_ref(), id),
                    "guide": {
                        "page": "People & sharing: who has access to the project, and invitations waiting to be accepted. Which computer holds the project is Hosting, not this page. Inviting and revoking are done in the page's own controls; not here.",
                        "controls": { "People with access": "participants", "Invite to this project": "the person's own invitation flow" },
                        "commands": {},
                    },
                }),
                &[],
            ),
            page(
                "work-data",
                json!({
                    "project": id,
                    "network_isolated": project.network_isolated,
                    "run_purpose": project.run_purpose,
                    "targets": wb.library.work_targets.values()
                        .filter(|target| matches!(&target.owner, WorkTargetOwner::Project { project_id } if project_id == id))
                        .map(|target| json!({ "id": target.id, "name": target.name, "kind": target.kind, "status": target.status }))
                        .collect::<Vec<_>>(),
                    "guide": {
                        "page": "Work & data: the project's work targets (the repositories and folders its Agents work in) and its network access.",
                        "controls": {
                            "Work targets: Rename": "a target's name",
                            "Network access: Isolate / Allow network": "network_isolated",
                        },
                        "commands": {
                            TARGET_NAME_SET: {
                                "does": "Renames one work target. Chats working on it follow the new name.",
                                "control": "Work targets: Rename",
                                "payload": { "target_id": "target-1", "name": "website" },
                            },
                            ISOLATION_SET: isolation_guide(),
                        },
                    },
                }),
                &[ISOLATION_SET, TARGET_NAME_SET],
            ),
            page(
                "hosting",
                json!({
                    "project": id,
                    "home_id": project.home_id,
                    "guide": {
                        "page": "Hosting: which computer holds the project, and moving it to a paired, trusted device. Who may open the project is People & sharing, not this page. Handing off is done in the page's own controls; not here.",
                        "controls": { "Project Host": "home_id", "Hand off": "the person's own handoff flow" },
                        "commands": {},
                    },
                }),
                &[],
            ),
            page(
                "agents",
                json!({
                    "project": id,
                    "placements": wb.library.instances.values()
                        .filter(|placement| placement.project_id.as_deref() == Some(id))
                        .map(|placement| json!({
                            "id": placement.id, "agent_id": placement.agent_id,
                            "agent_name": wb.library.agents.get(&placement.agent_id).map(|agent| agent.name.as_str()),
                            "kind": placement.placement_kind, "version": placement.version,
                            "admission": placement.admission,
                        }))
                        .collect::<Vec<_>>(),
                    "guide": {
                        "page": "Agents & placements: each Agent placed in this project, its version and whether it is admitted. Placing an Agent from the Workshop and upgrading a placement are done in the page's own controls; not here.",
                        "controls": { "Placed Agents": "placements", "Add from Workshop": "the person's own placement flow" },
                        "commands": {},
                    },
                }),
                &[],
            ),
            page(
                "model-access",
                match crate::project_model_selection::current_selection(wb, id) {
                    Ok(selection) => {
                        json!({ "project": id, "organization_selection": selection, "guide": model_access_guide() })
                    }
                    Err(_) => {
                        json!({ "project": id, "unavailable": "Model selection could not be read", "guide": model_access_guide() })
                    }
                },
                &[],
            ),
        ]
    }

    fn validate(envelope: &GaugeAppCommandEnvelope) -> Result<(), Box<Response>> {
        payload(envelope).map(|_| ())
    }

    fn apply(
        wb: &mut Workbench,
        _actor: &str,
        id: &str,
        envelope: &GaugeAppCommandEnvelope,
    ) -> Result<Applied, Box<Response>> {
        if wb.project_moving(id) {
            return Err(boxed_error(
                StatusCode::CONFLICT,
                crate::federation::PAUSED_FOR_MOVE,
            ));
        }
        let mut project = current_project(wb, id)?.clone();
        let id = id.to_owned();
        match payload(envelope)? {
            SettingsChange::Project { name, isolated } => {
                if let Some(name) = name {
                    project.name = name;
                }
                if let Some(isolated) = isolated {
                    project.network_isolated = isolated;
                }
                let record = CommandRecordFact {
                    scope_id: LIBRARY_SCOPE.into(),
                    kind: "project".into(),
                    payload: serde_json::to_string(&project).map_err(|reason| {
                        boxed_error(StatusCode::INTERNAL_SERVER_ERROR, reason.to_string())
                    })?,
                };
                Ok(Applied {
                    facts: vec![record],
                    committed: Box::new(move |wb, positions| {
                        if wb.library.apply_project_at(project, Some(positions[0])) {
                            wb.notify_library_changed("project", &id, "upsert");
                        }
                    }),
                })
            }
            SettingsChange::TargetName { target_id, name } => {
                // The name lives on collaboration Main, which the target record
                // then projects; the host's receipt records the command.
                let synced_chats = wb
                    .rename_project_target(&id, &target_id, &name)
                    .map_err(|reason| boxed_error(StatusCode::CONFLICT, reason))?;
                Ok(Applied {
                    facts: Vec::new(),
                    committed: Box::new(move |wb, _| {
                        wb.notify_library_changed("project", &id, "upsert");
                        for chat in &synced_chats {
                            wb.notify_library_changed("chat", chat, "upsert");
                        }
                    }),
                })
            }
        }
    }
}

/// Admit a person to one project at its authoritative Home, and say whether
/// they may change it. Every project-scoped GaugeApp admits through this, so a
/// placement's settings never admit more than its project's do.
/// The isolation command appears on two pages; one description serves both.
/// Labels are `ProjectSettings.tsx`'s own.
fn isolation_guide() -> Value {
    json!({
        "does": "Isolates the project (true: its Agents cannot make network requests) or allows the network again (false). It applies to every Agent run in the project.",
        "control": "Network access: Isolate / Allow network",
        "payload": { "isolated": true },
    })
}

fn model_access_guide() -> Value {
    json!({
        "page": "Model access: which personal or shared connection this project's work may use, any project override, and the effective cap and policy. You can explain it; changing it is done in the page's own controls, not by a command here.",
        "controls": {},
        "commands": {},
    })
}

pub(crate) fn admit_project(
    wb: &Workbench,
    headers: &HeaderMap,
    id: &str,
) -> Result<Admission, Box<Response>> {
    let actor = wb
        .admit_data_request_with_client(
            net_http::bearer(headers),
            Some(id),
            &req_scope(headers),
            ClientBuild::from_headers(headers),
            true,
        )
        .map_err(|(status, reason)| boxed_error(status, reason))?;
    if !wb
        .project_visibility_in(net_http::bearer(headers), &req_scope(headers))
        .allows(id)
    {
        return Err(boxed_error(
            StatusCode::FORBIDDEN,
            "project access required",
        ));
    }
    let project = current_project(wb, id)?;
    if &project.home_id != wb.home_id() {
        return Err(boxed_error(
            StatusCode::CONFLICT,
            "use the project's authoritative Home",
        ));
    }
    let directory =
        crate::org::Org::rebuild_in(wb.store_ref(), &req_scope(headers)).map_err(|_| {
            boxed_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "project membership is unavailable",
            )
        })?;
    let provisioned = directory
        .members
        .values()
        .any(|member| member.status == crate::org::MembershipStatus::Active);
    let can_manage = can_manage_project(directory.role_of(&actor), provisioned);
    Ok(Admission { actor, can_manage })
}

fn can_manage_project(role: Option<Role>, provisioned: bool) -> bool {
    !provisioned
        || matches!(role, Some(role)
        if role == Role::owner() || role == Role::admin() || role == Role::member())
}

fn current_project<'a>(
    wb: &'a Workbench,
    id: &str,
) -> Result<&'a crate::library::ProjectRecord, Box<Response>> {
    wb.library
        .projects
        .get(id)
        .filter(|record| record.op == crate::library::RecordOp::Upsert)
        .ok_or_else(|| boxed_error(StatusCode::NOT_FOUND, "project is unavailable"))
}

/// What a project settings command changes.
enum SettingsChange {
    Project {
        name: Option<String>,
        isolated: Option<bool>,
    },
    /// A target's name, recorded on collaboration Main (DR-0248).
    TargetName { target_id: String, name: String },
}

fn payload(envelope: &GaugeAppCommandEnvelope) -> Result<SettingsChange, Box<Response>> {
    let object = envelope.payload.as_object().ok_or_else(|| {
        boxed_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "settings command requires an object",
        )
    })?;
    match envelope.command_id.as_str() {
        NAME_SET if object.len() == 1 => {
            let name = object
                .get("name")
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or("");
            if name.is_empty() || name.len() > 120 || name.chars().any(char::is_control) {
                return Err(boxed_error(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "name must be 1–120 printable characters",
                ));
            }
            Ok(SettingsChange::Project {
                name: Some(name.into()),
                isolated: None,
            })
        }
        TARGET_NAME_SET if object.len() == 2 => {
            let text = |key: &str| object.get(key).and_then(Value::as_str).unwrap_or("");
            let target_id = text("target_id");
            if target_id.is_empty() {
                return Err(boxed_error(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "target_id is required",
                ));
            }
            // The folder rules and project-wide uniqueness are the target
            // name's own (DR-0248), checked when the rename is applied.
            Ok(SettingsChange::TargetName {
                target_id: target_id.into(),
                name: text("name").into(),
            })
        }
        ISOLATION_SET if object.len() == 1 => object
            .get("isolated")
            .and_then(Value::as_bool)
            .map(|isolated| SettingsChange::Project {
                name: None,
                isolated: Some(isolated),
            })
            .ok_or_else(|| {
                boxed_error(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "isolated must be true or false",
                )
            }),
        _ => Err(boxed_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "unknown or invalid project settings command",
        )),
    }
}

// The names the tests below were written against, kept so they read the
// same against the shared host.
#[cfg(test)]
use crate::{
    gaugeapp_agent::{gaugeapp_agent_transcript, GaugeAppAgentContext},
    gaugeapp_contract::GaugeAppClient,
    LockUnpoisoned,
};
#[cfg(test)]
const APP: GaugeAppKind = GaugeAppKind::ProjectSettings;
#[cfg(test)]
const PAGE: &str = "overview";
#[cfg(test)]
fn build(
    wb: &Workbench,
    headers: &HeaderMap,
    id: &str,
) -> Result<GaugeAppAgentContext, Box<Response>> {
    crate::gaugeapp_host::context::<ProjectSettings>(wb, headers, id)
}
#[cfg(test)]
fn apply(
    wb: &mut Workbench,
    headers: &HeaderMap,
    id: &str,
    envelope: &GaugeAppCommandEnvelope,
) -> Result<Value, Box<Response>> {
    crate::gaugeapp_host::apply_command::<ProjectSettings>(wb, headers, id, envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gaugeapp_agent::{append_gaugeapp_agent_exchange, GaugeAppAgentTurn};

    #[test]
    fn viewer_and_auditor_cannot_receive_project_edit_commands() {
        assert!(can_manage_project(None, false)); // solo Home
        assert!(can_manage_project(Some(Role::member()), true));
        assert!(can_manage_project(Some(Role::owner()), true));
        assert!(!can_manage_project(Some(Role::viewer()), true));
        assert!(!can_manage_project(Some(Role::new("auditor")), true));
        assert!(!can_manage_project(None, true));
    }

    #[test]
    fn committed_project_callbacks_reject_delayed_records_after_a_newer_command() {
        let root = tempfile::tempdir().unwrap();
        let shared = crate::open_workbench(root.path()).unwrap();
        let headers = HeaderMap::new();
        let mut wb = shared.lock_unpoisoned();
        let project =
            crate::library_routes::create_named_project(&mut wb, "positioned-project", "Original")
                .unwrap()["id"]
                .as_str()
                .unwrap()
                .to_owned();
        let session = build(&wb, &headers, &project).unwrap().session;
        let envelope = |key: &str, name: &str| GaugeAppCommandEnvelope {
            session_id: session.id.clone(),
            generation: session.generation.clone(),
            app: APP,
            scope: session.scope.clone(),
            page_id: PAGE.into(),
            command_id: NAME_SET.into(),
            expected_basis: session.pages[0].resource_basis.clone(),
            idempotency_key: key.into(),
            payload: json!({ "name": name }),
            client: GaugeAppClient::Web,
        };

        // Admit an older real domain record while retaining its projection
        // callback. This models delayed projection application, not concurrent
        // command authorization outside the current Workbench lock.
        let older_envelope = envelope("older", "Older");
        let older =
            ProjectSettings::apply(&mut wb, &session.actor, &project, &older_envelope).unwrap();
        let older_admission = wb
            .store_mut()
            .admit_record_facts(
                "positioned-project-command",
                "older",
                &serde_json::to_string(&older_envelope).unwrap(),
                &older.facts,
            )
            .unwrap();
        assert!(!older_admission.replayed);
        assert_eq!(older_admission.positions.len(), 1);

        // The ordinary host appends the project, its command receipt fact and
        // chained audit record to different scopes. Only the project position
        // belongs to this callback; a receipt/audit position cannot substitute.
        let newer_envelope = envelope("newer", "Newer");
        apply(&mut wb, &headers, &project, &newer_envelope).unwrap();
        assert_eq!(wb.library.projects[&project].name, "Newer");
        (older.committed)(&mut wb, &older_admission.positions);
        assert_eq!(wb.library.projects[&project].name, "Newer");

        // A genuine command retry must not re-apply its earlier projection.
        let mut newest = wb.library.projects[&project].clone();
        newest.name = "Newest".into();
        wb.write_project_record(newest);
        apply(&mut wb, &headers, &project, &newer_envelope).unwrap();
        assert_eq!(wb.library.projects[&project].name, "Newest");
    }

    #[test]
    fn every_page_guides_the_settings_assistant() {
        let root = tempfile::tempdir().unwrap();
        let shared = crate::open_workbench(root.path()).unwrap();
        let mut wb = shared.lock_unpoisoned();
        let project = crate::library_routes::create_named_project(&mut wb, "proj-guided", "Site")
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned();
        crate::gaugeapp_host::assert_pages_are_guided::<ProjectSettings>(&ProjectSettings::pages(
            &wb, &project,
        ));
    }

    #[test]
    fn a_target_is_renamed_on_main_from_project_settings() {
        let root = tempfile::tempdir().unwrap();
        let shared = crate::open_workbench(root.path()).unwrap();
        let headers = HeaderMap::new();
        let project = {
            let mut wb = shared.lock_unpoisoned();
            crate::library_routes::create_named_project(&mut wb, "proj-rename", "Site").unwrap()
                ["id"]
                .as_str()
                .unwrap()
                .to_owned()
        };
        let (session, target_id) = {
            let wb = shared.lock_unpoisoned();
            let target_id = wb
                .library
                .work_targets
                .values()
                .find(|target| matches!(&target.owner, WorkTargetOwner::Project { project_id } if project_id == &project))
                .unwrap()
                .id
                .clone();
            (build(&wb, &headers, &project).unwrap().session, target_id)
        };
        let work_data = session
            .pages
            .iter()
            .find(|page| page.id == "work-data")
            .unwrap();
        assert!(work_data
            .commands
            .iter()
            .any(|command| command == "project.target.name.set"));
        let envelope = |key: &str, name: &str| GaugeAppCommandEnvelope {
            session_id: session.id.clone(),
            generation: session.generation.clone(),
            app: APP,
            scope: session.scope.clone(),
            page_id: "work-data".into(),
            command_id: "project.target.name.set".into(),
            expected_basis: work_data.resource_basis.clone(),
            idempotency_key: key.into(),
            payload: json!({ "target_id": target_id, "name": name }),
            client: GaugeAppClient::Web,
        };
        let mut wb = shared.lock_unpoisoned();
        for invalid in [".hidden", "a/b", ""] {
            assert!(apply(&mut wb, &headers, &project, &envelope(invalid, invalid)).is_err());
        }
        let renamed = envelope("rename-website", "website");
        assert!(apply(&mut wb, &headers, &project, &renamed).is_ok());
        assert_eq!(wb.library.work_targets[&target_id].name, "website");
        assert_eq!(
            wb.main_target_name(&project, &target_id).as_deref(),
            Some("website")
        );
        // A replay applies nothing twice.
        assert!(apply(&mut wb, &headers, &project, &renamed).is_ok());
    }

    #[test]
    fn project_commands_and_conversations_stay_in_their_exact_scope() {
        let root = tempfile::tempdir().unwrap();
        let shared = crate::open_workbench(root.path()).unwrap();
        let headers = HeaderMap::new();
        let (first, second) = {
            let mut wb = shared.lock_unpoisoned();
            let first = crate::library_routes::create_named_project(&mut wb, "proj-first", "First")
                .unwrap();
            let second =
                crate::library_routes::create_named_project(&mut wb, "proj-second", "Second")
                    .unwrap();
            (
                first["id"].as_str().unwrap().to_owned(),
                second["id"].as_str().unwrap().to_owned(),
            )
        };
        let first_session = {
            let wb = shared.lock_unpoisoned();
            build(&wb, &headers, &first).unwrap().session
        };
        assert_eq!(
            first_session
                .pages
                .iter()
                .map(|page| page.id.as_str())
                .collect::<Vec<_>>(),
            [
                "overview",
                "people",
                "work-data",
                "hosting",
                "agents",
                "model-access"
            ]
        );
        let envelope = GaugeAppCommandEnvelope {
            session_id: first_session.id.clone(),
            generation: first_session.generation.clone(),
            app: APP,
            scope: first_session.scope.clone(),
            page_id: PAGE.into(),
            command_id: "project.network-isolation.set".into(),
            expected_basis: first_session.pages[0].resource_basis.clone(),
            idempotency_key: "isolate-first".into(),
            payload: json!({ "isolated": true }),
            client: GaugeAppClient::Web,
        };
        {
            let mut wb = shared.lock_unpoisoned();
            assert!(apply(&mut wb, &headers, &first, &envelope).is_ok());
            assert!(apply(&mut wb, &headers, &first, &envelope).is_ok());
            assert!(wb.library.projects[&first].network_isolated);
            assert!(!wb.library.projects[&second].network_isolated);
            assert!(apply(&mut wb, &headers, &second, &envelope).is_err());
        }
        append_gaugeapp_agent_exchange(
            &shared,
            &first_session,
            "turn-first",
            "Describe settings",
            &GaugeAppAgentTurn {
                message: "First project".into(),
                proposals: vec![],
            },
        )
        .unwrap();
        let wb = shared.lock_unpoisoned();
        let second_session = build(&wb, &headers, &second).unwrap().session;
        assert_eq!(
            gaugeapp_agent_transcript(wb.store_ref(), &first_session)
                .unwrap()
                .len(),
            2
        );
        assert!(gaugeapp_agent_transcript(wb.store_ref(), &second_session)
            .unwrap()
            .is_empty());
    }
}
