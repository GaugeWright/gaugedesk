//! Agent Settings, a GaugeApp served by [`crate::gaugeapp_host`] for one
//! Agent at the Home that owns it. Only a person who may author the Agent is
//! admitted, by the same check its config, ability and Panel-profile routes
//! use, and every command goes through the state method those routes call.
use axum::{http::HeaderMap, http::StatusCode, response::Response};
use serde_json::{json, Map, Value};

use crate::{
    gaugeapp_agent::contains_secret,
    gaugeapp_contract::{GaugeAppCommandEnvelope, GaugeAppKind},
    gaugeapp_host::{boxed_error, Admission, Applied, GaugeAppDefinition, Page},
    library::{AgentKind, PanelPublicProfile},
    Workbench,
};

/// The Agent-owned management GaugeApp.
pub struct AgentSettings;

const MODEL_SET: &str = "agent.model.set";
const ABILITIES_SET: &str = "agent.abilities.set";
const PANEL_PROFILE_SET: &str = "agent.panel-profile.set";

/// The store scope holding one Agent's settings receipts and the pointers of
/// its management conversations.
pub fn agent_settings_scope(agent_id: &str) -> String {
    format!("agent-settings::{agent_id}")
}

impl GaugeAppDefinition for AgentSettings {
    type Services = ();

    const APP: GaugeAppKind = GaugeAppKind::AgentSettings;
    const PATH: &'static str = "/archetypes/{id}/settings";
    const SCOPE: &'static str = "agent";
    const LABEL: &'static str = "agent settings";
    const CAPABILITY: &'static str = "agent.manage";
    const COMMANDS: &'static [&'static str] = &[MODEL_SET, ABILITIES_SET, PANEL_PROFILE_SET];

    fn admit(wb: &Workbench, headers: &HeaderMap, id: &str) -> Result<Admission, Box<Response>> {
        let actor = crate::library_routes::admit_agent_authoring_owner(wb, id, headers)
            .map_err(Box::new)?;
        Ok(Admission {
            actor,
            can_manage: true,
        })
    }

    fn pages(wb: &Workbench, id: &str) -> Vec<Page> {
        let Some(agent) = wb.agent_record(id) else {
            return Vec::new();
        };
        let page = |id: &'static str, model: Value, commands: &'static [&'static str]| Page {
            id,
            read_model: format!("agent.settings.{id}"),
            model,
            commands,
        };
        let model = serde_json::from_str::<Value>(&agent.config)
            .ok()
            .and_then(|config| config.get("model").cloned())
            .unwrap_or(Value::Null);
        let mut pages = vec![
            page(
                "overview",
                json!({ "agent": id, "name": agent.name, "kind": agent.agent_kind, "model": model, "guide": overview_guide() }),
                &[MODEL_SET],
            ),
            page(
                "abilities",
                match wb.archetype_abilities(id) {
                    Ok(abilities) => json!({
                        "agent": id,
                        "abilities": abilities,
                        "presets": ABILITY_PRESETS,
                        "optional": ["tracker.file", "question.ask"],
                        "guide": abilities_guide(),
                    }),
                    Err(reason) => {
                        json!({ "agent": id, "unavailable": reason, "guide": abilities_guide() })
                    }
                },
                &[ABILITIES_SET],
            ),
        ];
        if agent.agent_kind == AgentKind::Panel {
            pages.push(page(
                "panel-profile",
                match wb.panel_profile(id) {
                    Ok(profile) => json!({ "agent": id, "profile": profile, "guide": panel_profile_guide() }),
                    Err(reason) => json!({ "agent": id, "unavailable": reason, "guide": panel_profile_guide() }),
                },
                &[PANEL_PROFILE_SET],
            ));
        }
        pages
    }

    fn validate(envelope: &GaugeAppCommandEnvelope) -> Result<(), Box<Response>> {
        change(envelope).map(|_| ())
    }

    fn apply(
        wb: &mut Workbench,
        _actor: &str,
        id: &str,
        envelope: &GaugeAppCommandEnvelope,
    ) -> Result<Applied, Box<Response>> {
        let refused = |reason: String| {
            let status = if reason.starts_with("no such") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::UNPROCESSABLE_ENTITY
            };
            boxed_error(status, reason)
        };
        match change(envelope)? {
            Change::Model(model) => {
                let agent = wb
                    .agent_record(id)
                    .ok_or_else(|| refused("no such agent".into()))?;
                let config = with_model(&agent.config, model).map_err(refused)?;
                wb.update_agent_record(id, None, Some(config))
                    .ok_or_else(|| refused("no such agent".into()))?;
            }
            Change::Abilities(abilities) => {
                wb.set_archetype_abilities(id, abilities).map_err(refused)?;
            }
            Change::PanelProfile(profile) => {
                wb.set_panel_profile(id, *profile).map_err(refused)?;
            }
        }
        Ok(Applied::done())
    }
}

/// What the settings assistant needs to act on what the person sees, page by
/// page (`gaugeapp_host` says why every page carries one). The labels are the
/// Agent Settings form's own (`AgentSettings.tsx`, `PanelContractEditor.tsx`,
/// `panel-agent-presentation.ts`); change them together.
fn overview_guide() -> Value {
    json!({
        "page": "The Agent's name, kind (work or panel) and the model its own chats prefer. On the form this is \"Preferred model\", under \"The agent itself\" for a Panel agent.",
        "controls": { "Preferred model": "model: the model this Agent's chats use; null means the person's work-chat default" },
        "commands": {
            MODEL_SET: {
                "does": "Sets the Agent's preferred model, or returns it to the default with null.",
                "control": "Preferred model",
                "payload": { "model": "openai/gpt-6-luna" },
            },
        },
    })
}

fn abilities_guide() -> Value {
    json!({
        "page": "What the Agent itself may do in its chats. On the form this is \"Abilities\": one preset plus the \"File project tasks\" checkbox. For a Panel agent, what visitors' sessions may do is the panel-profile page instead, and it can never exceed these: raise these first when visitors need more.",
        "controls": {
            "Chat only": "abilities: []",
            "Read workspace": "abilities: [\"workspace.read\"]",
            "Create artifacts": "abilities: [\"workspace.read\", \"workspace.write\"]",
            "Run workspace commands": "abilities: [\"command.run\", \"workspace.read\", \"workspace.write\"]",
            "File project tasks": "adds \"tracker.file\" to whichever preset is chosen",
        },
        "commands": {
            ABILITIES_SET: {
                "does": "Replaces the Agent's abilities with exactly this list: a preset's abilities plus any optional ones to keep.",
                "control": "Abilities",
                "payload": { "abilities": ["workspace.read", "workspace.write", "tracker.file"] },
            },
        },
    })
}

/// Asked to "turn on collect results", the assistant found no field of that
/// name in the profile's wire form and guessed at an ability instead.
fn panel_profile_guide() -> Value {
    json!({
        "page": "A Panel agent's public contract: what visitors to its deployments see and may do, its model, how long their conversations are kept, and what is sent to the project Inbox. It is frozen into each version the owner publishes.",
        "controls": {
            "What visitors see": "panels.components, any of gw-chat (Chat), gw-viewer (Viewer), gw-files (Files: what the agent puts in artifacts/), gw-chats (Conversations)",
            "What the agent can do for visitors": "public_abilities: Chat only [], Read workspace [workspace.read], Create artifacts [workspace.read, workspace.write], Run workspace commands [command.run, workspace.read, workspace.write]. Each must also be one of the Agent's own abilities (the abilities page); the form greys out the rest. To give visitors more, raise the Agent's own abilities first, then the profile. Writing to artifacts/ or outbox/, including anything Collect results collects, needs workspace.write.",
            "Ask questions": "adds question.ask to public_abilities",
            "Model": "model.pinned; absent means Default, the publisher's work-chat default",
            "Resumable for": "retention.idle_ttl_seconds",
            "Deleted after at most": "retention.absolute_ttl_seconds",
            "Keep the transcript": "retention.transcript_retained",
            "Keep the visitor's files": "retention.workspace_retained",
            "Collect results": "collection: null is off; on is the collection object in this command's example payload",
            "Files to collect": "collection.exportable_paths: paths under outbox/, which visitors never see",
            "Largest file": "collection.max_artifact_bytes, in bytes, at most 8 MB",
            "Include the conversation transcript": "collection.transcript_eligible",
            "Result format (Advanced)": "collection.schema_ref: a label for the file's format, never checked against its contents",
            "Recipient class (Advanced)": "collection.recipient_class",
        },
        "commands": {
            PANEL_PROFILE_SET: {
                "does": "Replaces the whole Panel profile of the Agent's draft. Read the current profile, change the field the person asked about, and submit all of it. It does not change what visitors get yet: say that it reaches them only once a new version is published (the Agent's 'publish a new version') and each deployment is updated (its placement's Manage deployments, then Save changes).",
                "control": "Save",
                "payload": { "profile": example_panel_profile() },
            },
        },
    })
}

/// A whole profile the command admits: the new-agent default with collection
/// on, as ticking Collect results writes it.
fn example_panel_profile() -> Value {
    let mut profile = serde_json::to_value(PanelPublicProfile::default()).unwrap_or(Value::Null);
    profile["collection"] = json!({
        "exportable_paths": ["outbox/*"],
        "transcript_eligible": false,
        "schema_ref": "gaugewright.panel-output/v1",
        "recipient_class": "project",
        "max_artifact_bytes": 1_048_576,
    });
    profile
}

/// The ability presets `set_archetype_abilities` admits, named the way the
/// settings page names them, so the agent can choose among them.
const ABILITY_PRESETS: [(&str, &[&str]); 4] = [
    ("Chat only", &[]),
    ("Read workspace", &["workspace.read"]),
    ("Create artifacts", &["workspace.read", "workspace.write"]),
    (
        "Run workspace commands",
        &["command.run", "workspace.read", "workspace.write"],
    ),
];

enum Change {
    /// The preferred model; `None` returns the Agent to the default.
    Model(Option<String>),
    Abilities(Vec<String>),
    PanelProfile(Box<PanelPublicProfile>),
}

fn invalid(message: &str) -> Box<Response> {
    boxed_error(StatusCode::UNPROCESSABLE_ENTITY, message)
}

fn change(envelope: &GaugeAppCommandEnvelope) -> Result<Change, Box<Response>> {
    let object = envelope
        .payload
        .as_object()
        .filter(|object| object.len() == 1)
        .ok_or_else(|| invalid("an agent settings command takes one field"))?;
    match envelope.command_id.as_str() {
        MODEL_SET => match object.get("model") {
            Some(Value::Null) => Ok(Change::Model(None)),
            Some(Value::String(model)) => {
                let model = model.trim();
                if model.is_empty() {
                    return Ok(Change::Model(None));
                }
                if model.len() > 200 || model.chars().any(char::is_control) {
                    return Err(invalid("model must be at most 200 printable characters"));
                }
                Ok(Change::Model(Some(model.into())))
            }
            _ => Err(invalid("model must be a model name or null")),
        },
        ABILITIES_SET => object
            .get("abilities")
            .and_then(Value::as_array)
            .and_then(|abilities| {
                abilities
                    .iter()
                    .map(|ability| ability.as_str().map(str::to_owned))
                    .collect::<Option<Vec<_>>>()
            })
            .map(Change::Abilities)
            .ok_or_else(|| invalid("abilities must be a list of ability names")),
        PANEL_PROFILE_SET => {
            let profile = object
                .get("profile")
                .ok_or_else(|| invalid("profile is required"))?;
            if contains_secret(profile) {
                return Err(invalid("a Panel profile never carries a secret"));
            }
            serde_json::from_value::<PanelPublicProfile>(profile.clone())
                .map(|profile| Change::PanelProfile(Box::new(profile)))
                .map_err(|reason| {
                    boxed_error(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        format!("invalid Panel profile: {reason}"),
                    )
                })
        }
        _ => Err(invalid("unknown agent settings command")),
    }
}

/// The Agent's config with its preferred model changed, as the settings form
/// writes it: other runtime settings are kept, package-owned keys dropped.
fn with_model(config: &str, model: Option<String>) -> Result<String, String> {
    let mut settings = match serde_json::from_str::<Value>(config) {
        Ok(Value::Object(settings)) => settings,
        Ok(_) | Err(_) if config.trim().is_empty() => Map::new(),
        _ => return Err("the Agent's settings are not a JSON object".into()),
    };
    match model {
        Some(model) => settings.insert("model".into(), Value::String(model)),
        None => settings.remove("model"),
    };
    settings.remove("policy");
    settings.remove("tools");
    let text = Value::Object(settings).to_string();
    gaugedesk_boundary::AgentConfig::runtime_settings_from_json(&text)
        .map_err(|reason| format!("invalid agent config: {reason}"))?;
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gaugeapp_contract::{GaugeAppClient, GaugeAppSession};
    use crate::gaugeapp_host::{apply_command, context};
    use crate::LockUnpoisoned;
    use axum::http::HeaderValue;

    /// A Home with signed-in owner `alice`, one Agent she authors, and the
    /// headers each person sends.
    fn home(kind: AgentKind) -> (tempfile::TempDir, crate::SharedWorkbench, String) {
        let root = tempfile::tempdir().unwrap();
        let shared = crate::open_workbench(root.path()).unwrap();
        let id = {
            let mut wb = shared.lock_unpoisoned();
            match wb.create_archetype("Researcher".into(), kind, None) {
                Ok(created) => created.id,
                Err(_) => panic!("the Agent is created"),
            }
        };
        (root, shared, id)
    }

    fn session(wb: &Workbench, id: &str) -> GaugeAppSession {
        context::<AgentSettings>(wb, &HeaderMap::new(), id)
            .unwrap()
            .session
    }

    fn envelope(
        session: &GaugeAppSession,
        page: &str,
        command: &str,
        key: &str,
        payload: Value,
    ) -> GaugeAppCommandEnvelope {
        GaugeAppCommandEnvelope {
            session_id: session.id.clone(),
            generation: session.generation.clone(),
            app: GaugeAppKind::AgentSettings,
            scope: session.scope.clone(),
            page_id: page.into(),
            command_id: command.into(),
            expected_basis: session
                .pages
                .iter()
                .find(|candidate| candidate.id == page)
                .unwrap()
                .resource_basis
                .clone(),
            idempotency_key: key.into(),
            payload,
            client: GaugeAppClient::Web,
        }
    }

    fn page_model(wb: &Workbench, id: &str, page: &str) -> Value {
        context::<AgentSettings>(wb, &HeaderMap::new(), id)
            .unwrap()
            .pages
            .into_iter()
            .find(|candidate| candidate.id == page)
            .unwrap()
            .model
    }

    #[test]
    fn its_author_reads_the_agent_model_and_abilities() {
        let (_root, shared, id) = home(AgentKind::Work);
        let wb = shared.lock_unpoisoned();
        let context = context::<AgentSettings>(&wb, &HeaderMap::new(), &id).unwrap();
        assert_eq!(context.session.app, GaugeAppKind::AgentSettings);
        assert_eq!(context.session.scope.kind, "agent");
        assert_eq!(context.session.scope.id, id);
        assert_eq!(
            context
                .pages
                .iter()
                .map(|page| page.id.as_str())
                .collect::<Vec<_>>(),
            ["overview", "abilities"]
        );
        let overview = &context.pages[0].model;
        assert_eq!(overview["name"], "Researcher");
        assert_eq!(overview["kind"], "work");
        assert!(context.pages[1].model["abilities"].is_array());
        assert_eq!(
            context.pages[0].commands,
            [MODEL_SET],
            "the agent reaches the model command directly"
        );
    }

    #[test]
    fn a_panel_agent_shows_its_public_profile() {
        let (_root, shared, id) = home(AgentKind::Panel);
        let wb = shared.lock_unpoisoned();
        let profile = page_model(&wb, &id, "panel-profile");
        assert!(profile["profile"]["panels"].is_object(), "{profile}");
    }

    #[test]
    fn every_page_guides_the_settings_assistant() {
        for kind in [AgentKind::Work, AgentKind::Panel] {
            let (_root, shared, id) = home(kind);
            let wb = shared.lock_unpoisoned();
            crate::gaugeapp_host::assert_pages_are_guided::<AgentSettings>(&AgentSettings::pages(
                &wb, &id,
            ));
        }
    }

    #[test]
    fn turning_on_collect_results_as_the_form_says_is_admitted() {
        let (_root, shared, id) = home(AgentKind::Panel);
        let mut wb = shared.lock_unpoisoned();
        let page = page_model(&wb, &id, "panel-profile");
        let example = &page["guide"]["commands"][PANEL_PROFILE_SET]["payload"]["profile"];
        let mut profile = page["profile"].clone();
        assert_eq!(profile["collection"], Value::Null);
        profile["collection"] = example["collection"].clone();
        let set = envelope(
            &session(&wb, &id),
            "panel-profile",
            PANEL_PROFILE_SET,
            "collect-1",
            json!({ "profile": profile }),
        );
        let receipt =
            apply_command::<AgentSettings>(&mut wb, &HeaderMap::new(), &id, &set).unwrap();
        assert_eq!(receipt["receipt"]["status"], "applied");
        let after = page_model(&wb, &id, "panel-profile");
        assert_eq!(
            after["profile"]["collection"]["exportable_paths"],
            json!(["outbox/*"])
        );
    }

    #[test]
    fn a_command_changes_the_model_through_the_config_and_refreshes_the_page() {
        let (_root, shared, id) = home(AgentKind::Work);
        let mut wb = shared.lock_unpoisoned();
        let before = session(&wb, &id);
        let set = envelope(
            &before,
            "overview",
            MODEL_SET,
            "model-1",
            json!({ "model": "gpt-5.1" }),
        );
        let receipt =
            apply_command::<AgentSettings>(&mut wb, &HeaderMap::new(), &id, &set).unwrap();
        assert_eq!(receipt["agent"], json!(id));
        assert_eq!(receipt["receipt"]["status"], "applied");
        let config: Value = serde_json::from_str(&wb.agent_record(&id).unwrap().config).unwrap();
        assert_eq!(config["model"], "gpt-5.1");
        assert_eq!(page_model(&wb, &id, "overview")["model"], "gpt-5.1");
        // The old basis is stale now; a replay of the same key changes nothing.
        assert!(apply_command::<AgentSettings>(&mut wb, &HeaderMap::new(), &id, &set).is_ok());
        let stale = envelope(
            &before,
            "overview",
            MODEL_SET,
            "model-2",
            json!({ "model": "other" }),
        );
        assert!(apply_command::<AgentSettings>(&mut wb, &HeaderMap::new(), &id, &stale).is_err());
        let cleared = envelope(
            &session(&wb, &id),
            "overview",
            MODEL_SET,
            "model-3",
            json!({ "model": null }),
        );
        apply_command::<AgentSettings>(&mut wb, &HeaderMap::new(), &id, &cleared).unwrap();
        assert_eq!(page_model(&wb, &id, "overview")["model"], Value::Null);
    }

    #[test]
    fn a_new_agent_starts_chat_only_and_can_reach_every_preset() {
        let (_root, shared, id) = home(AgentKind::Work);
        let mut wb = shared.lock_unpoisoned();
        assert_eq!(wb.archetype_abilities(&id).unwrap(), ["question.ask"]);
        for preset in [
            vec!["workspace.read"],
            vec!["workspace.read", "workspace.write"],
            vec!["command.run", "workspace.read", "workspace.write"],
            vec![
                "command.run",
                "tracker.file",
                "workspace.read",
                "workspace.write",
            ],
            vec![],
        ] {
            let preset: Vec<String> = preset.into_iter().map(str::to_owned).collect();
            wb.set_archetype_abilities(&id, preset.clone())
                .unwrap_or_else(|error| panic!("{preset:?} is refused: {error}"));
            assert_eq!(wb.archetype_abilities(&id).unwrap(), preset);
        }
    }

    #[test]
    fn a_command_changes_the_abilities_through_their_setter() {
        let (_root, shared, id) = home(AgentKind::Work);
        let mut wb = shared.lock_unpoisoned();
        let read_only = envelope(
            &session(&wb, &id),
            "abilities",
            ABILITIES_SET,
            "abilities-1",
            json!({ "abilities": ["workspace.read"] }),
        );
        apply_command::<AgentSettings>(&mut wb, &HeaderMap::new(), &id, &read_only).unwrap();
        assert_eq!(wb.archetype_abilities(&id).unwrap(), ["workspace.read"]);
        assert_eq!(
            page_model(&wb, &id, "abilities")["abilities"],
            json!(["workspace.read"])
        );
        let unadmitted = envelope(
            &session(&wb, &id),
            "abilities",
            ABILITIES_SET,
            "abilities-2",
            json!({ "abilities": ["workspace.write"] }),
        );
        assert!(
            apply_command::<AgentSettings>(&mut wb, &HeaderMap::new(), &id, &unadmitted).is_err(),
            "a set outside the presets is refused by the setter"
        );
        let misplaced = envelope(
            &session(&wb, &id),
            "overview",
            ABILITIES_SET,
            "abilities-3",
            json!({ "abilities": [] }),
        );
        assert!(
            apply_command::<AgentSettings>(&mut wb, &HeaderMap::new(), &id, &misplaced).is_err(),
            "a command is admitted only on the page that declares it"
        );
    }

    #[test]
    fn someone_who_may_not_author_the_agent_is_refused() {
        let (_root, shared, id) = home(AgentKind::Work);
        let mut wb = shared.lock_unpoisoned();
        let owner = session(&wb, &id);
        let set = envelope(
            &owner,
            "overview",
            MODEL_SET,
            "model-1",
            json!({ "model": "gpt-5.1" }),
        );
        let mut agent = wb.agent_record(&id).unwrap();
        agent.authoring_owner = Some("person:mallory-owner".into());
        wb.write_agent_record(agent);
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer not-a-person"),
        );
        for headers in [HeaderMap::new(), headers] {
            assert!(context::<AgentSettings>(&wb, &headers, &id).is_err());
            assert!(apply_command::<AgentSettings>(&mut wb, &headers, &id, &set).is_err());
        }
        let config: Value =
            serde_json::from_str(&wb.agent_record(&id).unwrap().config).unwrap_or(json!({}));
        assert!(config.get("model").is_none());
    }

    #[test]
    fn deleting_the_agent_ends_its_settings_conversations() {
        let (_root, shared, id) = home(AgentKind::Work);
        let opened = {
            let wb = shared.lock_unpoisoned();
            session(&wb, &id)
        };
        crate::gaugeapp_agent::append_gaugeapp_agent_exchange(
            &shared,
            &opened,
            "turn-1",
            "What model is this?",
            &crate::gaugeapp_agent::GaugeAppAgentTurn {
                message: "The default.".into(),
                proposals: vec![],
            },
        )
        .unwrap();
        let mut wb = shared.lock_unpoisoned();
        assert_eq!(
            crate::gaugeapp_agent::gaugeapp_agent_transcript(wb.store_ref(), &opened)
                .unwrap()
                .len(),
            2
        );
        assert!(wb.delete_agent_cascade(&id).is_ok());
        assert!(context::<AgentSettings>(&wb, &HeaderMap::new(), &id).is_err());
    }

    #[test]
    fn the_model_keeps_other_runtime_settings_and_drops_package_owned_ones() {
        let config = with_model(
            r#"{"allow_network":false,"policy":{},"model":"old"}"#,
            Some("new".into()),
        )
        .unwrap();
        let config: Value = serde_json::from_str(&config).unwrap();
        assert_eq!(config, json!({ "allow_network": false, "model": "new" }));
        assert_eq!(with_model("{}", None).unwrap(), "{}");
        assert!(with_model("[]", None).is_err());
    }
}
