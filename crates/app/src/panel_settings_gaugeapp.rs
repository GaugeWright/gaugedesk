//! Panel Settings, a GaugeApp served by [`crate::gaugeapp_host`] for one Panel
//! placement at its project's authoritative Home (DR-0305).
//!
//! A Panel placement hosts no chats. Selecting one opens this instead: the
//! version it pins, the public deployments it owns, and the part of the
//! project's Inbox those deployments returned. Admission is the project's, so a
//! placement's settings never admit more than its project's do.
//!
//! The Inbox page is the quarantine *index* — provenance and disposition, never
//! an item's content. The management agent reads every page model whole, and no
//! agent may read unfiltered material (ADR 0110 §1), so nothing here ever
//! calls [`Workbench::read_quarantined_item`]. A person reads an item through
//! the reviewer's route and rules on it with `panel.inbox.review`, which the
//! agent can point to but never submit. The agent may ask the gate to screen an
//! item, because the gate is what reads it and only its verdict comes back.
use axum::{http::HeaderMap, http::StatusCode, response::Response};
use serde_json::{json, Value};

use crate::{
    gaugeapp_contract::{GaugeAppCommandEnvelope, GaugeAppKind},
    gaugeapp_host::{boxed_error, Admission, Applied, GaugeAppDefinition, Page},
    library::{
        InstanceKind, InstanceRecord, PlacementKind, PublicDeploymentBindingRecord, RecordOp,
    },
    quarantine::{ItemStatus, QuarantinedItem},
    Workbench,
};

/// The Panel-placement management GaugeApp.
pub struct PanelSettings;

const REVIEW: &str = "panel.inbox.review";
const SCREEN: &str = "panel.inbox.screen";

/// The store scope holding one Panel placement's settings receipts and the
/// pointers of its management conversations.
pub fn panel_settings_scope(placement_id: &str) -> String {
    format!("panel-settings::{placement_id}")
}

impl GaugeAppDefinition for PanelSettings {
    type Services = ();

    const APP: GaugeAppKind = GaugeAppKind::PanelSettings;
    const PATH: &'static str = "/placements/{id}/settings";
    const SCOPE: &'static str = "placement";
    const LABEL: &'static str = "panel settings";
    const CAPABILITY: &'static str = "placement.manage";
    const COMMANDS: &'static [&'static str] = &[SCREEN, REVIEW];

    fn admit(wb: &Workbench, headers: &HeaderMap, id: &str) -> Result<Admission, Box<Response>> {
        let placement = panel_placement(wb, id)?;
        let project = placement.project_id.as_deref().unwrap_or_default();
        crate::project_settings_gaugeapp::admit_project(wb, headers, project)
    }

    fn pages(wb: &Workbench, id: &str) -> Vec<Page> {
        let Ok(placement) = panel_placement(wb, id) else {
            return Vec::new();
        };
        let project = placement.project_id.clone().unwrap_or_default();
        let page = |id: &'static str, model: Value, commands: &'static [&'static str]| Page {
            id,
            read_model: format!("panel.settings.{id}"),
            model,
            commands,
        };
        let agent = wb.library.agents.get(&placement.agent_id);
        let profile = agent
            .and_then(|agent| agent.versions.get(&placement.version))
            .and_then(|version| version.panel_profile.clone());
        let inbox = match placement_inbox(wb, placement) {
            Ok(items) => json!({
                "placement": id,
                "project": project,
                "pending": items.iter().filter(|item| item.status == ItemStatus::Pending).count(),
                "items": items.iter().map(index_entry).collect::<Vec<_>>(),
                "kept_items": "A kept item is a file under inbound/ in the project's own folder, which the project's work chats can read.",
                "guide": inbox_guide(),
            }),
            Err(reason) => {
                json!({ "placement": id, "project": project, "unavailable": reason, "guide": inbox_guide() })
            }
        };
        vec![
            page(
                "overview",
                json!({
                    "placement": id,
                    "project": project,
                    "agent": placement.agent_id,
                    "name": agent.map(|agent| agent.name.as_str()),
                    "version": placement.version,
                    "current_version": agent.map(|agent| agent.current_version),
                    "upgrade_available": wb.library.upgrade_available(id),
                    "admission": placement.admission,
                    "collects": placement.collection_recipient.is_some(),
                    "profile": profile,
                    "guide": {
                        "page": "Overview: which Agent and version this Panel placement pins, whether a newer version is available, whether it collects results into the project Inbox, and the pinned public contract. The contract is changed by editing the Agent in the Workshop and publishing a new version, then upgrading this placement; not here.",
                        "controls": {
                            "Deployments": "opens the deployments page",
                            "Inbox": "opens the inbox page; pending is how many items await review",
                            "Deploy… / Manage deployments…": "opens the deploy flow, which the person completes in its own controls",
                        },
                        "commands": {},
                    },
                }),
                &[],
            ),
            page(
                "deployments",
                json!({
                    "placement": id,
                    "deployments": wb.library.public_deployments.values()
                        .filter(|binding| binding.placement_id == id && binding.op == RecordOp::Upsert)
                        .map(|binding| json!({
                            "id": binding.id,
                            "deployment_id": binding.hosted_deployment_id,
                            "edge_origin": binding.edge_origin,
                            "active_release_id": binding.active_release_id,
                            "status": binding.status,
                            "allowed_origins": binding.operational.allowed_origins,
                            "audience": binding.operational.audience,
                            "funding": binding.operational.funding_ref,
                            "per_visitor_turn_limit": binding.operational.per_visitor_turn_limit,
                            "max_concurrent_sessions": binding.operational.max_concurrent_sessions,
                            "retention_idle_ttl_seconds": binding.operational.retention_idle_ttl_seconds,
                            "retention_absolute_ttl_seconds": binding.operational.retention_absolute_ttl_seconds,
                        }))
                        .collect::<Vec<_>>(),
                    "guide": {
                        "page": "Deployments: where this Panel placement runs on the web, which release each serves, its allowed origins, audience, funding, limits and retention. Deploying and changing a deployment are done in the deploy flow the page opens; not here.",
                        "controls": {},
                        "commands": {},
                    },
                }),
                &[],
            ),
            page("inbox", inbox, &[SCREEN, REVIEW]),
        ]
    }

    fn validate(envelope: &GaugeAppCommandEnvelope) -> Result<(), Box<Response>> {
        change(envelope).map(|_| ())
    }

    fn apply(
        wb: &mut Workbench,
        actor: &str,
        id: &str,
        envelope: &GaugeAppCommandEnvelope,
    ) -> Result<Applied, Box<Response>> {
        let change = change(envelope)?;
        let placement = panel_placement(wb, id)?.clone();
        let project = placement.project_id.clone().unwrap_or_default();
        let item = change.item();
        let items = placement_inbox(wb, &placement)
            .map_err(|reason| boxed_error(StatusCode::SERVICE_UNAVAILABLE, reason))?;
        match items.iter().find(|candidate| candidate.item_id == item) {
            None => {
                return Err(boxed_error(
                    StatusCode::NOT_FOUND,
                    "no such item in this panel's Inbox",
                ))
            }
            Some(found) if found.status != ItemStatus::Pending => {
                return Err(boxed_error(
                    StatusCode::CONFLICT,
                    "the gate has already ruled on this item",
                ))
            }
            Some(_) => {}
        }
        // The gate coerces, if it coerces at all, with the credential of the
        // person running the pass, exactly as the project's own review routes
        // do; the default gate asks a person and needs none.
        let transport = crate::gate_service::HttpGateTransport;
        let ruled = match change {
            Change::Screen { item } => wb
                .screen_quarantined_as(actor, &project, &item, &transport)
                .map(|_| ()),
            Change::Review { item, verdict } => {
                // A verdict reaches a gate only as the answer to the question
                // it parked on. An item nothing has screened yet — drained by
                // another surface, or arrived before screening ran on drain —
                // has no such question, so a person's keep would settle nothing
                // and leave it pending. Run the gate's first pass, and answer
                // the question it parks; a screening gate that rules outright
                // has ruled.
                match wb.review_quarantined_as(actor, &project, &item, verdict, &transport) {
                    Ok(None) => {
                        match wb.screen_quarantined_as(actor, &project, &item, &transport) {
                            Ok(None) => wb
                                .review_quarantined_as(actor, &project, &item, verdict, &transport)
                                .map(|_| ()),
                            Ok(Some(_)) => Ok(()),
                            Err(error) => Err(error),
                        }
                    }
                    Ok(Some(_)) => Ok(()),
                    Err(error) => Err(error),
                }
            }
        };
        ruled.map_err(|error| boxed_error(StatusCode::CONFLICT, error.to_string()))?;
        Ok(Applied {
            facts: Vec::new(),
            committed: Box::new(move |wb, _| {
                wb.notify_library_changed("project", &project, "upsert");
            }),
        })
    }
}

/// What the settings assistant needs to act on the Inbox page; labels are
/// `PanelSettings.tsx`'s own.
fn inbox_guide() -> Value {
    json!({
        "page": "Inbox: what this Panel's deployments returned, listed by index only. You never see an item's content. Each pending item waits for the project's gate: screening asks the gate for its first pass, and keeping or flagging is the person's decision.",
        "controls": {
            "keep": "the person keeps the item: it lands under inbound/ in the project's folder",
            "flag": "the person flags the item: it is not kept",
            "refresh": "reads the Inbox again",
        },
        "commands": {
            SCREEN: {
                "does": "Asks the project's gate to screen one pending item. The gate may rule, or park it for the person.",
                "control": "none: the page screens on its own; offer this when an item is waiting unscreened",
                "payload": { "item_id": "item-1" },
            },
            REVIEW: {
                "does": "Records the person's keep or flag for one pending item. Submit only the verdict the person stated; it is theirs to make.",
                "control": "keep / flag",
                "payload": { "item_id": "item-1", "verdict": "keep" },
            },
        },
    })
}

/// An active Panel placement, refusing anything else by the same answer so a
/// placement id cannot be used to learn what else exists.
fn panel_placement<'a>(wb: &'a Workbench, id: &str) -> Result<&'a InstanceRecord, Box<Response>> {
    wb.library
        .instances
        .get(id)
        .filter(|placement| {
            placement.op == RecordOp::Upsert
                && placement.kind == InstanceKind::Using
                && placement.placement_kind == PlacementKind::Panel
                && placement
                    .project_id
                    .as_deref()
                    .is_some_and(|project| !project.is_empty())
        })
        .ok_or_else(|| boxed_error(StatusCode::NOT_FOUND, "panel placement is unavailable"))
}

/// Whether `id` is an active Panel placement Panel Settings would open.
pub(crate) fn opens(wb: &Workbench, id: &str) -> bool {
    panel_placement(wb, id).is_ok()
}

/// The project's quarantine items this placement's deployments returned.
fn placement_inbox(
    wb: &Workbench,
    placement: &InstanceRecord,
) -> Result<Vec<QuarantinedItem>, String> {
    let project = placement.project_id.as_deref().unwrap_or_default();
    let bindings = wb
        .library
        .public_deployments
        .values()
        .filter(|binding| binding.placement_id == placement.id && binding.project_id == project)
        .collect::<Vec<_>>();
    let items = crate::quarantine::list(wb.store_ref(), project)
        .map_err(|_| "the Inbox could not be read".to_owned())?;
    Ok(items
        .into_iter()
        .filter(|item| bindings.iter().any(|binding| returned(binding, item)))
        .collect())
}

/// Whether this deployment binding returned the item. An item names its
/// deployment binding; one drained before bindings existed names only the
/// hosted deployment, which still resolves through the binding. The task bar
/// asks this too, to open a placement's Inbox rather than the project's.
pub(crate) fn returned(binding: &PublicDeploymentBindingRecord, item: &QuarantinedItem) -> bool {
    item.deployment_binding_id.as_deref() == Some(binding.id.as_str())
        || (item.deployment_binding_id.is_none()
            && item.deployment_id.as_deref() == Some(binding.hosted_deployment_id.as_str()))
}

/// One Inbox row as the page shows it: where it came from and what the gate
/// made of it. Never its content.
fn index_entry(item: &QuarantinedItem) -> Value {
    json!({
        "item_id": item.item_id,
        "deployment_id": item.deployment_id,
        "public_session_id": item.public_session_id,
        "schema": item.schema_ref,
        "bytes": item.byte_len,
        "produced_at_unix_ms": item.produced_at_unix_ms,
        "arrived_at_unix_ms": item.arrived_at_unix_ms,
        "status": item.status.key(),
        "workspace_path": match &item.status {
            ItemStatus::Approved { workspace_path } => Some(workspace_path.as_str()),
            ItemStatus::Pending | ItemStatus::Rejected => None,
        },
    })
}

enum Change {
    Screen {
        item: String,
    },
    Review {
        item: String,
        verdict: crate::gate::Verdict,
    },
}

impl Change {
    fn item(&self) -> String {
        match self {
            Self::Screen { item } | Self::Review { item, .. } => item.clone(),
        }
    }
}

fn invalid(message: &str) -> Box<Response> {
    boxed_error(StatusCode::UNPROCESSABLE_ENTITY, message)
}

fn change(envelope: &GaugeAppCommandEnvelope) -> Result<Change, Box<Response>> {
    let object = envelope
        .payload
        .as_object()
        .ok_or_else(|| invalid("a panel settings command takes an object"))?;
    let item = object
        .get("item_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|item| !item.is_empty() && item.len() <= 200)
        .ok_or_else(|| invalid("item_id names one Inbox item"))?
        .to_owned();
    match envelope.command_id.as_str() {
        SCREEN if object.len() == 1 => Ok(Change::Screen { item }),
        REVIEW if object.len() == 2 => match object.get("verdict").and_then(Value::as_str) {
            Some("keep") => Ok(Change::Review {
                item,
                verdict: crate::gate::Verdict::Keep,
            }),
            Some("flag") => Ok(Change::Review {
                item,
                verdict: crate::gate::Verdict::Flag,
            }),
            _ => Err(invalid("verdict must be keep or flag")),
        },
        _ => Err(invalid("unknown or invalid panel settings command")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gaugeapp_agent::{
        gaugeapp_agent_transcript, GaugeAppAgentActionKind, GaugeAppAgentContext,
    };
    use crate::gaugeapp_contract::{GaugeAppClient, GaugeAppSession};
    use crate::gaugeapp_host::{apply_command, context};
    use crate::library::{
        DeploymentAudience, DeploymentBindingStatus, DeploymentOperationalConfig,
        PanelPublicProfile, PublicDeploymentBindingRecord, LIBRARY_RECORD_SCHEMA,
    };
    use crate::quarantine::QuarantinedItem;
    use crate::LockUnpoisoned;

    const PLACEMENT: &str = "inst-panel-survey";
    const OTHER: &str = "inst-panel-other";
    /// What a visitor typed. It must never appear in anything the agent reads.
    const ANSWER: &str = "favourite-number-forty-two";

    fn bind(wb: &mut Workbench, placement: &str, binding: &str, deployment: &str) {
        wb.write_public_deployment_record(PublicDeploymentBindingRecord {
            schema: LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: binding.into(),
            op: RecordOp::Upsert,
            project_id: crate::DEFAULT_PROJECT.into(),
            placement_id: placement.into(),
            hosted_deployment_id: deployment.into(),
            edge_origin: "https://edge.example.test".into(),
            active_release_id: Some("sha256:release".into()),
            operational: DeploymentOperationalConfig {
                allowed_origins: vec!["https://survey.example.test".into()],
                audience: DeploymentAudience::default(),
                funding_ref: "managed:plan".into(),
                credential_class: "managed".into(),
                credential_ref: String::new(),
                max_spend_cents: None,
                max_session_spend_cents: None,
                max_turn_spend_cents: None,
                per_visitor_turn_limit: 10,
                max_concurrent_sessions: 10,
                white_label: false,
                retention_idle_ttl_seconds: 600,
                retention_absolute_ttl_seconds: 3600,
            },
            status: DeploymentBindingStatus::Active,
        })
        .unwrap();
    }

    fn arrive(wb: &mut Workbench, item: &str, binding: &str, deployment: &str) {
        let payload = format!("{{\"answer\":\"{ANSWER}\"}}");
        wb.quarantine_payloads()
            .put(crate::DEFAULT_PROJECT, item, payload.as_bytes())
            .unwrap();
        crate::quarantine::record(
            wb.store_mut(),
            crate::DEFAULT_PROJECT,
            &QuarantinedItem {
                item_id: item.into(),
                source: format!("collection:{deployment}"),
                deployment_binding_id: Some(binding.into()),
                deployment_id: Some(deployment.into()),
                public_session_id: Some(format!("session-{item}")),
                source_id: item.into(),
                release_id: "sha256:release".into(),
                revision: 1,
                schema_ref: "survey.v1".into(),
                byte_len: payload.len() as u64,
                produced_at_unix_ms: 1,
                arrived_at_unix_ms: 2,
                status: ItemStatus::Pending,
            },
        )
        .unwrap();
    }

    /// A Home with two Panel placements in Personal, each with one deployment
    /// and one item it returned.
    #[test]
    fn every_page_guides_the_settings_assistant() {
        let (_root, shared) = home();
        let wb = shared.lock_unpoisoned();
        crate::gaugeapp_host::assert_pages_are_guided::<PanelSettings>(&PanelSettings::pages(
            &wb, PLACEMENT,
        ));
    }

    fn home() -> (tempfile::TempDir, crate::SharedWorkbench) {
        let root = tempfile::tempdir().unwrap();
        let shared = crate::open_workbench(root.path()).unwrap();
        {
            let mut wb = shared.lock_unpoisoned();
            for placement in [PLACEMENT, OTHER] {
                wb.seed_panel_placement(placement, PanelPublicProfile::default())
                    .unwrap();
            }
            bind(&mut wb, PLACEMENT, "binding-survey", "dep-survey");
            bind(&mut wb, OTHER, "binding-other", "dep-other");
            arrive(&mut wb, "survey-1", "binding-survey", "dep-survey");
            arrive(&mut wb, "other-1", "binding-other", "dep-other");
        }
        (root, shared)
    }

    fn opened(wb: &Workbench, id: &str) -> GaugeAppAgentContext {
        context::<PanelSettings>(wb, &HeaderMap::new(), id).unwrap()
    }

    fn envelope(
        session: &GaugeAppSession,
        command: &str,
        key: &str,
        payload: Value,
    ) -> GaugeAppCommandEnvelope {
        GaugeAppCommandEnvelope {
            session_id: session.id.clone(),
            generation: session.generation.clone(),
            app: GaugeAppKind::PanelSettings,
            scope: session.scope.clone(),
            page_id: "inbox".into(),
            command_id: command.into(),
            expected_basis: session
                .pages
                .iter()
                .find(|page| page.id == "inbox")
                .unwrap()
                .resource_basis
                .clone(),
            idempotency_key: key.into(),
            payload,
            client: GaugeAppClient::Web,
        }
    }

    fn inbox(wb: &Workbench, id: &str) -> Value {
        opened(wb, id)
            .pages
            .into_iter()
            .find(|page| page.id == "inbox")
            .unwrap()
            .model
    }

    #[test]
    fn a_panel_placement_shows_its_version_deployments_and_inbox() {
        let (_root, shared) = home();
        let wb = shared.lock_unpoisoned();
        let context = opened(&wb, PLACEMENT);
        assert_eq!(context.session.app, GaugeAppKind::PanelSettings);
        assert_eq!(context.session.scope.kind, "placement");
        assert_eq!(
            context
                .pages
                .iter()
                .map(|page| page.id.as_str())
                .collect::<Vec<_>>(),
            ["overview", "deployments", "inbox"]
        );
        assert_eq!(context.pages[0].model["version"], 1);
        assert!(context.pages[0].model["profile"]["panels"].is_object());
        let deployments = context.pages[1].model["deployments"].as_array().unwrap();
        assert_eq!(deployments.len(), 1, "only this placement's deployments");
        assert_eq!(deployments[0]["deployment_id"], "dep-survey");
        let items = context.pages[2].model["items"].as_array().unwrap();
        assert_eq!(
            items.len(),
            1,
            "only what this placement's deployments returned"
        );
        assert_eq!(items[0]["item_id"], "survey-1");
        assert_eq!(items[0]["status"], "pending");
        assert_eq!(context.pages[2].model["pending"], 1);
    }

    /// ADR 0110 §1: the agent reads every page model whole, so no page may
    /// carry what a visitor wrote.
    #[test]
    fn nothing_the_agent_reads_carries_an_items_content() {
        let (_root, shared) = home();
        let wb = shared.lock_unpoisoned();
        let context = opened(&wb, PLACEMENT);
        for page in &context.pages {
            assert!(
                !page.model.to_string().contains(ANSWER),
                "page {} carries quarantined content",
                page.id
            );
        }
        let inbox = context
            .pages
            .iter()
            .find(|page| page.id == "inbox")
            .unwrap();
        let kinds = inbox
            .actions
            .iter()
            .map(|action| (action.id.as_str(), action.kind))
            .collect::<Vec<_>>();
        assert!(kinds.contains(&(SCREEN, GaugeAppAgentActionKind::Direct)));
        assert!(kinds.contains(&(REVIEW, GaugeAppAgentActionKind::HumanCeremony)));
        assert_eq!(
            inbox.commands,
            [SCREEN],
            "the agent may screen but never keep or flag"
        );
    }

    #[test]
    fn a_person_keeps_an_item_and_the_gate_writes_it_where_work_chats_read() {
        let (_root, shared) = home();
        let mut wb = shared.lock_unpoisoned();
        let session = opened(&wb, PLACEMENT).session;
        let keep = envelope(
            &session,
            REVIEW,
            "keep-1",
            json!({ "item_id": "survey-1", "verdict": "keep" }),
        );
        let receipt = apply_command::<PanelSettings>(&mut wb, &HeaderMap::new(), PLACEMENT, &keep)
            .unwrap_or_else(|refusal| panic!("keep refused: {}", refusal.status()));
        assert_eq!(receipt["receipt"]["status"], "applied");
        let items = inbox(&wb, PLACEMENT)["items"].clone();
        assert_eq!(items[0]["status"], "approved", "{items}");
        let landed = items[0]["workspace_path"].as_str().unwrap();
        assert!(landed.starts_with("inbound/"), "{landed}");
        let repo = wb
            .targets_dir()
            .join(crate::library_state::managed_project_target_id(
                crate::DEFAULT_PROJECT,
            ))
            .join("repo");
        assert!(repo.join(landed).is_file(), "kept item at {landed}");
        // Ruled once; a second ruling is refused rather than repeated.
        let again = envelope(
            &opened(&wb, PLACEMENT).session,
            REVIEW,
            "keep-2",
            json!({ "item_id": "survey-1", "verdict": "flag" }),
        );
        assert!(
            apply_command::<PanelSettings>(&mut wb, &HeaderMap::new(), PLACEMENT, &again).is_err()
        );
    }

    /// The point of keeping an item: a work chat started afterwards reads it.
    /// An earlier chat already copied the project's folder onto the shared
    /// main line, which is the ordinary case and the one a write to disk alone
    /// never reached.
    #[test]
    fn a_work_chat_started_after_a_keep_reads_the_kept_item() {
        let (_root, shared) = home();
        let mut wb = shared.lock_unpoisoned();
        wb.create_chat_in_instance(crate::DEFAULT_PLACEMENT, "before the keep")
            .unwrap();
        let keep = envelope(
            &opened(&wb, PLACEMENT).session,
            REVIEW,
            "keep-1",
            json!({ "item_id": "survey-1", "verdict": "keep" }),
        );
        apply_command::<PanelSettings>(&mut wb, &HeaderMap::new(), PLACEMENT, &keep)
            .unwrap_or_else(|refusal| panic!("keep refused: {}", refusal.status()));
        let landed = inbox(&wb, PLACEMENT)["items"][0]["workspace_path"]
            .as_str()
            .unwrap()
            .to_owned();
        let chat = wb
            .create_chat_in_instance(crate::DEFAULT_PLACEMENT, "after the keep")
            .unwrap();
        let chat = chat["id"].as_str().unwrap();
        let files = wb.engagement_tree(chat).unwrap().unwrap();
        let path = files
            .iter()
            .map(|entry| entry.path.clone())
            .find(|path| path.ends_with(&landed))
            .unwrap_or_else(|| panic!("{landed} is not in the new chat: {files:?}"));
        let body = wb.engagements[chat].read_file(&path).unwrap();
        assert!(body.contains(ANSWER), "{body}");
    }

    #[test]
    fn another_placements_item_and_a_bad_verdict_are_refused() {
        let (_root, shared) = home();
        let mut wb = shared.lock_unpoisoned();
        let session = opened(&wb, PLACEMENT).session;
        for (key, payload) in [
            ("cross", json!({ "item_id": "other-1", "verdict": "keep" })),
            (
                "verdict",
                json!({ "item_id": "survey-1", "verdict": "maybe" }),
            ),
            (
                "extra",
                json!({ "item_id": "survey-1", "verdict": "keep", "x": 1 }),
            ),
        ] {
            let refused = envelope(&session, REVIEW, key, payload);
            assert!(
                apply_command::<PanelSettings>(&mut wb, &HeaderMap::new(), PLACEMENT, &refused)
                    .is_err(),
                "{key} is refused"
            );
        }
        let other = inbox(&wb, OTHER);
        assert_eq!(other["items"][0]["status"], "pending");
    }

    #[test]
    fn only_a_panel_placement_opens_panel_settings() {
        let (_root, shared) = home();
        let wb = shared.lock_unpoisoned();
        for id in [crate::DEFAULT_PLACEMENT, "inst-missing"] {
            let refused = context::<PanelSettings>(&wb, &HeaderMap::new(), id)
                .err()
                .unwrap();
            assert_eq!(refused.status(), StatusCode::NOT_FOUND, "{id}");
        }
    }

    #[test]
    fn removing_the_placement_ends_its_settings_conversations() {
        let (_root, shared) = home();
        let session = {
            let wb = shared.lock_unpoisoned();
            opened(&wb, PLACEMENT).session
        };
        crate::gaugeapp_agent::append_gaugeapp_agent_exchange(
            &shared,
            &session,
            "turn-1",
            "What came in?",
            &crate::gaugeapp_agent::GaugeAppAgentTurn {
                message: "One survey.".into(),
                proposals: vec![],
            },
        )
        .unwrap();
        let mut wb = shared.lock_unpoisoned();
        assert_eq!(
            gaugeapp_agent_transcript(wb.store_ref(), &session)
                .unwrap()
                .len(),
            2
        );
        wb.destroy_instance(PLACEMENT);
        assert!(context::<PanelSettings>(&wb, &HeaderMap::new(), PLACEMENT).is_err());
        assert!(gaugeapp_agent_transcript(wb.store_ref(), &session)
            .map(|messages| messages.is_empty())
            .unwrap_or(true));
    }
}
