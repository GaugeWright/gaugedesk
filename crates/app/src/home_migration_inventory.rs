//! Historical project ownership for the mixed legacy `library` scope.
//!
//! This is migration discovery, not a copy or Home activation. Each answer is
//! tied to the original library event position. A current Library projection
//! cannot assign an old chat or target row: its instance may have moved or
//! disappeared since that row was admitted. Unknown kinds and unresolved
//! ancestry remain gaps rather than acquiring today's project by inference.

use std::collections::{BTreeMap, BTreeSet};

use gaugedesk_store::{
    migration_inventory::{MigrationEventScopePopulation, MigrationSourceInventory},
    AdmitError, Store,
};
use serde_json::Value;

use crate::library::{LIBRARY_RECORD_SCHEMA, LIBRARY_SCOPE};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LegacyLibraryOwner {
    Project(String),
    /// A library definition or authoring resource retains its old authority.
    Shared,
    Gap(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyLibraryEntry {
    pub position: i64,
    pub kind: String,
    pub owner: LegacyLibraryOwner,
}

/// The classified library history and the complete product SQLite inventory
/// observed in the same read transaction. This remains only a product-store
/// snapshot; other runtime stores and Home journal state are outside it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyLibrarySnapshot {
    pub source: MigrationSourceInventory,
    pub event_scopes: Vec<MigrationEventScopePopulation>,
    pub entries: Vec<LegacyLibraryEntry>,
}

impl LegacyLibrarySnapshot {
    /// Scope discovery is not owner discovery. A migration planner must still
    /// classify every event inside each named scope and each non-event table.
    pub fn unclassified_event_scopes(&self, classified: &[&str]) -> Vec<String> {
        let classified: BTreeSet<&str> = classified.iter().copied().collect();
        self.event_scopes
            .iter()
            .filter(|scope| !classified.contains(scope.scope_id.as_str()))
            .map(|scope| scope.scope_id.clone())
            .collect()
    }
}

#[derive(Default)]
struct HistoricalLinks {
    agents: BTreeSet<String>,
    retired_agents: BTreeSet<String>,
    agent_instances: BTreeMap<String, String>,
    matched_authoring: BTreeSet<(String, String)>,
    projects: BTreeSet<String>,
    retired_projects: BTreeSet<String>,
    instances: BTreeMap<String, LegacyLibraryOwner>,
    authoring_instances: BTreeMap<String, String>,
    chats: BTreeMap<String, LegacyLibraryOwner>,
    chat_instances: BTreeMap<String, String>,
    workstreams: BTreeMap<String, LegacyLibraryOwner>,
    workstream_instances: BTreeMap<String, String>,
    targets: BTreeMap<String, LegacyLibraryOwner>,
}

fn field<'a>(record: &'a Value, name: &str) -> Option<&'a str> {
    record.get(name)?.as_str().filter(|value| !value.is_empty())
}

fn owner_of(
    links: &BTreeMap<String, LegacyLibraryOwner>,
    id: Option<&str>,
    gap: &'static str,
) -> LegacyLibraryOwner {
    id.and_then(|id| links.get(id))
        .cloned()
        .unwrap_or(LegacyLibraryOwner::Gap(gap))
}

fn project(links: &HistoricalLinks, id: Option<&str>) -> LegacyLibraryOwner {
    match id {
        Some(id) if links.projects.contains(id) => LegacyLibraryOwner::Project(id.to_owned()),
        _ => LegacyLibraryOwner::Gap("project was not declared at this position"),
    }
}

fn linked_owner(
    owners: &BTreeMap<String, LegacyLibraryOwner>,
    predecessors: &BTreeMap<String, String>,
    instances: &BTreeMap<String, LegacyLibraryOwner>,
    id: Option<&str>,
    gap: &'static str,
) -> LegacyLibraryOwner {
    let owner = owner_of(owners, id, gap);
    let predecessor = id.and_then(|id| predecessors.get(id));
    let current = predecessor.and_then(|instance| instances.get(instance));
    if current == Some(&owner) {
        owner
    } else {
        LegacyLibraryOwner::Gap("record and current placement disagree")
    }
}

fn referenced_targets(
    owner: LegacyLibraryOwner,
    targets: &BTreeMap<String, LegacyLibraryOwner>,
    ids: impl IntoIterator<Item = String>,
) -> LegacyLibraryOwner {
    for id in ids {
        let Some(target) = targets.get(&id) else {
            return LegacyLibraryOwner::Gap("selected target history is missing");
        };
        if target != &owner && target != &LegacyLibraryOwner::Shared {
            return LegacyLibraryOwner::Gap("selected target belongs to another project");
        }
    }
    owner
}

fn target_ids(record: &Value) -> Option<Vec<String>> {
    record
        .get("target_ids")?
        .as_array()?
        .iter()
        .map(|id| id.as_str().filter(|id| !id.is_empty()).map(str::to_owned))
        .collect()
}

fn retain_identity(
    links: &mut BTreeMap<String, LegacyLibraryOwner>,
    id: Option<&str>,
    owner: LegacyLibraryOwner,
    tombstone: bool,
) -> LegacyLibraryOwner {
    let Some(id) = id else {
        return LegacyLibraryOwner::Gap("record identity is missing");
    };
    if tombstone {
        links.insert(
            id.to_owned(),
            LegacyLibraryOwner::Gap("record identity was tombstoned"),
        );
        return owner;
    }
    // A changed owner or reused tombstoned identity needs an explicit
    // cross-Home migration. Later records cannot inherit the new project by
    // merely reading the latest projection.
    let owner = match links.get(id) {
        Some(before) if before != &owner => {
            LegacyLibraryOwner::Gap("record changed project ownership")
        }
        _ => owner,
    };
    links.insert(id.to_owned(), owner.clone());
    owner
}

fn classify(
    kind: &str,
    record: &Value,
    links: &mut HistoricalLinks,
    tombstone: bool,
) -> LegacyLibraryOwner {
    match kind {
        "project" => {
            let Some(id) = field(record, "id") else {
                return LegacyLibraryOwner::Gap("project identity is missing");
            };
            if tombstone {
                if !links.projects.remove(id) {
                    return LegacyLibraryOwner::Gap("project tombstone has no declared history");
                }
                links.retired_projects.insert(id.to_owned());
            } else if links.retired_projects.contains(id) {
                return LegacyLibraryOwner::Gap("project identity was reused after tombstone");
            } else {
                links.projects.insert(id.to_owned());
            }
            LegacyLibraryOwner::Project(id.to_owned())
        }
        "agent" => {
            let Some(id) = field(record, "id") else {
                return LegacyLibraryOwner::Gap("Agent identity is missing");
            };
            if tombstone {
                if !links.agents.remove(id) {
                    return LegacyLibraryOwner::Gap("Agent tombstone has no declared history");
                }
                links.retired_agents.insert(id.to_owned());
            } else {
                let Some(instance_id) = field(record, "instance_id") else {
                    links.agents.remove(id);
                    return LegacyLibraryOwner::Gap("Agent authoring instance is missing");
                };
                if links.retired_agents.contains(id) {
                    return LegacyLibraryOwner::Gap("Agent identity was reused after tombstone");
                }
                if links
                    .authoring_instances
                    .get(instance_id)
                    .map(String::as_str)
                    != Some(id)
                    || links.instances.get(instance_id) != Some(&LegacyLibraryOwner::Shared)
                {
                    links.agents.remove(id);
                    return LegacyLibraryOwner::Gap("Agent and authoring instance disagree");
                }
                if links
                    .agent_instances
                    .get(id)
                    .is_some_and(|previous| previous != instance_id)
                {
                    links.agents.remove(id);
                    return LegacyLibraryOwner::Gap("Agent changed authoring instance");
                }
                links.agents.insert(id.to_owned());
                links
                    .agent_instances
                    .insert(id.to_owned(), instance_id.to_owned());
                links
                    .matched_authoring
                    .insert((id.to_owned(), instance_id.to_owned()));
            }
            LegacyLibraryOwner::Shared
        }
        "instance" => {
            let id = field(record, "id");
            let owner = if tombstone {
                owner_of(&links.instances, id, "instance history is missing")
            } else {
                match field(record, "kind") {
                    Some("authoring") if record.get("project_id").is_none_or(Value::is_null) => {
                        match (id, field(record, "agent_id")) {
                            (Some(instance), Some(agent))
                                if links
                                    .authoring_instances
                                    .get(instance)
                                    .is_none_or(|previous| previous == agent) =>
                            {
                                links
                                    .authoring_instances
                                    .insert(instance.to_owned(), agent.to_owned());
                                LegacyLibraryOwner::Shared
                            }
                            _ => LegacyLibraryOwner::Gap(
                                "authoring instance Agent link is missing or changed",
                            ),
                        }
                    }
                    Some("using") => project(links, field(record, "project_id")),
                    _ => LegacyLibraryOwner::Gap("instance kind is unknown"),
                }
            };
            retain_identity(&mut links.instances, id, owner, tombstone)
        }
        "chat" => {
            let id = field(record, "id");
            let instance = field(record, "instance_id");
            let owner = if tombstone {
                owner_of(&links.chats, id, "chat history is missing")
            } else {
                match owner_of(&links.instances, instance, "chat placement is missing") {
                    LegacyLibraryOwner::Shared => {
                        LegacyLibraryOwner::Gap("chat refers to an authoring instance")
                    }
                    other => other,
                }
            };
            let owner = if !tombstone {
                match field(record, "forked_from") {
                    Some(parent) if links.chats.get(parent) != Some(&owner) => {
                        LegacyLibraryOwner::Gap("chat fork parent belongs to another project")
                    }
                    _ => owner,
                }
            } else {
                owner
            };
            if let (Some(id), Some(instance)) = (id, instance) {
                links
                    .chat_instances
                    .insert(id.to_owned(), instance.to_owned());
            }
            retain_identity(&mut links.chats, id, owner, tombstone)
        }
        "workstream" => {
            let id = field(record, "id");
            let instance = field(record, "instance_id");
            let owner = if tombstone {
                owner_of(&links.workstreams, id, "workstream history is missing")
            } else {
                owner_of(
                    &links.instances,
                    instance,
                    "workstream placement is missing",
                )
            };
            if let (Some(id), Some(instance)) = (id, instance) {
                links
                    .workstream_instances
                    .insert(id.to_owned(), instance.to_owned());
            }
            retain_identity(&mut links.workstreams, id, owner, tombstone)
        }
        "work_target" => {
            let id = field(record, "id");
            let owner = if tombstone {
                owner_of(&links.targets, id, "work target history is missing")
            } else {
                match field(&record["owner"], "kind") {
                    Some("project") => project(links, field(&record["owner"], "project_id")),
                    Some("archetype")
                        if field(&record["owner"], "archetype_id")
                            .is_some_and(|id| links.agents.contains(id)) =>
                    {
                        LegacyLibraryOwner::Shared
                    }
                    Some("archetype") => {
                        LegacyLibraryOwner::Gap("work target Agent history is missing")
                    }
                    _ => LegacyLibraryOwner::Gap("work target owner is unknown"),
                }
            };
            retain_identity(&mut links.targets, id, owner, tombstone)
        }
        "placement_targets" => {
            let owner = owner_of(
                &links.instances,
                field(record, "placement_id"),
                "placement target owner is missing",
            );
            match target_ids(record) {
                Some(ids) => referenced_targets(owner, &links.targets, ids),
                None => LegacyLibraryOwner::Gap("placement target selection is malformed"),
            }
        }
        "chat_target" | "chat_target_basis" => {
            let owner = linked_owner(
                &links.chats,
                &links.chat_instances,
                &links.instances,
                field(record, "chat_id"),
                "chat target owner is missing",
            );
            match field(record, "target_id") {
                Some(id) => referenced_targets(owner, &links.targets, [id.to_owned()]),
                None => LegacyLibraryOwner::Gap("chat target identity is missing"),
            }
        }
        "chat_target_set" => {
            let owner = linked_owner(
                &links.chats,
                &links.chat_instances,
                &links.instances,
                field(record, "chat_id"),
                "chat target owner is missing",
            );
            let Some(members) = record.get("members").and_then(Value::as_array) else {
                return LegacyLibraryOwner::Gap("chat target set is malformed");
            };
            let ids: Option<Vec<_>> = members
                .iter()
                .map(|member| field(member, "target_id").map(str::to_owned))
                .collect();
            match ids {
                Some(ids) if !ids.is_empty() => referenced_targets(owner, &links.targets, ids),
                _ => LegacyLibraryOwner::Gap("chat target set has no complete members"),
            }
        }
        "public_deployment_binding" => {
            let owner = project(links, field(record, "project_id"));
            let placement = owner_of(
                &links.instances,
                field(record, "placement_id"),
                "public deployment placement is missing",
            );
            if owner == placement {
                owner
            } else {
                LegacyLibraryOwner::Gap("public deployment project and placement disagree")
            }
        }
        "project_collaboration_workspace" => project(links, field(record, "project_id")),
        "workstream_root" => {
            let workstream = linked_owner(
                &links.workstreams,
                &links.workstream_instances,
                &links.instances,
                field(record, "workstream_id"),
                "workstream root owner is missing",
            );
            let workstream = match field(record, "project_id") {
                Some(id) if project(links, Some(id)) != workstream => {
                    LegacyLibraryOwner::Gap("workstream root project and line disagree")
                }
                _ => workstream,
            };
            if let Some(placement) = field(record, "placement_id") {
                if links.instances.get(placement) != Some(&workstream) {
                    return LegacyLibraryOwner::Gap("workstream root and placement disagree");
                }
            }
            match field(record, "target_id") {
                Some(id) => referenced_targets(workstream, &links.targets, [id.to_owned()]),
                None => workstream,
            }
        }
        _ => LegacyLibraryOwner::Gap("library record kind is unclassified"),
    }
}

/// Classify every *historical* library event in original position order. The
/// caller supplies the retained event history, including tombstones. A gap
/// never becomes a Home member or a migration mapping by default.
pub fn classify_legacy_library_events(
    events: &[(i64, String, String)],
) -> Result<Vec<LegacyLibraryEntry>, &'static str> {
    let mut links = HistoricalLinks::default();
    let mut entries = Vec::with_capacity(events.len());
    let mut authoring_entries = Vec::new();
    let mut previous = None;
    for (position, kind, payload) in events {
        if match previous {
            Some(last) => *position != last + 1,
            None => *position != 0,
        } {
            return Err("library event positions are not contiguous");
        }
        previous = Some(*position);
        let owner = match serde_json::from_str::<Value>(payload) {
            Ok(record) if record.is_object() => {
                let schema = record.get("schema").map(Value::as_u64).unwrap_or(Some(1));
                let op = record
                    .get("op")
                    .map(Value::as_str)
                    .unwrap_or(Some("upsert"));
                if !schema
                    .is_some_and(|schema| (1..=u64::from(LIBRARY_RECORD_SCHEMA)).contains(&schema))
                {
                    LegacyLibraryOwner::Gap("library schema or operation is unsupported")
                } else {
                    match op {
                        Some("upsert") => {
                            let owner = classify(kind, &record, &mut links, false);
                            if kind == "instance"
                                && field(&record, "kind") == Some("authoring")
                                && owner == LegacyLibraryOwner::Shared
                            {
                                if let (Some(agent), Some(instance)) =
                                    (field(&record, "agent_id"), field(&record, "id"))
                                {
                                    authoring_entries.push((
                                        entries.len(),
                                        agent.to_owned(),
                                        instance.to_owned(),
                                    ));
                                }
                            }
                            owner
                        }
                        Some("tombstone") => classify(kind, &record, &mut links, true),
                        _ => LegacyLibraryOwner::Gap("library schema or operation is unsupported"),
                    }
                }
            }
            _ => LegacyLibraryOwner::Gap("library payload is malformed"),
        };
        entries.push(LegacyLibraryEntry {
            position: *position,
            kind: kind.clone(),
            owner,
        });
    }
    for (index, agent, instance) in authoring_entries {
        if !links.matched_authoring.contains(&(agent, instance)) {
            entries[index].owner =
                LegacyLibraryOwner::Gap("authoring instance has no matching Agent history");
        }
    }
    Ok(entries)
}

/// Read the retained legacy library history through its codec and classify
/// each original position. A missing protected row refuses in the store; a
/// structurally present but unclassifiable row remains a visible gap. This
/// read is discovery, not a complete product or Home migration snapshot.
pub fn inspect_legacy_library(store: &Store) -> Result<LegacyLibrarySnapshot, AdmitError> {
    let snapshot = store.migration_source_inventory_with_retained_events(LIBRARY_SCOPE)?;
    let entries = classify_legacy_library_events(&snapshot.retained_events)
        .map_err(|reason| AdmitError::Codec(reason.to_owned()))?;
    Ok(LegacyLibrarySnapshot {
        source: snapshot.inventory,
        event_scopes: snapshot.event_scopes,
        entries,
    })
}

#[cfg(test)]
mod tests {
    use gaugedesk_store::Store;
    use serde_json::json;

    use super::{classify_legacy_library_events, inspect_legacy_library, LegacyLibraryOwner};

    fn row(position: i64, kind: &str, payload: serde_json::Value) -> (i64, String, String) {
        (position, kind.to_owned(), payload.to_string())
    }

    #[test]
    fn historical_project_links_keep_each_original_library_coordinate() {
        let events = vec![
            row(0, "project", json!({"id":"project-a"})),
            row(
                1,
                "instance",
                json!({"id":"placement-a","kind":"using","project_id":"project-a"}),
            ),
            row(
                2,
                "work_target",
                json!({"id":"target-a","owner":{"kind":"project","project_id":"project-a"}}),
            ),
            row(
                3,
                "chat",
                json!({"id":"chat-a","instance_id":"placement-a"}),
            ),
            row(
                4,
                "chat_target",
                json!({"chat_id":"chat-a","target_id":"target-a"}),
            ),
            row(
                5,
                "workstream",
                json!({"id":"branch-a","instance_id":"placement-a"}),
            ),
            row(
                6,
                "workstream_root",
                json!({"workstream_id":"branch-a","project_id":"project-a"}),
            ),
            row(
                7,
                "placement_targets",
                json!({"placement_id":"placement-a","target_ids":["target-a"]}),
            ),
            row(
                8,
                "public_deployment_binding",
                json!({"id":"release-a","project_id":"project-a","placement_id":"placement-a"}),
            ),
            row(
                9,
                "project_collaboration_workspace",
                json!({"project_id":"project-a","workspace_id":"workspace-a"}),
            ),
        ];
        let owners = classify_legacy_library_events(&events).expect("ordered history");
        for (position, entry) in owners.iter().enumerate() {
            assert_eq!(entry.position, position as i64);
            assert_eq!(entry.owner, LegacyLibraryOwner::Project("project-a".into()));
        }
    }

    #[test]
    fn shared_definitions_and_unresolved_or_moved_project_links_remain_gaps() {
        let events = vec![
            row(
                0,
                "instance",
                json!({"id":"authoring-a","kind":"authoring","agent_id":"agent-a"}),
            ),
            row(
                1,
                "agent",
                json!({"id":"agent-a","instance_id":"authoring-a"}),
            ),
            row(
                2,
                "work_target",
                json!({"id":"archetype-target","owner":{"kind":"archetype","archetype_id":"agent-a"}}),
            ),
            row(
                3,
                "chat_target",
                json!({"chat_id":"missing-chat","target_id":"archetype-target"}),
            ),
            row(4, "project", json!({"id":"project-a"})),
            row(5, "project", json!({"id":"project-b"})),
            row(
                6,
                "instance",
                json!({"id":"placement-a","kind":"using","project_id":"project-a"}),
            ),
            row(
                7,
                "chat",
                json!({"id":"chat-a","instance_id":"placement-a"}),
            ),
            row(
                8,
                "instance",
                json!({"id":"placement-a","kind":"using","project_id":"project-b"}),
            ),
            row(
                9,
                "chat_target",
                json!({"chat_id":"chat-a","target_id":"archetype-target"}),
            ),
            row(
                10,
                "workstream",
                json!({"id":"branch-a","instance_id":"placement-a"}),
            ),
            row(11, "unknown_future_kind", json!({"id":"new"})),
            row(12, "project", json!({"id":"future","schema":99})),
        ];
        let owners = classify_legacy_library_events(&events).expect("ordered history");
        assert_eq!(owners[0].owner, LegacyLibraryOwner::Shared);
        assert_eq!(owners[1].owner, LegacyLibraryOwner::Shared);
        assert_eq!(owners[2].owner, LegacyLibraryOwner::Shared);
        assert!(matches!(owners[3].owner, LegacyLibraryOwner::Gap(_)));
        assert_eq!(
            owners[7].owner,
            LegacyLibraryOwner::Project("project-a".into())
        );
        for entry in &owners[8..] {
            assert!(matches!(entry.owner, LegacyLibraryOwner::Gap(_)));
        }
    }

    #[test]
    fn cross_project_forks_and_target_selections_need_explicit_migration_evidence() {
        let events = vec![
            row(0, "project", json!({"id":"project-a"})),
            row(1, "project", json!({"id":"project-b"})),
            row(
                2,
                "instance",
                json!({"id":"placement-a","kind":"using","project_id":"project-a"}),
            ),
            row(
                3,
                "instance",
                json!({"id":"placement-b","kind":"using","project_id":"project-b"}),
            ),
            row(
                4,
                "work_target",
                json!({"id":"target-b","owner":{"kind":"project","project_id":"project-b"}}),
            ),
            row(
                5,
                "chat",
                json!({"id":"chat-b","instance_id":"placement-b"}),
            ),
            row(
                6,
                "chat",
                json!({"id":"chat-a","instance_id":"placement-a"}),
            ),
            row(
                7,
                "chat_target",
                json!({"chat_id":"chat-a","target_id":"target-b"}),
            ),
            row(
                8,
                "placement_targets",
                json!({"placement_id":"placement-a","target_ids":["target-b"]}),
            ),
            row(
                9,
                "chat",
                json!({"id":"fork-a","instance_id":"placement-a","forked_from":"chat-b"}),
            ),
            row(
                10,
                "chat_target_set",
                json!({"chat_id":"chat-a","members":[{"target_id":"target-b"}]}),
            ),
        ];
        let owners = classify_legacy_library_events(&events).expect("ordered history");
        for position in [7, 8, 9, 10] {
            assert!(matches!(owners[position].owner, LegacyLibraryOwner::Gap(_)));
        }
    }

    #[test]
    fn shared_archetype_target_requires_retained_agent_history() {
        let target =
            |id: &str| json!({"id":id,"owner":{"kind":"archetype","archetype_id":"agent-a"}});
        let events = vec![
            row(0, "work_target", target("before-agent")),
            row(
                1,
                "instance",
                json!({"id":"authoring-a","kind":"authoring","agent_id":"agent-a"}),
            ),
            row(
                2,
                "agent",
                json!({"id":"agent-a","instance_id":"authoring-a"}),
            ),
            row(3, "work_target", target("while-live")),
            row(4, "agent", json!({"id":"agent-a","op":"tombstone"})),
            row(5, "work_target", target("after-tombstone")),
            row(
                6,
                "agent",
                json!({"id":"agent-a","instance_id":"authoring-a"}),
            ),
            row(7, "work_target", target("after-reuse")),
        ];
        let owners = classify_legacy_library_events(&events).expect("ordered history");
        assert!(matches!(owners[0].owner, LegacyLibraryOwner::Gap(_)));
        assert_eq!(owners[1].owner, LegacyLibraryOwner::Shared);
        assert_eq!(owners[2].owner, LegacyLibraryOwner::Shared);
        assert_eq!(owners[3].owner, LegacyLibraryOwner::Shared);
        assert_eq!(owners[4].owner, LegacyLibraryOwner::Shared);
        for entry in &owners[5..] {
            assert!(matches!(entry.owner, LegacyLibraryOwner::Gap(_)));
        }
    }

    #[test]
    fn an_authoring_instance_needs_a_later_matching_agent_record() {
        let events = vec![
            row(
                0,
                "instance",
                json!({"id":"orphan","kind":"authoring","agent_id":"agent-orphan"}),
            ),
            row(
                1,
                "instance",
                json!({"id":"authoring-a","kind":"authoring","agent_id":"agent-a"}),
            ),
            row(
                2,
                "agent",
                json!({"id":"agent-a","instance_id":"wrong-instance"}),
            ),
            row(
                3,
                "agent",
                json!({"id":"agent-a","instance_id":"authoring-a"}),
            ),
        ];
        let owners = classify_legacy_library_events(&events).expect("ordered history");
        assert!(matches!(owners[0].owner, LegacyLibraryOwner::Gap(_)));
        assert_eq!(owners[1].owner, LegacyLibraryOwner::Shared);
        assert!(matches!(owners[2].owner, LegacyLibraryOwner::Gap(_)));
        assert_eq!(owners[3].owner, LegacyLibraryOwner::Shared);
    }

    #[test]
    fn tombstone_and_reuse_do_not_reassign_a_project_identity() {
        let events = vec![
            row(0, "project", json!({"id":"project-a"})),
            row(
                1,
                "instance",
                json!({"id":"placement-a","kind":"using","project_id":"project-a"}),
            ),
            row(2, "instance", json!({"id":"placement-a","op":"tombstone"})),
            row(
                3,
                "chat",
                json!({"id":"chat-a","instance_id":"placement-a"}),
            ),
            row(4, "project", json!({"id":"project-a","op":"tombstone"})),
            row(5, "project", json!({"id":"project-a"})),
            row(
                6,
                "instance",
                json!({"id":"placement-a","kind":"using","project_id":"project-a"}),
            ),
        ];
        let owners = classify_legacy_library_events(&events).expect("ordered history");
        assert_eq!(
            owners[2].owner,
            LegacyLibraryOwner::Project("project-a".into())
        );
        assert!(matches!(owners[3].owner, LegacyLibraryOwner::Gap(_)));
        assert!(matches!(owners[5].owner, LegacyLibraryOwner::Gap(_)));
        assert!(matches!(owners[6].owner, LegacyLibraryOwner::Gap(_)));
        assert!(classify_legacy_library_events(&events[1..]).is_err());
        let out_of_order = vec![events[0].clone(), events[2].clone()];
        assert!(classify_legacy_library_events(&out_of_order).is_err());
    }

    #[test]
    fn store_adapter_keeps_original_library_positions() {
        let mut store = Store::open_in_memory().expect("store");
        store
            .append_record("library", "project", &json!({"id":"p"}).to_string())
            .expect("project");
        store
            .append_record(
                "library",
                "instance",
                &json!({"id":"i","kind":"using","project_id":"p"}).to_string(),
            )
            .expect("instance");
        store
            .append_record("chat:one", "message", "other retained population")
            .expect("other scope");
        let snapshot = inspect_legacy_library(&store).expect("inspection");
        assert_eq!(snapshot.entries.len(), 2);
        assert_eq!(snapshot.entries[0].position, 0);
        assert_eq!(snapshot.entries[1].position, 1);
        assert_eq!(
            snapshot.entries[1].owner,
            LegacyLibraryOwner::Project("p".into())
        );
        assert_eq!(
            snapshot
                .source
                .tables
                .iter()
                .find(|table| table.table == "events")
                .expect("events population")
                .rows,
            3
        );
        assert_eq!(snapshot.event_scopes.len(), 2);
        assert_eq!(snapshot.event_scopes[0].scope_id, "chat:one");
        assert_eq!(snapshot.event_scopes[1].scope_id, "library");
        assert_eq!(snapshot.event_scopes[1].rows, 2);
        assert_eq!(
            snapshot.unclassified_event_scopes(&["library"]),
            vec!["chat:one"]
        );
    }
}
