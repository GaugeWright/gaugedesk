//! Store-side evidence for the hosted GaugeVault member-standing fence
//! (DR-0460). No remote authority is called while a Workbench is locked.

use std::collections::{BTreeMap, BTreeSet};

use gaugedesk_core::{ids::ScopeId, Rejection};
use gaugedesk_store::{AdmitError, CommandRecordFact, Store};

use crate::org::{
    tenant_scope, MembershipRecord, MembershipStatus, OrgRecord, RecordOp, ORG_SCOPE,
};

fn invalid_owner() -> AdmitError {
    AdmitError::Rejected(Rejection {
        reason: "member-standing fence requires an exact named tenant scope",
    })
}

fn validate_named_owner(owner_scope: &ScopeId) -> Result<(), AdmitError> {
    let scope = owner_scope.as_str();
    let tenant = scope
        .strip_prefix(&format!("{ORG_SCOPE}::"))
        .filter(|tenant| !tenant.is_empty() && tenant.trim() == *tenant)
        .ok_or_else(invalid_owner)?;
    if tenant_scope(tenant) != scope {
        return Err(invalid_owner());
    }
    Ok(())
}

/// Every person ever named by the exact hosted tenant's membership history.
/// Tombstones and deprovisioned records remain binding for deletion and
/// erasure preparation, even when the current projection no longer lists the
/// member. The local singleton directory has no hosted Cosmos partition.
/// An unavailable or malformed member record refuses the entire read.
pub fn historical_named_members(
    store: &Store,
    owner_scope: &ScopeId,
) -> Result<BTreeSet<String>, AdmitError> {
    validate_named_owner(owner_scope)?;
    let scope = owner_scope.as_str();
    let mut members = BTreeSet::new();
    for payload in store.retained_records(scope, "membership")? {
        let record: MembershipRecord = serde_json::from_str(&payload)?;
        let member = record.authority.trim();
        if member.is_empty() {
            if record.op == RecordOp::Upsert && record.status == MembershipStatus::Invited {
                continue;
            }
            return Err(AdmitError::Rejected(Rejection {
                reason: "member-standing history has a record without an authority",
            }));
        }
        if member != record.authority {
            return Err(AdmitError::Rejected(Rejection {
                reason: "member-standing history has an uncanonical authority",
            }));
        }
        members.insert(member.to_owned());
    }
    Ok(members)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MembershipTransition {
    Deny {
        owner_scope: ScopeId,
        member: String,
    },
    Activate {
        owner_scope: ScopeId,
        member: String,
    },
}

/// Classify an authorized product command's facts for one authenticated owner
/// before any remote call. A command cannot span two Cosmos account partitions.
/// An organization tombstone closes every person ever named in its retained
/// membership history, not merely those in the current Org projection. The
/// caller must first authenticate and authorize the command, then replan it
/// after unlocked Cosmos I/O before Store admission.
pub fn membership_transitions(
    store: &Store,
    owner_scope: &ScopeId,
    facts: &[CommandRecordFact],
) -> Result<Vec<MembershipTransition>, AdmitError> {
    validate_named_owner(owner_scope)?;
    let mut by_member = BTreeMap::<String, bool>::new();
    let mut closing = false;
    for fact in facts {
        if !matches!(fact.kind.as_str(), "membership" | "org") {
            continue;
        }
        if fact.scope_id != owner_scope.as_str() {
            return Err(invalid_owner());
        }
        let insert = |by_member: &mut BTreeMap<String, bool>, member: String, active| {
            if by_member
                .insert(member, active)
                .is_some_and(|prior| prior != active)
            {
                return Err(AdmitError::Rejected(Rejection {
                    reason: "membership command gives one person conflicting standing",
                }));
            }
            Ok(())
        };
        if fact.kind == "membership" {
            let record: MembershipRecord = serde_json::from_str(&fact.payload)?;
            let member = record.authority.trim();
            if member.is_empty() {
                if record.op == RecordOp::Upsert && record.status == MembershipStatus::Invited {
                    continue;
                }
                return Err(AdmitError::Rejected(Rejection {
                    reason: "membership fact has no person authority",
                }));
            }
            if member != record.authority {
                return Err(AdmitError::Rejected(Rejection {
                    reason: "membership fact has an uncanonical person authority",
                }));
            }
            insert(
                &mut by_member,
                member.to_owned(),
                record.op == RecordOp::Upsert && record.status == MembershipStatus::Active,
            )?;
        } else {
            let record: OrgRecord = serde_json::from_str(&fact.payload)?;
            if record.op == RecordOp::Tombstone {
                closing = true;
                for member in historical_named_members(store, owner_scope)? {
                    insert(&mut by_member, member, false)?;
                }
            }
        }
    }
    if closing && by_member.values().any(|active| *active) {
        return Err(AdmitError::Rejected(Rejection {
            reason: "organization closure cannot activate a member",
        }));
    }
    Ok(by_member
        .into_iter()
        .map(|(member, active)| {
            let owner_scope = owner_scope.clone();
            if active {
                MembershipTransition::Activate {
                    owner_scope,
                    member,
                }
            } else {
                MembershipTransition::Deny {
                    owner_scope,
                    member,
                }
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use gaugedesk_store::ContentCodec;

    use super::*;

    fn record(authority: &str, status: MembershipStatus, op: RecordOp) -> String {
        serde_json::to_string(&MembershipRecord {
            id: authority.into(),
            op,
            org_id: "tenant".into(),
            authority: authority.into(),
            email: String::new(),
            role: "member".into(),
            status,
            managed_by_scim: false,
            team: None,
        })
        .unwrap()
    }

    struct ErasedMember;

    struct ErasedUnrelated;

    impl ContentCodec for ErasedMember {
        fn encode(&self, _: &str, _: &str, payload: &str) -> Result<String, String> {
            Ok(payload.to_owned())
        }

        fn decode(&self, _: &str, kind: &str, payload: &str) -> Option<String> {
            (kind != "membership").then(|| payload.to_owned())
        }
    }

    impl ContentCodec for ErasedUnrelated {
        fn encode(&self, _: &str, _: &str, payload: &str) -> Result<String, String> {
            Ok(payload.to_owned())
        }

        fn decode(&self, _: &str, kind: &str, payload: &str) -> Option<String> {
            (kind != "unrelated").then(|| payload.to_owned())
        }
    }

    #[test]
    fn deletion_reads_every_named_historical_member_and_refuses_lost_history() {
        let owner = ScopeId::from("org::organization:tenant");
        let mut store = Store::open_in_memory().unwrap();
        for (member, status, op) in [
            (
                "retired",
                MembershipStatus::Deprovisioned,
                RecordOp::Tombstone,
            ),
            ("active", MembershipStatus::Active, RecordOp::Upsert),
            ("", MembershipStatus::Invited, RecordOp::Upsert),
        ] {
            store
                .append_record(owner.as_str(), "membership", &record(member, status, op))
                .unwrap();
        }
        store
            .append_record(owner.as_str(), "unrelated", "unavailable content")
            .unwrap();
        assert_eq!(
            historical_named_members(&store, &owner).unwrap(),
            BTreeSet::from(["active".to_owned(), "retired".to_owned()])
        );
        assert!(historical_named_members(&store, &ScopeId::from(ORG_SCOPE)).is_err());
        assert!(historical_named_members(&store, &ScopeId::from("org:: ")).is_err());
        let store = store.with_codec(Arc::new(ErasedUnrelated));
        assert_eq!(historical_named_members(&store, &owner).unwrap().len(), 2);
        let store = store.with_codec(Arc::new(ErasedMember));
        assert!(matches!(
            historical_named_members(&store, &owner),
            Err(AdmitError::Codec(_))
        ));
    }

    #[test]
    fn transitions_classify_active_removed_and_tenant_tombstone_facts() {
        let mut store = Store::open_in_memory().unwrap();
        let closing = ScopeId::from("org::organization:closing");
        store
            .append_record(
                closing.as_str(),
                "membership",
                &record(
                    "retired",
                    MembershipStatus::Deprovisioned,
                    RecordOp::Tombstone,
                ),
            )
            .unwrap();
        let tombstone = OrgRecord {
            id: "org".into(),
            op: RecordOp::Tombstone,
            ..Default::default()
        };
        let live = ScopeId::from("org::organization:live");
        let live_facts = [
            CommandRecordFact {
                scope_id: live.as_str().into(),
                kind: "membership".into(),
                payload: record("alice", MembershipStatus::Active, RecordOp::Upsert),
            },
            CommandRecordFact {
                scope_id: live.as_str().into(),
                kind: "membership".into(),
                payload: record("bob", MembershipStatus::Deprovisioned, RecordOp::Upsert),
            },
        ];
        assert_eq!(
            membership_transitions(&store, &live, &live_facts).unwrap(),
            vec![
                MembershipTransition::Activate {
                    owner_scope: live.clone(),
                    member: "alice".into(),
                },
                MembershipTransition::Deny {
                    owner_scope: live.clone(),
                    member: "bob".into(),
                },
            ]
        );
        let closure = CommandRecordFact {
            scope_id: closing.as_str().into(),
            kind: "org".into(),
            payload: serde_json::to_string(&tombstone).unwrap(),
        };
        assert_eq!(
            membership_transitions(&store, &closing, std::slice::from_ref(&closure)).unwrap(),
            vec![MembershipTransition::Deny {
                owner_scope: closing.clone(),
                member: "retired".into(),
            }]
        );
        let conflict = [
            live_facts[0].clone(),
            CommandRecordFact {
                scope_id: live_facts[0].scope_id.clone(),
                kind: "membership".into(),
                payload: record("alice", MembershipStatus::Deprovisioned, RecordOp::Upsert),
            },
        ];
        assert!(membership_transitions(&store, &live, &conflict).is_err());
        assert!(
            membership_transitions(&store, &live, &[live_facts[0].clone(), closure.clone()])
                .is_err()
        );
        let new_active_during_closure = CommandRecordFact {
            scope_id: closing.as_str().into(),
            ..live_facts[0].clone()
        };
        assert!(
            membership_transitions(&store, &closing, &[new_active_during_closure, closure])
                .is_err()
        );
        let malformed_scope = [CommandRecordFact {
            scope_id: "org:: ".into(),
            kind: "membership".into(),
            payload: live_facts[0].payload.clone(),
        }];
        assert!(membership_transitions(&store, &live, &malformed_scope).is_err());
    }
}
