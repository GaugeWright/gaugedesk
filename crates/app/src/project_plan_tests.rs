//! WS-13: a plan's standing admitted end to end in one Home — propose, claim,
//! work under the claim, attest, settle — with a second claim refused.
use super::*;
use crate::app_support::{LockUnpoisoned, DEFAULT_PROJECT};
use crate::at_rest::LoopbackKeyWrap;
use crate::library::LIBRARY_SCOPE;
use crate::org::{MembershipRecord, MembershipStatus, RecordOp, ORG_ID, ORG_SCOPE};
use gaugedesk_core::plan::{PlanPhase, Readiness};
use std::collections::BTreeSet;

fn member(wb: &mut Workbench, actor: &str, role: &str) {
    let record = MembershipRecord {
        id: actor.into(),
        op: RecordOp::Upsert,
        org_id: ORG_ID.into(),
        authority: actor.into(),
        email: String::new(),
        role: role.into(),
        status: MembershipStatus::Active,
        managed_by_scim: false,
        team: None,
    };
    wb.store_mut()
        .append_record(
            ORG_SCOPE,
            "membership",
            &serde_json::to_string(&record).unwrap(),
        )
        .unwrap();
}

fn project_grant(wb: &mut Workbench, actor: &str, op: RecordOp) {
    let grant = crate::org::MemberGrantRecord {
        id: crate::org::MemberGrantRecord::make_id(actor, DEFAULT_PROJECT),
        authority: actor.into(),
        project_id: DEFAULT_PROJECT.into(),
        op,
    };
    wb.store_mut()
        .append_record(
            ORG_SCOPE,
            "member_grant",
            &serde_json::to_string(&grant).unwrap(),
        )
        .unwrap();
}

fn person(wb: &mut Workbench, actor: &str, role: &str) -> AuthenticatedActionContext {
    member(wb, actor, role);
    project_grant(wb, actor, RecordOp::Upsert);
    let token = wb.mint_account_session(actor, "passkey", 3600).unwrap();
    wb.authenticate_action_context(&token).unwrap()
}

fn open(root: &std::path::Path) -> crate::SharedWorkbench {
    let shared = crate::workbench_state::open_lean_workbench_with_content_keywrap(root, |_| {
        Ok(Box::new(LoopbackKeyWrap::new([41; 32])))
    })
    .unwrap();
    // The project's key is held while someone works in it, as a route's
    // session holds it; a plan is sealed under that key.
    shared
        .lock_unpoisoned()
        .hold_session_for_tests(DEFAULT_PROJECT);
    shared
}

fn decide(request_id: &str, decision: PlanDecision) -> DecideProjectPlan {
    DecideProjectPlan {
        project: DEFAULT_PROJECT.into(),
        plan_id: "importer".into(),
        request_id: request_id.into(),
        decision,
    }
}

fn reason(error: AdmitError) -> &'static str {
    match error {
        AdmitError::Rejected(rejection) => rejection.reason,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn steps() -> Vec<StepSpec> {
    vec![
        StepSpec {
            id: "parse".into(),
            title: "Parse the export".into(),
            blocked_by: BTreeSet::new(),
        },
        StepSpec {
            id: "load".into(),
            title: "Load it".into(),
            blocked_by: BTreeSet::from(["parse".to_string()]),
        },
    ]
}

#[test]
fn propose_claim_work_attest_settle_in_one_home() {
    let root = tempfile::tempdir().unwrap();
    let shared = open(root.path());
    let mut wb = shared.lock_unpoisoned();
    let alice = person(&mut wb, "alice", "owner");
    let bob = person(&mut wb, "bob", "member");
    let mut project = wb.library.projects[DEFAULT_PROJECT].clone();
    crate::project_owner::record_owner(&mut project.extra, "alice");
    wb.store_mut()
        .append_record(
            LIBRARY_SCOPE,
            "project",
            &serde_json::to_string(&project).unwrap(),
        )
        .unwrap();
    wb.ensure_project_tasks_tracker(DEFAULT_PROJECT).unwrap();

    // Propose.
    let propose = decide(
        "propose",
        PlanDecision::Propose {
            title: "Ship the importer".into(),
            steps: steps(),
            policy: None,
        },
    );
    let plan = wb.decide_project_plan(&alice, &propose).unwrap();
    assert_eq!(plan.phase, PlanPhase::Active);
    assert_eq!(plan.epoch(), Some(0));
    assert!(matches!(
        plan.readiness("load", 0),
        Some(Readiness::Blocked { .. })
    ));
    // The same request key replays; it proposes nothing twice.
    assert_eq!(wb.decide_project_plan(&alice, &propose).unwrap(), plan);

    // Claim. A blocked step cannot be claimed.
    let claim = |id: &str, step: &str| {
        decide(
            id,
            PlanDecision::Claim {
                step: step.into(),
                lease_seconds: 3600,
            },
        )
    };
    assert_eq!(
        reason(
            wb.decide_project_plan(&alice, &claim("claim-load", "load"))
                .unwrap_err()
        ),
        "claim: a step blocking this one is not settled"
    );
    let plan = wb
        .decide_project_plan(&alice, &claim("claim-parse", "parse"))
        .unwrap();
    assert_eq!(
        plan.steps["parse"].claim.as_ref().unwrap().holder.as_str(),
        "alice"
    );

    // A second claim on the held step is refused, by anyone.
    assert_eq!(
        reason(
            wb.decide_project_plan(&bob, &claim("bob-claims", "parse"))
                .unwrap_err()
        ),
        "claim: the step already has a live claim"
    );
    assert_eq!(
        reason(
            wb.decide_project_plan(&alice, &claim("claim-again", "parse"))
                .unwrap_err()
        ),
        "claim: the step already has a live claim"
    );

    // Work under the claim: the holder records what she produced.
    let plan = wb
        .decide_project_plan(
            &alice,
            &decide(
                "work",
                PlanDecision::RecordEvidence {
                    step: "parse".into(),
                    evidence: EvidenceKind::WorkRecord,
                    reference: "cut:7f3a".into(),
                },
            ),
        )
        .unwrap();
    let work = plan.evidence.keys().next().unwrap().clone();
    // Her own record does not settle the step under the default policy.
    let settle = |id: &str, evidence: &str| {
        decide(
            id,
            PlanDecision::Settle {
                step: "parse".into(),
                evidence: evidence.into(),
            },
        )
    };
    assert_eq!(
        reason(
            wb.decide_project_plan(&alice, &settle("settle-own", &work))
                .unwrap_err()
        ),
        "settle: the policy epoch does not accept this kind of evidence"
    );

    // Attest: someone else vouches for the exact version.
    let plan = wb
        .decide_project_plan(
            &bob,
            &decide(
                "attest",
                PlanDecision::RecordEvidence {
                    step: "parse".into(),
                    evidence: EvidenceKind::Attestation,
                    reference: "cut:7f3a".into(),
                },
            ),
        )
        .unwrap();
    let attestation = plan
        .evidence
        .values()
        .find(|e| e.author.as_str() == "bob")
        .unwrap()
        .id
        .clone();

    // Settle.
    let plan = wb
        .decide_project_plan(&alice, &settle("settle", &attestation))
        .unwrap();
    let settlement = plan.steps["parse"].settlement.as_ref().unwrap();
    assert_eq!(settlement.evidence, attestation);
    assert_eq!(settlement.epoch, 0);
    assert_eq!(plan.readiness("parse", u64::MAX), Some(Readiness::Settled));
    assert_eq!(plan.readiness("load", 0), Some(Readiness::Ready));

    // The standing is what the Home reads back, and a reopen needs a cause.
    let read = wb
        .read_project_plan(&bob, DEFAULT_PROJECT, "importer")
        .unwrap();
    assert_eq!(read, plan);
    assert_eq!(
        reason(
            wb.decide_project_plan(
                &bob,
                &decide(
                    "reopen-bare",
                    PlanDecision::Reopen {
                        step: "parse".into(),
                        cause: ReopenCause {
                            reference: String::new(),
                            reason: String::new(),
                        },
                    },
                ),
            )
            .unwrap_err()
        ),
        "reopen: it must cite a cause"
    );

    // Only the proposer supersedes, and a superseded plan refuses claims.
    let supersede = decide(
        "supersede",
        PlanDecision::Supersede {
            successor: "importer-v2".into(),
            reason: "split into two plans".into(),
        },
    );
    assert_eq!(
        reason(wb.decide_project_plan(&bob, &supersede).unwrap_err()),
        "only the plan's proposer may revise or supersede it"
    );
    let plan = wb.decide_project_plan(&alice, &supersede).unwrap();
    assert_eq!(plan.phase, PlanPhase::Superseded);
    assert_eq!(
        reason(
            wb.decide_project_plan(&bob, &claim("late", "load"))
                .unwrap_err()
        ),
        "the plan is superseded"
    );
}

#[test]
fn standing_needs_current_access_to_the_projects_tasks() {
    let root = tempfile::tempdir().unwrap();
    let shared = open(root.path());
    let mut wb = shared.lock_unpoisoned();
    let alice = person(&mut wb, "alice", "owner");
    let carol = person(&mut wb, "carol", "member");
    let mut project = wb.library.projects[DEFAULT_PROJECT].clone();
    crate::project_owner::record_owner(&mut project.extra, "alice");
    wb.store_mut()
        .append_record(
            LIBRARY_SCOPE,
            "project",
            &serde_json::to_string(&project).unwrap(),
        )
        .unwrap();
    wb.ensure_project_tasks_tracker(DEFAULT_PROJECT).unwrap();
    wb.decide_project_plan(
        &alice,
        &decide(
            "propose",
            PlanDecision::Propose {
                title: "Ship the importer".into(),
                steps: steps(),
                policy: None,
            },
        ),
    )
    .unwrap();

    // Carol loses her project grant: she can neither read nor decide.
    project_grant(&mut wb, "carol", RecordOp::Tombstone);
    let before = wb.store_ref().scope_high_water_marks().unwrap();
    assert!(wb
        .decide_project_plan(
            &carol,
            &decide(
                "carol-claims",
                PlanDecision::Claim {
                    step: "parse".into(),
                    lease_seconds: 60,
                },
            ),
        )
        .is_err());
    assert!(wb
        .read_project_plan(&carol, DEFAULT_PROJECT, "importer")
        .is_err());
    assert_eq!(wb.store_ref().scope_high_water_marks().unwrap(), before);

    // A lease longer than a week is refused.
    assert!(wb
        .decide_project_plan(
            &alice,
            &decide(
                "greedy",
                PlanDecision::Claim {
                    step: "parse".into(),
                    lease_seconds: MAX_STEP_LEASE_SECONDS + 1,
                },
            ),
        )
        .is_err());

    // A plan's events are content: they are sealed at rest.
    let scope = plan_scope(DEFAULT_PROJECT, "importer").unwrap();
    let db = rusqlite::Connection::open(wb.store_ref().path()).unwrap();
    let mut rows = db
        .prepare("SELECT payload FROM events WHERE scope_id=?1")
        .unwrap();
    let raw: Vec<String> = rows
        .query_map([&scope], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert!(!raw.is_empty());
    assert!(raw
        .iter()
        .all(|payload| !payload.contains("Ship the importer")));
    let snapshots: Vec<String> = db
        .prepare("SELECT snapshot_json FROM commands WHERE scope_id=?1")
        .unwrap()
        .query_map([&scope], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert!(!snapshots.is_empty());
    assert!(snapshots.iter().all(|s| !s.contains("Ship the importer")));
}
