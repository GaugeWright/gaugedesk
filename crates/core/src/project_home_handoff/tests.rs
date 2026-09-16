use super::*;
use crate::handoff::{decide, evolve, HandoffCommand, HandoffState, Home};

fn request() -> HandoffRequest {
    HandoffRequest {
        version: HANDOFF_PREPARATION_VERSION,
        tenant_id: "tenant:acme".into(),
        project_id: "project:alpha".into(),
        expected_current_home_id: "home:origin".into(),
        target_home_id: "home:target".into(),
        requested_by: "authority:owner".into(),
    }
}

fn facts() -> CurrentFacts {
    CurrentFacts {
        actor_may_move_projects: true,
        project_tenant_id: "tenant:acme".into(),
        project_is_personal: false,
        project_current_home_id: "home:origin".into(),
        target_tenant_id: "tenant:acme".into(),
        target_registered: true,
        target_possession_current: true,
        target_accepts_placement: true,
    }
}

#[test]
fn preparation_yields_an_intent_and_moves_nothing_by_itself() {
    let intent = prepare(&request(), &facts()).unwrap();
    assert_eq!(intent.origin_home_id, "home:origin");
    assert_eq!(intent.target_home_id, "home:target");

    // Preparing is not relocating. The one Home fact only moves when the
    // existing lifecycle commits, and it still requires the target to hold the
    // complete state first.
    let state = HandoffState::default();
    assert_eq!(state.home, Home::Origin);
    let offered = decide(&state, HandoffCommand::OfferHandoff)
        .unwrap()
        .into_iter()
        .fold(state, |state, event| evolve(&state, event));
    assert_eq!(offered.home, Home::Origin, "an offer is not a transfer");
}

#[test]
fn every_recheck_refuses_and_names_what_moved() {
    for (mutate, expected) in [
        (
            (|facts: &mut CurrentFacts| facts.actor_may_move_projects = false)
                as fn(&mut CurrentFacts),
            PreparationError::NotPermitted,
        ),
        (
            |facts: &mut CurrentFacts| facts.project_tenant_id = "tenant:other".into(),
            PreparationError::TenantMismatch,
        ),
        (
            |facts: &mut CurrentFacts| facts.target_tenant_id = "tenant:other".into(),
            PreparationError::TenantMismatch,
        ),
        (
            |facts: &mut CurrentFacts| facts.project_is_personal = true,
            PreparationError::PersonalProjectNotTransferable,
        ),
        (
            |facts: &mut CurrentFacts| facts.target_registered = false,
            PreparationError::TargetNotRegistered,
        ),
        (
            |facts: &mut CurrentFacts| facts.target_possession_current = false,
            PreparationError::TargetPossessionStale,
        ),
        (
            |facts: &mut CurrentFacts| facts.target_accepts_placement = false,
            PreparationError::TargetNotEligible,
        ),
    ] {
        let mut current = facts();
        mutate(&mut current);
        assert_eq!(prepare(&request(), &current), Err(expected));
    }
}

#[test]
fn a_project_that_moved_since_the_page_read_it_is_refused_not_retargeted() {
    // Another administrator's move completed first. Preparing against the
    // stale belief would ship the project from a Home that no longer holds it.
    let mut moved = facts();
    moved.project_current_home_id = "home:somewhere-else".into();
    assert_eq!(
        prepare(&request(), &moved),
        Err(PreparationError::StaleHomeBasis)
    );

    // And a project already on the target is not a move.
    let mut arrived = facts();
    arrived.project_current_home_id = "home:target".into();
    let mut asked = request();
    asked.expected_current_home_id = "home:target".into();
    assert_eq!(
        prepare(&asked, &arrived),
        Err(PreparationError::AlreadyHome)
    );
}

#[test]
fn an_exact_retry_is_the_same_intent_and_a_changed_subject_is_a_different_one() {
    let first = prepare(&request(), &facts()).unwrap();
    let again = prepare(&request(), &facts()).unwrap();
    assert_eq!(
        first.intent_id, again.intent_id,
        "an exact retry is the same move"
    );

    // Changing any part of the subject must not reuse an identity that was
    // already approved.
    for mutate in [
        (|request: &mut HandoffRequest| request.project_id = "project:beta".into())
            as fn(&mut HandoffRequest),
        |request: &mut HandoffRequest| request.target_home_id = "home:third".into(),
        |request: &mut HandoffRequest| request.tenant_id = "tenant:beta".into(),
    ] {
        let mut changed = request();
        mutate(&mut changed);
        let mut current = facts();
        current.tenant_id_align(&changed);
        let other = prepare(&changed, &current).unwrap();
        assert_ne!(first.intent_id, other.intent_id);
    }
}

impl CurrentFacts {
    /// Keep the supplied facts consistent with a mutated request so the test
    /// exercises intent identity rather than a tenant refusal.
    fn tenant_id_align(&mut self, request: &HandoffRequest) {
        self.project_tenant_id = request.tenant_id.clone();
        self.target_tenant_id = request.tenant_id.clone();
    }
}
