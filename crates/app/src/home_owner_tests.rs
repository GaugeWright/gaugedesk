//! DR-0187: the account that makes a computer its Home owns it, once.
use super::*;
use crate::{org::Org, DEFAULT_PROJECT};

fn open() -> (tempfile::TempDir, SharedWorkbench) {
    let root = tempfile::tempdir().unwrap();
    let wb = crate::open_workbench(root.path()).unwrap();
    (root, wb)
}

fn org(wb: &SharedWorkbench) -> Org {
    Org::rebuild(wb.lock_unpoisoned().store_ref()).unwrap()
}

fn claims(wb: &SharedWorkbench) -> Vec<HomeOwnerClaim> {
    wb.lock_unpoisoned()
        .store_ref()
        .records(ORG_SCOPE, CLAIM_KIND)
        .unwrap()
        .iter()
        .map(|raw| serde_json::from_str(raw).unwrap())
        .collect()
}

fn set_membership(wb: &SharedWorkbench, account: &str, status: MembershipStatus) {
    let record = MembershipRecord {
        id: account.into(),
        op: RecordOp::Upsert,
        org_id: ORG_ID.into(),
        authority: account.into(),
        email: String::new(),
        role: "owner".into(),
        status,
        managed_by_scim: false,
        team: None,
    };
    wb.lock_unpoisoned()
        .store_mut()
        .append_record(
            ORG_SCOPE,
            "membership",
            &serde_json::to_string(&record).unwrap(),
        )
        .unwrap();
}

#[test]
fn nobody_signed_in_claims_nothing_and_leaves_the_question_open() {
    let (_root, wb) = open();
    assert!(
        matches!(claim_state(&wb).unwrap(), HomeClaimState::Available { projects } if projects >= 1)
    );
    assert_eq!(claim_if_never_claimed(&wb).unwrap(), HomeClaim::NotSignedIn);
    assert!(
        claims(&wb).is_empty(),
        "signing in later still leaves the claim open"
    );
    assert_eq!(org(&wb).active_count_with_role("owner"), 0);
}

#[test]
fn the_signed_in_account_becomes_the_owner_once() {
    let (_root, wb) = open();
    crate::account_signin::store_session_for_test(&wb);
    assert_eq!(
        claim_if_never_claimed(&wb).unwrap(),
        HomeClaim::Owner("account-root".into())
    );
    assert_eq!(
        claim_state(&wb).unwrap(),
        HomeClaimState::Claimed {
            owner: "account-root".into()
        }
    );
    let directory = org(&wb);
    assert_eq!(
        directory.role_of("account-root"),
        Some(gaugedesk_core::abac::Role::owner())
    );
    assert!(directory.can_access_project("account-root", DEFAULT_PROJECT));
    let recorded = claims(&wb);
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].account.as_deref(), Some("account-root"));
    assert!(
        recorded[0].session.is_some(),
        "the claim names the session that made it"
    );

    assert_eq!(
        claim_if_never_claimed(&wb).unwrap(),
        HomeClaim::AlreadyClaimed
    );
    assert_eq!(
        claims(&wb).len(),
        1,
        "the wake loop asks again and writes nothing"
    );
}

#[test]
fn a_hub_check_for_one_account_cannot_claim_after_selection_changes() {
    let (_root, wb) = open();
    crate::account_signin::store_session_for_test(&wb);
    crate::account_signin::store_session_as_for_test(&wb, "someone-else");
    assert_eq!(
        claim_verified_selected(&wb, "account-root").unwrap(),
        HomeClaim::NotSignedIn,
    );
    assert!(matches!(
        claim_state(&wb).unwrap(),
        HomeClaimState::Available { .. }
    ));
}

/// The condition is the claim, not an empty directory: an owner who is later
/// removed does not leave the Home to whoever signs in next.
#[test]
fn a_later_sign_in_never_reclaims_the_home() {
    let (_root, wb) = open();
    crate::account_signin::store_session_for_test(&wb);
    claim_if_never_claimed(&wb).unwrap();
    set_membership(&wb, "account-root", MembershipStatus::Deprovisioned);
    assert_eq!(org(&wb).active_count_with_role("owner"), 0);

    crate::account_signin::store_session_as_for_test(&wb, "someone-else");
    assert_eq!(
        claim_if_never_claimed(&wb).unwrap(),
        HomeClaim::AlreadyClaimed
    );
    assert_eq!(org(&wb).role_of("someone-else"), None);
    assert!(!org(&wb).can_access_project("someone-else", DEFAULT_PROJECT));
}

#[test]
fn a_home_that_already_has_an_owner_is_marked_claimed_without_adding_one() {
    let (_root, wb) = open();
    set_membership(&wb, "tenant-owner", MembershipStatus::Active);
    crate::account_signin::store_session_for_test(&wb);
    assert_eq!(claim_if_never_claimed(&wb).unwrap(), HomeClaim::Governed);
    assert_eq!(org(&wb).role_of("account-root"), None, "no second owner");
    let recorded = claims(&wb);
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].account, None);
    assert_eq!(
        claim_if_never_claimed(&wb).unwrap(),
        HomeClaim::AlreadyClaimed
    );
}

#[test]
fn explicit_claim_refuses_a_governed_home_without_writing_a_marker() {
    let (root, wb) = open();
    set_membership(&wb, "tenant-owner", MembershipStatus::Active);
    crate::account_signin::store_session_as_for_test(&wb, "tenant-owner");
    assert_eq!(
        claim_verified_selected(&wb, "tenant-owner").unwrap(),
        HomeClaim::Governed
    );
    assert!(claims(&wb).is_empty());
    assert!(!crate::first_home::attach_if_never_offered(&wb, root.path()).unwrap());
    assert!(!wb.lock_unpoisoned().library_sync_active());
}

#[test]
fn a_hosted_home_is_governed_by_its_provisioned_directory() {
    let (_root, wb) = open();
    wb.lock_unpoisoned().enable_hosted_home_mode();
    crate::account_signin::store_session_for_test(&wb);
    assert_eq!(claim_if_never_claimed(&wb).unwrap(), HomeClaim::Governed);
    assert_eq!(org(&wb).role_of("account-root"), None);
}

/// What the claim is for: a native action that refused the person whose Home
/// it is now admits them. Declaring a tracker in Personal is the first thing
/// Basics needs, and it was refused at the directory before this.
#[test]
fn the_owner_can_take_a_native_action_the_empty_directory_refused() {
    let (_root, wb) = open();
    crate::account_signin::store_session_for_test(&wb);
    let context = {
        let mut guard = wb.lock_unpoisoned();
        let token = guard
            .mint_account_session("account-root", "passkey", 3600)
            .unwrap();
        guard.authenticate_action_context(&token).unwrap()
    };
    let declare = |request: &str| {
        wb.lock_unpoisoned().declare_project_tracker(
            &context,
            DEFAULT_PROJECT,
            "tutorials",
            request,
            gaugedesk_core::abac::ResourceAttributes::default(),
        )
    };
    let refused = declare("before").unwrap_err();
    assert!(
        format!("{refused:?}").contains("exceeds current project or Home authority"),
        "{refused:?}"
    );
    claim_if_never_claimed(&wb).unwrap();
    declare("after").expect("the owner declares a tracker in their own Personal project");
}
