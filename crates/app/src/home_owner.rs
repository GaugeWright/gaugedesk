//! The account that makes a computer its Home owns it (DR-0187).
//!
//! A desktop Home's own directory starts empty, and every native action admits
//! its actor from that directory, so without this the person whose Home it is
//! could use none of them. A Cloud Home is provisioned with its tenant's owner;
//! a desktop Home is claimed once, by an explicit act after account sign-in.
//!
//! The claim is a durable record beside the membership it grants, written in
//! one transaction. The question it answers is "has this Home ever been
//! claimed", deliberately not "does this directory have an owner": an owner who
//! is later removed must not leave the Home to whoever signs in next.

use crate::{
    org::{MembershipRecord, MembershipStatus, Org, RecordOp, ORG_ID, ORG_SCOPE},
    LockUnpoisoned, SharedWorkbench,
};
use serde::{Deserialize, Serialize};

/// The record kind, in the Home's own directory scope.
pub(crate) const CLAIM_KIND: &str = "home_owner_claim";

/// What was decided the one time this Home was claimed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HomeOwnerClaim {
    /// The account that became the owner, or `None` when the Home was already
    /// governed by a directory and the claim added nobody.
    pub account: Option<String>,
    /// A digest identifying the Hub session that authenticated the claim.
    pub session: Option<String>,
    pub claimed_at_ms: i64,
}

/// What [`claim_if_never_claimed`] did.
#[derive(Debug, PartialEq, Eq)]
pub enum HomeClaim {
    /// Nobody is signed in: the explicit claim waits for account selection.
    NotSignedIn,
    /// This Home was claimed before; nothing changed.
    AlreadyClaimed,
    /// This Home was governed by an existing directory; it is now marked
    /// claimed and nobody was added.
    Governed,
    /// This account is now the Home's owner.
    Owner(String),
}

/// Whether the selected account can claim this computer. A previous claim is
/// never reopened merely because its owner later lost their membership.
#[derive(Debug, PartialEq, Eq)]
pub enum HomeClaimState {
    Available { projects: usize },
    Claimed { owner: String },
    Governed,
}

pub fn claim_state(wb: &SharedWorkbench) -> Result<HomeClaimState, String> {
    let guard = wb.lock_unpoisoned();
    let store = guard.store_ref();
    let err = |error: gaugedesk_store::AdmitError| format!("home owner claim: {error:?}");
    let claims = store.records(ORG_SCOPE, CLAIM_KIND).map_err(err)?;
    if let Some(raw) = claims.first() {
        return Ok(match serde_json::from_str::<HomeOwnerClaim>(raw) {
            Ok(HomeOwnerClaim {
                account: Some(owner),
                ..
            }) => HomeClaimState::Claimed { owner },
            _ => HomeClaimState::Governed,
        });
    }
    if guard.hosted_home_mode()
        || guard.idp.is_some()
        || Org::rebuild(store)
            .map_err(err)?
            .active_count_with_role("owner")
            > 0
    {
        return Ok(HomeClaimState::Governed);
    }
    let projects = guard
        .library
        .projects
        .values()
        .filter(|project| &project.home_id == guard.home_id())
        .count();
    Ok(HomeClaimState::Available { projects })
}

/// Claim this Home for the signed-in account, once. Only the explicit desktop
/// claim route calls this in production (DR-0219).
pub fn claim_if_never_claimed(wb: &SharedWorkbench) -> Result<HomeClaim, String> {
    claim_selected(wb, None)
}

/// The production claim route passes the account the Hub just authenticated.
/// A selection changed during that network check cannot claim for the new
/// account on the old account's proof.
pub fn claim_verified_selected(wb: &SharedWorkbench, verified: &str) -> Result<HomeClaim, String> {
    claim_selected(wb, Some(verified))
}

fn claim_selected(wb: &SharedWorkbench, verified: Option<&str>) -> Result<HomeClaim, String> {
    // Taken before the guard: reading the session locks the workbench itself.
    let Some(crate::account_signin::HubStanding {
        person: account,
        session,
        ..
    }) = crate::account_signin::hub_standing(wb)
    else {
        return Ok(HomeClaim::NotSignedIn);
    };
    if verified.is_some_and(|expected| expected != account) {
        return Ok(HomeClaim::NotSignedIn);
    }
    if crate::account_signin::live_hub_session_actor(wb).as_deref() != Some(account.as_str()) {
        return Ok(HomeClaim::NotSignedIn);
    }
    let mut guard = wb.lock_unpoisoned();
    let store = guard.store_ref();
    let err = |error: gaugedesk_store::AdmitError| format!("home owner claim: {error:?}");
    if crate::account_signin::selected_person_in_store(store).as_deref() != Some(account.as_str()) {
        return Ok(HomeClaim::NotSignedIn);
    }
    if !store
        .records(ORG_SCOPE, CLAIM_KIND)
        .map_err(err)?
        .is_empty()
    {
        return Ok(HomeClaim::AlreadyClaimed);
    }
    // A Home governed by a directory of its own — a Cloud Home, one with an
    // identity provider, or any Home that already has an active owner — is not
    // given a second owner by whoever signs in on the machine serving it.
    let governed = guard.hosted_home_mode()
        || guard.idp.is_some()
        || Org::rebuild(store)
            .map_err(err)?
            .active_count_with_role("owner")
            > 0;
    // The explicit claim refuses an already governed Home without modifying
    // its history. The older helper preserves the original marker behavior
    // for existing migration and unit-test callers.
    if governed && verified.is_some() {
        return Ok(HomeClaim::Governed);
    }
    let claim = HomeOwnerClaim {
        account: (!governed).then(|| account.clone()),
        session: Some(session),
        claimed_at_ms: i64::try_from(crate::account::session_now_ms()).unwrap_or(i64::MAX),
    };
    let claim = serde_json::to_string(&claim).map_err(|e| e.to_string())?;
    let membership = MembershipRecord {
        id: account.clone(),
        op: RecordOp::Upsert,
        org_id: ORG_ID.to_owned(),
        authority: account.clone(),
        email: String::new(),
        role: "owner".into(),
        status: MembershipStatus::Active,
        managed_by_scim: false,
        team: None,
    };
    let membership = serde_json::to_string(&membership).map_err(|e| e.to_string())?;
    let mut records = vec![(ORG_SCOPE, CLAIM_KIND, claim.as_str())];
    if !governed {
        records.push((ORG_SCOPE, "membership", membership.as_str()));
    }
    guard
        .store_mut()
        .append_records_atomically(&records)
        .map_err(err)?;
    Ok(if governed {
        HomeClaim::Governed
    } else {
        HomeClaim::Owner(account)
    })
}

#[cfg(test)]
#[path = "home_owner_tests.rs"]
mod tests;
