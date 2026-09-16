//! Preparing a project handoff from Administration (ADR 0171).
//!
//! `project-home.handoff` is an entry point into the existing
//! [project-handoff lifecycle](crate::handoff), not a second way to move a
//! project. Building an Administration-specific move protocol would create two
//! reducers able to change the one Home fact, which is the split-brain that
//! lifecycle exists to prevent. So nothing here moves anything: preparation
//! either yields an intent the origin may offer, or refuses.
//!
//! What it is for is the rechecking. By the time an administrator's reviewed
//! command reaches the server, the role that authorized it, the target's
//! standing, and the project's current Home may all have changed. Each is
//! rechecked against facts the caller supplies, and a stale one is a refusal
//! that names what moved.

use sha2::{Digest, Sha256};

pub const HANDOFF_PREPARATION_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreparationError {
    /// The actor's current role does not admit moving a project.
    NotPermitted,
    /// The project or the target belongs to a different tenant.
    TenantMismatch,
    /// Personal is not a transferable ordinary project.
    PersonalProjectNotTransferable,
    /// The project's Home is not the one this request was built against —
    /// something moved it first.
    StaleHomeBasis,
    /// The target is not an admitted Project Host of this tenant.
    TargetNotRegistered,
    /// The target's route possession is not current, so it cannot be offered a
    /// project on the strength of an old proof.
    TargetPossessionStale,
    /// The target is suspended, retiring, or otherwise not accepting placement.
    TargetNotEligible,
    /// The project already lives there.
    AlreadyHome,
}

/// What an administrator asked for.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HandoffRequest {
    pub version: u8,
    pub tenant_id: String,
    pub project_id: String,
    /// The Home the page believed the project was on. Carried explicitly so a
    /// concurrent move is a refusal rather than a silent retarget.
    pub expected_current_home_id: String,
    pub target_home_id: String,
    pub requested_by: String,
}

/// Current truth, read by the caller at preparation time. None of it comes from
/// the request body: a browser cannot assert that a target is registered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrentFacts {
    pub actor_may_move_projects: bool,
    pub project_tenant_id: String,
    pub project_is_personal: bool,
    pub project_current_home_id: String,
    pub target_tenant_id: String,
    pub target_registered: bool,
    pub target_possession_current: bool,
    pub target_accepts_placement: bool,
}

/// An idempotent intent the origin may offer into the handoff lifecycle.
///
/// `intent_id` is derived from the exact subject, so retrying the same move
/// produces the same intent, and changing any part of it produces a different
/// one. A changed subject therefore cannot ride in under an identity that was
/// already approved.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HandoffIntent {
    pub version: u8,
    pub intent_id: String,
    pub tenant_id: String,
    pub project_id: String,
    pub origin_home_id: String,
    pub target_home_id: String,
}

fn intent_id(request: &HandoffRequest, origin_home_id: &str) -> String {
    let mut hash = Sha256::new();
    for part in [
        "gaugedesk-project-home-handoff.v1",
        &request.tenant_id,
        &request.project_id,
        origin_home_id,
        &request.target_home_id,
    ] {
        hash.update(part.as_bytes());
        hash.update([0u8]);
    }
    hex::encode(hash.finalize())
}

/// Recheck everything and produce the intent, or say what stopped it.
///
/// Order matters only for which refusal a caller sees first; every check is
/// independent and all of them must hold.
pub fn prepare(
    request: &HandoffRequest,
    facts: &CurrentFacts,
) -> Result<HandoffIntent, PreparationError> {
    if request.version != HANDOFF_PREPARATION_VERSION {
        return Err(PreparationError::TenantMismatch);
    }
    if !facts.actor_may_move_projects {
        return Err(PreparationError::NotPermitted);
    }
    if facts.project_tenant_id != request.tenant_id || facts.target_tenant_id != request.tenant_id {
        return Err(PreparationError::TenantMismatch);
    }
    if facts.project_is_personal {
        return Err(PreparationError::PersonalProjectNotTransferable);
    }
    // The page's belief about where the project lives is checked against where
    // it actually lives. Without this a second administrator's completed move
    // would be silently overwritten by this one.
    if facts.project_current_home_id != request.expected_current_home_id {
        return Err(PreparationError::StaleHomeBasis);
    }
    if facts.project_current_home_id == request.target_home_id {
        return Err(PreparationError::AlreadyHome);
    }
    if !facts.target_registered {
        return Err(PreparationError::TargetNotRegistered);
    }
    // An old possession proof says where the Home used to answer. Offering a
    // project on that basis could ship it at a route the Home no longer holds.
    if !facts.target_possession_current {
        return Err(PreparationError::TargetPossessionStale);
    }
    if !facts.target_accepts_placement {
        return Err(PreparationError::TargetNotEligible);
    }
    Ok(HandoffIntent {
        version: HANDOFF_PREPARATION_VERSION,
        intent_id: intent_id(request, &facts.project_current_home_id),
        tenant_id: request.tenant_id.clone(),
        project_id: request.project_id.clone(),
        origin_home_id: facts.project_current_home_id.clone(),
        target_home_id: request.target_home_id.clone(),
    })
}

#[cfg(test)]
mod tests;
