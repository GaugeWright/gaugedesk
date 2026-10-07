//! The office-controlled profile binding (DR-0258, DR-0371; HIPAA-1, WS-424).
//!
//! An office administrator enrolls the organization whose directory this Home
//! holds, and names this Home as the local Project Host that keeps its work.
//! The binding is a record in the organization's own scope, not a client flag,
//! a resource `regulated` label or a setting, so a stale client cannot assert
//! it and a changed setting cannot remove it.
//!
//! It is one-way. The fold keeps the first enrollment and ignores every later
//! record of its kind — a tombstone, a rebind to another Home, a replayed
//! enrollment — so there is no silent exit and no route that leaves it. Any
//! migration needs a separately reviewed export and admission path, which does
//! not exist; until it does, a project on an enrolled Home cannot be moved to
//! another Home or given to an account outside the organization.
//!
//! The checks here are authority checks. They read only the store and the
//! Home's own composition, so a route can refuse before it reads a body.

use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

use gaugedesk_store::AdmitError;

use crate::library::RecordOp;
use crate::org::{ORG_ID, ORG_SCOPE};
use crate::Workbench;

/// The record kind holding the binding, in the organization's scope.
pub const OFFICE_PROFILE_KIND: &str = "office_profile";

/// The organization's enrollment in the office-controlled profile.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct OfficeProfileRecord {
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    /// The organization tenant whose directory was enrolled.
    pub organization: String,
    /// The local Project Host that holds the profile's work.
    pub home_id: String,
    /// The organization administrator who enrolled it.
    pub enrolled_by: String,
    pub enrolled_at_ms: u64,
}

/// Fold the binding's records in position order. The first upsert is the
/// binding, whatever follows it; nothing that comes after can clear or move it.
pub fn fold_office_profile<I>(rows: I) -> Result<Option<OfficeProfileRecord>, serde_json::Error>
where
    I: IntoIterator<Item = String>,
{
    for row in rows {
        let record: OfficeProfileRecord = serde_json::from_str(&row)?;
        if record.op == RecordOp::Upsert {
            return Ok(Some(record));
        }
    }
    Ok(None)
}

/// The secret-free state the organization-policy page shows.
pub fn office_profile_view(
    profile: Option<&OfficeProfileRecord>,
    this_home: &str,
    enrollable: Result<(), &'static str>,
) -> serde_json::Value {
    match profile {
        Some(profile) => serde_json::json!({
            "state": "enrolled",
            "home_id": profile.home_id,
            "this_home": this_home,
            "bound_here": profile.home_id == this_home,
            "enrolled_by": profile.enrolled_by,
            "enrolled_at_ms": profile.enrolled_at_ms,
        }),
        None => match enrollable {
            Ok(()) => serde_json::json!({
                "state": "available",
                "this_home": this_home,
            }),
            Err(reason) => serde_json::json!({
                "state": "unavailable",
                "this_home": this_home,
                "reason": reason,
            }),
        },
    }
}

impl Workbench {
    /// The binding of the organization whose directory this Home holds.
    pub fn office_profile(&self) -> Result<Option<OfficeProfileRecord>, AdmitError> {
        let rows = self.store_ref().records(ORG_SCOPE, OFFICE_PROFILE_KIND)?;
        Ok(fold_office_profile(rows)?)
    }

    /// Whether the directory at `scope` may be enrolled on this Home, before
    /// asking who is enrolling it.
    pub fn office_profile_enrollable(&self, scope: &str) -> Result<(), &'static str> {
        if scope != ORG_SCOPE {
            return Err("the office-controlled profile binds the organization this Home holds");
        }
        if self.hosted_home_mode() {
            return Err("a hosted Home cannot hold the office-controlled profile");
        }
        Ok(())
    }

    /// Validate an administrator's enrollment and return the record to append.
    /// `requested_home` is the Project Host the administrator was shown; a
    /// client showing another one is stale and is refused.
    pub fn plan_office_profile_enrollment(
        &self,
        scope: &str,
        organization: &str,
        requested_home: &str,
        actor: &str,
        now_ms: u64,
    ) -> Result<OfficeProfileRecord, (StatusCode, &'static str)> {
        self.office_profile_enrollable(scope)
            .map_err(|reason| (StatusCode::CONFLICT, reason))?;
        let org = crate::org::Org::rebuild_in(self.store_ref(), scope).map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "the organization directory is unavailable",
            )
        })?;
        let role = org.role_of(actor);
        if role != Some(gaugedesk_core::abac::Role::owner())
            && role != Some(gaugedesk_core::abac::Role::admin())
        {
            return Err((
                StatusCode::FORBIDDEN,
                "only an organization administrator can enroll the office-controlled profile",
            ));
        }
        match self.office_profile() {
            Err(_) => {
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    "the office-controlled profile is unavailable",
                ))
            }
            Ok(Some(_)) => {
                return Err((
                    StatusCode::CONFLICT,
                    "this organization already holds the office-controlled profile",
                ))
            }
            Ok(None) => {}
        }
        if requested_home != self.home_id().as_str() {
            return Err((
                StatusCode::CONFLICT,
                "the enrollment names another Project Host; reload and confirm this one",
            ));
        }
        Ok(OfficeProfileRecord {
            id: ORG_ID.to_owned(),
            op: RecordOp::Upsert,
            organization: organization.to_owned(),
            home_id: requested_home.to_owned(),
            enrolled_by: actor.to_owned(),
            enrolled_at_ms: now_ms,
        })
    }

    /// The refusal for any act that would take work off this Home or out of
    /// the organization: a move to another Home, a transfer to an account, a
    /// hand-off. An unreadable binding refuses too.
    pub fn office_profile_exit_refusal(&self) -> Option<&'static str> {
        match self.office_profile() {
            Ok(None) => None,
            Ok(Some(_)) => Some(
                "this Home holds the office-controlled profile; its work cannot leave this Project Host",
            ),
            Err(_) => Some("the office-controlled profile is unavailable; nothing can leave this Home"),
        }
    }

    /// The refusal for the office staff channel: it serves only a Home that
    /// is office-operated and is the Project Host its organization enrolled.
    /// A restored or copied store on another Home is refused rather than
    /// re-bound.
    pub(crate) fn office_profile_channel_refusal(&self) -> Option<(StatusCode, &'static str)> {
        if self.hosted_home_mode() {
            return Some((
                StatusCode::FORBIDDEN,
                "the office-controlled profile requires office-operated custody",
            ));
        }
        match self.office_profile() {
            Err(_) => Some((
                StatusCode::SERVICE_UNAVAILABLE,
                "the office-controlled profile is unavailable",
            )),
            Ok(None) => Some((
                StatusCode::FORBIDDEN,
                "this Home has not been enrolled in the office-controlled profile",
            )),
            Ok(Some(profile)) if profile.home_id != self.home_id().as_str() => Some((
                StatusCode::FORBIDDEN,
                "the office-controlled profile is bound to another Project Host",
            )),
            Ok(Some(_)) => None,
        }
    }

    /// Append an enrollment directly. Test fixtures use it; the product path is
    /// the reviewed Administration command, which checks the administrator.
    #[cfg(test)]
    pub(crate) fn enroll_office_profile_for_test(&mut self, actor: &str) {
        let record = OfficeProfileRecord {
            id: ORG_ID.to_owned(),
            op: RecordOp::Upsert,
            organization: ORG_ID.to_owned(),
            home_id: self.home_id().as_str().to_owned(),
            enrolled_by: actor.to_owned(),
            enrolled_at_ms: 1,
        };
        self.store_mut()
            .append_record(
                ORG_SCOPE,
                OFFICE_PROFILE_KIND,
                &serde_json::to_string(&record).unwrap(),
            )
            .unwrap();
    }
}

#[cfg(test)]
#[path = "office_profile_tests.rs"]
mod tests;
