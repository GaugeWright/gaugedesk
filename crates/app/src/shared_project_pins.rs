//! The shared projects a member reaches, vouched for by the member's own
//! computer ([DR-0458](../../../specs/decisions/0458-a-members-own-computer-vouches-for-a-shared-projects-key.md)).
//!
//! Accepting an invitation pins the shared project's authority key on the
//! device that accepted (DR-0370 §2, DR-0451). A member's other devices learn
//! it from the member's own account: this computer, which holds the member's
//! account keys, keeps each pin under that account and, whenever it publishes
//! the member's entry, includes the project's route as the owning account's
//! entries carry it, and only while its placement is signed by the pinned key.
//! The member's root signs the entry, so the member's other devices trust the
//! key it names as they trust the member's own projects. Nothing here comes
//! from the Hub.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::account_signin::DesktopOperatorPlane;
use crate::home::OpaqueHomeRoute;
use crate::net_http::HttpClient;
use crate::{net_http, LockUnpoisoned, SharedWorkbench, Workbench};

/// The record kind, in the member's own account store scope.
pub const SHARED_PROJECT_PIN_KIND: &str = "shared_project_pin";

/// One shared project the member reaches, and the key it was pinned to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedProjectPin {
    /// The project's id, which the record is keyed by.
    pub id: String,
    pub home_id: String,
    pub project_key: String,
    /// The owning account's directory root, where the project's route is read.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub owner_root: String,
}

impl Workbench {
    /// The shared projects `account` has pinned on this computer.
    pub fn shared_project_pins(&self, account: &str) -> Vec<SharedProjectPin> {
        let scope = self.desktop_account_store_scope(account);
        let mut pins = std::collections::BTreeMap::new();
        for raw in self
            .store_ref()
            .records(&scope, SHARED_PROJECT_PIN_KIND)
            .unwrap_or_default()
        {
            if let Ok(pin) = serde_json::from_str::<SharedProjectPin>(&raw) {
                pins.insert(pin.id.clone(), pin);
            }
        }
        pins.into_values().collect()
    }

    /// Keep `pin` for `account`. A project already pinned to a different key
    /// is refused: a project's key changes only by a hand-over the outgoing
    /// key signs (DR-0370 §5).
    pub fn keep_shared_project_pin(
        &mut self,
        account: &str,
        pin: &SharedProjectPin,
    ) -> Result<(), PinRefusal> {
        if pin.id.trim().is_empty()
            || pin.home_id.trim().is_empty()
            || pin.project_key.trim().is_empty()
        {
            return Err(PinRefusal::Incomplete);
        }
        if let Some(held) = self
            .shared_project_pins(account)
            .into_iter()
            .find(|held| held.id == pin.id)
        {
            if held.project_key != pin.project_key {
                return Err(PinRefusal::DifferentKey);
            }
            if held == *pin {
                return Ok(());
            }
        }
        let scope = self.desktop_account_store_scope(account);
        let raw = serde_json::to_string(pin).map_err(|_| PinRefusal::Store)?;
        self.store_mut()
            .append_record(&scope, SHARED_PROJECT_PIN_KIND, &raw)
            .map(|_| ())
            .map_err(|_| PinRefusal::Store)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum PinRefusal {
    Incomplete,
    DifferentKey,
    Store,
}

/// The routes this computer vouches for under the member's entry: for each
/// pin, the newest route to its project among the owning account's entries
/// whose placement the pinned key signed. A pin naming no owner root, or whose
/// owner publishes no such route, contributes nothing. Blocking.
pub fn vouched_routes(
    http: &HttpClient,
    directory: &str,
    pins: &[SharedProjectPin],
) -> Vec<OpaqueHomeRoute> {
    let mut routes = Vec::new();
    for pin in pins {
        if pin.owner_root.is_empty() {
            continue;
        }
        let Ok(entries) =
            crate::directory_sync::fetch_live_entries(http, directory, &pin.owner_root)
        else {
            continue;
        };
        if let Some(route) = newest_placed(&entries, pin) {
            routes.push(route);
        }
    }
    routes
}

/// The route to `pin`'s project among `entries`, newest generation first,
/// whose placement holds against the pinned key.
pub fn newest_placed(
    entries: &[crate::directory_sync::FetchedRecord],
    pin: &SharedProjectPin,
) -> Option<OpaqueHomeRoute> {
    let mut candidates: Vec<(u64, OpaqueHomeRoute)> = entries
        .iter()
        .flat_map(|record| {
            record
                .entry
                .directory
                .home_routes
                .iter()
                .filter(|route| route.project == pin.id)
                .map(move |route| (record.entry.generation, route.clone()))
        })
        .filter(|(_, route)| {
            gaugedesk_directory_protocol::placement_verifies(route, &pin.project_key)
        })
        .collect();
    candidates.sort_by_key(|(generation, _)| std::cmp::Reverse(*generation));
    candidates.into_iter().next().map(|(_, route)| route)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinBody {
    pub project: String,
    pub home_id: String,
    pub project_key: String,
    #[serde(default)]
    pub owner_root: String,
}

/// `POST /account/shared-projects`: keep the pin of a shared project the
/// window's signed-in account just accepted, so this computer vouches for its
/// key under the account's own entry (DR-0458).
pub async fn post_shared_project_pin(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    window: Option<Extension<DesktopOperatorPlane>>,
    Json(body): Json<PinBody>,
) -> Response {
    let refusal = |status: StatusCode, message: &'static str| {
        (status, Json(json!({ "error": message }))).into_response()
    };
    let account = {
        let wb = wb.lock_unpoisoned();
        if !wb.desktop_account_mode() {
            return refusal(
                StatusCode::NOT_FOUND,
                "shared project pins are kept on a desktop",
            );
        }
        if window.is_none() {
            return refusal(
                StatusCode::FORBIDDEN,
                "only this computer's own window keeps a shared project's pin",
            );
        }
        match net_http::bearer(&headers)
            .and_then(|token| wb.resolve_account_session(token))
            .map(|(account, _)| account)
            .filter(|account| account != wb.authority().as_str())
        {
            Some(account) => account,
            None => return refusal(StatusCode::UNAUTHORIZED, "sign in to the account first"),
        }
    };
    let pin = SharedProjectPin {
        id: body.project,
        home_id: body.home_id,
        project_key: body.project_key,
        owner_root: body.owner_root,
    };
    let kept = wb.lock_unpoisoned().keep_shared_project_pin(&account, &pin);
    match kept {
        Ok(()) => {
            crate::account_publish::spawn_publish(&wb, &account);
            Json(json!({ "account": account, "project": pin.id })).into_response()
        }
        Err(PinRefusal::Incomplete) => refusal(
            StatusCode::UNPROCESSABLE_ENTITY,
            "a shared project's pin names the project, its Home and its key",
        ),
        Err(PinRefusal::DifferentKey) => refusal(
            StatusCode::CONFLICT,
            "this project is already pinned to a different key",
        ),
        Err(PinRefusal::Store) => refusal(
            StatusCode::INTERNAL_SERVER_ERROR,
            "the pin could not be kept",
        ),
    }
}

#[cfg(test)]
#[path = "shared_project_pins_tests.rs"]
mod tests;
