//! An account publishes its own reachability from each computer it is signed in
//! on ([DR-0359](../../../specs/decisions/0359-every-account-reaches-its-computers-under-its-own-keys.md),
//! [DR-0361](../../../specs/decisions/0361-account-and-project-key-custody.md)).
//!
//! Signing in publishes: this computer writes its own entry under the account's
//! root, naming itself, with the routes of the account's projects it serves and
//! the account's state sealed under the account's own key. Signing out withdraws
//! that entry and leaves the account's other computers' entries standing.
//!
//! The root comes from [`crate::account_keys`]. Which one this computer may
//! publish under depends on what the Hub already names for the account:
//!
//! - nothing: this is the account's first computer, so it mints the account's
//!   keys, publishes, and then announces the root;
//! - the root this computer holds: it publishes;
//! - this computer's own install key, for the account that claimed it: that key
//!   is not adopted (DR-0361 §3). The account moves to fresh keys, and the
//!   install key signs the hand-over to them;
//! - anything else: another computer holds the account's root, and this one
//!   publishes nothing until it is enrolled from there.
//!
//! The entry is published before the root is announced, so a reader the Hub
//! points at the root always finds an entry there (ADR 0133 §2).

use gaugedesk_directory_protocol::{RootTransition, SignedDirectoryPut};
use serde_json::{json, Value};

use crate::account_keys::AccountKeys;
use crate::directory_sync::FetchedRecord;
use crate::net_http::HttpClient;
use crate::project_owner::ProjectOwner;
use crate::{LockUnpoisoned, SharedWorkbench, Workbench};

/// What the Hub's account directory projection says about the account.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Projection {
    /// The root the Hub names, if any.
    pub root: Option<String>,
    /// Whether the Hub keeps signed root hand-overs (#1200). A Hub that does
    /// not would replace a root outright, and every reader that pinned the old
    /// one would read the change as a substitution.
    pub keeps_hand_overs: bool,
}

impl Projection {
    pub fn from_json(value: &Value) -> Self {
        Self {
            root: value
                .get("root_pubkey")
                .and_then(Value::as_str)
                .filter(|root| !root.is_empty())
                .map(str::to_owned),
            keeps_hand_overs: value.get("transitions").is_some_and(Value::is_array),
        }
    }
}

/// How the root is told to the Hub after this computer has published.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Announce {
    /// The Hub already names this root.
    Nothing,
    /// The Hub names no root yet.
    Root,
    /// The Hub names this computer's install key; that key signs the hand-over.
    HandOverFromInstall,
}

/// What this computer does for an account, from what it holds and what the
/// Hub names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootStep {
    Publish {
        mint: bool,
        announce: Announce,
    },
    /// Another computer holds the account's root.
    NeedsEnrollment,
    /// The account must move off this computer's install key, and the Hub
    /// cannot keep the hand-over yet.
    HubPredatesHandOvers,
}

/// Decide, without I/O. `install_root` is this computer's install key and
/// `install_owner` whether the account owns the install's account scope.
pub fn plan(
    projected: &Projection,
    held_root: Option<&str>,
    install_root: &str,
    install_owner: bool,
) -> RootStep {
    let moving_off_install = install_owner
        && projected.root.as_deref() == Some(install_root)
        && !install_root.is_empty();
    match (projected.root.as_deref(), held_root) {
        (None, held) => RootStep::Publish {
            mint: held.is_none(),
            announce: Announce::Root,
        },
        (Some(named), Some(held)) if named == held => RootStep::Publish {
            mint: false,
            announce: Announce::Nothing,
        },
        _ if moving_off_install && !projected.keeps_hand_overs => RootStep::HubPredatesHandOvers,
        (_, held) if moving_off_install => RootStep::Publish {
            mint: held.is_none(),
            announce: Announce::HandOverFromInstall,
        },
        _ => RootStep::NeedsEnrollment,
    }
}

/// The name this computer's entry carries under the account root: its device
/// key, which the root's delegation binds.
pub fn device_name(keys: &AccountKeys) -> String {
    keys.device.public_key().as_str().to_owned()
}

/// The generation this computer's next entry takes: one past its latest,
/// published or withdrawn, among the root's entries.
pub fn next_generation(entries: &[FetchedRecord], device: &str) -> Option<u64> {
    entries
        .iter()
        .filter(|record| record.entry.device == device)
        .map(|record| record.entry.generation)
        .max()
        .unwrap_or(0)
        .checked_add(1)
}

impl Workbench {
    /// The routes this computer serves for `account`'s projects.
    fn account_routes_served_here(&self, account: &str) -> Vec<crate::home::OpaqueHomeRoute> {
        let home = self.home_id().clone();
        let legacy = self.legacy_project_owner();
        let owned = |project: &str| {
            self.library.projects.get(project).is_some_and(|record| {
                record.home_id == home
                    && self.project_owner_with(record, &legacy)
                        == ProjectOwner::Account(account.to_owned())
            })
        };
        crate::account::Account::rebuild_in(self.store_ref(), crate::account::ACCOUNT_SCOPE)
            .map(|state| state.home_routes)
            .unwrap_or_default()
            .into_values()
            .filter(|record| {
                record.op == crate::account::RecordOp::Upsert
                    && record.home_id == home
                    && owned(&record.id)
            })
            .map(|record| self.placed(record.into()))
            .collect()
    }

    /// `route` with its project's signed placement and this host's signed
    /// locator (DR-0370), when the project has an authority key here. A
    /// project without one keeps the route the account's root alone speaks for.
    pub(crate) fn placed(
        &self,
        route: crate::home::OpaqueHomeRoute,
    ) -> crate::home::OpaqueHomeRoute {
        let (Ok(project), Ok(host)) = (
            self.project_signing_key(&route.project),
            self.host_signing_key(),
        ) else {
            return route;
        };
        gaugedesk_directory_protocol::sign_placement(route.clone(), &project, &host)
            .unwrap_or(route)
    }

    /// This host's own signing key, which signs where its Home is reachable
    /// (DR-0361 §5, DR-0370 §4). Apart from the relay's TLS identity, which
    /// cannot sign, and from the install's governance key.
    pub(crate) fn host_signing_key(
        &self,
    ) -> std::io::Result<gaugedesk_core::signature::SigningKey> {
        if self.root_path().as_os_str().is_empty() {
            return Err(std::io::Error::other("no key store for a host signing key"));
        }
        crate::key_store::FileKeyStore::new(self.root_path().join("keys")).random_signing_key(
            &gaugedesk_core::ids::AuthorityId::new(format!("{}::host", self.authority().as_str())),
        )
    }

    /// Give each of `account`'s projects served here an authority key, so its
    /// routes can carry the project's own placement. A project whose key
    /// cannot be made keeps the route the root alone speaks for.
    fn ensure_served_project_authorities(&mut self, account: &str) {
        let home = self.home_id().clone();
        let legacy = self.legacy_project_owner();
        let owned: Vec<String> = self
            .library
            .projects
            .values()
            .filter(|record| {
                record.home_id == home
                    && self.project_owner_with(record, &legacy)
                        == ProjectOwner::Account(account.to_owned())
            })
            .map(|record| record.id.clone())
            .collect();
        for project in owned {
            if self.project_signing_key(&project).is_err() {
                if let Err(error) = self.initialize_project_authority(&project) {
                    tracing::debug!("a project's authority key could not be made: {error}");
                }
            }
        }
    }

    /// This computer's entry for `account` at `generation`, signed by the
    /// account's root, its state sealed under the account's own key.
    pub fn account_signed_entry(
        &self,
        account: &str,
        keys: &AccountKeys,
        generation: u64,
    ) -> Option<SignedDirectoryPut> {
        let scope = self.desktop_account_store_scope(account);
        let state = crate::account::Account::rebuild_in(self.store_ref(), &scope).ok()?;
        let mut entry = crate::directory_sync::signed_put(
            &keys.root,
            keys.account_key,
            &state,
            generation,
            Vec::new(),
            self.account_routes_served_here(account),
        )?
        .entry;
        entry.device = device_name(keys);
        gaugedesk_directory_protocol::sign_entry(entry, &keys.root).ok()
    }

    /// Whether `account` owns the install's account scope: the claimant of a
    /// claimed computer, whose root the install key has been.
    fn owns_install_scope(&self, account: &str) -> bool {
        self.install_scope_owner()
            .or_else(|| self.home_owner_account())
            .is_some_and(|owner| owner == account)
    }
}

/// What publishing did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Published {
    /// This computer's entry is published under the account's root.
    Entry {
        root: String,
        generation: u64,
        announced: bool,
    },
    NeedsEnrollment,
    HubPredatesHandOvers,
}

/// The account's root's entries, withdrawn ones included, so a computer finds
/// its own latest generation.
fn root_entries(
    http: &HttpClient,
    directory: &str,
    root: &str,
) -> Result<Vec<FetchedRecord>, String> {
    let url = format!(
        "{}/directory/{root}/entries",
        directory.trim_end_matches('/')
    );
    let (status, body) = http.get_string_headers(&url, &[])?;
    match status {
        200..=299 => {
            #[derive(serde::Deserialize)]
            struct Listed {
                puts: Vec<String>,
            }
            let listed: Listed =
                serde_json::from_str(&body).map_err(|e| format!("parse entries: {e}"))?;
            listed
                .puts
                .iter()
                .map(|put| {
                    serde_json::from_str::<SignedDirectoryPut>(put)
                        .map(|put| FetchedRecord {
                            entry: put.entry,
                            signature: Some(put.signature),
                        })
                        .map_err(|e| format!("parse entry: {e}"))
                })
                .collect()
        }
        404 => Err("the directory does not keep an entry per computer yet".to_owned()),
        _ => Err(format!("directory entries HTTP {status}: {body}")),
    }
}

/// Publish `account`'s entry from this computer, minting the account's keys on
/// its first computer. Blocking; run off the async runtime. `hub` and `bearer`
/// are the account's Hub session, `directory` the blind directory's origin.
pub fn publish_from_here(
    wb: &SharedWorkbench,
    account: &str,
    hub: &str,
    bearer: &str,
    directory: &str,
) -> Result<Published, String> {
    let http = HttpClient::new();
    let headers = [("authorization".to_owned(), format!("Bearer {bearer}"))];
    let projection = match http.get_string_headers(&format!("{hub}/account/directory"), &headers)? {
        (200, body) => Projection::from_json(
            &serde_json::from_str(&body).map_err(|e| format!("parse projection: {e}"))?,
        ),
        (404, _) => Projection::default(),
        (status, body) => return Err(format!("account directory HTTP {status}: {body}")),
    };
    let now = now_secs();
    let (held, install_root, install_owner) = {
        let guard = wb.lock_unpoisoned();
        (
            guard
                .account_key_store()
                .held(account, now)
                .map_err(|e| format!("read the account's keys: {e}"))?,
            guard.governance_public_key().as_str().to_owned(),
            guard.owns_install_scope(account),
        )
    };
    let held_root = held
        .as_ref()
        .map(|keys| keys.root.public_key().as_str().to_owned());
    let step = plan(
        &projection,
        held_root.as_deref(),
        &install_root,
        install_owner,
    );
    let RootStep::Publish { mint, announce } = step else {
        return Ok(match step {
            RootStep::NeedsEnrollment => Published::NeedsEnrollment,
            _ => Published::HubPredatesHandOvers,
        });
    };
    let keys = match held {
        Some(keys) => keys,
        None if mint => wb
            .lock_unpoisoned()
            .account_key_store()
            .mint(account, now)
            .map_err(|e| format!("mint the account's keys: {e}"))?,
        None => return Err("the account's keys are missing".to_owned()),
    };
    let root = keys.root.public_key().as_str().to_owned();
    let device = device_name(&keys);
    let generation = next_generation(&root_entries(&http, directory, &root)?, &device)
        .ok_or_else(|| "this computer's directory generation is exhausted".to_owned())?;
    let put = {
        let mut guard = wb.lock_unpoisoned();
        guard.ensure_served_project_authorities(account);
        guard
            .account_signed_entry(account, &keys, generation)
            .ok_or_else(|| "this computer's entry could not be signed".to_owned())?
    };
    crate::directory_sync::publish(&http, directory, &put)?;

    let transition = match announce {
        Announce::Nothing => {
            return Ok(Published::Entry {
                root,
                generation,
                announced: false,
            })
        }
        Announce::Root => None,
        Announce::HandOverFromInstall => Some(install_hand_over(wb, &root)?),
    };
    let mut body = json!({ "root_pubkey": root, "origin": directory });
    if let Some(transition) = transition {
        body["transition"] = serde_json::to_value(transition).map_err(|e| e.to_string())?;
    }
    // This computer's device key proves an enrolled device of the account is
    // publishing (ADR 0133 §2). A Hub that issues no challenge yet takes the
    // root without one.
    if let Ok((200, answer)) = http.post_json_headers(
        &format!("{hub}/account/directory/challenge"),
        &headers,
        "{}",
    ) {
        let challenge = serde_json::from_str::<Value>(&answer)
            .ok()
            .and_then(|value| value.get("challenge")?.as_str().map(str::to_owned))
            .ok_or_else(|| "the Hub's publication challenge is malformed".to_owned())?;
        let proof =
            crate::root_publication::prove(&challenge, &root, &keys.device, &keys.delegation);
        body["proof"] = serde_json::to_value(proof).map_err(|e| e.to_string())?;
    }
    let announced = matches!(
        http.post_json_headers(
            &format!("{hub}/account/directory"),
            &headers,
            &body.to_string()
        ),
        Ok((200..=299, _))
    );
    Ok(Published::Entry {
        root,
        generation,
        announced,
    })
}

/// The install key's signed hand-over to the account's fresh root.
fn install_hand_over(wb: &SharedWorkbench, to: &str) -> Result<RootTransition, String> {
    let install = {
        let guard = wb.lock_unpoisoned();
        crate::key_store::FileKeyStore::new(guard.root_path().join("keys"))
            .existing_signing_key(guard.authority())
            .map_err(|e| format!("read this computer's install key: {e}"))?
    };
    gaugedesk_directory_protocol::sign_root_transition(to, now_secs() * 1000, &install)
        .map_err(|e| format!("sign the hand-over: {e}"))
}

/// Withdraw this computer's entry for `account`. `Ok(false)` when it holds no
/// keys for the account or has no live entry. Blocking.
pub fn withdraw_from_here(
    wb: &SharedWorkbench,
    account: &str,
    directory: &str,
) -> Result<bool, String> {
    let Some(keys) = wb
        .lock_unpoisoned()
        .account_key_store()
        .held(account, now_secs())
        .map_err(|e| format!("read the account's keys: {e}"))?
    else {
        return Ok(false);
    };
    let http = HttpClient::new();
    let root = keys.root.public_key().as_str().to_owned();
    let device = device_name(&keys);
    let entries = root_entries(&http, directory, &root)?;
    let live = entries
        .iter()
        .filter(|record| record.entry.device == device)
        .max_by_key(|record| record.entry.generation)
        .is_some_and(|record| !record.entry.retracted);
    if !live {
        return Ok(false);
    }
    let generation = next_generation(&entries, &device)
        .ok_or_else(|| "this computer's directory generation is exhausted".to_owned())?;
    let entry = gaugedesk_directory_protocol::device_retraction_entry(root, device, generation);
    let put = gaugedesk_directory_protocol::sign_entry(entry, &keys.root)
        .map_err(|e| format!("sign the withdrawal: {e}"))?;
    crate::directory_sync::publish(&http, directory, &put)?;
    Ok(true)
}

/// Publish `account`'s entry from this computer in the background, after it
/// signs in or what it serves changes. Each outcome is logged by its kind
/// alone. Unit tests drive [`publish_from_here`] against a stand-in instead,
/// so no test reaches a real Hub.
pub fn spawn_publish(wb: &SharedWorkbench, account: &str) {
    if cfg!(test) || !wb.lock_unpoisoned().desktop_account_mode() {
        return;
    }
    let Some(hub) = crate::account_signin::hub_base() else {
        return;
    };
    let Some(bearer) = crate::account_signin::hub_session_token_for(wb, account) else {
        return;
    };
    let (wb, account) = (wb.clone(), account.to_owned());
    std::thread::spawn(move || {
        let directory = crate::directory_sync::directory_url_from_env();
        match publish_from_here(&wb, &account, &hub, &bearer, &directory) {
            Ok(Published::Entry { generation, .. }) => {
                tracing::info!("published this computer's entry for an account at generation {generation}")
            }
            Ok(Published::NeedsEnrollment) => tracing::info!(
                "another computer holds this account's root; this one publishes once enrolled from it"
            ),
            Ok(Published::HubPredatesHandOvers) => tracing::info!(
                "the Hub cannot keep a root hand-over yet; this account stays on the install key"
            ),
            Err(error) => tracing::warn!("could not publish this computer's entry: {error}"),
        }
    });
}

/// Withdraw `account`'s entry from this computer in the background, as it
/// signs out.
pub fn spawn_withdraw(wb: &SharedWorkbench, account: &str) {
    if cfg!(test) || !wb.lock_unpoisoned().desktop_account_mode() {
        return;
    }
    let (wb, account) = (wb.clone(), account.to_owned());
    std::thread::spawn(move || {
        let directory = crate::directory_sync::directory_url_from_env();
        if let Err(error) = withdraw_from_here(&wb, &account, &directory) {
            tracing::warn!("could not withdraw this computer's entry: {error}");
        }
    });
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
#[path = "account_publish_tests.rs"]
mod tests;
