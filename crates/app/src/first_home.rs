//! Signing in on a computer makes it your first Home (DR-0183).
//!
//! `specs/experience/desk.md` promises that installing GaugeDesk and signing in
//! makes that computer the person's first Home, "which desk will then open".
//! The page saying so shipped in August 2026; this is the half that makes it
//! true.
//!
//! Two things here are easy to get wrong and expensive to get wrong.
//!
//! **It writes to the hosted authority, not to local state.** The desktop
//! serves `/account/homes` from its own store, and desk reads the authority's.
//! A Home registered locally is invisible to desk forever, which is exactly the
//! state a person met after signing in successfully. `account_signin.rs` says
//! why this is deliberate rather than an oversight — "adding a hosted operation
//! requires adding its native custody boundary deliberately too" — so these two
//! operations are added on purpose and nothing else came with them.
//!
//! **It reconciles; it is not an event handler.** `supervise_home_reachability`
//! learned this already and wrote it down: a hook on the moment something
//! changes misses every other path into the same state, and the failure is a
//! Home that stays unreachable with nothing saying why. So this compares what
//! the authority holds against what this Home actually is, and is called
//! whenever the answer could have changed — a leg parking, an epoch rotating.
//! Calling it twice costs two GETs and writes nothing.

use crate::net_http::HttpClient;
use crate::{LockUnpoisoned, SharedWorkbench};

/// The facility that publication and therefore reachability follow (ADR 0131
/// §6). Attached when a person signs in, because the page that sent them here
/// already told them that signing in is what makes this computer their Home —
/// asking again immediately afterwards would be asking them to confirm
/// something they were just told they had done (DR-0183 §2).
pub const LIBRARY_SYNC_FACILITY_ID: &str = "library-sync";

/// Attach `library_sync` if it is not already active. Idempotent, and returns
/// whether it wrote, so a caller can say so once rather than on every pass.
pub fn attach_library_sync(wb: &SharedWorkbench) -> Result<bool, String> {
    let mut guard = wb.lock_unpoisoned();
    if guard.library_sync_active() {
        return Ok(false);
    }
    let record = crate::facility::FacilityRecord {
        id: LIBRARY_SYNC_FACILITY_ID.to_owned(),
        op: crate::account::RecordOp::Upsert,
        kind: crate::facility::FacilityKind::LibrarySync,
        owner: crate::facility::FacilityOwner::Person,
        status: crate::facility::FacilityStatus::Active,
        display_name: "Library sync".to_owned(),
        ..Default::default()
    };
    guard
        .upsert_account_facility(&record)
        .map_err(|error| format!("attach library sync: {error:?}"))?;
    Ok(true)
}

/// The marker recording that this computer has been offered as a Home once.
///
/// A file under the control-plane root, and deliberately not an account record:
/// the fact is about this computer, and an account record would sync to the
/// person's other computers through the very facility it is deciding whether to
/// attach — suppressing the same catch-up on each of them.
const OFFERED_MARKER: &str = "first-home-offered";

/// Attach `library_sync` on a computer that is signed in and has never been
/// offered as a Home.
///
/// The attach above is called when a person signs in, and that is the moment the
/// page they came from described. But a hook on a transition reaches only the
/// computers that cross it, and a desktop that was already signed in when this
/// shipped never signs in again — so it never becomes a Home, and nothing says
/// why. That is precisely the state this module exists to end, arriving through
/// the one door the sign-in hook does not cover, and it is the state every
/// existing install upgrades into. So the question is asked from state here as
/// well, which is what the rest of this module already does.
///
/// The condition is deliberately not `!library_sync_active()`, and not the
/// absence of a facility record either. Detaching library sync tombstones the
/// record, so the projection it rebuilds into is indistinguishable from a fresh
/// install's — a reconcile keyed on either one re-attaches what the person just
/// turned off, on the next wake, which the detach's own publication change
/// causes immediately. So what is recorded is that the question was asked.
pub fn attach_if_never_offered(
    wb: &SharedWorkbench,
    root: &std::path::Path,
) -> Result<bool, String> {
    // Taken before the guard: reading the session locks the workbench itself.
    // No session is the ordinary state of a fresh install, not a failure, and
    // leaves the marker unwritten so that signing in later is still the moment.
    if crate::account_signin::hub_session_actor(wb).is_none() {
        return Ok(false);
    }
    let marker = root.join(OFFERED_MARKER);
    if marker.exists() {
        return Ok(false);
    }
    // Attached first: a marker written before a failed attach would retire the
    // question permanently and leave the Home unregistered, which is the defect
    // this function exists to repair. A failure here is retried on the next
    // wake, and an attach whose marker does not land is found active then and
    // reported once.
    let wrote = attach_library_sync(wb)?;
    std::fs::write(&marker, b"").map_err(|error| {
        format!(
            "record the first-Home offer at {}: {error}",
            marker.display()
        )
    })?;
    Ok(wrote)
}

/// What the authority should be told about this Home, as of now.
struct Standing {
    hub: String,
    bearer: String,
    home_id: String,
    root_pubkey: String,
    locator: crate::home::OpaqueRelayLocator,
}

fn standing(
    wb: &SharedWorkbench,
    route: &gaugedesk_relay_transport::RelayRoute,
) -> Option<Standing> {
    let hub = crate::account_signin::hub_base()?;
    // No session means nobody has signed in on this computer, which is not a
    // failure: it is the ordinary state of a fresh install, and the reconcile
    // simply has nothing to say yet.
    let bearer = crate::account_signin::hub_session_token(wb)?;
    let guard = wb.lock_unpoisoned();
    Some(Standing {
        hub,
        bearer,
        home_id: guard.home_id().as_str().to_owned(),
        root_pubkey: guard.governance_public_key().as_str().to_owned(),
        locator: crate::home_reachability::locator_of(route),
    })
}

fn auth(bearer: &str) -> Vec<(String, String)> {
    vec![("Authorization".to_owned(), format!("Bearer {bearer}"))]
}

/// Tell the authority which root signs this account's directory record, unless
/// it already knows the same one (DESK-5f).
///
/// The route cannot check that the caller holds the root and does not pretend
/// to; the defence is that a browser pins the first key it sees and refuses a
/// later change (ADR 0132 §2). What this closes is that nothing was publishing
/// at all, so a browser had no key to pin and no address to fetch from — the
/// directory is addressed BY the root key.
fn publish_root(http: &HttpClient, s: &Standing) -> Result<bool, String> {
    let url = format!("{}/account/directory", s.hub);
    if let Ok((200, body)) = http.get_string_headers(&url, &auth(&s.bearer)) {
        if serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("root_pubkey")?.as_str().map(str::to_owned))
            .is_some_and(|known| known == s.root_pubkey)
        {
            return Ok(false);
        }
    }
    let body = serde_json::json!({
        "root_pubkey": s.root_pubkey,
        "origin": crate::directory_sync::DIRECTORY_URL,
    });
    match http.post_json_headers(&url, &auth(&s.bearer), &body.to_string()) {
        Ok((status, _)) if (200..300).contains(&status) => Ok(true),
        Ok((status, body)) => Err(format!("publish root key: HTTP {status}: {body}")),
        Err(error) => Err(format!("publish root key: {error}")),
    }
}

/// Register this computer as a Home on the account, with the locator it is
/// currently reachable at, and select it when the account has selected none.
///
/// Re-registers when the published locator differs from the live one. The relay
/// proof rotates on a timer, and a Home whose published proof is stale is a Home
/// desk cannot reach — so "already registered" is not the question; "registered
/// as what it now is" is.
fn register_home(http: &HttpClient, s: &Standing) -> Result<bool, String> {
    let url = format!("{}/account/homes", s.hub);
    let mut selected_is_set = false;
    if let Ok((200, body)) = http.get_string_headers(&url, &auth(&s.bearer)) {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&body) {
            selected_is_set = value
                .get("selected_home")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|id| !id.is_empty());
            let current = value
                .get("homes")
                .and_then(serde_json::Value::as_array)
                .and_then(|homes| {
                    homes
                        .iter()
                        .find(|home| {
                            home.get("id").and_then(serde_json::Value::as_str)
                                == Some(s.home_id.as_str())
                        })
                        .cloned()
                });
            if let Some(home) = current {
                let published = home.get("relay").and_then(|relay| {
                    serde_json::from_value::<crate::home::OpaqueRelayLocator>(relay.clone()).ok()
                });
                if published.as_ref() == Some(&s.locator) && selected_is_set {
                    return Ok(false);
                }
            }
        }
    }
    let body = serde_json::json!({
        "id": s.home_id,
        "kind": "registered",
        // Empty on purpose: this Home is reachable through the relay, not at a
        // public address of its own, and `valid_reachability` accepts exactly
        // that pairing.
        "endpoint": "",
        "relay": s.locator,
        "selected": !selected_is_set,
    });
    match http.post_json_headers(&url, &auth(&s.bearer), &body.to_string()) {
        Ok((status, _)) if (200..300).contains(&status) => Ok(true),
        Ok((status, body)) => Err(format!("register Home: HTTP {status}: {body}")),
        Err(error) => Err(format!("register Home: {error}")),
    }
}

/// Publish this account's routes to the blind directory, if what is there is not
/// already this Home at the locator it is reachable at right now.
///
/// This is the third link, and without it the first two are a promise to a page
/// that then fetches nothing: desk pins the announced root key and reads the
/// directory AT that key, so a registered Home whose routes were never published
/// is a browser holding an address for a 404. Until this existed the publish
/// happened only when a person drove `POST /account/library-sync` by hand, and
/// nothing in the sign-in path ever did — the record was simply absent.
///
/// It is skipped when the directory already carries this Home at this epoch,
/// because a publish always takes the next generation: republishing on every
/// restart would walk the generation up for no change, and the fence exists to
/// order real ones.
fn publish_directory(wb: &SharedWorkbench, s: &Standing) -> Result<bool, String> {
    let base = crate::directory_sync::directory_url_from_env();
    let http = HttpClient::new();
    let head = crate::directory_sync::fetch(&http, &base, &s.root_pubkey)?;
    let current = head
        .as_ref()
        .filter(|record| !record.entry.retracted)
        .map(|record| {
            let mine = record
                .entry
                .directory
                .home_routes
                .iter()
                .filter(|route| route.home_id.as_str() == s.home_id);
            let mut any = false;
            let all_current = mine
                .inspect(|_| any = true)
                .all(|route| route.relay.as_ref() == Some(&s.locator));
            any && all_current
        })
        .unwrap_or(false);
    if current {
        return Ok(false);
    }
    crate::directory_sync::publish_current(wb, &base, &s.root_pubkey)
        .map(|published| {
            if let Some(reason) = published.declined {
                eprintln!("[first-home] published without reconciling against the head: {reason}");
            }
            true
        })
        .map_err(|error| format!("publish routes to the directory: {error}"))
}

/// Bring the authority's picture of this Home up to date. Called when a relay
/// leg parks and on every rotation; does nothing when nobody has signed in.
///
/// Errors are reported and not propagated: a Home that cannot reach the
/// authority is still a working Home for the person sitting at it, and failing
/// the local control plane over it would be the wrong trade. Saying nothing
/// would be worse — an unreachable Home with a silent cause is the exact state
/// this whole decision exists to end.
pub fn reconcile(wb: &SharedWorkbench, route: &gaugedesk_relay_transport::RelayRoute) {
    let Some(s) = standing(wb, route) else {
        return;
    };
    let http = HttpClient::new();
    // In this order, deliberately (DESK-5f, ADR 0133 §2): the announcement below
    // tells a browser to read the directory at this root, so announcing before
    // the record exists points every reader at a 404 and makes a working account
    // look broken. `post_library_sync_publish` has always said so; this path was
    // announcing first.
    match publish_directory(wb, &s) {
        Ok(true) => eprintln!(
            "[first-home] published this Home's project routes to the directory at epoch {}",
            s.locator.route_epoch,
        ),
        Ok(false) => {}
        Err(error) => eprintln!("[first-home] {error}"),
    }
    match publish_root(&http, &s) {
        Ok(true) => eprintln!("[first-home] published the account root key for desk to pin"),
        Ok(false) => {}
        Err(error) => eprintln!("[first-home] {error}"),
    }
    match register_home(&http, &s) {
        Ok(true) => eprintln!(
            "[first-home] registered {} at epoch {} — desk can open this computer now",
            s.home_id, s.locator.route_epoch,
        ),
        Ok(false) => {}
        Err(error) => eprintln!("[first-home] {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The facility is what publication and reachability follow, so "signing in
    /// makes this computer your Home" is false unless signing in attaches it.
    /// This is the assertion that the promise on the desk page is kept.
    #[test]
    fn attaching_turns_publication_on_and_is_idempotent() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        assert!(
            !wb.lock_unpoisoned().library_sync_active(),
            "a fresh install publishes nothing until someone signs in",
        );
        assert!(
            attach_library_sync(&wb).expect("attach"),
            "the first call writes"
        );
        assert!(
            wb.lock_unpoisoned().library_sync_active(),
            "after signing in, this Home authors and publishes its reachability",
        );
        assert!(
            !attach_library_sync(&wb).expect("attach again"),
            "a second pass writes nothing: this reconciles rather than churning the log",
        );
    }

    /// A desktop that was already signed in when this shipped is the install
    /// every existing person has, and the sign-in hook cannot reach it. Without
    /// this the promise stays false on exactly the computers that have been
    /// waiting for it longest.
    #[test]
    fn a_computer_already_signed_in_still_becomes_a_home() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        assert!(
            !attach_if_never_offered(&wb, root.path()).expect("no session"),
            "with nobody signed in there is nothing to attach",
        );
        assert!(
            !root.path().join(OFFERED_MARKER).exists(),
            "and the question is left open, so signing in later is still the moment",
        );
        crate::account_signin::store_session_for_test(&wb);
        assert!(
            attach_if_never_offered(&wb, root.path()).expect("attach"),
            "an upgrade finds the session already there and attaches anyway",
        );
        assert!(wb.lock_unpoisoned().library_sync_active());
        assert!(
            !attach_if_never_offered(&wb, root.path()).expect("again"),
            "and says so once, not on every pass of the reconcile loop",
        );
    }

    /// Detaching library sync is an answer to this question, so the reconcile
    /// must not keep asking it. A tombstoned facility rebuilds into a
    /// projection identical to a fresh install's, and the loop wakes on the
    /// publication change the detach itself causes — so getting this wrong
    /// overrules the person within a moment of their turning it off.
    #[test]
    fn a_detached_home_is_not_re_attached() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        crate::account_signin::store_session_for_test(&wb);
        assert!(attach_if_never_offered(&wb, root.path()).expect("attach"));
        wb.lock_unpoisoned()
            .revoke_account_facility(LIBRARY_SYNC_FACILITY_ID)
            .expect("detach");
        assert!(
            !wb.lock_unpoisoned().library_sync_active(),
            "the detach took effect",
        );
        assert!(
            wb.lock_unpoisoned()
                .account_facilities()
                .unwrap()
                .get(LIBRARY_SYNC_FACILITY_ID)
                .is_none(),
            "and left nothing behind to tell it apart from a fresh install",
        );
        assert!(
            !attach_if_never_offered(&wb, root.path()).expect("reconcile"),
            "a person who turned this off is not overruled on the next wake",
        );
        assert!(!wb.lock_unpoisoned().library_sync_active());
    }

    /// Nobody has signed in on a fresh install, and that is the ordinary state
    /// rather than a failure. `standing` returning `None` is what keeps
    /// `reconcile` from being a source of noise on every rotation before a
    /// person ever arrives.
    #[test]
    fn nothing_is_claimed_before_anyone_signs_in() {
        let root = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(root.path()).unwrap();
        let identity =
            gaugedesk_relay_transport::TlsIdentity::load_or_generate(root.path()).unwrap();
        let config = gaugedesk_relay_transport::HomeRelayConfig::load_or_mint(
            root.path(),
            "wss://relay.example",
        )
        .unwrap();
        let route = config.relay_route(&identity).unwrap();
        assert!(
            standing(&wb, &route).is_none(),
            "with no account session there is nothing to tell the authority",
        );
    }
}
