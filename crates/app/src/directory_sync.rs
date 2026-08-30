//! Library sync — the account-side **blind-directory client** (`ADR 0054` / the `library_sync`
//! facility, `ADR 0077`). The device holding the account root key publishes its **sealed account
//! blob** + a **readable directory record** to the always-on blind directory
//! ([`crate::account::AccountBlob`] / [`crate::account::DirectoryRecord`]), so the person's other
//! (enrolled) devices can pull their account state — devices, settings, the sealed linked model
//! key — even with the first machine off. The directory stores the blob **opaquely** (`INV-10`);
//! only a device holding the shared account key can open it.
//!
//! This is the **client** half of the deployed directory *service* (`gaugewright-directory`,
//! `PUT/GET /directory/:root`): it signs the publish with the root key (only the root may
//! overwrite its own record) and fetches the opaque record back. The wire shapes
//! ([`DirectoryEntry`] / [`SignedDirectoryPut`] / [`signing_bytes`]) mirror the service exactly —
//! same [`DirectoryRecord`] + `serde_json`, so the signatures agree — and are the canonical
//! definitions the service should import (a byte-compatible unify is owed).
//!
//! It runs where the **root key lives** — the desktop workbench (the hosted hub authenticates a
//! person via OIDC and holds no sovereign keypair, so it does not publish). The facility flag in
//! the person's account scope says whether sync is on.

use gaugedesk_core::signature::{Signature, SigningKey};
pub use gaugedesk_directory_protocol::{
    put_verifies, signing_bytes, DirectoryEntry, SignedDirectoryPut,
};

use crate::account::{directory_record, seal_account_blob, Account};
use crate::key_store::KeyStore; // brings the `signing_key` trait method into scope
use crate::net_http::HttpClient;

/// Build the signed publish for the account rooted at `signing_key`: seal the account blob under
/// the account `key`, assemble the readable directory record (root pubkey + active device
/// pubkeys + placement pointers), and sign it with the root key. Pure (no I/O), so it is testable
/// against the same [`verify_signature`] the service runs. `None` if the blob fails to seal.
pub fn signed_put(
    signing_key: &SigningKey,
    key: [u8; 32],
    acct: &Account,
    generation: u64,
    placement_pointers: Vec<String>,
    home_routes: Vec<crate::home::OpaqueHomeRoute>,
) -> Option<SignedDirectoryPut> {
    if generation == 0 {
        return None;
    }
    let root_pubkey = signing_key.public_key().as_str().to_string();
    let entry = DirectoryEntry {
        generation,
        directory: directory_record(&root_pubkey, acct, placement_pointers, home_routes),
        sealed_blob: seal_account_blob(key, acct)?,
        retracted: false,
    };
    gaugedesk_directory_protocol::sign_entry(entry, signing_key).ok()
}

/// Build the signed **retraction** for the account rooted at `signing_key` (ADR 0153): an
/// empty routing record + empty sealed blob marked `retracted`, signed with the root key.
/// Publishing it withdraws the account's published presence — the host folds a retracted
/// latest entry to `410 Gone`. Pure (no I/O); unlike [`signed_put`] it needs no account key
/// or state (a retraction discloses nothing beyond the already-public root pubkey), so it can
/// be signed even as the account is being erased. `None` for the read-only `generation == 0`.
pub fn signed_retract(signing_key: &SigningKey, generation: u64) -> Option<SignedDirectoryPut> {
    if generation == 0 {
        return None;
    }
    let root_pubkey = signing_key.public_key().as_str().to_string();
    let entry = gaugedesk_directory_protocol::retraction_entry(root_pubkey, generation);
    gaugedesk_directory_protocol::sign_entry(entry, signing_key).ok()
}

/// Publish a signed record to the blind directory (`PUT {base}/directory/:root`). `base` is the
/// directory service origin (e.g. `https://…:7901`). A non-2xx status is an error.
pub fn publish(http: &HttpClient, base: &str, put: &SignedDirectoryPut) -> Result<(), String> {
    let root = &put.entry.directory.root_pubkey;
    let url = format!("{}/directory/{}", base.trim_end_matches('/'), root);
    let body = serde_json::to_string(put).map_err(|e| format!("serialize: {e}"))?;
    let (status, resp) = http.put_json(&url, &body)?;
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(format!("directory publish HTTP {status}: {resp}"))
    }
}

/// A directory read, carrying whatever authentication the wire gave it.
///
/// The signature is optional because two wire shapes are still served (see
/// [`fetch`]) — not because it is optional to check. A record read as a bare
/// [`DirectoryEntry`] has nothing to check *against*, which is a degradation of
/// what its routing may be used for and never a licence to use it anyway; that
/// is [`route_trust`]'s job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchedRecord {
    pub entry: DirectoryEntry,
    /// The account root's signature over [`signing_bytes`] of `entry`, when the
    /// directory served the whole [`SignedDirectoryPut`].
    pub signature: Option<Signature>,
}

impl FetchedRecord {
    /// Reassemble the signed put this record was read from, so it can be handed
    /// to the one verifier ([`put_verifies`]) the directory host and the edge
    /// Worker also run. `None` for the bare-entry shape.
    fn as_signed_put(&self) -> Option<SignedDirectoryPut> {
        Some(SignedDirectoryPut {
            entry: self.entry.clone(),
            signature: self.signature.clone()?,
        })
    }
}

/// What a fetched record's **cleartext** routing may be trusted for.
///
/// The sealed blob authenticates itself — it opens only under the account key,
/// so a foreign or tampered blob simply fails to open. `directory.home_routes`
/// has no such property: it sits outside the seal, and a route carries a
/// `home_fingerprint`, which is a *pinning instruction* (ADR 0131 §3). It is
/// therefore the one part of a directory read a hostile directory could use, and
/// the only part that needs the root signature checked before it is believed.
///
/// The posture is the browser's, deliberately (`resolve-home-routes.ts`):
/// **degrade, never fail closed.** A directory too old to serve the signature, a
/// record that will not verify — each means *no signed routes*, which is an
/// ordinary state and not a broken account. The one condition that is not a
/// degradation is a record signed by a *different* root, because that is the
/// substitution the check exists to catch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteTrust {
    /// The record carried a root signature, the signature holds, and the root it
    /// names is the one this device itself holds. Its routes may be merged.
    Signed,
    /// Nothing verifiable was available, so the routing is dropped and the rest
    /// of the record still merges. The reason is structural — which check
    /// declined, never what it was carrying — because degrading *silently* is
    /// how a device can quietly stop learning any relay-only Home with nothing
    /// anywhere saying so.
    Degraded(&'static str),
    /// The record is signed by a different account root than the one this device
    /// holds. This is an alarm rather than a degradation: a self-consistent
    /// signature under an attacker's own root verifies perfectly, so the
    /// comparison against the key we hold — not the signature — is what binds
    /// the record to *this* account. The routing is still only dropped: a
    /// substitution must not also take away the reachability the person had.
    RootMismatch,
}

impl RouteTrust {
    /// Why routing was declined, when it was. `None` when it was accepted.
    pub fn declined(&self) -> Option<&'static str> {
        match self {
            RouteTrust::Signed => None,
            RouteTrust::Degraded(reason) => Some(reason),
            RouteTrust::RootMismatch => {
                Some("the directory record is signed by a different account root than this device")
            }
        }
    }
}

/// Decide what `record`'s routing may be used for, against the account root
/// pubkey this device holds.
///
/// This is the desktop's answer to ADR 0132, and it is the stronger one that
/// ADR 0132 §4 already anticipates: a browser has no authenticated channel to
/// the root key and so pins it on first sight, while this machine *holds* the
/// root key it publishes under, so it compares against the key itself rather
/// than against a remembered one. There is no first sight to trust and nothing
/// to store.
///
/// Verify first, then compare, exactly as `signed-routes.ts` does — the two
/// implementations are meant to read the same way. [`put_verifies`] checks the
/// signature against the root the entry *names*, which proves only
/// self-consistency; the comparison is what makes it mean something.
pub fn route_trust(record: &FetchedRecord, root_pubkey: &str) -> RouteTrust {
    if root_pubkey.is_empty() {
        return RouteTrust::Degraded(
            "this device holds no account root to check the record against",
        );
    }
    let Some(put) = record.as_signed_put() else {
        return RouteTrust::Degraded("the directory served a record with no root signature");
    };
    if !put_verifies(&put) {
        return RouteTrust::Degraded("the directory record failed root-signature verification");
    }
    if record.entry.directory.root_pubkey != root_pubkey {
        return RouteTrust::RootMismatch;
    }
    RouteTrust::Signed
}

/// Fetch the readable record + opaque sealed blob for `root` (`GET {base}/directory/:root`).
/// `Ok(None)` when the directory has nothing for `root` (404). The blob stays sealed — the caller
/// opens it with [`crate::account::open_account_blob`] under the account key.
///
/// **Two shapes, deliberately.** The directory served a bare [`DirectoryEntry`]
/// for this route and is moving to the whole [`SignedDirectoryPut`], because a
/// reader that cannot see the signature cannot verify anything — which is
/// exactly why a browser silently degraded to endpoint-only reachability
/// (ADR 0131 §3). Both shapes are still accepted, so the service can move
/// without stranding a desktop built before the change; what the caller gets is
/// a [`FetchedRecord`] that says which shape arrived, so the half of a record
/// that only a signature can authenticate is not used when there is none.
///
/// The two are unambiguous: a put has no `directory`/`sealed_blob` at the top
/// level and an entry has no `entry`/`signature`, so neither parses as the
/// other.
pub fn fetch(http: &HttpClient, base: &str, root: &str) -> Result<Option<FetchedRecord>, String> {
    let url = format!("{}/directory/{}", base.trim_end_matches('/'), root);
    let (status, body) = http.get_string_headers(&url, &[])?;
    match status {
        200..=299 => Ok(Some(parse_fetched_record(&body)?)),
        // A **retracted** root is served `410 Gone` (ADR 0153) with the empty retraction entry
        // as its body — it discloses nothing beyond the already-public root, so returning it to
        // the caller is safe and lets the owner read the generation (to re-publish and re-appear)
        // and the `retracted` flag (to treat a re-retraction as idempotent). A public reader
        // still sees `410`; this client authenticates by the sealed blob opening, not the status.
        410 => Ok(Some(parse_fetched_record(&body)?)),
        // No record yet — not a failure.
        404 => Ok(None),
        _ => Err(format!("directory fetch HTTP {status}: {body}")),
    }
}

fn parse_fetched_record(body: &str) -> Result<FetchedRecord, String> {
    if let Ok(put) = serde_json::from_str::<SignedDirectoryPut>(body) {
        return Ok(FetchedRecord {
            entry: put.entry,
            signature: Some(put.signature),
        });
    }
    serde_json::from_str(body)
        .map(|entry| FetchedRecord {
            entry,
            signature: None,
        })
        .map_err(|e| format!("parse entry: {e}"))
}

impl crate::Workbench {
    /// Whether the `library_sync` facility is active for this account (`ADR 0077`). The store-side
    /// gate the publish/pull halves check; sync is off unless the person attached it.
    pub fn library_sync_active(&self) -> bool {
        crate::facility::Facilities::rebuild_account(self.store_ref())
            .map(|f| f.has_active(crate::facility::FacilityKind::LibrarySync))
            .unwrap_or(false)
    }

    /// The account root pubkey this workbench publishes under (its governance key) — the directory
    /// path/identity for [`fetch`].
    pub fn library_sync_root(&self) -> String {
        self.governance_public_key().as_str().to_string()
    }

    /// The signed publish for the current account state, **iff** library sync is active — built
    /// under the workbench lock (store + root key), so the caller can then publish it over the
    /// network *off* the lock. `None` when sync is off or the blob fails to seal.
    pub fn library_sync_signed_put(&self, generation: u64) -> Option<SignedDirectoryPut> {
        if !self.library_sync_active() {
            return None;
        }
        let signing_key = crate::key_store::FileKeyStore::new(self.root_path().join("keys"))
            .signing_key(self.authority());
        let acct = Account::rebuild(self.store_ref()).ok()?;
        // Live routes this root may speak for, plus the retractions it may
        // carry onward (ADR 0155 §3). A retraction is a signed statement with
        // the same standing as the route it retracts, and travels the same way.
        let home_routes = acct
            .home_routes
            .values()
            .filter(|record| republishable(record))
            .chain(
                acct.departed_home_routes
                    .values()
                    .filter(|record| publishable_retraction(record)),
            )
            .cloned()
            .map(Into::into)
            .collect();
        signed_put(
            &signing_key,
            self.account_key(),
            &acct,
            generation,
            vec![],
            home_routes,
        )
    }

    /// The signed **retraction** for this account's directory entry (ADR 0153) — built under
    /// the workbench lock so the caller can PUT it *off* the lock, mirroring
    /// [`library_sync_signed_put`](Self::library_sync_signed_put). Unlike a publish it is not
    /// gated on the `library_sync` facility being active: a retraction withdraws whatever is
    /// published regardless of the facility's current state, so a person who has since turned
    /// sync off can still remove a live entry (and account-erase can retract it). `None` when
    /// there is no on-disk root key to sign with (a loopback/test workbench, `root_path()`
    /// empty — the same discriminator [`crate::Workbench::governance_seed`] uses) or for the
    /// read-only `generation == 0`.
    pub fn library_sync_signed_retract(&self, generation: u64) -> Option<SignedDirectoryPut> {
        if self.root_path().as_os_str().is_empty() {
            return None;
        }
        let signing_key = crate::key_store::FileKeyStore::new(self.root_path().join("keys"))
            .signing_key(self.authority());
        signed_retract(&signing_key, generation)
    }

    /// Merge a fetched directory record into the local account scope (the pull half).
    ///
    /// Two halves with two different authentications, and they are not
    /// interchangeable. The **sealed blob** — devices, credentials, homes,
    /// settings — opens only under this account's key, so a foreign or tampered
    /// blob simply fails to open and the whole pull errors. The **project→Home
    /// routes** ride in the record's cleartext, covered by neither the seal nor
    /// (on the legacy wire shape) anything at all, so they are merged only when
    /// [`route_trust`] says the record was signed by the root this device holds.
    ///
    /// Declining the routing never fails the pull: the blob half stands on its
    /// own authentication, and per ADR 0132 §3 reachability degrades rather than
    /// failing closed into unusability.
    pub fn library_sync_apply(
        &mut self,
        record: &FetchedRecord,
    ) -> Result<LibrarySyncMerge, String> {
        use crate::account::{open_account_blob, ACCOUNT_SCOPE};
        let entry = &record.entry;
        let blob = open_account_blob(self.account_key(), &entry.sealed_blob)
            .ok_or_else(|| "sealed blob did not open under this account key".to_string())?;
        let mut n = 0usize;
        for d in &blob.devices {
            if self
                .write_account_record_in(ACCOUNT_SCOPE, "device", &d.id, d)
                .is_ok()
            {
                n += 1;
            }
        }
        for c in &blob.credentials {
            if self
                .write_account_record_in(ACCOUNT_SCOPE, "credential", &c.id, c)
                .is_ok()
            {
                n += 1;
            }
        }
        for home in &blob.homes {
            if self
                .write_account_record_in(ACCOUNT_SCOPE, "home", home.id.as_str(), home)
                .is_ok()
            {
                n += 1;
            }
        }
        let routes = self.library_sync_reconcile_routes(record);
        n += routes.written - routes.retracted;
        for (id, value) in &blob.settings {
            let rec = crate::account::SettingRecord {
                id: id.clone(),
                op: crate::account::RecordOp::Upsert,
                value: value.clone(),
            };
            if self
                .write_account_record_in(ACCOUNT_SCOPE, "setting", id, &rec)
                .is_ok()
            {
                n += 1;
            }
        }
        Ok(LibrarySyncMerge {
            merged: n,
            retracted: routes.retracted,
            routes_verified: routes.declined.is_none(),
            declined: routes.declined,
        })
    }

    /// Reconcile this device's project→Home routes against a verified directory
    /// record (ADR 0154).
    ///
    /// **The record is a snapshot, not an addition.** Every other field it
    /// carries — device pubkeys, placement pointers, the sealed blob — is a
    /// whole-value replacement at each generation, and routes now read the same
    /// way. So presence upserts *and absence retracts*, which is what makes
    /// ADR 0131 §7's departure real: a Home that stops serving a project drops
    /// the route from its next snapshot, and every device folds it away.
    ///
    /// Absence is only allowed to mean that over the class the record is actually
    /// authority for — **a route naming a Home other than this one and claiming no
    /// author** (§2). The other two classes are deliberately exempt:
    ///
    /// - A route naming *this* Home is this Home's to author (§3). A pulled record
    ///   may neither create nor resurrect one, or a device pulling its own stale
    ///   record would undo its own departure.
    /// - A route carrying a proven third-party author is merged but never retracted
    ///   by absence (§4). Its retraction travels the federation channel that
    ///   delivered it, and letting a stale record retract it would make the two
    ///   channels race with the directory sometimes winning on older news.
    ///
    /// An unverified record reconciles nothing at all (§5). Fail-open is the safe
    /// direction here: not retracting costs a stale locator, retracting on an
    /// attacker's word costs a person the reachability they had.
    pub fn library_sync_reconcile_routes(&mut self, record: &FetchedRecord) -> RouteReconcile {
        use crate::account::ACCOUNT_SCOPE;
        let trust = route_trust(record, &self.library_sync_root());
        if trust != RouteTrust::Signed {
            return RouteReconcile {
                declined: trust.declined(),
                ..RouteReconcile::default()
            };
        }
        let this_home = self.home_id().clone();
        let mut reconcile = RouteReconcile::default();

        // What the record *validly* states, which is not the same as what it
        // lists: a route whose author claim does not hold is not an assertion
        // this device can read, so it neither merges nor keeps a local route
        // alive by being mentioned.
        let mut stated = std::collections::BTreeSet::new();
        for route in &record.entry.directory.home_routes {
            if !authorship_holds(route) {
                continue;
            }
            stated.insert(route.project.clone());
            if route.home_id == this_home {
                continue;
            }
            let merged = crate::account::HomeRouteRecord {
                id: route.project.clone(),
                // A proven author, no endpoint, no relay: that is a retraction,
                // and it is the same shape the federation channel already reads
                // as one (ADR 0155 §4). Folding it as a live route would state
                // something no author ever said — a route with no way to reach
                // what it names.
                op: if is_retraction_shape(route) {
                    crate::account::RecordOp::Tombstone
                } else {
                    crate::account::RecordOp::Upsert
                },
                home_id: route.home_id.clone(),
                endpoint: route.endpoint.clone(),
                relay: route.relay.clone(),
                author_authority: route.author_authority.clone(),
                author_root_pubkey: route.author_root_pubkey.clone(),
                author_signature: route.author_signature.clone(),
            };
            let carried_retraction = merged.op == crate::account::RecordOp::Tombstone;
            if self
                .write_account_record_in(ACCOUNT_SCOPE, "home_route", &merged.id, &merged)
                .is_ok()
            {
                reconcile.written += 1;
                if carried_retraction {
                    reconcile.retracted += 1;
                }
            }
        }

        let departed: Vec<crate::account::HomeRouteRecord> = Account::rebuild(self.store_ref())
            .map(|account| account.home_routes)
            .unwrap_or_default()
            .into_values()
            .filter(|held| directory_owns(held, &this_home) && !stated.contains(&held.id))
            .collect();
        for held in departed {
            let tombstone = crate::account::HomeRouteRecord {
                op: crate::account::RecordOp::Tombstone,
                ..held
            };
            if self
                .write_account_record_in(ACCOUNT_SCOPE, "home_route", &tombstone.id, &tombstone)
                .is_ok()
            {
                reconcile.written += 1;
                reconcile.retracted += 1;
            }
        }
        reconcile
    }
}

/// What a route reconcile did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RouteReconcile {
    /// Records written — merges plus tombstones.
    pub written: usize,
    /// Routes the record's silence retracted (ADR 0154 §2).
    pub retracted: usize,
    /// Why nothing was reconciled, when nothing was. `None` on a verified record.
    pub declined: Option<&'static str>,
}

/// Whether the directory record is authority for `held` — the one class whose
/// absence from a verified record retracts it (ADR 0154 §2). A route naming this
/// Home is ours to author (§3); a route proving a third-party author belongs to
/// the channel that delivered it (§4).
fn directory_owns(
    held: &crate::account::HomeRouteRecord,
    this_home: &gaugedesk_core::ids::HomeId,
) -> bool {
    held.home_id != *this_home
        && !claims_an_author(&crate::home::OpaqueHomeRoute::from(held.clone()))
}

/// What a pull merged, and what it declined.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LibrarySyncMerge {
    /// How many account records the record added or updated. Tombstones are not
    /// counted here — a retraction is not a thing merged.
    pub merged: usize,
    /// Routes the record's silence retracted (ADR 0154 §2). Reported separately
    /// because a person reading "merged 5 records" would otherwise be told a
    /// removal was an addition.
    pub retracted: usize,
    /// Whether the record's project→Home routes were verified and merged. A
    /// caller must not infer this from a route carrying a relay locator, because
    /// an account may legitimately have none.
    pub routes_verified: bool,
    /// Why routing was declined, when it was — the structural reason, never the
    /// payload. `None` when it was accepted.
    pub declined: Option<&'static str>,
}

/// Whether a route that **claims** a third-party author actually proves it.
///
/// A route with no authorship fields is this account root's own word — its own
/// Home's, or one carried out of a record this same root already signed — and
/// needs nothing further. A **shared** route (ADR 0131 §1, DESK-5d) is different:
/// the serving Home is the author and this account root only carries the proof
/// to its other clients, so an unproven claim must never be taken on the account
/// root's authority. This is the same rule the federation handoff already applies
/// at its own ingest (`federation.rs`, `HandoffMsgKind::Route`).
fn authorship_holds(route: &crate::home::OpaqueHomeRoute) -> bool {
    !claims_an_author(route) || crate::home::shared_home_route_verifies(route)
}

/// Whether a route asserts that someone other than this account root authored it.
fn claims_an_author(route: &crate::home::OpaqueHomeRoute) -> bool {
    !route.author_authority.is_empty()
        || !route.author_root_pubkey.is_empty()
        || route.author_signature.is_some()
}

/// Whether a route *is* a retraction: it names a project and a Home and offers no
/// way to reach either. This is what the federation channel signs when a Home
/// departs, and `home_route_signing_bytes` covers both fields, so the shape can be
/// neither forged nor stripped back into a live route.
fn is_retraction_shape(route: &crate::home::OpaqueHomeRoute) -> bool {
    route.endpoint.is_empty() && route.relay.is_none()
}

/// Whether a retained tombstone may be published into the directory snapshot
/// (ADR 0155 §3, §5).
///
/// Only a **proven third-party** retraction travels. A Home's own departure is
/// already published by absence under ADR 0154 §2 and needs no explicit statement;
/// putting one on the wire would say the same thing twice, and say it in the one
/// form this root has no standing to author. So the tombstone must claim an author
/// and that claim must hold — the same test its live counterpart passes.
fn publishable_retraction(record: &crate::account::HomeRouteRecord) -> bool {
    let route = crate::home::OpaqueHomeRoute::from(record.clone());
    claims_an_author(&route) && is_retraction_shape(&route) && authorship_holds(&route)
}

/// Whether this device may re-sign `record` into its next directory publish.
///
/// A publish is a snapshot of `acct.home_routes`, so every route a device holds
/// is re-attested under the account root each time it publishes. That is correct
/// for a route this Home authored and for one that arrived inside a record this
/// account's own root had already signed — both are the root restating something
/// it is entitled to say, and it is how a person's second device keeps their
/// first device's routes alive in the directory.
///
/// It is not correct for a shared route whose author proof does not hold:
/// re-signing one would convert an unverifiable third-party claim into something
/// bearing this account's own root signature — laundering, on the one wire field
/// that carries a certificate pin. The check is [`authorship_holds`], applied at
/// *both* ends deliberately. Ingest alone would leave routes merged before this
/// gate existed to be re-attested on the next publish; publish alone would leave
/// the device holding, and serving to its own federation and pool, a route it
/// refuses to stand behind.
fn republishable(record: &crate::account::HomeRouteRecord) -> bool {
    authorship_holds(&crate::home::OpaqueHomeRoute::from(record.clone()))
}

/// Canonical public blind-directory origin. Development and hermetic tests may
/// override it with `GAUGEDESK_DIRECTORY_URL`; a release never silently
/// disables account sync because an environment variable was omitted.
pub const DIRECTORY_URL: &str = "https://directory.gaugewright.com";

pub fn directory_url_from_env() -> String {
    gaugedesk_env::var("DIRECTORY_URL")
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| DIRECTORY_URL.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{open_account_blob, DeviceRecord, DeviceStatus, RecordOp, SettingRecord};

    fn seeded_account() -> Account {
        let mut a = Account::default();
        a.devices.insert(
            "phone".into(),
            DeviceRecord {
                id: "phone".into(),
                op: RecordOp::Upsert,
                label: "My phone".into(),
                subkey_pubkey: "dev-pub-1".into(),
                status: DeviceStatus::Active,
                enrolled_at: 1_700_000_000,
            },
        );
        a.settings.insert(
            "theme".into(),
            SettingRecord {
                id: "theme".into(),
                op: RecordOp::Upsert,
                value: "dark".into(),
            },
        );
        a
    }

    #[test]
    fn canonical_directory_origin_is_public_tls() {
        assert_eq!(DIRECTORY_URL, "https://directory.gaugewright.com");
    }

    fn key() -> SigningKey {
        SigningKey::from_seed(&[7u8; 32]).unwrap()
    }

    /// A fixed account (sealing) key for these tests — distinct from the signing key.
    const AKEY: [u8; 32] = [11u8; 32];
    const OTHER_AKEY: [u8; 32] = [22u8; 32];

    #[test]
    fn signed_put_verifies_under_its_own_root_key() {
        // The signature the client produces passes the exact check the directory service runs at
        // PUT — so a real publish would be accepted (and a forged one rejected).
        let k = key();
        let put = signed_put(&k, AKEY, &seeded_account(), 1, vec![], vec![]).expect("seals");
        assert_eq!(put.entry.generation, 1);
        assert_eq!(put.entry.directory.root_pubkey, k.public_key().as_str());
        assert!(put_verifies(&put), "verifies under its own root key");

        // Tampering with the entry (a different device pubkey) breaks the signature (fail-closed).
        let mut forged = put.clone();
        forged.entry.directory.device_pubkeys = vec!["attacker".into()];
        assert!(!put_verifies(&forged));
        assert!(
            signed_put(&k, AKEY, &seeded_account(), 0, vec![], vec![]).is_none(),
            "generation zero is reserved for reading legacy entries"
        );
    }

    #[test]
    fn signed_retract_verifies_and_carries_no_routing() {
        // A retraction the client signs passes the same PUT verification as a publish, so the
        // directory host accepts it — but it discloses nothing beyond the already-public root, and
        // it needs no account key or state (it can be signed as the account is being erased).
        let k = key();
        let retract = signed_retract(&k, 4).expect("signs a retraction");
        assert!(
            put_verifies(&retract),
            "retraction verifies under its own root key"
        );
        assert_eq!(retract.entry.generation, 4);
        assert_eq!(retract.entry.directory.root_pubkey, k.public_key().as_str());
        assert!(retract.entry.retracted);
        assert!(retract.entry.directory.device_pubkeys.is_empty());
        assert!(retract.entry.directory.placement_pointers.is_empty());
        assert!(retract.entry.sealed_blob.is_empty());
        assert!(
            signed_retract(&k, 0).is_none(),
            "generation zero is reserved for reading legacy entries"
        );
    }

    /// The read shape is moving from a bare entry to the whole signed put,
    /// because a reader that cannot see the signature cannot verify anything.
    /// This machine must keep working across that change in either direction —
    /// a desktop older than the service, and a service older than the desktop —
    /// and, on the newer shape, must **keep** the signature rather than dropping
    /// it on the floor, because a signature that never reaches the caller is the
    /// same as no signature at all.
    #[test]
    fn a_fetched_record_parses_whether_or_not_it_carries_its_signature() {
        let put = signed_put(&key(), AKEY, &seeded_account(), 1, vec![], vec![]).expect("seals");

        let whole = serde_json::to_string(&put).expect("serializes");
        let from_put = parse_fetched_record(&whole).expect("a signed put is readable");
        assert_eq!(from_put.entry, put.entry);
        assert_eq!(
            from_put.signature.as_ref(),
            Some(&put.signature),
            "the signature must survive the read or nothing downstream can check it"
        );

        let bare = serde_json::to_string(&put.entry).expect("serializes");
        let from_entry = parse_fetched_record(&bare).expect("a bare entry is readable");
        assert_eq!(from_entry.entry, put.entry);
        assert_eq!(from_entry.signature, None, "a bare entry carries no proof");

        // Neither shape is mistaken for the other, and neither is mistaken for
        // something that is simply not a directory read.
        assert!(parse_fetched_record("{\"nope\":1}").is_err());
    }

    /// The whole point of keeping the signature: a self-consistent record signed
    /// by an *attacker's own* root verifies perfectly, so verification alone is
    /// worthless. What binds a record to this account is the comparison against
    /// the root key this device holds (ADR 0132 §4 — enrollment supersedes the
    /// browser's trust-on-first-use pin wherever the key is actually held).
    #[test]
    fn routing_is_trusted_only_under_the_root_key_this_device_holds() {
        let mine = key();
        let root = mine.public_key().as_str().to_string();
        let put = signed_put(&mine, AKEY, &seeded_account(), 1, vec![], vec![]).expect("seals");
        let signed = FetchedRecord {
            entry: put.entry.clone(),
            signature: Some(put.signature.clone()),
        };
        assert_eq!(route_trust(&signed, &root), RouteTrust::Signed);
        assert_eq!(route_trust(&signed, &root).declined(), None);

        // The legacy wire shape: nothing to check, so nothing is believed. This
        // is a degradation and not an alarm — a directory older than this client
        // is an ordinary state.
        let unsigned = FetchedRecord {
            entry: put.entry.clone(),
            signature: None,
        };
        assert!(matches!(
            route_trust(&unsigned, &root),
            RouteTrust::Degraded(_)
        ));

        // Tampered bytes under a real signature.
        let mut tampered = signed.clone();
        tampered.entry.directory.home_routes.push(hostile_route());
        assert!(matches!(
            route_trust(&tampered, &root),
            RouteTrust::Degraded(_)
        ));

        // The attack this closes: a hostile directory serves its own perfectly
        // valid record. `put_verifies` is satisfied; the comparison is not.
        let attacker = SigningKey::from_seed(&[9u8; 32]).unwrap();
        let forged = signed_put(&attacker, AKEY, &seeded_account(), 1, vec![], vec![])
            .expect("an attacker seals their own record just as validly");
        assert!(put_verifies(&forged), "self-consistency proves nothing");
        let forged = FetchedRecord {
            entry: forged.entry,
            signature: Some(forged.signature),
        };
        assert_eq!(route_trust(&forged, &root), RouteTrust::RootMismatch);
        assert!(route_trust(&forged, &root).declined().is_some());

        // A device with no root of its own has nothing to compare against, and
        // says so rather than accepting whatever arrived.
        assert!(matches!(route_trust(&signed, ""), RouteTrust::Degraded(_)));
    }

    fn hostile_route() -> crate::home::OpaqueHomeRoute {
        crate::home::OpaqueHomeRoute {
            project: "project-forged".into(),
            home_id: gaugedesk_core::ids::HomeId::new("home:attacker"),
            endpoint: "https://attacker.example".into(),
            relay: Some(crate::home::OpaqueRelayLocator {
                endpoint: "wss://attacker.example".into(),
                handle: "a".repeat(43),
                proof: "b".repeat(43),
                route_epoch: 1,
                // The cert the client would pin — the reason routing may not be
                // taken on a directory's word (ADR 0131 §3).
                home_fingerprint: "c".repeat(64),
            }),
            author_authority: String::new(),
            author_root_pubkey: String::new(),
            author_signature: None,
        }
    }

    /// End to end through the pull: the sealed half authenticates itself and is
    /// always merged, the cleartext routing is merged only under this device's
    /// own root, and a refusal degrades rather than failing the pull.
    #[test]
    fn a_pull_merges_the_sealed_half_always_and_routes_only_when_verified() {
        use crate::account::ACCOUNT_SCOPE;
        use crate::LockUnpoisoned;

        let dir = tempfile::tempdir().unwrap();
        let shared = crate::open_workbench(dir.path()).unwrap();
        let mut guard = shared.lock_unpoisoned();

        let root_key = crate::key_store::FileKeyStore::new(guard.root_path().join("keys"))
            .signing_key(guard.authority());
        assert_eq!(
            root_key.public_key().as_str(),
            guard.library_sync_root(),
            "the key a publish signs with and the key a pull checks against are one key"
        );

        let entry = DirectoryEntry {
            generation: 1,
            directory: directory_record(
                root_key.public_key().as_str(),
                &seeded_account(),
                vec![],
                vec![hostile_route()],
            ),
            sealed_blob: seal_account_blob(guard.account_key(), &seeded_account())
                .expect("seals under this workbench's own account key"),
            retracted: false,
        };
        let routes = |guard: &crate::Workbench| {
            Account::rebuild(guard.store_ref())
                .unwrap()
                .home_routes
                .len()
        };

        // Unsigned: the legacy shape a hostile directory can also produce at
        // will. The blob still merges; the routing does not.
        let merged = guard
            .library_sync_apply(&FetchedRecord {
                entry: entry.clone(),
                signature: None,
            })
            .expect("the blob opens, so the pull succeeds");
        assert!(merged.merged > 0, "the sealed half is merged regardless");
        assert!(!merged.routes_verified);
        assert!(merged.declined.is_some(), "and it says why");
        assert_eq!(routes(&guard), 0, "no route may enter unverified");

        // Signed by someone else's root: an alarm, and still not a failure —
        // a substitution must not take away the reachability the person had.
        let attacker = SigningKey::from_seed(&[9u8; 32]).unwrap();
        let mut foreign = entry.clone();
        foreign.directory.root_pubkey = attacker.public_key().as_str().to_string();
        let foreign = gaugedesk_directory_protocol::sign_entry(foreign, &attacker).unwrap();
        let merged = guard
            .library_sync_apply(&FetchedRecord {
                entry: foreign.entry,
                signature: Some(foreign.signature),
            })
            .expect("a foreign signature does not fail the pull");
        assert!(!merged.routes_verified);
        assert_eq!(routes(&guard), 0);

        // Signed by the root this device itself holds: the routes land — but a
        // route inside it that *claims* a third-party author and cannot prove it
        // still does not, because this root's signature is not standing behind a
        // claim it was never in a position to make.
        let mut with_unproven = entry.clone();
        let mut unproven = hostile_route();
        unproven.project = "project-unproven".into();
        unproven.author_authority = "root-p256:someone-else".into();
        unproven.author_root_pubkey = "root-p256:someone-else".into();
        with_unproven.directory.home_routes.push(unproven);
        let entry = with_unproven;

        let mine = gaugedesk_directory_protocol::sign_entry(entry, &root_key).unwrap();
        let merged = guard
            .library_sync_apply(&FetchedRecord {
                entry: mine.entry,
                signature: Some(mine.signature),
            })
            .expect("merges");
        assert!(merged.routes_verified);
        assert_eq!(merged.declined, None);
        assert_eq!(
            routes(&guard),
            1,
            "the verified route is merged and the unproven claim is not"
        );
        assert!(guard
            .store_ref()
            .records(ACCOUNT_SCOPE, "home_route")
            .is_ok());
    }

    /// ADR 0155: a retraction is a signed statement with the same standing as the
    /// route it retracts, so it is retained and republished exactly like one.
    /// Before this, a recipient's tombstone folded out of the projection and had
    /// nowhere to live, so the retraction reached no other device — ever.
    #[test]
    fn a_proven_retraction_is_carried_onward_and_applied_as_one() {
        use crate::account::{RecordOp, ACCOUNT_SCOPE};
        use crate::LockUnpoisoned;

        let dir = tempfile::tempdir().unwrap();
        let shared = crate::open_workbench(dir.path()).unwrap();
        let mut guard = shared.lock_unpoisoned();
        let root_key = crate::key_store::FileKeyStore::new(guard.root_path().join("keys"))
            .signing_key(guard.authority());

        // Exactly what a serving Home signs when it departs a shared project:
        // the route, with its reachability cleared, under its own governance root.
        let serving = SigningKey::from_seed(&[5u8; 32]).unwrap();
        let retraction = crate::home::sign_home_route(
            "root-p256:serving",
            crate::home::OpaqueHomeRoute {
                project: "project-shared".into(),
                home_id: gaugedesk_core::ids::HomeId::new("home:theirs"),
                endpoint: String::new(),
                relay: None,
                author_authority: String::new(),
                author_root_pubkey: String::new(),
                author_signature: None,
            },
            &serving,
        )
        .unwrap();
        assert!(
            crate::home::shared_home_route_verifies(&retraction),
            "the retraction proves itself, so it can travel a channel that trusts nobody"
        );

        // It arrives in a record this account's own root signed, as it would
        // from a sibling device that received it over the federation channel.
        let entry = DirectoryEntry {
            generation: 1,
            directory: directory_record(
                root_key.public_key().as_str(),
                &seeded_account(),
                vec![],
                vec![retraction.clone()],
            ),
            sealed_blob: String::new(),
            retracted: false,
        };
        let put = gaugedesk_directory_protocol::sign_entry(entry, &root_key).unwrap();
        let applied = guard.library_sync_reconcile_routes(&FetchedRecord {
            entry: put.entry,
            signature: Some(put.signature),
        });

        // §4: it folds as a retraction, not as a live route with nowhere to go.
        assert_eq!(applied.retracted, 1);
        let account = Account::rebuild(guard.store_ref()).unwrap();
        assert!(
            !account.home_routes.contains_key("project-shared"),
            "a proven retraction removes the route it names"
        );

        // §1: and the departure is *retained*, which is what gives it somewhere
        // to live between arriving and being carried onward.
        let held = account
            .departed_home_routes
            .get("project-shared")
            .expect("the departure is retained, not discarded");
        assert_eq!(held.op, RecordOp::Tombstone);
        assert!(crate::home::shared_home_route_verifies(
            &crate::home::OpaqueHomeRoute::from(held.clone())
        ));

        // §3: the next publish carries it, so this account's other devices learn
        // it — the path that did not exist at all before.
        guard
            .write_account_record_in(
                ACCOUNT_SCOPE,
                "facility",
                "library-sync",
                &serde_json::json!({
                    "id": "library-sync",
                    "op": "upsert",
                    "kind": "library_sync",
                    "status": "active",
                }),
            )
            .unwrap();
        let published = guard
            .library_sync_signed_put(1)
            .expect("library sync is active, so the publish is built");
        let carried = published
            .entry
            .directory
            .home_routes
            .iter()
            .find(|route| route.project == "project-shared")
            .expect("the retraction is published alongside live routes");
        assert!(
            is_retraction_shape(carried),
            "and it travels as a retraction"
        );
        assert!(
            crate::home::shared_home_route_verifies(carried),
            "still under its own author's signature, which the recipient checks"
        );
    }

    /// §5: a Home's own departure is already published by absence (ADR 0154 §2).
    /// Putting it on the wire would say the same thing twice, in the one form
    /// this root has no standing to author.
    #[test]
    fn an_unattested_departure_stays_off_the_wire() {
        use crate::account::{HomeRouteRecord, RecordOp, ACCOUNT_SCOPE};

        let departed = HomeRouteRecord {
            id: "project-own".into(),
            op: RecordOp::Tombstone,
            home_id: gaugedesk_core::ids::HomeId::new("home:mine"),
            // `author_home_routes` keeps the departed route's reachability on the
            // tombstone, so this is not even retraction-shaped.
            endpoint: "https://mine.example".into(),
            relay: None,
            author_authority: String::new(),
            author_root_pubkey: String::new(),
            author_signature: None,
        };
        assert!(!publishable_retraction(&departed));

        let bare = HomeRouteRecord {
            endpoint: String::new(),
            ..departed
        };
        assert!(
            !publishable_retraction(&bare),
            "retraction-shaped is not enough — an unattested one is absence's job"
        );

        // And a claimed author that does not hold may not be carried either, for
        // the same reason its live counterpart may not: this root would be
        // signing a statement it was never in a position to make.
        let forged = HomeRouteRecord {
            id: "project-forged".into(),
            op: RecordOp::Tombstone,
            home_id: gaugedesk_core::ids::HomeId::new("home:theirs"),
            endpoint: String::new(),
            relay: None,
            author_authority: "root-p256:someone-else".into(),
            author_root_pubkey: "root-p256:someone-else".into(),
            author_signature: None,
        };
        assert!(!publishable_retraction(&forged));
        let _ = ACCOUNT_SCOPE;
    }

    /// ADR 0154: the record is a snapshot of the routes it owns, so its silence
    /// retracts them. This is what makes ADR 0131 §7's departure real — a Home
    /// that stops serving a project drops the route from its next snapshot, and
    /// every device that already pulled it folds the stale locator away.
    #[test]
    fn a_verified_records_silence_retracts_the_routes_it_owns() {
        use crate::LockUnpoisoned;

        let dir = tempfile::tempdir().unwrap();
        let shared = crate::open_workbench(dir.path()).unwrap();
        let mut guard = shared.lock_unpoisoned();
        let root_key = crate::key_store::FileKeyStore::new(guard.root_path().join("keys"))
            .signing_key(guard.authority());

        // A sibling device's Home serves two projects, and this device learns
        // both from the account's own signed record.
        let sibling = |project: &str| crate::home::OpaqueHomeRoute {
            project: project.into(),
            home_id: gaugedesk_core::ids::HomeId::new("home:sibling"),
            endpoint: "https://sibling.example".into(),
            ..hostile_route()
        };
        let entry = |routes: Vec<crate::home::OpaqueHomeRoute>| DirectoryEntry {
            generation: 1,
            directory: directory_record(
                root_key.public_key().as_str(),
                &seeded_account(),
                vec![],
                routes,
            ),
            sealed_blob: String::new(),
            retracted: false,
        };
        // The same record with and without the proof that makes it mean anything.
        let unsigned = |routes: Vec<crate::home::OpaqueHomeRoute>| FetchedRecord {
            entry: entry(routes),
            signature: None,
        };
        let signed = |routes: Vec<crate::home::OpaqueHomeRoute>| {
            let put = gaugedesk_directory_protocol::sign_entry(entry(routes), &root_key).unwrap();
            FetchedRecord {
                entry: put.entry,
                signature: Some(put.signature),
            }
        };
        let held = |guard: &crate::Workbench| -> Vec<String> {
            let mut ids: Vec<String> = Account::rebuild(guard.store_ref())
                .unwrap()
                .home_routes
                .into_keys()
                .collect();
            ids.sort();
            ids
        };

        let merged = guard.library_sync_reconcile_routes(&signed(vec![
            sibling("project-kept"),
            sibling("project-relocated"),
        ]));
        assert_eq!(merged.retracted, 0);
        assert_eq!(held(&guard), vec!["project-kept", "project-relocated"]);

        // The sibling relocates one project. Its next snapshot simply does not
        // mention it, and that silence is the retraction.
        let gone = guard.library_sync_reconcile_routes(&signed(vec![sibling("project-kept")]));
        assert_eq!(gone.retracted, 1);
        assert_eq!(
            held(&guard),
            vec!["project-kept"],
            "a relocated project must not keep a live pointer at its former Home"
        );

        // §5: an unverified record retracts nothing. Fail-open is the safe
        // direction — not retracting costs a stale locator, retracting on an
        // attacker's word costs the person reachability they had.
        let unverified = guard.library_sync_reconcile_routes(&unsigned(vec![]));
        assert!(unverified.declined.is_some());
        assert_eq!(unverified.retracted, 0);
        assert_eq!(held(&guard), vec!["project-kept"]);
    }

    /// §3 and §4: the classes the directory is *not* authority for. Getting
    /// either wrong is worse than the gap this closes — one undoes a Home's own
    /// departure, the other lets a stale record win a race against the channel
    /// that actually delivers a shared route's retraction.
    #[test]
    fn a_record_governs_neither_this_homes_own_routes_nor_a_proven_authors() {
        use crate::account::{HomeRouteRecord, RecordOp, ACCOUNT_SCOPE};
        use crate::LockUnpoisoned;

        let dir = tempfile::tempdir().unwrap();
        let shared = crate::open_workbench(dir.path()).unwrap();
        let mut guard = shared.lock_unpoisoned();
        let root_key = crate::key_store::FileKeyStore::new(guard.root_path().join("keys"))
            .signing_key(guard.authority());
        let this_home = guard.home_id().clone();

        // This Home serves a project of its own.
        let own = HomeRouteRecord {
            id: "project-own".into(),
            op: RecordOp::Upsert,
            home_id: this_home.clone(),
            endpoint: "https://mine.example".into(),
            relay: None,
            author_authority: String::new(),
            author_root_pubkey: String::new(),
            author_signature: None,
        };
        guard
            .write_account_record_in(ACCOUNT_SCOPE, "home_route", &own.id, &own)
            .unwrap();

        // A shared project on someone else's Home, delivered by the federation
        // handoff under that Home's own governance root.
        let serving = SigningKey::from_seed(&[5u8; 32]).unwrap();
        let shared_route = crate::home::sign_home_route(
            "root-p256:serving",
            crate::home::OpaqueHomeRoute {
                project: "project-shared".into(),
                home_id: gaugedesk_core::ids::HomeId::new("home:theirs"),
                endpoint: "https://theirs.example".into(),
                relay: None,
                author_authority: String::new(),
                author_root_pubkey: String::new(),
                author_signature: None,
            },
            &serving,
        )
        .unwrap();
        let carried = HomeRouteRecord {
            id: shared_route.project.clone(),
            op: RecordOp::Upsert,
            home_id: shared_route.home_id.clone(),
            endpoint: shared_route.endpoint.clone(),
            relay: None,
            author_authority: shared_route.author_authority.clone(),
            author_root_pubkey: shared_route.author_root_pubkey.clone(),
            author_signature: shared_route.author_signature.clone(),
        };
        guard
            .write_account_record_in(ACCOUNT_SCOPE, "home_route", &carried.id, &carried)
            .unwrap();

        // An empty but perfectly valid record for this account: it mentions
        // neither, and must retract neither.
        let empty = gaugedesk_directory_protocol::sign_entry(
            DirectoryEntry {
                generation: 1,
                directory: directory_record(
                    root_key.public_key().as_str(),
                    &seeded_account(),
                    vec![],
                    vec![],
                ),
                sealed_blob: String::new(),
                retracted: false,
            },
            &root_key,
        )
        .unwrap();
        let reconcile = guard.library_sync_reconcile_routes(&FetchedRecord {
            entry: empty.entry,
            signature: Some(empty.signature),
        });
        assert_eq!(
            reconcile.retracted, 0,
            "the record owns neither this Home's routes nor a proven author's"
        );
        let ids: Vec<String> = Account::rebuild(guard.store_ref())
            .unwrap()
            .home_routes
            .into_keys()
            .collect();
        assert!(ids.contains(&"project-own".to_string()));
        assert!(ids.contains(&"project-shared".to_string()));

        // §3, the other half: a record may not *resurrect* a route naming this
        // Home either, or a device pulling its own stale record would undo its
        // own departure — the failure §7 exists to fix, arriving by a new door.
        let departed = HomeRouteRecord {
            op: RecordOp::Tombstone,
            ..own.clone()
        };
        guard
            .write_account_record_in(ACCOUNT_SCOPE, "home_route", &departed.id, &departed)
            .unwrap();
        let stale = gaugedesk_directory_protocol::sign_entry(
            DirectoryEntry {
                generation: 2,
                directory: directory_record(
                    root_key.public_key().as_str(),
                    &seeded_account(),
                    vec![],
                    vec![crate::home::OpaqueHomeRoute::from(own)],
                ),
                sealed_blob: String::new(),
                retracted: false,
            },
            &root_key,
        )
        .unwrap();
        guard.library_sync_reconcile_routes(&FetchedRecord {
            entry: stale.entry,
            signature: Some(stale.signature),
        });
        assert!(
            !Account::rebuild(guard.store_ref())
                .unwrap()
                .home_routes
                .contains_key("project-own"),
            "this Home's own departure survives its own stale record"
        );
    }

    /// A publish re-signs the whole route set under the account root, so what a
    /// device may carry forward is a question about that signature, not about
    /// the route's origin. A route claiming a third-party author must still
    /// prove it, or this root would be attesting to a claim it cannot make.
    #[test]
    fn a_publish_re_signs_only_routes_this_root_may_speak_for() {
        use crate::account::{HomeRouteRecord, RecordOp};

        let own = HomeRouteRecord {
            id: "project-own".into(),
            op: RecordOp::Upsert,
            home_id: gaugedesk_core::ids::HomeId::new("home:mine"),
            endpoint: "https://mine.example".into(),
            relay: None,
            author_authority: String::new(),
            author_root_pubkey: String::new(),
            author_signature: None,
        };
        assert!(
            republishable(&own),
            "an unattested route is this account's own word — its own Home's, or              one carried out of a record this same root already signed"
        );

        // A shared route (ADR 0131 §1, DESK-5d): the serving Home is the author
        // and this root only carries the proof onward.
        let serving = SigningKey::from_seed(&[5u8; 32]).unwrap();
        let shared = crate::home::sign_home_route(
            "root-p256:serving",
            crate::home::OpaqueHomeRoute {
                project: "project-shared".into(),
                home_id: gaugedesk_core::ids::HomeId::new("home:theirs"),
                endpoint: "https://theirs.example".into(),
                relay: None,
                author_authority: String::new(),
                author_root_pubkey: String::new(),
                author_signature: None,
            },
            &serving,
        )
        .unwrap();
        let carried = HomeRouteRecord {
            id: shared.project.clone(),
            op: RecordOp::Upsert,
            home_id: shared.home_id.clone(),
            endpoint: shared.endpoint.clone(),
            relay: shared.relay.clone(),
            author_authority: shared.author_authority.clone(),
            author_root_pubkey: shared.author_root_pubkey.clone(),
            author_signature: shared.author_signature.clone(),
        };
        assert!(republishable(&carried), "a proof that holds travels");

        // The laundering case: an author is claimed and the proof does not hold.
        // Re-signing it would put this account's root behind a third-party claim
        // on the one wire field that carries a certificate pin.
        let mut broken = carried.clone();
        broken.endpoint = "https://attacker.example".into();
        assert!(!republishable(&broken));

        let mut unproven = carried;
        unproven.author_signature = None;
        assert!(!republishable(&unproven));
    }

    #[test]
    fn the_directory_record_carries_no_secrets_and_the_blob_round_trips() {
        // The readable record is routing-only (root + device pubkeys); the settings/credentials
        // live only inside the sealed blob, which opens only under the same account key.
        let put = signed_put(
            &key(),
            AKEY,
            &seeded_account(),
            7,
            vec!["relay://x".into()],
            vec![],
        )
        .expect("seals");
        assert_eq!(
            put.entry.directory.device_pubkeys,
            vec!["dev-pub-1".to_string()]
        );
        assert_eq!(
            put.entry.directory.placement_pointers,
            vec!["relay://x".to_string()]
        );
        // the sealed blob is opaque hex, not the plaintext settings.
        assert!(!put.entry.sealed_blob.contains("dark"));
        // the same account key opens it back to the account metadata.
        let blob = open_account_blob(AKEY, &put.entry.sealed_blob).expect("opens");
        assert_eq!(blob.settings.get("theme").map(String::as_str), Some("dark"));
        assert_eq!(blob.devices.len(), 1);
        // a different account key cannot open it (fail-closed).
        assert!(open_account_blob(OTHER_AKEY, &put.entry.sealed_blob).is_none());
    }
}
