//! A desktop's half of DR-0334: keep the provider links of each account
//! signed in here in step with the account.
//!
//! For each signed-in account, [`reconcile`]:
//!
//! 1. registers this device's recipient key for the account, from
//!    [`LinkRecipientStore`], so the account can seal for it;
//! 2. reads the account's links, opens this device's copy of every version it
//!    has not yet taken, and writes it into the account's local credential
//!    scope sealed with this install's own key, which is where turns read it;
//! 3. removes a link the account revoked; and
//! 4. seals every link it holds for the account's devices still waiting for
//!    one, since the Hub cannot.
//!
//! [`publish_link`] is the other direction: a link made on this desktop for a
//! signed-in account becomes a new version of the account's link, sealed here
//! for every trusted device.
//!
//! Which version of the account's link a local credential mirrors is recorded
//! beside it as a [`MirrorRecord`]: the local credential keeps its own version
//! counter, which turns bind to, so the two cannot share one number.
//!
//! The authority is a [`LinkAuthority`]: the Hub over HTTP in production, and
//! in tests an in-memory one that runs [`crate::account_links`]' own rules.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::account::{
    credentials_in_scope, CredentialAuthentication, CredentialStatus, ModelExecutionClass, RecordOp,
};
use crate::account_link_seal::{
    open_link_copy, seal_link_copies, LinkContext, LinkRecipient, LinkRecipientStore,
    SealedLinkCopy,
};
use crate::account_links::{LinkStatus, PutLink};
use crate::{LockUnpoisoned, SharedWorkbench};

/// Which version of the account's link a local credential holds.
pub const MIRROR_KIND: &str = "account_link_mirror";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirrorRecord {
    /// The provider.
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    pub account: String,
    pub version: u64,
    /// The local credential's own version when it last matched the account's.
    /// A local record past it was changed here: a link made, refreshed or
    /// unlinked on this desktop, which the account has not heard of yet.
    #[serde(default)]
    pub local_version: u64,
}

/// One link as the authority lists it.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct LinkSummary {
    pub provider: String,
    pub version: u64,
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub authentication: CredentialAuthentication,
    #[serde(default)]
    pub execution_classes: BTreeSet<ModelExecutionClass>,
    pub status: LinkStatus,
    #[serde(default)]
    pub has_copy: bool,
    #[serde(default)]
    pub waiting: Vec<String>,
}

/// This device's copy of a link's current version.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct CopyEnvelope {
    pub provider: String,
    pub version: u64,
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub execution_classes: BTreeSet<ModelExecutionClass>,
    pub copy: SealedLinkCopy,
}

/// The account authority, as this device's session sees it.
pub trait LinkAuthority {
    /// Register this device's recipient key; returns this device's id.
    fn register(&self, public_key: &str) -> Result<String, String>;
    fn recipients(&self) -> Result<Vec<LinkRecipient>, String>;
    fn links(&self) -> Result<Vec<LinkSummary>, String>;
    fn copy(&self, provider: &str) -> Result<Option<CopyEnvelope>, String>;
    /// Admit a new version; returns its number.
    fn put(&self, provider: &str, put: &PutLink) -> Result<u64, String>;
    fn add_copies(
        &self,
        provider: &str,
        version: u64,
        copies: &[SealedLinkCopy],
    ) -> Result<(), String>;
    /// Revoke the link: every device loses it.
    fn revoke(&self, provider: &str) -> Result<(), String>;
    /// Ask to be the one device refreshing an OAuth link.
    fn take_lease(&self, provider: &str, ttl_ms: u64) -> Result<Lease, String>;
}

/// What [`LinkAuthority::register`] answers when the account authority does
/// not hold provider links at all: a Hub from before DR-0334. A desktop then
/// keeps its links as it always has, and says nothing about it.
pub const NOT_SERVED: &str = "this account does not hold provider links yet";

/// The answer to [`LinkAuthority::take_lease`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lease {
    Granted,
    /// Another of the account's devices is refreshing it now.
    HeldElsewhere,
}

/// What one reconcile did, for the log and for tests.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reconciled {
    pub device_id: String,
    /// Providers whose newer version this device took.
    pub taken: Vec<String>,
    /// Providers the account revoked and this device removed.
    pub removed: Vec<String>,
    /// Devices this device sealed a link for, as `(provider, device)`.
    pub sealed_for: Vec<(String, String)>,
    /// Providers linked or changed here that this device made the account's.
    pub published: Vec<String>,
    /// Providers unlinked here that this device revoked at the account.
    pub revoked: Vec<String>,
}

fn mirrors(wb: &SharedWorkbench, scope: &str) -> std::collections::BTreeMap<String, MirrorRecord> {
    let guard = wb.lock_unpoisoned();
    let mut folded = std::collections::BTreeMap::new();
    for payload in guard
        .store_ref()
        .records(scope, MIRROR_KIND)
        .unwrap_or_default()
    {
        if let Ok(record) = serde_json::from_str::<MirrorRecord>(&payload) {
            match record.op {
                RecordOp::Upsert => folded.insert(record.id.clone(), record),
                RecordOp::Tombstone => folded.remove(&record.id),
            };
        }
    }
    folded
}

fn write_mirror(wb: &SharedWorkbench, scope: &str, record: &MirrorRecord) -> Result<(), String> {
    wb.lock_unpoisoned()
        .write_account_record_in(scope, MIRROR_KIND, &record.id, record)
        .map_err(|error| format!("could not record the link's version: {error:?}"))
}

/// Open this device's copy of `provider`'s current version.
fn open_copy(
    account: &str,
    keys: &LinkRecipientStore,
    envelope: &CopyEnvelope,
) -> Result<Vec<u8>, String> {
    let context = LinkContext::new(account, &envelope.provider, envelope.version)
        .map_err(|error| format!("the link's context is invalid: {error:?}"))?;
    let key = keys
        .open(account)
        .map_err(|error| format!("this device holds no recipient key: {error}"))?;
    open_link_copy(&context, &key, &envelope.copy)
        .map_err(|_| "this device's copy did not open".to_owned())
}

/// Bring `account`'s local links in step with the account. `scope` is where
/// this desktop keeps that account's credentials.
pub fn reconcile(
    wb: &SharedWorkbench,
    account: &str,
    scope: &str,
    keys: &LinkRecipientStore,
    authority: &dyn LinkAuthority,
) -> Result<Reconciled, String> {
    let public_key = keys
        .ensure(account)
        .map_err(|error| format!("could not hold a recipient key: {error}"))?;
    let device_id = authority.register(public_key.as_str())?;
    let mut done = Reconciled {
        device_id,
        ..Reconciled::default()
    };
    // What changed here first: a link this desktop holds for a signed-in
    // account is the account's (DR-0334 §9), whether it was made through the
    // credential route, a provider sign-in, a refresh, or before this desktop
    // knew the account held links at all.
    let locals = credentials_in_scope(wb.lock_unpoisoned().store_ref(), scope);
    let mirrored = mirrors(wb, scope);
    for (provider, record) in &locals {
        let mirror = mirrored.get(provider);
        let usable = record.status == CredentialStatus::Active && !record.sealed_token.is_empty();
        if usable && mirror.is_none_or(|m| m.local_version != record.version) {
            publish_record(wb, account, scope, provider, authority)?;
            done.published.push(provider.clone());
        } else if !usable && mirror.is_some() {
            authority.revoke(provider)?;
            write_mirror(
                wb,
                scope,
                &MirrorRecord {
                    id: provider.clone(),
                    op: RecordOp::Tombstone,
                    account: account.to_owned(),
                    version: 0,
                    local_version: record.version,
                },
            )?;
            done.revoked.push(provider.clone());
        }
    }
    let mirrored = mirrors(wb, scope);
    let mut recipients = None;
    for link in authority.links()? {
        let mirror = mirrored.get(&link.provider);
        if link.status == LinkStatus::Revoked {
            if mirror.is_some() {
                let mut guard = wb.lock_unpoisoned();
                guard
                    .tombstone_account_credential_in(scope, link.provider.clone())
                    .map_err(|error| format!("could not remove a revoked link: {error:?}"))?;
                drop(guard);
                write_mirror(
                    wb,
                    scope,
                    &MirrorRecord {
                        id: link.provider.clone(),
                        op: RecordOp::Tombstone,
                        account: account.to_owned(),
                        version: link.version,
                        local_version: 0,
                    },
                )?;
                done.removed.push(link.provider.clone());
            }
            continue;
        }
        if !link.has_copy {
            // Waiting for another of the account's devices to seal for us.
            continue;
        }
        let behind = mirror.is_none_or(|m| m.version != link.version);
        if !behind && link.waiting.is_empty() {
            continue;
        }
        let Some(envelope) = authority.copy(&link.provider)? else {
            continue;
        };
        let secret = open_copy(account, keys, &envelope)?;
        if behind {
            let text = String::from_utf8(secret.clone())
                .map_err(|_| "a provider link's secret is not text".to_owned())?;
            let mut guard = wb.lock_unpoisoned();
            let sealed = guard
                .seal_account_secret(&text)
                .ok_or_else(|| "could not seal the link on this device".to_owned())?;
            guard
                .upsert_account_credential_in_with_policy(
                    scope,
                    link.provider.clone(),
                    sealed,
                    envelope.base_url.clone(),
                    envelope.execution_classes.clone(),
                )
                .map_err(|error| format!("could not store the link: {error:?}"))?;
            let local_version = credentials_in_scope(guard.store_ref(), scope)
                .get(&link.provider)
                .map_or(0, |record| record.version);
            drop(guard);
            write_mirror(
                wb,
                scope,
                &MirrorRecord {
                    id: link.provider.clone(),
                    op: RecordOp::Upsert,
                    account: account.to_owned(),
                    version: envelope.version,
                    local_version,
                },
            )?;
            done.taken.push(link.provider.clone());
        }
        if !link.waiting.is_empty() {
            let all = match &recipients {
                Some(all) => all,
                None => recipients.insert(authority.recipients()?),
            };
            let waiting: Vec<LinkRecipient> = all
                .iter()
                .filter(|r| link.waiting.contains(&r.device_id))
                .cloned()
                .collect();
            let context = LinkContext::new(account, &link.provider, envelope.version)
                .map_err(|error| format!("the link's context is invalid: {error:?}"))?;
            let copies = seal_link_copies(&context, &secret, &waiting)
                .map_err(|error| format!("could not seal for a waiting device: {error:?}"))?;
            authority.add_copies(&link.provider, envelope.version, &copies)?;
            done.sealed_for.extend(
                waiting
                    .into_iter()
                    .map(|r| (link.provider.clone(), r.device_id)),
            );
        }
    }
    Ok(done)
}

/// Make the credential this desktop holds for `provider` the account's link:
/// seal it for every trusted device and admit it as the next version.
pub fn publish_link(
    wb: &SharedWorkbench,
    account: &str,
    scope: &str,
    provider: &str,
    keys: &LinkRecipientStore,
    authority: &dyn LinkAuthority,
) -> Result<u64, String> {
    let public_key = keys
        .ensure(account)
        .map_err(|error| format!("could not hold a recipient key: {error}"))?;
    authority.register(public_key.as_str())?;
    publish_record(wb, account, scope, provider, authority)
}

fn publish_record(
    wb: &SharedWorkbench,
    account: &str,
    scope: &str,
    provider: &str,
    authority: &dyn LinkAuthority,
) -> Result<u64, String> {
    let (secret, record) = {
        let guard = wb.lock_unpoisoned();
        let record = credentials_in_scope(guard.store_ref(), scope)
            .remove(provider)
            .filter(|record| record.status == CredentialStatus::Active)
            .filter(|record| !record.sealed_token.is_empty())
            .ok_or_else(|| format!("this desktop holds no {provider} link"))?;
        let secret = guard
            .unseal_account_secret(&record.sealed_token)
            .ok_or_else(|| "the local link could not be opened".to_owned())?;
        (secret, record)
    };
    let current = authority
        .links()?
        .into_iter()
        .find(|link| link.provider == provider)
        .map_or(0, |link| link.version);
    let recipients = authority.recipients()?;
    let context = LinkContext::new(account, provider, current + 1)
        .map_err(|error| format!("the link's context is invalid: {error:?}"))?;
    let copies = seal_link_copies(&context, secret.as_bytes(), &recipients)
        .map_err(|error| format!("could not seal the link: {error:?}"))?;
    let version = authority.put(
        provider,
        &PutLink {
            expected_version: current,
            base_url: record.base_url.clone(),
            authentication: record.authentication,
            execution_classes: record.execution_classes.clone(),
            copies,
        },
    )?;
    write_mirror(
        wb,
        scope,
        &MirrorRecord {
            id: provider.to_owned(),
            op: RecordOp::Upsert,
            account: account.to_owned(),
            version,
            local_version: record.version,
        },
    )?;
    Ok(version)
}

/// Revoke `provider`'s link at the account: every device loses it.
pub fn revoke(provider: &str, authority: &dyn LinkAuthority) -> Result<(), String> {
    authority.revoke(provider)
}

// ---- refreshing an OAuth link the account holds -------------------------------

/// What a desktop about to refresh an expiring OAuth login should do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefreshTurn {
    /// Refresh it: this device holds the lease, or the login is this
    /// desktop's alone, or the account cannot be reached to coordinate.
    Refresh,
    /// Another device refreshed it and this device has taken that version.
    Taken,
    /// Another device is refreshing it and has not published yet.
    Busy(String),
}

/// How long a device waits for another to publish a refresh before giving up
/// on this turn. A refresh is one provider round trip and one publish.
const REFRESH_WAIT: std::time::Duration = std::time::Duration::from_secs(15);

/// Before refreshing `provider`'s login in `scope`: when it is a signed-in
/// account's link, refresh only under the account's lease, so two devices
/// never spend one refresh token (DR-0334 §6).
pub fn before_refresh(wb: &SharedWorkbench, scope: &str, provider: &str) -> RefreshTurn {
    let Some(mirror) = mirrors(wb, scope).remove(provider) else {
        return RefreshTurn::Refresh;
    };
    let Some((authority, _, keys)) = signed_in(wb, &mirror.account) else {
        return RefreshTurn::Refresh;
    };
    before_refresh_with(
        wb,
        &mirror.account,
        scope,
        provider,
        &keys,
        &authority,
        REFRESH_WAIT,
    )
}

/// [`before_refresh`] against a given authority, for tests.
pub fn before_refresh_with(
    wb: &SharedWorkbench,
    account: &str,
    scope: &str,
    provider: &str,
    keys: &LinkRecipientStore,
    authority: &dyn LinkAuthority,
    wait: std::time::Duration,
) -> RefreshTurn {
    let before = mirrors(wb, scope).get(provider).map(|m| m.version);
    let advanced =
        |wb: &SharedWorkbench| mirrors(wb, scope).get(provider).map(|m| m.version) > before;
    // Another device may already have refreshed it, spending the refresh
    // token this device holds; take that version rather than refresh again.
    if reconcile(wb, account, scope, keys, authority).is_ok() && advanced(wb) {
        return RefreshTurn::Taken;
    }
    match authority.take_lease(provider, crate::account_links::MAX_LEASE_MS) {
        Ok(Lease::Granted) => return RefreshTurn::Refresh,
        // Unreachable: a desktop keeps working offline, at the risk the
        // account could not take away.
        Err(_) => return RefreshTurn::Refresh,
        Ok(Lease::HeldElsewhere) => {}
    }
    let deadline = std::time::Instant::now() + wait;
    loop {
        if reconcile(wb, account, scope, keys, authority).is_ok() && advanced(wb) {
            return RefreshTurn::Taken;
        }
        if std::time::Instant::now() >= deadline {
            return RefreshTurn::Busy(format!(
                "another of your devices is refreshing the {provider} sign-in; try again in a moment"
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(500).min(wait));
    }
}

/// After refreshing `provider`'s login in `scope`, publish the new bundle
/// while this device still holds the lease.
pub fn after_refresh(wb: &SharedWorkbench, scope: &str, provider: &str) {
    if let Some(mirror) = mirrors(wb, scope).remove(provider) {
        spawn_publish(wb, &mirror.account, provider);
    }
}

// ---- the Hub ----------------------------------------------------------------

/// The account authority at the Hub, as one desktop session sees it.
pub struct HubLinkAuthority {
    hub: String,
    bearer: String,
    http: crate::net_http::HttpClient,
}

impl HubLinkAuthority {
    pub fn new(hub: String, bearer: String) -> Self {
        Self {
            hub,
            bearer,
            http: crate::net_http::HttpClient::with_timeout_no_redirects(
                std::time::Duration::from_secs(15),
            ),
        }
    }

    fn headers(&self, mutation: bool) -> Vec<(String, String)> {
        let mut headers = vec![(
            "authorization".to_owned(),
            format!("Bearer {}", self.bearer),
        )];
        if mutation {
            let mut nonce = [0_u8; 16];
            // A key the Hub has never seen is all a one-shot write needs; a
            // failed draw only makes the retry a fresh write.
            let _ = getrandom::getrandom(&mut nonce);
            headers.push((
                "idempotency-key".to_owned(),
                format!("account-link-{}", hex::encode(nonce)),
            ));
        }
        headers
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.hub.trim_end_matches('/'))
    }

    fn provider_path(provider: &str, rest: &str) -> String {
        format!(
            "/account/links/{}{rest}",
            url::form_urlencoded::byte_serialize(provider.as_bytes()).collect::<String>()
        )
    }

    fn answer<T: serde::de::DeserializeOwned>(
        what: &str,
        response: Result<(u16, String), String>,
    ) -> Result<T, String> {
        let (status, body) = response.map_err(|error| format!("{what}: {error}"))?;
        if !(200..300).contains(&status) {
            return Err(format!("{what}: the account answered {status}: {body}"));
        }
        serde_json::from_str(&body).map_err(|error| format!("{what}: {error}"))
    }
}

impl LinkAuthority for HubLinkAuthority {
    fn register(&self, public_key: &str) -> Result<String, String> {
        #[derive(Deserialize)]
        struct Registered {
            device_id: String,
        }
        let body = serde_json::json!({ "public_key": public_key }).to_string();
        let response = self.http.post_json_headers(
            &self.url("/account/link-recipients"),
            &self.headers(true),
            &body,
        );
        if matches!(response, Ok((404, _))) {
            return Err(NOT_SERVED.to_owned());
        }
        let registered: Registered =
            Self::answer("registering this device's recipient key", response)?;
        Ok(registered.device_id)
    }

    fn recipients(&self) -> Result<Vec<LinkRecipient>, String> {
        #[derive(Deserialize)]
        struct Recipients {
            recipients: Vec<LinkRecipient>,
        }
        let listed: Recipients = Self::answer(
            "reading the account's devices",
            self.http
                .get_string_headers(&self.url("/account/link-recipients"), &self.headers(false)),
        )?;
        Ok(listed.recipients)
    }

    fn links(&self) -> Result<Vec<LinkSummary>, String> {
        #[derive(Deserialize)]
        struct Links {
            links: Vec<LinkSummary>,
        }
        let listed: Links = Self::answer(
            "reading the account's provider links",
            self.http
                .get_string_headers(&self.url("/account/links"), &self.headers(false)),
        )?;
        Ok(listed.links)
    }

    fn copy(&self, provider: &str) -> Result<Option<CopyEnvelope>, String> {
        let response = self.http.get_string_headers(
            &self.url(&Self::provider_path(provider, "/copy")),
            &self.headers(false),
        );
        if matches!(response, Ok((404, _))) {
            return Ok(None);
        }
        Self::answer("reading this device's copy", response).map(Some)
    }

    fn put(&self, provider: &str, put: &PutLink) -> Result<u64, String> {
        #[derive(Deserialize)]
        struct Admitted {
            version: u64,
        }
        let body = serde_json::to_string(put).map_err(|error| error.to_string())?;
        let admitted: Admitted = Self::answer(
            "publishing the provider link",
            self.http.put_json_headers(
                &self.url(&Self::provider_path(provider, "")),
                &self.headers(true),
                &body,
            ),
        )?;
        Ok(admitted.version)
    }

    fn add_copies(
        &self,
        provider: &str,
        version: u64,
        copies: &[SealedLinkCopy],
    ) -> Result<(), String> {
        let body = serde_json::json!({ "version": version, "copies": copies }).to_string();
        Self::answer::<serde_json::Value>(
            "sealing the link for a waiting device",
            self.http.post_json_headers(
                &self.url(&Self::provider_path(provider, "/copies")),
                &self.headers(true),
                &body,
            ),
        )
        .map(|_| ())
    }

    fn take_lease(&self, provider: &str, ttl_ms: u64) -> Result<Lease, String> {
        let body = serde_json::json!({ "ttl_ms": ttl_ms }).to_string();
        let response = self.http.post_json_headers(
            &self.url(&Self::provider_path(provider, "/refresh-lease")),
            &self.headers(true),
            &body,
        );
        if matches!(response, Ok((409, _))) {
            return Ok(Lease::HeldElsewhere);
        }
        Self::answer::<serde_json::Value>("taking the refresh lease", response)
            .map(|_| Lease::Granted)
    }

    fn revoke(&self, provider: &str) -> Result<(), String> {
        let response = self.http.delete_headers(
            &self.url(&Self::provider_path(provider, "")),
            &self.headers(true),
        );
        // No such link, or a Hub that holds none: nothing to revoke.
        if matches!(response, Ok((404, _))) {
            return Ok(());
        }
        Self::answer::<serde_json::Value>("revoking the provider link", response).map(|_| ())
    }
}

// ---- when a desktop does this -------------------------------------------------

/// The signed-in account a desktop request acts for, when it is one this
/// desktop holds a Hub session for. The signed-out window is the computer's
/// local account, which no authority holds links for (DR-0334 §9).
pub fn hub_account_for(wb: &crate::Workbench, bearer: Option<&str>) -> Option<String> {
    if !wb.desktop_account_mode() {
        return None;
    }
    let (account, _) = wb.resolve_account_session(bearer?)?;
    Some(account)
}

/// Where this desktop's link-recipient keys live.
fn recipient_store(wb: &SharedWorkbench) -> Option<LinkRecipientStore> {
    let root = wb.lock_unpoisoned().root_path().to_path_buf();
    // A bare workbench has no disk to hold a device key on.
    (!root.as_os_str().is_empty())
        .then(|| LinkRecipientStore::new(root.join("keys").join("account-link")))
}

/// The authority and local scope for `account`, if this desktop is signed in
/// to it at a Hub.
fn signed_in(
    wb: &SharedWorkbench,
    account: &str,
) -> Option<(HubLinkAuthority, String, LinkRecipientStore)> {
    let hub = crate::account_signin::hub_base()?;
    let bearer = crate::account_signin::hub_session_token_for(wb, account)?;
    let scope = wb.lock_unpoisoned().desktop_account_store_scope(account);
    Some((
        HubLinkAuthority::new(hub, bearer),
        scope,
        recipient_store(wb)?,
    ))
}

/// How often a status poll may start a reconcile for one account.
const RECONCILE_EVERY: std::time::Duration = std::time::Duration::from_secs(60);

fn last_runs() -> &'static std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>> {
    static RUNS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>,
    > = std::sync::OnceLock::new();
    RUNS.get_or_init(Default::default)
}

/// Reconcile `account` in the background. Unless `now`, at most once a
/// minute per account; a failure is logged and retried at the next one.
pub fn spawn_reconcile(wb: &SharedWorkbench, account: &str, now: bool) {
    {
        let mut runs = last_runs()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if !now
            && runs
                .get(account)
                .is_some_and(|last| last.elapsed() < RECONCILE_EVERY)
        {
            return;
        }
        runs.insert(account.to_owned(), std::time::Instant::now());
    }
    let Some((authority, scope, keys)) = signed_in(wb, account) else {
        return;
    };
    let (wb, account) = (wb.clone(), account.to_owned());
    std::thread::spawn(
        move || match reconcile(&wb, &account, &scope, &keys, &authority) {
            Ok(done)
                if !done.taken.is_empty()
                    || !done.removed.is_empty()
                    || !done.sealed_for.is_empty() =>
            {
                eprintln!(
                    "[account-links] took {:?}, removed {:?}, sealed {:?}",
                    done.taken, done.removed, done.sealed_for
                );
            }
            Ok(_) => {}
            Err(error) if error == NOT_SERVED => {}
            Err(error) => eprintln!("[account-links] could not reconcile provider links: {error}"),
        },
    );
}

/// After `account` links `provider` on this desktop, make it the account's.
pub fn spawn_publish(wb: &SharedWorkbench, account: &str, provider: &str) {
    let Some((authority, scope, keys)) = signed_in(wb, account) else {
        return;
    };
    let (wb, account, provider) = (wb.clone(), account.to_owned(), provider.to_owned());
    std::thread::spawn(move || {
        match publish_link(&wb, &account, &scope, &provider, &keys, &authority) {
            Ok(_) => {}
            Err(error) if error == NOT_SERVED => {}
            Err(error) => {
                eprintln!("[account-links] could not publish the {provider} link: {error}")
            }
        }
    });
}

/// After `account` unlinks `provider` on this desktop, revoke it everywhere.
pub fn spawn_revoke(wb: &SharedWorkbench, account: &str, provider: &str) {
    let Some((authority, _, _)) = signed_in(wb, account) else {
        return;
    };
    let provider = provider.to_owned();
    std::thread::spawn(move || {
        if let Err(error) = revoke(&provider, &authority) {
            eprintln!("[account-links] could not revoke the {provider} link: {error}");
        }
    });
}

#[cfg(test)]
#[path = "account_links_sync_tests.rs"]
mod tests;
