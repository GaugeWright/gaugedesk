//! The account authority's half of DR-0334: a person's provider links, held
//! as one sealed copy per trusted device.
//!
//! The Hub keeps, in the person's `account::<person>` scope:
//!
//! - each trusted device's **recipient key**, registered by that device itself
//!   from a session bound to it;
//! - each **link**'s non-secret record — provider, version, endpoint,
//!   authentication kind, execution classes, revocation state;
//! - one **copy** of each link's secret per device, sealed on the linking side
//!   by [`crate::account_link_seal`]; and
//! - an OAuth link's **refresh lease**, so one device refreshes at a time.
//!
//! Each hosted Home that serves the person — one whose tenant lists them as an
//! active member — is a recipient too, for links that allow `private-home`
//! (DR-0380). Its key is a [`HostedHomeRecipientRecord`] in its tenant's scope,
//! which the Hub records itself and no session can write.
//!
//! None of it is readable here: a copy opens only under its recipient's
//! private key, which never leaves the device or the Home. So the rules below are about coverage
//! rather than content. A new version must carry a copy for exactly the
//! devices that hold recipient keys, no more and no fewer; a device trusted
//! later is sealed for by a device that holds the link; revoking a device
//! deletes its recipient key and its copies.
//!
//! The rules are a pure decision over [`LinkSet`]; the routes in
//! [`authority_routes`] authenticate the person and their device, read the
//! set, decide, and append. They answer only on the Hub ([`web_account_mode`]):
//! a desktop holds its own links and is never anyone's authority for them.

use std::collections::{BTreeMap, BTreeSet};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::account::{
    Account, CredentialAuthentication, DeviceStatus, ModelExecutionClass, RecordOp,
};
use crate::account_link_seal::{LinkRecipientPublicKey, SealedLinkCopy};
use crate::workbench_auth::web_account_mode;
use crate::{net_http, LockUnpoisoned, SharedWorkbench};
use gaugedesk_store::{AdmitError, Store};

pub const LINK_RECIPIENT_KIND: &str = "account_link_recipient";
pub const LINK_KIND: &str = "account_link";
pub const LINK_COPY_KIND: &str = "account_link_copy";
pub const LINK_LEASE_KIND: &str = "account_link_refresh_lease";
pub const LINK_CHECK_KIND: &str = "account_link_check";
/// A hosted Home's recipient key, in its tenant's scope (DR-0380).
pub const HOSTED_HOME_RECIPIENT_KIND: &str = "hosted_home_recipient";

/// The longest a device may hold a refresh lease. A refresh is one provider
/// round trip and one publish; a holder that dies leaves the link refreshable
/// again within this bound.
pub const MAX_LEASE_MS: u64 = 120_000;

/// A trusted device's registered recipient key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkRecipientRecord {
    /// The trusted-device id.
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    pub public_key: LinkRecipientPublicKey,
    pub registered_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LinkStatus {
    #[default]
    Active,
    Revoked,
}

/// One link's non-secret record. Its id is the provider.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountLinkRecord {
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    pub version: u64,
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub authentication: CredentialAuthentication,
    #[serde(default)]
    pub execution_classes: BTreeSet<ModelExecutionClass>,
    #[serde(default)]
    pub status: LinkStatus,
    pub updated_at_ms: u64,
}

/// One device's copy of one version of a link.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkCopyRecord {
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    pub provider: String,
    pub version: u64,
    pub copy: SealedLinkCopy,
}

/// Who may refresh an OAuth link, and until when.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshLeaseRecord {
    /// The provider.
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    pub device_id: String,
    pub expires_at_ms: u64,
}

/// Whether a provider accepted a link's key, as a device that used it found
/// (DR-0360). It names no secret, so the account may keep and show it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkCheckRecord {
    /// The provider.
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    pub version: u64,
    pub device_id: String,
    pub reachable: bool,
    pub checked_at_ms: u64,
}

/// A hosted Home's recipient key, recorded in its tenant's scope by the Hub,
/// from the Home itself: when the Hub provisions it, or by asking it over the
/// private network. Never from a caller's session, so a leaked session cannot
/// make a person's devices seal to a key of its choosing (DR-0380 §2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostedHomeRecipientRecord {
    /// The Home id; copies sealed for it name it as their recipient.
    pub id: String,
    #[serde(default)]
    pub op: RecordOp,
    pub public_key: LinkRecipientPublicKey,
    pub recorded_at_ms: u64,
}

/// Whether `id` names a hosted Home rather than a trusted device.
pub fn is_home_recipient(id: &str) -> bool {
    id.starts_with("home:")
}

/// Record `home_id`'s recipient key in `tenant`. Recording the same key again
/// writes nothing. Only the Hub's own provisioning and its private-network
/// read of a Home call this.
pub fn record_hosted_home_recipient(
    wb: &mut crate::Workbench,
    tenant: &str,
    home_id: &str,
    public_key: &str,
    now_ms: u64,
) -> Result<bool, String> {
    if !is_home_recipient(home_id) || tenant.trim().is_empty() {
        return Err("a hosted Home is named home:… and belongs to a tenant".into());
    }
    let public_key = LinkRecipientPublicKey::parse(public_key)
        .map_err(|_| "the Home's recipient key is not a P-256 public key".to_owned())?;
    let scope = crate::org::tenant_scope(tenant);
    let current = fold_retained(
        wb.store_ref(),
        &scope,
        HOSTED_HOME_RECIPIENT_KIND,
        |record: &HostedHomeRecipientRecord| (&record.id, record.op),
    )
    .map_err(|error| format!("could not read the tenant's Homes: {error:?}"))?;
    if current
        .get(home_id)
        .is_some_and(|existing| existing.public_key == public_key)
    {
        return Ok(false);
    }
    let record = HostedHomeRecipientRecord {
        id: home_id.to_owned(),
        op: RecordOp::Upsert,
        public_key,
        recorded_at_ms: now_ms,
    };
    // A copy names its recipient, not a key revision. A changed key and every
    // old ciphertext tombstone must therefore become visible in one commit.
    // Discover actual copy-owning scopes, including accounts no longer active
    // in this tenant; a current-members roster would miss retained copies.
    let mut records = Vec::new();
    let mut cursor = None;
    let page_size = std::num::NonZeroUsize::new(128).expect("positive discovery page");
    loop {
        let scopes = wb
            .store_ref()
            .scope_ids_with_kind(LINK_COPY_KIND, cursor.as_deref(), page_size)
            .map_err(|error| format!("could not discover Home copies: {error:?}"))?;
        if scopes.is_empty() {
            break;
        }
        cursor = scopes.last().cloned();
        for account_scope in scopes {
            let is_account = account_scope == crate::account::ACCOUNT_SCOPE
                || account_scope
                    .strip_prefix("account::")
                    .is_some_and(|person| !person.is_empty());
            if !is_account {
                continue;
            }
            let copies = fold_retained(
                wb.store_ref(),
                &account_scope,
                LINK_COPY_KIND,
                |copy: &LinkCopyRecord| (&copy.id, copy.op),
            )
            .map_err(|error| format!("could not read retained Home copies: {error:?}"))?;
            for copy in copies
                .into_values()
                .filter(|copy| copy.copy.device_id == home_id)
            {
                let tombstone = LinkCopyRecord {
                    op: RecordOp::Tombstone,
                    ..copy
                };
                records.push((
                    account_scope.clone(),
                    LINK_COPY_KIND,
                    serde_json::to_string(&tombstone)
                        .map_err(|_| "could not encode a Home copy tombstone".to_owned())?,
                ));
            }
        }
    }
    records.push((
        scope,
        HOSTED_HOME_RECIPIENT_KIND,
        serde_json::to_string(&record)
            .map_err(|_| "could not encode the Home's recipient key".to_owned())?,
    ));
    let borrowed: Vec<_> = records
        .iter()
        .map(|(scope, kind, body)| (scope.as_str(), *kind, body.as_str()))
        .collect();
    wb.store_mut()
        .append_records_atomically(&borrowed)
        .map_err(|error| {
            format!("could not record the Home's key and invalidate its copies: {error:?}")
        })?;
    wb.notify_library_changed("account", home_id, "upsert");
    Ok(true)
}

/// Forget `home_id`'s recipient key, when the Home is erased. Every person's
/// copies for it stop counting at once and are deleted as each account next
/// changes (DR-0380 §5).
pub fn forget_hosted_home_recipient(
    wb: &mut crate::Workbench,
    tenant: &str,
    home_id: &str,
) -> Result<(), AdmitError> {
    let scope = crate::org::tenant_scope(tenant);
    let Some(existing) = hosted_home_recipients_in(wb.store_ref(), &scope)?.remove(home_id) else {
        return Ok(());
    };
    let record = HostedHomeRecipientRecord {
        op: RecordOp::Tombstone,
        ..existing
    };
    wb.write_account_record_in(&scope, HOSTED_HOME_RECIPIENT_KIND, home_id, &record)
}

/// The hosted Homes recorded in one tenant's scope.
pub fn hosted_home_recipients_in(
    store: &Store,
    tenant_scope: &str,
) -> Result<BTreeMap<String, HostedHomeRecipientRecord>, AdmitError> {
    fold(
        store,
        tenant_scope,
        HOSTED_HOME_RECIPIENT_KIND,
        |r: &HostedHomeRecipientRecord| (&r.id, r.op),
    )
}

/// The hosted Homes serving `person`: those of every tenant whose directory
/// lists them as an active member.
fn homes_serving(
    store: &Store,
    person: &str,
    scope: &str,
) -> Result<BTreeMap<String, LinkRecipientPublicKey>, AdmitError> {
    let mut homes = BTreeMap::new();
    if person.is_empty() {
        return Ok(homes);
    }
    for tenant in crate::tenancy::Tenancy::rebuild_in(store, scope)?
        .tenants
        .into_keys()
    {
        let tenant_scope = crate::org::tenant_scope(&tenant);
        let member = crate::org::Org::rebuild_in(store, &tenant_scope)
            .map(|org| org.role_of(person).is_some())
            .unwrap_or(false);
        if !member {
            continue;
        }
        for (id, record) in hosted_home_recipients_in(store, &tenant_scope)? {
            homes.insert(id, record.public_key);
        }
    }
    Ok(homes)
}

/// Whether a link may be sealed for the person's hosted Homes: it allows
/// `private-home`, and it is not a sign-in a Home would have to refresh on its
/// own (DR-0380 §6).
pub fn reaches_homes(
    authentication: CredentialAuthentication,
    classes: &BTreeSet<ModelExecutionClass>,
) -> bool {
    authentication != CredentialAuthentication::OAuth
        && classes.contains(&ModelExecutionClass::PrivateHome)
}

fn copy_id(provider: &str, device_id: &str) -> String {
    format!("{}/{}", hex::encode(provider), hex::encode(device_id))
}

/// Everything the authority holds for one account, folded latest-wins by id.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LinkSet {
    pub recipients: BTreeMap<String, LinkRecipientRecord>,
    pub links: BTreeMap<String, AccountLinkRecord>,
    pub copies: BTreeMap<String, LinkCopyRecord>,
    pub leases: BTreeMap<String, RefreshLeaseRecord>,
    pub checks: BTreeMap<String, LinkCheckRecord>,
    /// The account's trusted devices that are active now. A recipient key or
    /// copy for any other device is never counted or served.
    pub active_devices: BTreeSet<String>,
    /// The hosted Homes serving the person now, with their recipient keys.
    /// A copy for any other Home is never counted or served.
    pub homes: BTreeMap<String, LinkRecipientPublicKey>,
}

/// Rotation is an authority transition: missing or malformed retained history
/// must refuse before any key or copy write, never masquerade as an empty set.
fn fold_retained<T, F>(
    store: &Store,
    scope: &str,
    kind: &str,
    id: F,
) -> Result<BTreeMap<String, T>, AdmitError>
where
    T: serde::de::DeserializeOwned,
    F: Fn(&T) -> (&str, RecordOp),
{
    let mut folded = BTreeMap::new();
    for payload in store.retained_records(scope, kind)? {
        let record: T = serde_json::from_str(&payload)?;
        let (key, op) = id(&record);
        let key = key.to_owned();
        match op {
            RecordOp::Upsert => {
                folded.insert(key, record);
            }
            RecordOp::Tombstone => {
                folded.remove(&key);
            }
        }
    }
    Ok(folded)
}

fn fold<T, F>(
    store: &Store,
    scope: &str,
    kind: &str,
    id: F,
) -> Result<BTreeMap<String, T>, AdmitError>
where
    T: serde::de::DeserializeOwned,
    F: Fn(&T) -> (&str, RecordOp),
{
    let mut folded = BTreeMap::new();
    for payload in store.records(scope, kind)? {
        let Ok(record) = serde_json::from_str::<T>(&payload) else {
            continue;
        };
        let (key, op) = id(&record);
        let key = key.to_owned();
        match op {
            RecordOp::Upsert => {
                folded.insert(key, record);
            }
            RecordOp::Tombstone => {
                folded.remove(&key);
            }
        }
    }
    Ok(folded)
}

impl LinkSet {
    pub fn rebuild(store: &Store, scope: &str) -> Result<Self, AdmitError> {
        let active_devices = Account::rebuild_in(store, scope)?
            .devices
            .into_values()
            .filter(|device| device.status == DeviceStatus::Active)
            .map(|device| device.id)
            .collect();
        let person = scope
            .strip_prefix(crate::account::ACCOUNT_SCOPE)
            .and_then(|rest| rest.strip_prefix("::"))
            .unwrap_or_default();
        let homes = homes_serving(store, person, scope)?;
        Ok(Self {
            recipients: fold(
                store,
                scope,
                LINK_RECIPIENT_KIND,
                |r: &LinkRecipientRecord| (&r.id, r.op),
            )?,
            links: fold(store, scope, LINK_KIND, |r: &AccountLinkRecord| {
                (&r.id, r.op)
            })?,
            copies: fold(store, scope, LINK_COPY_KIND, |r: &LinkCopyRecord| {
                (&r.id, r.op)
            })?,
            leases: fold(store, scope, LINK_LEASE_KIND, |r: &RefreshLeaseRecord| {
                (&r.id, r.op)
            })?,
            checks: fold(store, scope, LINK_CHECK_KIND, |r: &LinkCheckRecord| {
                (&r.id, r.op)
            })?,
            active_devices,
            homes,
        })
    }

    /// Devices that hold a recipient key and are still trusted: exactly the
    /// devices a new version must be sealed for.
    pub fn recipients(&self) -> BTreeMap<&str, &LinkRecipientPublicKey> {
        self.recipients
            .values()
            .filter(|r| self.active_devices.contains(&r.id))
            .map(|r| (r.id.as_str(), &r.public_key))
            .collect()
    }

    /// Every recipient a device seals for: the trusted devices above and the
    /// hosted Homes serving the person. Which Homes a given link reaches is
    /// [`LinkSet::reaches_homes`]'s answer.
    pub fn all_recipients(&self) -> BTreeMap<&str, &LinkRecipientPublicKey> {
        let mut all = self.recipients();
        all.extend(self.homes.iter().map(|(id, key)| (id.as_str(), key)));
        all
    }

    /// Whether `provider`'s current version is sealed for the person's Homes.
    pub fn reaches_homes(&self, provider: &str) -> bool {
        self.links.get(provider).is_some_and(|link| {
            link.status == LinkStatus::Active
                && reaches_homes(link.authentication, &link.execution_classes)
        })
    }

    /// Whether `recipient` may hold `provider`'s current version.
    fn may_hold(&self, provider: &str, recipient: &str) -> bool {
        if is_home_recipient(recipient) {
            self.homes.contains_key(recipient) && self.reaches_homes(provider)
        } else {
            self.active_devices.contains(recipient)
        }
    }

    fn current_copy(&self, provider: &str, device_id: &str) -> Option<&LinkCopyRecord> {
        let link = self.links.get(provider)?;
        (link.status == LinkStatus::Active).then_some(())?;
        self.copies
            .get(&copy_id(provider, device_id))
            .filter(|copy| copy.version == link.version)
    }

    /// The trusted devices with a recipient key, and the hosted Homes the link
    /// reaches, that do not yet hold a copy of this link's current version:
    /// the ones waiting to be sealed for.
    pub fn waiting(&self, provider: &str) -> Vec<String> {
        match self.links.get(provider) {
            Some(link) if link.status == LinkStatus::Active => self
                .all_recipients()
                .into_keys()
                .filter(|recipient| self.may_hold(provider, recipient))
                .filter(|recipient| self.current_copy(provider, recipient).is_none())
                .map(str::to_owned)
                .collect(),
            _ => Vec::new(),
        }
    }

    /// The hosted Homes holding `provider`'s current version.
    pub fn homes_holding(&self, provider: &str) -> Vec<String> {
        self.homes
            .keys()
            .filter(|home| self.copy_for(provider, home).is_some())
            .cloned()
            .collect()
    }

    /// Copies whose recipient no longer may hold them: a device revoked, a
    /// Home the person left or that was erased, or a link that stopped
    /// reaching Homes. Never served; this deletes the ciphertext too.
    pub fn departed_copies(&self) -> Vec<LinkFact> {
        self.copies
            .values()
            .filter(|copy| {
                self.links.contains_key(&copy.provider)
                    && !self.may_hold(&copy.provider, &copy.copy.device_id)
            })
            .map(|copy| {
                LinkFact::Copy(LinkCopyRecord {
                    op: RecordOp::Tombstone,
                    ..copy.clone()
                })
            })
            .collect()
    }

    /// Fold admitted facts in, as [`LinkSet::rebuild`] would read them back.
    pub fn apply(&mut self, facts: Vec<LinkFact>) {
        fn put<T>(map: &mut BTreeMap<String, T>, id: String, op: RecordOp, record: T) {
            match op {
                RecordOp::Upsert => {
                    map.insert(id, record);
                }
                RecordOp::Tombstone => {
                    map.remove(&id);
                }
            }
        }
        for fact in facts {
            match fact {
                LinkFact::Recipient(r) => put(&mut self.recipients, r.id.clone(), r.op, r),
                LinkFact::Link(r) => put(&mut self.links, r.id.clone(), r.op, r),
                LinkFact::Copy(r) => put(&mut self.copies, r.id.clone(), r.op, r),
                LinkFact::Lease(r) => put(&mut self.leases, r.id.clone(), r.op, r),
                LinkFact::Check(r) => put(&mut self.checks, r.id.clone(), r.op, r),
            }
        }
    }

    /// What a device found when it used the current version, if any did.
    pub fn check(&self, provider: &str) -> Option<&LinkCheckRecord> {
        let link = self.links.get(provider)?;
        self.checks
            .get(provider)
            .filter(|check| check.version == link.version)
    }

    /// The recipient's copy of the current version, when it has one.
    pub fn copy_for(&self, provider: &str, device_id: &str) -> Option<&SealedLinkCopy> {
        self.may_hold(provider, device_id).then_some(())?;
        self.current_copy(provider, device_id)
            .map(|record| &record.copy)
    }
}

/// Why the authority refused. Each maps to one HTTP status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkRefusal {
    /// The caller is not a person on the Hub.
    Unauthenticated,
    /// Only a trusted device may do this, and the session is not bound to one
    /// that is still trusted.
    NotADevice,
    InvalidKey,
    InvalidCopy(String),
    /// A link serves interactive and private-Home work; public use is a
    /// deployment's grant, not a class on the link.
    InvalidClasses,
    /// No trusted device holds a recipient key, so nothing could open a copy.
    NoRecipients,
    /// A new version must carry a copy for exactly the devices that hold keys.
    Coverage {
        missing: Vec<String>,
        unexpected: Vec<String>,
    },
    /// The link moved since the caller read it.
    Stale {
        current: u64,
    },
    NotFound,
    /// The named hosted Home does not serve the person: it is not one of their
    /// tenants' Homes, or it has no recipient key recorded.
    HomeNotServing,
    /// Another device holds the refresh lease.
    LeaseHeld {
        device_id: String,
        expires_at_ms: u64,
    },
}

impl LinkRefusal {
    fn status(&self) -> StatusCode {
        match self {
            Self::Unauthenticated => StatusCode::UNAUTHORIZED,
            Self::NotADevice => StatusCode::FORBIDDEN,
            Self::InvalidKey | Self::InvalidCopy(_) | Self::InvalidClasses => {
                StatusCode::BAD_REQUEST
            }
            Self::NoRecipients | Self::Coverage { .. } => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Stale { .. } | Self::LeaseHeld { .. } => StatusCode::CONFLICT,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::HomeNotServing => StatusCode::FORBIDDEN,
        }
    }

    fn body(&self) -> serde_json::Value {
        match self {
            Self::Unauthenticated => json!({ "error": "sign in to your account" }),
            Self::NotADevice => {
                json!({ "error": "only a trusted device of this account may do that" })
            }
            Self::InvalidKey => json!({ "error": "the recipient key is not a P-256 public key" }),
            Self::InvalidCopy(why) => {
                json!({ "error": format!("a sealed copy is malformed: {why}") })
            }
            Self::InvalidClasses => json!({
                "error": "a provider link serves interactive or private Home work; public use needs a deployment's own grant",
            }),
            Self::NoRecipients => json!({
                "error": "none of your trusted devices can hold provider links yet; open GaugeDesk on one of them first",
            }),
            Self::Coverage {
                missing,
                unexpected,
            } => json!({
                "error": "a provider link must be sealed for exactly your trusted devices",
                "missing": missing,
                "unexpected": unexpected,
            }),
            Self::Stale { current } => json!({
                "error": "this provider link changed since it was read",
                "current_version": current,
            }),
            Self::NotFound => json!({ "error": "no such provider link" }),
            Self::HomeNotServing => json!({
                "error": "this Home does not serve your account",
                "home_serves": false,
            }),
            Self::LeaseHeld {
                device_id,
                expires_at_ms,
            } => json!({
                "error": "another of your devices is refreshing this provider link",
                "device_id": device_id,
                "expires_at_ms": expires_at_ms,
            }),
        }
    }
}

impl IntoResponse for LinkRefusal {
    fn into_response(self) -> Response {
        (self.status(), Json(self.body())).into_response()
    }
}

/// One write the authority admits, appended in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkFact {
    Recipient(LinkRecipientRecord),
    Link(AccountLinkRecord),
    Copy(LinkCopyRecord),
    Lease(RefreshLeaseRecord),
    Check(LinkCheckRecord),
}

impl LinkFact {
    pub(crate) fn append(&self, wb: &mut crate::Workbench, scope: &str) -> Result<(), AdmitError> {
        match self {
            Self::Recipient(r) => wb.write_account_record_in(scope, LINK_RECIPIENT_KIND, &r.id, r),
            Self::Link(r) => wb.write_account_record_in(scope, LINK_KIND, &r.id, r),
            Self::Copy(r) => wb.write_account_record_in(scope, LINK_COPY_KIND, &r.id, r),
            Self::Lease(r) => wb.write_account_record_in(scope, LINK_LEASE_KIND, &r.id, r),
            Self::Check(r) => wb.write_account_record_in(scope, LINK_CHECK_KIND, &r.id, r),
        }
    }
}

fn check_copy(copy: &SealedLinkCopy) -> Result<(), LinkRefusal> {
    let hex_of = |value: &str, what: &str| {
        hex::decode(value)
            .map(|_| ())
            .map_err(|_| LinkRefusal::InvalidCopy(format!("{what} is not hex")))
    };
    hex_of(&copy.ephemeral_pubkey, "the ephemeral key")?;
    hex_of(&copy.ciphertext, "the ciphertext")?;
    // A nonce, an empty secret's tag and nothing else is 28 bytes.
    if copy.ciphertext.len() < 56 || copy.ciphertext.len() > 64 * 1024 {
        return Err(LinkRefusal::InvalidCopy(
            "the ciphertext is the wrong size".into(),
        ));
    }
    LinkRecipientPublicKey::parse(copy.ephemeral_pubkey.clone())
        .map_err(|_| LinkRefusal::InvalidCopy("the ephemeral key is not a P-256 point".into()))?;
    Ok(())
}

/// A device registers its own recipient key. Registering the same key again
/// changes nothing; a new key replaces the old one, and the copies sealed to
/// the old one stop counting until they are sealed again.
pub fn register_recipient(
    set: &LinkSet,
    device_id: &str,
    public_key: &str,
    now_ms: u64,
) -> Result<Vec<LinkFact>, LinkRefusal> {
    if !set.active_devices.contains(device_id) {
        return Err(LinkRefusal::NotADevice);
    }
    let public_key =
        LinkRecipientPublicKey::parse(public_key).map_err(|_| LinkRefusal::InvalidKey)?;
    if set
        .recipients
        .get(device_id)
        .is_some_and(|existing| existing.public_key == public_key)
    {
        return Ok(Vec::new());
    }
    let mut facts = vec![LinkFact::Recipient(LinkRecipientRecord {
        id: device_id.to_owned(),
        op: RecordOp::Upsert,
        public_key,
        registered_at_ms: now_ms,
    })];
    facts.extend(drop_copies_of(set, device_id));
    Ok(facts)
}

fn drop_copies_of(set: &LinkSet, device_id: &str) -> Vec<LinkFact> {
    set.copies
        .values()
        .filter(|copy| copy.copy.device_id == device_id)
        .map(|copy| {
            LinkFact::Copy(LinkCopyRecord {
                op: RecordOp::Tombstone,
                ..copy.clone()
            })
        })
        .collect()
}

/// A new version of a link, as the linking side submits it.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PutLink {
    /// The version the caller read; 0 for a provider never linked.
    pub expected_version: u64,
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub authentication: CredentialAuthentication,
    pub execution_classes: BTreeSet<ModelExecutionClass>,
    pub copies: Vec<SealedLinkCopy>,
}

/// Admit a new version of `provider`'s link. `caller_device` is the device
/// making it, when a device makes it; a browser page has none.
pub fn put_link(
    set: &LinkSet,
    provider: &str,
    caller_device: Option<&str>,
    put: &PutLink,
    now_ms: u64,
) -> Result<Vec<LinkFact>, LinkRefusal> {
    let current = set.links.get(provider).map_or(0, |link| link.version);
    if put.expected_version != current {
        return Err(LinkRefusal::Stale { current });
    }
    if let Some(lease) = set.leases.get(provider) {
        if lease.expires_at_ms > now_ms && Some(lease.device_id.as_str()) != caller_device {
            return Err(LinkRefusal::LeaseHeld {
                device_id: lease.device_id.clone(),
                expires_at_ms: lease.expires_at_ms,
            });
        }
    }
    // Public use of a person's link needs a deployment's own grant (ADR 0085),
    // never a flag on the link; and a link with no class serves nothing.
    if put.execution_classes.is_empty()
        || put
            .execution_classes
            .contains(&ModelExecutionClass::PublicDeployment)
    {
        return Err(LinkRefusal::InvalidClasses);
    }
    let recipients = set.recipients();
    if recipients.is_empty() {
        return Err(LinkRefusal::NoRecipients);
    }
    // Copies for hosted Homes ride along when the new version reaches them
    // (DR-0380 §3). A copy for a Home a link does not reach is dropped rather
    // than refused: a device lists every recipient and seals for all of them.
    let to_homes = reaches_homes(put.authentication, &put.execution_classes);
    let mut sealed_for = BTreeSet::new();
    let mut kept = Vec::new();
    let mut unknown = Vec::new();
    for copy in &put.copies {
        check_copy(copy)?;
        if !sealed_for.insert(copy.device_id.as_str()) {
            return Err(LinkRefusal::InvalidCopy(format!(
                "{} has two copies",
                copy.device_id
            )));
        }
        if is_home_recipient(&copy.device_id) {
            if !set.homes.contains_key(&copy.device_id) {
                unknown.push(copy.device_id.clone());
            } else if to_homes {
                kept.push(copy);
            }
        } else {
            kept.push(copy);
        }
    }
    let expected: BTreeSet<&str> = recipients.keys().copied().collect();
    let devices_sealed: BTreeSet<&str> = sealed_for
        .iter()
        .copied()
        .filter(|id| !is_home_recipient(id))
        .collect();
    if devices_sealed != expected || !unknown.is_empty() {
        return Err(LinkRefusal::Coverage {
            missing: expected
                .difference(&devices_sealed)
                .map(|d| d.to_string())
                .collect(),
            unexpected: devices_sealed
                .difference(&expected)
                .map(|d| d.to_string())
                .chain(unknown)
                .collect(),
        });
    }
    let version = current + 1;
    let mut facts = vec![LinkFact::Link(AccountLinkRecord {
        id: provider.to_owned(),
        op: RecordOp::Upsert,
        version,
        base_url: put.base_url.clone(),
        authentication: put.authentication,
        execution_classes: put.execution_classes.clone(),
        status: LinkStatus::Active,
        updated_at_ms: now_ms,
    })];
    facts.extend(kept.iter().map(|copy| {
        LinkFact::Copy(LinkCopyRecord {
            id: copy_id(provider, &copy.device_id),
            op: RecordOp::Upsert,
            provider: provider.to_owned(),
            version,
            copy: (*copy).clone(),
        })
    }));
    // A copy of an earlier version that this one does not replace would never
    // be served; drop it rather than keep ciphertext nothing will read. A Home
    // not sealed for here waits for a device, as a device trusted later does.
    let replaced: BTreeSet<&str> = kept.iter().map(|copy| copy.device_id.as_str()).collect();
    facts.extend(
        set.copies
            .values()
            .filter(|copy| {
                copy.provider == provider && !replaced.contains(copy.copy.device_id.as_str())
            })
            .map(|copy| {
                LinkFact::Copy(LinkCopyRecord {
                    op: RecordOp::Tombstone,
                    ..copy.clone()
                })
            }),
    );
    if let Some(lease) = set.leases.get(provider) {
        facts.push(LinkFact::Lease(RefreshLeaseRecord {
            op: RecordOp::Tombstone,
            ..lease.clone()
        }));
    }
    Ok(facts)
}

/// A device that holds the link seals it for devices still waiting. Only a
/// waiting device may be added, and only at the current version.
pub fn add_copies(
    set: &LinkSet,
    provider: &str,
    version: u64,
    copies: &[SealedLinkCopy],
) -> Result<Vec<LinkFact>, LinkRefusal> {
    let link = set
        .links
        .get(provider)
        .filter(|link| link.status == LinkStatus::Active)
        .ok_or(LinkRefusal::NotFound)?;
    if version != link.version {
        return Err(LinkRefusal::Stale {
            current: link.version,
        });
    }
    let mut waiting: BTreeSet<String> = set.waiting(provider).into_iter().collect();
    let mut facts = Vec::new();
    for copy in copies {
        check_copy(copy)?;
        // Removing it as it is sealed for also refuses a second copy for it.
        if !waiting.remove(&copy.device_id) {
            return Err(LinkRefusal::Coverage {
                missing: Vec::new(),
                unexpected: vec![copy.device_id.clone()],
            });
        }
        facts.push(LinkFact::Copy(LinkCopyRecord {
            id: copy_id(provider, &copy.device_id),
            op: RecordOp::Upsert,
            provider: provider.to_owned(),
            version,
            copy: copy.clone(),
        }));
    }
    Ok(facts)
}

/// Revoke a link: keep its record as revoked, delete every copy.
pub fn revoke_link(
    set: &LinkSet,
    provider: &str,
    now_ms: u64,
) -> Result<Vec<LinkFact>, LinkRefusal> {
    let link = set.links.get(provider).ok_or(LinkRefusal::NotFound)?;
    let mut facts = vec![LinkFact::Link(AccountLinkRecord {
        status: LinkStatus::Revoked,
        updated_at_ms: now_ms,
        ..link.clone()
    })];
    facts.extend(
        set.copies
            .values()
            .filter(|copy| copy.provider == provider)
            .map(|copy| {
                LinkFact::Copy(LinkCopyRecord {
                    op: RecordOp::Tombstone,
                    ..copy.clone()
                })
            }),
    );
    if let Some(lease) = set.leases.get(provider) {
        facts.push(LinkFact::Lease(RefreshLeaseRecord {
            op: RecordOp::Tombstone,
            ..lease.clone()
        }));
    }
    Ok(facts)
}

/// Revoking a trusted device: delete its recipient key and every copy sealed
/// to it, and free any lease it held. The providers it held are returned so
/// the person can be offered their rotation.
pub fn forget_device(set: &LinkSet, device_id: &str) -> (Vec<LinkFact>, Vec<String>) {
    let held: Vec<String> = set
        .copies
        .values()
        .filter(|copy| copy.copy.device_id == device_id)
        .map(|copy| copy.provider.clone())
        .collect();
    let mut facts = drop_copies_of(set, device_id);
    if let Some(recipient) = set.recipients.get(device_id) {
        facts.push(LinkFact::Recipient(LinkRecipientRecord {
            op: RecordOp::Tombstone,
            ..recipient.clone()
        }));
    }
    facts.extend(
        set.leases
            .values()
            .filter(|lease| lease.device_id == device_id)
            .map(|lease| {
                LinkFact::Lease(RefreshLeaseRecord {
                    op: RecordOp::Tombstone,
                    ..lease.clone()
                })
            }),
    );
    (facts, held)
}

/// Take the refresh lease for an OAuth link. The holder may take it again;
/// another device may take it only once it has expired.
pub fn take_lease(
    set: &LinkSet,
    provider: &str,
    device_id: &str,
    ttl_ms: u64,
    now_ms: u64,
) -> Result<Vec<LinkFact>, LinkRefusal> {
    if !set.active_devices.contains(device_id) {
        return Err(LinkRefusal::NotADevice);
    }
    set.links
        .get(provider)
        .filter(|link| link.status == LinkStatus::Active)
        .ok_or(LinkRefusal::NotFound)?;
    if let Some(lease) = set.leases.get(provider) {
        if lease.expires_at_ms > now_ms && lease.device_id != device_id {
            return Err(LinkRefusal::LeaseHeld {
                device_id: lease.device_id.clone(),
                expires_at_ms: lease.expires_at_ms,
            });
        }
    }
    Ok(vec![LinkFact::Lease(RefreshLeaseRecord {
        id: provider.to_owned(),
        op: RecordOp::Upsert,
        device_id: device_id.to_owned(),
        expires_at_ms: now_ms + ttl_ms.clamp(1, MAX_LEASE_MS),
    })])
}

/// A device that holds the current version records whether the provider
/// accepted its key (DR-0360). A check of an older version, or by a device
/// with no copy, is refused: it says nothing about the key the account holds.
pub fn record_check(
    set: &LinkSet,
    provider: &str,
    device_id: &str,
    version: u64,
    reachable: bool,
    now_ms: u64,
) -> Result<Vec<LinkFact>, LinkRefusal> {
    let link = set
        .links
        .get(provider)
        .filter(|link| link.status == LinkStatus::Active)
        .ok_or(LinkRefusal::NotFound)?;
    if version != link.version {
        return Err(LinkRefusal::Stale {
            current: link.version,
        });
    }
    set.copy_for(provider, device_id)
        .ok_or(LinkRefusal::NotADevice)?;
    Ok(vec![LinkFact::Check(LinkCheckRecord {
        id: provider.to_owned(),
        op: RecordOp::Upsert,
        version,
        device_id: device_id.to_owned(),
        reachable,
        checked_at_ms: now_ms,
    })])
}

/// The page every surface lists links from. `device` is the caller's own
/// device, when it is one.
pub fn links_view(set: &LinkSet, device: Option<&str>) -> serde_json::Value {
    let links: Vec<_> = set
        .links
        .values()
        .map(|link| {
            json!({
                "provider": link.id,
                "version": link.version,
                "base_url": link.base_url,
                "authentication": link.authentication,
                "execution_classes": link.execution_classes,
                "status": link.status,
                "updated_at_ms": link.updated_at_ms,
                "has_copy": device.is_some_and(|d| set.copy_for(&link.id, d).is_some()),
                "reachable": set.check(&link.id).map(|check| check.reachable),
                "checked_at_ms": set.check(&link.id).map(|check| check.checked_at_ms),
                "waiting": set.waiting(&link.id),
                "reaches_homes": set.reaches_homes(&link.id),
                "homes": set.homes_holding(&link.id),
            })
        })
        .collect();
    json!({ "links": links })
}

/// Move the provider links the Hub held before DR-0334 into the account's
/// per-device copies, once the account has a device to seal for (DR-0334,
/// Consequences): each is sealed for every current recipient and admitted as
/// the link's next version, and the Hub's own record is revoked, so it is
/// never served or used again. Its earlier ciphertext stays in the Hub's
/// append-only log under the Hub's key (`INV-6`), which seals every person's
/// Hub-held secrets alike, so no one record can be crypto-erased; a person who
/// wants the old key unreadable there too rotates it at the provider. A
/// provider the account already holds a link for
/// keeps that one; the older Hub-held copy is only revoked. A link that
/// served only private-Home work also serves the person's devices, which is
/// what linking it on the web was for. Returns the providers moved.
pub(crate) fn migrate_held_links(
    wb: &mut crate::Workbench,
    account: &str,
    scope: &str,
    now_ms: u64,
) -> Result<Vec<String>, Refused> {
    use crate::account::CredentialStatus;
    use crate::account_link_seal::{seal_link_copies, LinkContext, LinkRecipient};
    let held: Vec<_> = crate::account::credentials_in_scope(wb.store_ref(), scope)
        .into_values()
        .filter(|record| {
            record.status == CredentialStatus::Active && !record.sealed_token.is_empty()
        })
        .collect();
    if held.is_empty() {
        return Ok(Vec::new());
    }
    let mut moved = Vec::new();
    for record in held {
        let set = LinkSet::rebuild(wb.store_ref(), scope)?;
        let recipients: Vec<LinkRecipient> = set
            .recipients()
            .into_iter()
            .filter_map(|(device, key)| LinkRecipient::new(device, key.clone()).ok())
            .collect();
        if recipients.is_empty() {
            return Ok(moved);
        }
        let already = set
            .links
            .get(&record.id)
            .is_some_and(|link| link.status == LinkStatus::Active);
        if !already {
            let Some(secret) = wb.unseal_account_secret(&record.sealed_token) else {
                continue;
            };
            let current = set.links.get(&record.id).map_or(0, |link| link.version);
            let Ok(context) = LinkContext::new(account, &record.id, current + 1) else {
                continue;
            };
            let Ok(copies) = seal_link_copies(&context, secret.as_bytes(), &recipients) else {
                continue;
            };
            let mut execution_classes: BTreeSet<ModelExecutionClass> = record
                .execution_classes
                .iter()
                .copied()
                .filter(|class| *class != ModelExecutionClass::PublicDeployment)
                .collect();
            execution_classes.insert(ModelExecutionClass::LocalInteractive);
            let facts = put_link(
                &set,
                &record.id,
                None,
                &PutLink {
                    expected_version: current,
                    base_url: record.base_url.clone(),
                    authentication: record.authentication,
                    execution_classes,
                    copies,
                },
                now_ms,
            )?;
            admit(wb, scope, &facts)?;
            moved.push(record.id.clone());
        }
        wb.tombstone_account_credential_in(scope, record.id.clone())?;
    }
    Ok(moved)
}

// ---- HTTP ------------------------------------------------------------------

/// The routes the Hub mounts. Each refuses outside the Hub.
pub fn authority_routes() -> Router<SharedWorkbench> {
    Router::new()
        .route(
            "/account/link-recipients",
            get(get_recipients).post(post_recipient),
        )
        .route("/account/links", get(get_links))
        .route(
            "/account/links/{provider}",
            put(put_link_route).delete(delete_link),
        )
        .route("/account/links/{provider}/copy", get(get_copy))
        .route("/account/links/{provider}/copies", post(post_copies))
        .route("/account/links/{provider}/refresh-lease", post(post_lease))
        .route("/account/links/{provider}/check", post(post_check))
        .route("/account/home-links/{home_id}", get(get_home_links))
}

/// The person, their account scope, and the trusted device their session is
/// bound to, if it is bound to one that is still trusted.
struct Caller {
    account: String,
    scope: String,
    device: Option<String>,
}

fn caller(wb: &crate::Workbench, headers: &HeaderMap) -> Result<Caller, LinkRefusal> {
    caller_on(wb, net_http::bearer(headers), web_account_mode())
}

/// [`caller`] with whether this process is the Hub passed in, so a test need
/// not set the process-wide variable every other test reads.
fn caller_on(wb: &crate::Workbench, token: Option<&str>, hub: bool) -> Result<Caller, LinkRefusal> {
    if !hub {
        return Err(LinkRefusal::Unauthenticated);
    }
    let token = token.ok_or(LinkRefusal::Unauthenticated)?;
    let (account, _) = wb
        .resolve_account_session(token)
        .ok_or(LinkRefusal::Unauthenticated)?;
    let scope = crate::account::account_scope(&account);
    let session = crate::account_session::session_id(token);
    let device = crate::account_auth::AccountAuth::rebuild(wb.store_ref())
        .ok()
        .and_then(|auth| auth.sessions.get(&session).map(|s| s.device_id.clone()))
        .filter(|device| !device.is_empty());
    Ok(Caller {
        account,
        scope,
        device,
    })
}

fn now_ms() -> u64 {
    crate::account::session_now_ms()
}

/// A refusal, or a store that would not take the write.
pub(crate) enum Refused {
    Link(LinkRefusal),
    Store(Box<AdmitError>),
}

impl From<LinkRefusal> for Refused {
    fn from(refusal: LinkRefusal) -> Self {
        Self::Link(refusal)
    }
}

impl From<AdmitError> for Refused {
    fn from(error: AdmitError) -> Self {
        Self::Store(Box::new(error))
    }
}

fn admit(wb: &mut crate::Workbench, scope: &str, facts: &[LinkFact]) -> Result<(), Refused> {
    for fact in facts {
        fact.append(wb, scope)?;
    }
    Ok(())
}

/// Authenticate the caller, read their account's links, and decide.
fn with_set(
    wb: &SharedWorkbench,
    headers: &HeaderMap,
    decide: impl FnOnce(&mut crate::Workbench, &Caller, &LinkSet) -> Result<Response, Refused>,
) -> Response {
    let mut guard = wb.lock_unpoisoned();
    let outcome = caller(&guard, headers)
        .map_err(Refused::from)
        .and_then(|caller| {
            let set = LinkSet::rebuild(guard.store_ref(), &caller.scope)?;
            decide(&mut guard, &caller, &set)
        });
    match outcome {
        Ok(response) => response,
        Err(Refused::Link(refusal)) => refusal.into_response(),
        Err(Refused::Store(error)) => crate::err_response(*error),
    }
}

#[derive(Deserialize)]
struct RecipientBody {
    public_key: String,
}

async fn post_recipient(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Json(body): Json<RecipientBody>,
) -> Response {
    with_set(&wb, &headers, |wb, caller, set| {
        let device = caller.device.as_deref().ok_or(LinkRefusal::NotADevice)?;
        let facts = register_recipient(set, device, &body.public_key, now_ms())?;
        admit(wb, &caller.scope, &facts)?;
        // With a device to seal for, what the Hub held before DR-0334 moves.
        let migrated = migrate_held_links(wb, &caller.account, &caller.scope, now_ms())?;
        Ok(Json(json!({ "device_id": device, "migrated": migrated })).into_response())
    })
}

async fn get_recipients(State(wb): State<SharedWorkbench>, headers: HeaderMap) -> Response {
    with_set(&wb, &headers, |_, _, set| {
        // Homes are listed beside devices: a device seals for every recipient
        // it is given, and the authority drops a Home's copy of a link that
        // does not reach Homes.
        let recipients: Vec<_> = set
            .all_recipients()
            .into_iter()
            .map(|(id, public_key)| {
                let kind = if is_home_recipient(id) {
                    "home"
                } else {
                    "device"
                };
                json!({ "device_id": id, "public_key": public_key, "kind": kind })
            })
            .collect();
        Ok(Json(json!({ "recipients": recipients })).into_response())
    })
}

async fn get_links(State(wb): State<SharedWorkbench>, headers: HeaderMap) -> Response {
    with_set(&wb, &headers, |wb, caller, set| {
        // Copies for a Home the person left, or one erased, stop counting at
        // once; their ciphertext goes the next time the account is read.
        admit(wb, &caller.scope, &set.departed_copies())?;
        Ok(Json(links_view(set, caller.device.as_deref())).into_response())
    })
}

/// What a hosted Home holds for the person, asked with the person's own
/// session when they reach it (DR-0380 §4): each link that reaches Homes, and
/// that Home's copy of its current version when a device has sealed one. Every
/// copy is ciphertext only the Home can open, so the session needs no device.
/// A Home that does not serve the person is told so, and drops what it holds.
pub fn home_links_view(set: &LinkSet, home_id: &str) -> Result<serde_json::Value, LinkRefusal> {
    if !is_home_recipient(home_id) || !set.homes.contains_key(home_id) {
        return Err(LinkRefusal::HomeNotServing);
    }
    let links: Vec<_> = set
        .links
        .values()
        .filter(|link| set.reaches_homes(&link.id))
        .map(|link| {
            json!({
                "provider": link.id,
                "version": link.version,
                "base_url": link.base_url,
                "authentication": link.authentication,
                "execution_classes": link.execution_classes,
                "copy": set.copy_for(&link.id, home_id),
            })
        })
        .collect();
    Ok(json!({ "home_id": home_id, "links": links }))
}

async fn get_home_links(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Path(home_id): Path<String>,
) -> Response {
    let guard = wb.lock_unpoisoned();
    // A Home forwards whichever sign-in the person reached it with: an opaque
    // session, or the shared cookie's verified id-token. Either names the
    // account here.
    let account = net_http::bearer(&headers)
        .filter(|_| web_account_mode())
        .and_then(|token| guard.authenticate_bearer(token))
        .map(|authority| authority.as_str().to_owned());
    let Some(account) = account else {
        return LinkRefusal::Unauthenticated.into_response();
    };
    let scope = crate::account::account_scope(&account);
    let outcome = LinkSet::rebuild(guard.store_ref(), &scope)
        .map_err(Refused::from)
        .and_then(|set| Ok(home_links_view(&set, &home_id)?));
    match outcome {
        Ok(mut view) => {
            // The Home opens each copy under this account, which is not
            // always the id the Home itself knows the person by.
            view["account"] = json!(account);
            Json(view).into_response()
        }
        Err(Refused::Link(refusal)) => refusal.into_response(),
        Err(Refused::Store(error)) => crate::err_response(*error),
    }
}

async fn put_link_route(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Path(provider): Path<String>,
    Json(body): Json<PutLink>,
) -> Response {
    with_set(&wb, &headers, |wb, caller, set| {
        let facts = put_link(set, &provider, caller.device.as_deref(), &body, now_ms())?;
        admit(wb, &caller.scope, &facts)?;
        Ok(
            Json(json!({ "provider": provider, "version": body.expected_version + 1 }))
                .into_response(),
        )
    })
}

async fn delete_link(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Path(provider): Path<String>,
) -> Response {
    with_set(&wb, &headers, |wb, caller, set| {
        let facts = revoke_link(set, &provider, now_ms())?;
        admit(wb, &caller.scope, &facts)?;
        Ok(Json(json!({ "provider": provider, "status": LinkStatus::Revoked })).into_response())
    })
}

async fn get_copy(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Path(provider): Path<String>,
) -> Response {
    with_set(&wb, &headers, |_, caller, set| {
        let device = caller.device.as_deref().ok_or(LinkRefusal::NotADevice)?;
        let link = set.links.get(&provider).ok_or(LinkRefusal::NotFound)?;
        let copy = set
            .copy_for(&provider, device)
            .ok_or(LinkRefusal::NotFound)?;
        Ok(Json(json!({
            "provider": provider,
            "version": link.version,
            "base_url": link.base_url,
            "authentication": link.authentication,
            "execution_classes": link.execution_classes,
            "copy": copy,
        }))
        .into_response())
    })
}

#[derive(Deserialize)]
struct CopiesBody {
    version: u64,
    copies: Vec<SealedLinkCopy>,
}

async fn post_copies(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Path(provider): Path<String>,
    Json(body): Json<CopiesBody>,
) -> Response {
    with_set(&wb, &headers, |wb, caller, set| {
        // Only a device that holds the link can have opened it to seal again.
        let device = caller.device.as_deref().ok_or(LinkRefusal::NotADevice)?;
        set.copy_for(&provider, device)
            .ok_or(LinkRefusal::NotADevice)?;
        let facts = add_copies(set, &provider, body.version, &body.copies)?;
        admit(wb, &caller.scope, &facts)?;
        Ok(Json(json!({ "provider": provider, "added": facts.len() })).into_response())
    })
}

#[derive(Deserialize)]
struct LeaseBody {
    ttl_ms: u64,
}

async fn post_lease(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Path(provider): Path<String>,
    Json(body): Json<LeaseBody>,
) -> Response {
    with_set(&wb, &headers, |wb, caller, set| {
        let device = caller.device.as_deref().ok_or(LinkRefusal::NotADevice)?;
        let facts = take_lease(set, &provider, device, body.ttl_ms, now_ms())?;
        let expires_at_ms = match facts.first() {
            Some(LinkFact::Lease(lease)) => lease.expires_at_ms,
            _ => 0,
        };
        admit(wb, &caller.scope, &facts)?;
        Ok(Json(json!({ "provider": provider, "expires_at_ms": expires_at_ms })).into_response())
    })
}

#[derive(Deserialize)]
struct CheckBody {
    version: u64,
    reachable: bool,
}

async fn post_check(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Path(provider): Path<String>,
    Json(body): Json<CheckBody>,
) -> Response {
    with_set(&wb, &headers, |wb, caller, set| {
        let device = caller.device.as_deref().ok_or(LinkRefusal::NotADevice)?;
        let facts = record_check(
            set,
            &provider,
            device,
            body.version,
            body.reachable,
            now_ms(),
        )?;
        admit(wb, &caller.scope, &facts)?;
        Ok(Json(
            json!({ "provider": provider, "version": body.version, "reachable": body.reachable }),
        )
        .into_response())
    })
}

#[cfg(test)]
#[path = "account_links_tests.rs"]
mod tests;
