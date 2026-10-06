//! Home-local authentication lease for native office staff (DR-0263, WS-545).
//!
//! A lease identifies a person; project, software and exact Home-admission
//! checks remain mandatory at each work boundary. This service is not mounted.

use std::collections::BTreeMap;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::Instant;

use gaugedesk_core::ids::HomeId;
use gaugedesk_store::{AdmitError, Store};

use super::source::SourceCheck;

pub const LEASE_KIND: &str = "office_staff_lease_v1";
const OUTAGE_MS: u64 = 60 * 60 * 1000;

#[derive(Debug)]
pub enum LeaseError {
    Refused,
    Storage(AdmitError),
}
impl From<AdmitError> for LeaseError {
    fn from(error: AdmitError) -> Self {
        Self::Storage(error)
    }
}

#[path = "office_staff_lease_custody.rs"]
mod custody;
use custody::{load, publish, scope, Record};

#[path = "office_staff_action_authority.rs"]
mod action_authority;
pub use action_authority::OfficeStaffActionAuthority;

/// A verified local observation, not a request credential or project grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OfficeStaffLease {
    home: HomeId,
    reference: String,
    account: String,
    deadline_ms: u64,
}
impl OfficeStaffLease {
    pub fn home(&self) -> &HomeId {
        &self.home
    }
    pub fn reference(&self) -> &str {
        &self.reference
    }
    pub fn account(&self) -> &str {
        &self.account
    }
    pub fn deadline_ms(&self) -> u64 {
        self.deadline_ms
    }
}

/// An explicit product read basis plus a process-local monotonic ceiling.
/// It is not serializable, transferable across restart, or permission to work.
pub struct OfficeStaffLeaseBasis {
    home: HomeId,
    account: gaugedesk_core::ids::AuthorityId,
    reference: String,
    process_id: [u8; 32],
    elapsed_deadline_ms: u128,
    basis: gaugedesk_store::command_dispatch::DispatchReadBasis,
}

impl OfficeStaffLeaseBasis {
    /// Carry the exact Home admission's cancellation standing into execution.
    pub fn bind_home(
        mut self,
        standing: crate::home_admission::HomeAdmissionStanding,
    ) -> Result<Self, LeaseError> {
        if !standing.is_active()
            || !standing.is_bound_to(&self.home, &self.account)
            || standing.source_lease() != Some(self.reference.as_str())
        {
            return Err(LeaseError::Refused);
        }
        self.basis = self.basis.with_process_guard(move || standing.is_active());
        Ok(self)
    }

    /// Compose authentication with the caller's independently admitted project
    /// and resource observation. Both scope heads and deadlines remain fenced.
    pub fn combine(
        mut self,
        basis: gaugedesk_store::command_dispatch::DispatchReadBasis,
    ) -> Result<Self, LeaseError> {
        self.basis = self.basis.combine(basis)?;
        Ok(self)
    }
}

struct LiveBound {
    active: Arc<AtomicBool>,
    revision_floor: Arc<AtomicU64>,
    revoked: bool,
    elapsed_deadline_ms: u128,
    revision: u64,
}

/// One Home's lease verifier. Process-local monotonic bounds complement durable
/// wall clocks. Reconstructing this service has no live offline authority.
pub struct OfficeStaffLeases {
    home: HomeId,
    started_at_ms: u64,
    started: Instant,
    live: BTreeMap<String, LiveBound>,
    process_id: [u8; 32],
    alive: Arc<AtomicBool>,
}

impl Drop for OfficeStaffLeases {
    fn drop(&mut self) {
        self.alive.store(false, Ordering::Release);
    }
}

impl OfficeStaffLeases {
    pub fn new(home: HomeId) -> Self {
        Self {
            home,
            started_at_ms: crate::account::session_now_ms(),
            started: Instant::now(),
            live: BTreeMap::new(),
            process_id: crate::session::random_bytes(),
            alive: Arc::new(AtomicBool::new(true)),
        }
    }

    pub(crate) fn process_epoch(&self) -> String {
        hex::encode(self.process_id)
    }

    pub(crate) fn home(&self) -> &HomeId {
        &self.home
    }

    pub(crate) fn recognizes_source(&self, store: &Store, reference: &str) -> bool {
        self.live.contains_key(reference) || !matches!(load(store, reference), Ok(None))
    }

    pub(crate) fn source_reference(&self, issuer: &str, source_ref: &str) -> String {
        scope(&self.home, issuer, source_ref)
    }

    fn revision_floor(&self, reference: &str, revision: u64) -> Arc<AtomicU64> {
        let floor = self
            .live
            .get(reference)
            .map(|bound| Arc::clone(&bound.revision_floor))
            .unwrap_or_else(|| Arc::new(AtomicU64::new(revision)));
        floor.fetch_max(revision, Ordering::AcqRel);
        floor
    }

    fn time(&self) -> (u64, u128) {
        let elapsed = self.started.elapsed().as_millis();
        let floor = self
            .started_at_ms
            .saturating_add(elapsed.min(u64::MAX as u128) as u64);
        (crate::account::session_now_ms().max(floor), elapsed)
    }

    /// Called after verification outside the Home mutex. `Unavailable` can use
    /// only an already live lease; `Refused` durably terminates this exact source.
    pub fn observe(
        &mut self,
        store: &mut Store,
        issuer: &str,
        source_ref: &str,
        check: SourceCheck,
    ) -> Result<OfficeStaffLease, LeaseError> {
        let (now, elapsed) = self.time();
        let lease = self.observe_at(store, issuer, source_ref, check, now, elapsed)?;
        self.current(store, lease.reference())
    }

    fn observe_at(
        &mut self,
        store: &mut Store,
        issuer: &str,
        source_ref: &str,
        check: SourceCheck,
        now: u64,
        elapsed: u128,
    ) -> Result<OfficeStaffLease, LeaseError> {
        let reference = scope(&self.home, issuer, source_ref);
        match check {
            SourceCheck::Unavailable => self.current_at(store, &reference, now, elapsed),
            SourceCheck::Refused => {
                self.revoke_at(store, &reference, now)?;
                Err(LeaseError::Refused)
            }
            SourceCheck::Verified(proof) => {
                if proof.issuer() != issuer
                    || proof.session().session_ref != source_ref
                    || proof.checked_at_ms() < self.started_at_ms
                    || proof.checked_at_ms() > now
                    || now.saturating_sub(proof.checked_at_ms()) > 30_000
                {
                    return Err(LeaseError::Refused);
                }
                if self.live.get(&reference).is_some_and(|bound| bound.revoked) {
                    return Err(LeaseError::Refused);
                }
                if let Some(previous) = load(store, &reference)? {
                    if previous.revoked {
                        if let Some(bound) = self.live.get(&reference) {
                            bound.active.store(false, Ordering::Release);
                        }
                        self.live.insert(
                            reference.clone(),
                            LiveBound {
                                active: Arc::new(AtomicBool::new(false)),
                                revision_floor: Arc::new(AtomicU64::new(previous.revision)),
                                revoked: true,
                                elapsed_deadline_ms: 0,
                                revision: previous.revision,
                            },
                        );
                        return Err(LeaseError::Refused);
                    }
                    if previous.account != proof.account()
                        || previous.method != proof.session().method
                        || previous.source_mint_ms != proof.session().issued_at_ms
                    {
                        self.revoke_at(store, &reference, now)?;
                        return Err(LeaseError::Refused);
                    }
                }
                let (record, basis) =
                    store.read_for_dispatch(&[&reference, crate::org::ORG_SCOPE], |reader| {
                        let previous = load(reader, &reference).map_err(storage_error)?;
                        if let Some(bound) = self.live.get(&reference) {
                            if previous
                                .as_ref()
                                .is_none_or(|record| record.revision < bound.revision)
                            {
                                return Err(storage_error(LeaseError::Refused));
                            }
                        }
                        let org = current_org(reader, proof.account()).map_err(storage_error)?;
                        if org.sso_enforced()
                            && !org.enterprise_session_method_matches(&proof.session().method)
                        {
                            return Err(storage_error(LeaseError::Refused));
                        }
                        let mut record = match previous {
                            Some(old) => {
                                if old.revoked
                                    || old.account != proof.account()
                                    || old.method != proof.session().method
                                    || old.source_mint_ms != proof.session().issued_at_ms
                                    || now < old.last_observed_ms
                                    || old.absolute_deadline_ms.is_some_and(|end| now >= end)
                                    || old.idle_timeout_ms.is_some_and(|idle| {
                                        now >= old.last_activity_ms.saturating_add(idle)
                                    })
                                    || proof.checked_at_ms() < old.last_verified_ms
                                {
                                    return Err(storage_error(LeaseError::Refused));
                                }
                                let mut next = old;
                                next.revision = next
                                    .revision
                                    .checked_add(1)
                                    .ok_or_else(|| storage_error(LeaseError::Refused))?;
                                next
                            }
                            None => Record {
                                home: self.home.clone(),
                                issuer: issuer.into(),
                                account: proof.account().into(),
                                source_ref: source_ref.into(),
                                method: proof.session().method.clone(),
                                source_mint_ms: proof.session().issued_at_ms,
                                source_expiry_ms: proof.session().expires_at_ms,
                                office_started_ms: proof.checked_at_ms(),
                                last_activity_ms: proof.checked_at_ms(),
                                last_verified_ms: proof.checked_at_ms(),
                                last_observed_ms: now,
                                absolute_deadline_ms: None,
                                idle_timeout_ms: None,
                                revision: 0,
                                revoked: false,
                            },
                        };
                        record.last_verified_ms = proof.checked_at_ms();
                        record.source_expiry_ms = proof.session().expires_at_ms;
                        record.last_observed_ms = now;
                        let (absolute, idle) = org.session_bounds_ms();
                        record.tighten(absolute, idle);
                        if !record.valid() || record.deadline() <= now {
                            return Err(storage_error(LeaseError::Refused));
                        }
                        Ok(record)
                    })?;
                // Commit and receipt precede any process-local authority. The
                // command snapshot contains only a digest, never workforce facts.
                publish(store, &reference, &record, basis)?;
                let revision_floor = self.revision_floor(&reference, record.revision);
                self.live.insert(
                    reference.clone(),
                    LiveBound {
                        active: self
                            .live
                            .get(&reference)
                            .map(|bound| Arc::clone(&bound.active))
                            .unwrap_or_else(|| Arc::new(AtomicBool::new(true))),
                        revision_floor,
                        revoked: false,
                        elapsed_deadline_ms: elapsed
                            .saturating_add(u128::from(record.deadline() - now)),
                        revision: record.revision,
                    },
                );
                Ok(observation(&reference, &record))
            }
        }
    }

    pub fn current(&self, store: &Store, reference: &str) -> Result<OfficeStaffLease, LeaseError> {
        let (now, elapsed) = self.time();
        self.current_at(store, reference, now, elapsed)
    }

    fn current_at(
        &self,
        store: &Store,
        reference: &str,
        now: u64,
        elapsed: u128,
    ) -> Result<OfficeStaffLease, LeaseError> {
        let bound = self.live.get(reference).ok_or(LeaseError::Refused)?;
        let mut record = load(store, reference)?.ok_or(LeaseError::Refused)?;
        if record.home != self.home
            || bound.revoked
            || record.revoked
            || now < record.last_observed_ms
            || record.revision < bound.revision
            || elapsed >= bound.elapsed_deadline_ms
        {
            return Err(LeaseError::Refused);
        }
        let org = current_org(store, &record.account)?;
        if org.sso_enforced() && !org.enterprise_session_method_matches(&record.method) {
            return Err(LeaseError::Refused);
        }
        let (absolute, idle) = org.session_bounds_ms();
        record.tighten(absolute, idle);
        if record.deadline() <= now {
            return Err(LeaseError::Refused);
        }
        Ok(observation(reference, &record))
    }

    /// Capture authentication scopes and deadline for separately authorized
    /// work. The returned wrapper keeps the monotonic guard through execution.
    pub fn prepare(
        &self,
        store: &Store,
        reference: &str,
    ) -> Result<(OfficeStaffLease, OfficeStaffLeaseBasis), LeaseError> {
        let (now, elapsed) = self.time();
        let (lease, basis) =
            store.read_for_dispatch(&[reference, crate::org::ORG_SCOPE], |reader| {
                self.current_at(reader, reference, now, elapsed)
                    .map_err(storage_error)
            })?;
        let bound = self.live.get(reference).ok_or(LeaseError::Refused)?;
        let basis = basis.with_deadline(
            std::time::UNIX_EPOCH + std::time::Duration::from_millis(lease.deadline_ms),
        );
        let remaining = lease.deadline_ms.saturating_sub(now);
        let elapsed_deadline_ms = bound
            .elapsed_deadline_ms
            .min(elapsed.saturating_add(u128::from(remaining)));
        let monotonic_end = self
            .started
            .checked_add(std::time::Duration::from_millis(
                u64::try_from(elapsed_deadline_ms).map_err(|_| LeaseError::Refused)?,
            ))
            .ok_or(LeaseError::Refused)?;
        let alive = Arc::clone(&self.alive);
        let active = Arc::clone(&bound.active);
        let revision_floor = Arc::clone(&bound.revision_floor);
        let revision = bound.revision;
        let basis = basis.with_process_guard(move || {
            alive.load(Ordering::Acquire)
                && active.load(Ordering::Acquire)
                && revision_floor.load(Ordering::Acquire) == revision
                && Instant::now() < monotonic_end
        });
        let captured = OfficeStaffLeaseBasis {
            home: self.home.clone(),
            account: gaugedesk_core::ids::AuthorityId::new(lease.account()),
            reference: reference.into(),
            process_id: self.process_id,
            elapsed_deadline_ms,
            basis,
        };
        Ok((lease, captured))
    }

    /// Run a bounded operation under the final product writer fence. The
    /// callback acts on separate runtime/target stores, never this product store.
    pub fn with_prepared<T>(
        &self,
        store: &mut Store,
        prepared: &OfficeStaffLeaseBasis,
        operation: impl FnOnce() -> T,
    ) -> Result<T, LeaseError> {
        if prepared.process_id != self.process_id {
            return Err(LeaseError::Refused);
        }
        let observer = store.read_only_sibling().map_err(AdmitError::from)?;
        store.with_dispatch_basis(&prepared.basis, || {
            let (now, elapsed) = self.time();
            if elapsed >= prepared.elapsed_deadline_ms {
                return Err(LeaseError::Refused);
            }
            self.current_at(&observer, &prepared.reference, now, elapsed)?;
            Ok(operation())
        })?
    }

    /// Record admitted user activity without refreshing hosted verification.
    /// The work boundary calls this only after project, software and Home checks.
    pub fn touch(
        &mut self,
        store: &mut Store,
        reference: &str,
    ) -> Result<OfficeStaffLease, LeaseError> {
        let (now, elapsed) = self.time();
        self.touch_at(store, reference, now, elapsed)?;
        self.current(store, reference)
    }

    pub(crate) fn touch_admitted(
        &mut self,
        store: &mut Store,
        reference: &str,
        authority: gaugedesk_store::command_dispatch::DispatchReadBasis,
    ) -> Result<OfficeStaffLease, LeaseError> {
        let (now, elapsed) = self.time();
        self.touch_at_guarded(store, reference, now, elapsed, Some(authority))?;
        self.current(store, reference)
    }

    fn touch_at(
        &mut self,
        store: &mut Store,
        reference: &str,
        now: u64,
        elapsed: u128,
    ) -> Result<OfficeStaffLease, LeaseError> {
        self.touch_at_guarded(store, reference, now, elapsed, None)
    }

    fn touch_at_guarded(
        &mut self,
        store: &mut Store,
        reference: &str,
        now: u64,
        elapsed: u128,
        authority: Option<gaugedesk_store::command_dispatch::DispatchReadBasis>,
    ) -> Result<OfficeStaffLease, LeaseError> {
        self.current_at(store, reference, now, elapsed)?;
        let (mut record, basis) =
            store.read_for_dispatch(&[reference, crate::org::ORG_SCOPE], |reader| {
                self.current_at(reader, reference, now, elapsed)
                    .map_err(storage_error)?;
                load(reader, reference)
                    .map_err(storage_error)?
                    .ok_or_else(|| storage_error(LeaseError::Refused))
            })?;
        let basis = match authority {
            Some(authority) => basis.combine(authority)?,
            None => basis,
        };
        let org = current_org(store, &record.account)?;
        let (absolute, idle) = org.session_bounds_ms();
        record.tighten(absolute, idle);
        record.last_activity_ms = now;
        record.last_observed_ms = now;
        record.revision = record.revision.checked_add(1).ok_or(LeaseError::Refused)?;
        publish(store, reference, &record, basis)?;
        let revision_floor = self.revision_floor(reference, record.revision);
        self.live.insert(
            reference.into(),
            LiveBound {
                revision_floor,
                active: Arc::clone(&self.live.get(reference).ok_or(LeaseError::Refused)?.active),
                revoked: false,
                elapsed_deadline_ms: elapsed.saturating_add(u128::from(record.deadline() - now)),
                revision: record.revision,
            },
        );
        Ok(observation(reference, &record))
    }

    /// Terminal local/source revocation. Callers separately prove administrator
    /// or exact admitted person authority. It never rotates into another lease.
    pub fn revoke(&mut self, store: &mut Store, reference: &str) -> Result<(), LeaseError> {
        self.revoke_at(store, reference, self.time().0)
    }

    fn revoke_at(
        &mut self,
        store: &mut Store,
        reference: &str,
        now: u64,
    ) -> Result<(), LeaseError> {
        if let Some(bound) = self.live.get_mut(reference) {
            bound.active.store(false, Ordering::Release);
            bound.revoked = true;
        }
        let (record, basis) = store.read_for_dispatch(&[reference], |reader| {
            load(reader, reference).map_err(storage_error)
        })?;
        let Some(mut record) = record else {
            return Ok(());
        };
        if record.home != self.home {
            return Err(LeaseError::Refused);
        }
        if record.revoked {
            self.live.insert(
                reference.into(),
                LiveBound {
                    active: Arc::new(AtomicBool::new(false)),
                    revision_floor: Arc::new(AtomicU64::new(record.revision)),
                    revoked: true,
                    elapsed_deadline_ms: 0,
                    revision: record.revision,
                },
            );
            return Ok(());
        }
        record.revoked = true;
        record.last_observed_ms = record.last_observed_ms.max(now);
        record.revision = record.revision.checked_add(1).ok_or(LeaseError::Refused)?;
        publish(store, reference, &record, basis)?;
        self.live.insert(
            reference.into(),
            LiveBound {
                active: Arc::new(AtomicBool::new(false)),
                revision_floor: Arc::new(AtomicU64::new(record.revision)),
                revoked: true,
                elapsed_deadline_ms: 0,
                revision: record.revision,
            },
        );
        Ok(())
    }
}

fn storage_error(error: LeaseError) -> AdmitError {
    match error {
        LeaseError::Storage(error) => error,
        LeaseError::Refused => AdmitError::Rejected(gaugedesk_core::Rejection {
            reason: "office staff lease refused",
        }),
    }
}
fn current_org(store: &Store, account: &str) -> Result<crate::org::Org, LeaseError> {
    store.retained_events(crate::org::ORG_SCOPE)?;
    let org = crate::org::Org::rebuild(store)?;
    if org.role_of(account).is_none() {
        return Err(LeaseError::Refused);
    }
    Ok(org)
}
fn observation(reference: &str, record: &Record) -> OfficeStaffLease {
    OfficeStaffLease {
        home: record.home.clone(),
        reference: reference.into(),
        account: record.account.clone(),
        deadline_ms: record.deadline(),
    }
}
#[cfg(test)]
#[path = "office_staff_lease_tests.rs"]
mod tests;
