//! Process-local staff action identity, constructed only after exact admission.
use super::*;
use gaugedesk_core::ids::AuthorityId;
use gaugedesk_store::command_dispatch::DispatchReadBasis;

/// Opaque, nonserializable authentication standing. It supplies neither project
/// permissions nor a credential and cannot be reconstructed from stored facts.
#[derive(Clone)]
pub struct OfficeStaffActionAuthority(Arc<Standing>);

struct Standing {
    home: HomeId,
    process_epoch: String,
    actor: AuthorityId,
    reference: String,
    revision_floor: Arc<AtomicU64>,
    deadline_ms: u64,
    started_at_ms: u64,
    started: Instant,
    monotonic_end: Instant,
    alive: Arc<AtomicBool>,
    active: Arc<AtomicBool>,
    admission: crate::home_admission::HomeAdmissionStanding,
}

impl std::fmt::Debug for OfficeStaffActionAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OfficeStaffActionAuthority")
            .field("home", &self.0.home)
            .field("actor", &self.0.actor)
            .finish_non_exhaustive()
    }
}
impl PartialEq for OfficeStaffActionAuthority {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for OfficeStaffActionAuthority {}

impl OfficeStaffLeases {
    /// The caller separately checks project and software admission. The exact
    /// Home token must have been issued for this source lease, not merely actor.
    pub fn action_context(
        &self,
        store: &Store,
        reference: &str,
        admission: crate::home_admission::HomeAdmissionStanding,
    ) -> Result<crate::identity::AuthenticatedActionContext, LeaseError> {
        let (lease, basis) = self.prepare(store, reference)?;
        if !admission.is_active()
            || !admission.is_bound_to(lease.home(), &AuthorityId::new(lease.account()))
            || admission.source_lease() != Some(reference)
        {
            return Err(LeaseError::Refused);
        }
        let bound = self.live.get(reference).ok_or(LeaseError::Refused)?;
        let monotonic_end = self
            .started
            .checked_add(std::time::Duration::from_millis(
                u64::try_from(basis.elapsed_deadline_ms).map_err(|_| LeaseError::Refused)?,
            ))
            .ok_or(LeaseError::Refused)?;
        let authority = OfficeStaffActionAuthority(Arc::new(Standing {
            home: lease.home().clone(),
            process_epoch: self.process_epoch(),
            actor: AuthorityId::new(lease.account()),
            reference: reference.into(),
            revision_floor: Arc::clone(&bound.revision_floor),
            deadline_ms: lease.deadline_ms(),
            started_at_ms: self.started_at_ms,
            started: self.started,
            monotonic_end,
            alive: Arc::clone(&self.alive),
            active: Arc::clone(&bound.active),
            admission,
        }));
        authority.revalidate(store, &self.home, &authority.0.actor)?;
        Ok(crate::identity::AuthenticatedActionContext::office_staff(
            authority,
        ))
    }
}

impl OfficeStaffActionAuthority {
    pub(crate) fn source_reference(&self) -> &str {
        &self.0.reference
    }
    pub(crate) fn process_epoch(&self) -> &str {
        &self.0.process_epoch
    }
    pub(crate) fn original_deadline_ms(&self) -> u64 {
        self.0.deadline_ms
    }
    pub(crate) fn admission_reference(&self) -> &str {
        self.0.admission.reference()
    }

    pub(crate) fn actor(&self) -> &AuthorityId {
        &self.0.actor
    }

    pub(crate) fn now_ms(&self) -> u64 {
        crate::account::session_now_ms().max(
            self.0.started_at_ms.saturating_add(
                self.0
                    .started
                    .elapsed()
                    .as_millis()
                    .min(u128::from(u64::MAX)) as u64,
            ),
        )
    }

    fn process_active(&self) -> bool {
        self.0.alive.load(Ordering::Acquire)
            && self.0.active.load(Ordering::Acquire)
            && self.0.admission.is_active()
            && Instant::now() < self.0.monotonic_end
    }

    pub(crate) fn revalidate(
        &self,
        store: &Store,
        home: &HomeId,
        actor: &AuthorityId,
    ) -> Result<u64, LeaseError> {
        if &self.0.home != home || &self.0.actor != actor || !self.process_active() {
            return Err(LeaseError::Refused);
        }
        let mut record = load(store, &self.0.reference)?.ok_or(LeaseError::Refused)?;
        let now = self.now_ms();
        if record.home != *home
            || record.account != actor.as_str()
            || record.revoked
            || record.revision < self.0.revision_floor.load(Ordering::Acquire)
            || now < record.last_observed_ms
        {
            return Err(LeaseError::Refused);
        }
        let org = current_org(store, actor.as_str())?;
        if org.sso_enforced() && !org.enterprise_session_method_matches(&record.method) {
            return Err(LeaseError::Refused);
        }
        let (absolute, idle) = org.session_bounds_ms();
        record.tighten(absolute, idle);
        let deadline = self.0.deadline_ms.min(record.deadline());
        if deadline <= now {
            return Err(LeaseError::Refused);
        }
        Ok(deadline)
    }

    /// Fence authentication scopes even if a caller's resource snapshot forgot
    /// them. A newer lease may shorten this observation; it never extends it.
    pub(crate) fn bind_basis(
        &self,
        store: &Store,
        basis: DispatchReadBasis,
        ceiling: Option<u64>,
    ) -> Result<DispatchReadBasis, AdmitError> {
        let ((deadline, revision), auth_basis) =
            store.read_for_dispatch(&[&self.0.reference, crate::org::ORG_SCOPE], |reader| {
                let revision = self.0.revision_floor.load(Ordering::Acquire);
                let deadline = self
                    .revalidate(reader, &self.0.home, &self.0.actor)
                    .map_err(storage_error)?;
                Ok((
                    ceiling.map_or(deadline, |ceiling| ceiling.min(deadline)),
                    revision,
                ))
            })?;
        let captured = Instant::now();
        let now = self.now_ms();
        if deadline <= now {
            return Err(storage_error(LeaseError::Refused));
        }
        let end = captured
            .checked_add(std::time::Duration::from_millis(
                deadline.saturating_sub(now),
            ))
            .ok_or_else(|| storage_error(LeaseError::Refused))?;
        let authority = self.clone();
        Ok(basis
            .combine(auth_basis)?
            .with_deadline(std::time::UNIX_EPOCH + std::time::Duration::from_millis(deadline))
            .with_process_guard(move || {
                authority.process_active()
                    && authority.0.revision_floor.load(Ordering::Acquire) == revision
                    && Instant::now() < end
            }))
    }
}

#[cfg(test)]
#[path = "office_staff_action_authority_tests.rs"]
mod tests;
