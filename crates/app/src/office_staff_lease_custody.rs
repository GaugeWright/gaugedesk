//! Durable office lease history and atomic admission custody.
use super::{LeaseError, LEASE_KIND, OUTAGE_MS};
use gaugedesk_core::ids::HomeId;
use gaugedesk_store::{CommandRecordFact, Store};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub(super) home: HomeId,
    pub(super) issuer: String,
    pub(super) account: String,
    pub(super) source_ref: String,
    pub(super) method: String,
    pub(super) source_mint_ms: u64,
    pub(super) source_expiry_ms: u64,
    pub(super) office_started_ms: u64,
    pub(super) last_activity_ms: u64,
    pub(super) last_verified_ms: u64,
    pub(super) last_observed_ms: u64,
    pub(super) absolute_deadline_ms: Option<u64>,
    pub(super) idle_timeout_ms: Option<u64>,
    pub(super) revision: u64,
    pub(super) revoked: bool,
}

impl Record {
    pub(super) fn scope(&self) -> String {
        scope(&self.home, &self.issuer, &self.source_ref)
    }

    pub(super) fn deadline(&self) -> u64 {
        let mut deadline = self
            .last_verified_ms
            .saturating_add(OUTAGE_MS)
            .min(self.source_expiry_ms);
        if let Some(absolute) = self.absolute_deadline_ms {
            deadline = deadline.min(absolute);
        }
        if let Some(idle) = self.idle_timeout_ms {
            deadline = deadline.min(self.last_activity_ms.saturating_add(idle));
        }
        deadline
    }

    pub(super) fn same_source(&self, other: &Self) -> bool {
        self.home == other.home
            && self.issuer == other.issuer
            && self.account == other.account
            && self.source_ref == other.source_ref
            && self.method == other.method
            && self.source_mint_ms == other.source_mint_ms
            && self.office_started_ms == other.office_started_ms
    }

    pub(super) fn valid(&self) -> bool {
        self.source_mint_ms > 0
            && self.source_mint_ms <= self.office_started_ms
            && self.office_started_ms <= self.last_activity_ms
            && self.office_started_ms <= self.last_verified_ms
            && self.last_activity_ms <= self.last_observed_ms
            && self.last_verified_ms <= self.last_observed_ms
            && self.source_expiry_ms > self.source_mint_ms
            && self.source_expiry_ms
                <= self
                    .source_mint_ms
                    .saturating_add(crate::account::SESSION_ABSOLUTE_LIFETIME_MS)
            && !self.account.trim().is_empty()
            && !self.method.trim().is_empty()
            && !self.issuer.is_empty()
            && !self.source_ref.is_empty()
            && self.idle_timeout_ms != Some(0)
    }

    pub(super) fn tighten(&mut self, absolute_ms: u64, idle_ms: u64) {
        if absolute_ms > 0 {
            let ceiling = self.office_started_ms.saturating_add(absolute_ms);
            self.absolute_deadline_ms = Some(
                self.absolute_deadline_ms
                    .map_or(ceiling, |old| old.min(ceiling)),
            );
        }
        if idle_ms > 0 {
            self.idle_timeout_ms =
                Some(self.idle_timeout_ms.map_or(idle_ms, |old| old.min(idle_ms)));
        }
    }
}

pub(super) fn scope(home: &HomeId, issuer: &str, source_ref: &str) -> String {
    let encoded =
        serde_json::to_vec(&(home.as_str(), issuer, source_ref)).expect("string tuple serializes");
    let mut hash = Sha256::new();
    hash.update(b"gaugedesk:office-staff-lease:v1\0");
    hash.update(encoded);
    format!("office-staff-lease:{}", hex::encode(hash.finalize()))
}

pub(super) fn load(store: &Store, reference: &str) -> Result<Option<Record>, LeaseError> {
    let mut latest: Option<Record> = None;
    // Projection reads omit erased rows. Authentication must instead refuse an
    // unreadable newer revocation or clock rather than expose an older grant.
    for (_, kind, payload) in store.retained_events(reference)? {
        if kind != LEASE_KIND {
            return Err(LeaseError::Refused);
        }
        let record: Record = serde_json::from_str(&payload).map_err(|_| LeaseError::Refused)?;
        if !record.valid() || record.scope() != reference {
            return Err(LeaseError::Refused);
        }
        let digest = hex::encode(Sha256::digest(payload.as_bytes()));
        let command_key = format!("lease:{}:{digest}", record.revision);
        let expected = serde_json::to_string(&("office_staff_lease_command_v1", &digest))
            .map_err(|_| LeaseError::Refused)?;
        if store
            .committed_record_snapshot(reference, &command_key)?
            .as_deref()
            != Some(expected.as_str())
        {
            return Err(LeaseError::Refused);
        }
        let valid_transition = match &latest {
            None => record.revision == 0 && !record.revoked,
            Some(previous) => {
                previous.same_source(&record)
                    && record.revision == previous.revision.saturating_add(1)
                    && (!previous.revoked || record.revoked)
                    && record.last_activity_ms >= previous.last_activity_ms
                    && record.last_verified_ms >= previous.last_verified_ms
                    && record.last_observed_ms >= previous.last_observed_ms
                    && previous
                        .absolute_deadline_ms
                        .is_none_or(|old| record.absolute_deadline_ms.is_some_and(|new| new <= old))
                    && previous
                        .idle_timeout_ms
                        .is_none_or(|old| record.idle_timeout_ms.is_some_and(|new| new <= old))
            }
        };
        if !valid_transition {
            return Err(LeaseError::Refused);
        }
        latest = Some(record);
    }
    Ok(latest)
}

pub(super) fn publish(
    store: &mut Store,
    reference: &str,
    record: &Record,
    basis: gaugedesk_store::command_dispatch::DispatchReadBasis,
) -> Result<(), LeaseError> {
    let basis = if record.revoked {
        basis
    } else {
        basis.with_deadline(
            std::time::UNIX_EPOCH + std::time::Duration::from_millis(record.deadline()),
        )
    };
    let payload = serde_json::to_string(record).map_err(|_| LeaseError::Refused)?;
    let digest = hex::encode(Sha256::digest(payload.as_bytes()));
    let snapshot = serde_json::to_string(&("office_staff_lease_command_v1", &digest))
        .map_err(|_| LeaseError::Refused)?;
    let facts = [CommandRecordFact {
        scope_id: reference.into(),
        kind: LEASE_KIND.into(),
        payload,
    }];
    store.with_dispatch_record_admission(&basis, |writer| {
        writer.commit(
            reference,
            &format!("lease:{}:{digest}", record.revision),
            &snapshot,
            &facts,
        )
    })??;
    Ok(())
}
