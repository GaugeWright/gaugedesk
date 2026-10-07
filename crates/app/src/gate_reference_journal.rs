//! Select the registered project's journal without silently falling back after
//! a missing file, incomplete creation or binding mismatch. Unregistered legacy
//! projects retain their prototype path during migration; it establishes no
//! project Home coverage and must not feed the authoritative planner.

use gaugedesk_store::home_reference_journal::{
    HomeReferenceJournal, JournalError, ReferenceCompletion, ReferenceEvidence, ReferenceOperation,
    ReferenceUseEvidence, ReferenceUsePin, RevalidatedReferenceEvidence,
};
use gaugedesk_store::Store;

pub(super) enum GateHomeJournal<'a> {
    Project {
        journal: Box<HomeReferenceJournal>,
        product: &'a mut Store,
    },
    LegacyPrototype(&'a mut Store),
}

impl GateHomeJournal<'_> {
    pub fn register_checked_program_request(
        &mut self,
        home_id: &str,
        target_store: &str,
        target_store_incarnation: &str,
        request_key: &str,
        basis_digest: &str,
    ) -> Result<ReferenceOperation, JournalError> {
        match self {
            Self::Project { journal, .. } => journal.register_checked_program_request(
                home_id,
                target_store,
                target_store_incarnation,
                request_key,
                basis_digest,
            ),
            Self::LegacyPrototype(store) => store.register_checked_program_request(
                home_id,
                target_store,
                target_store_incarnation,
                request_key,
                basis_digest,
            ),
        }
    }

    pub fn complete_reference_operation<F>(
        &mut self,
        home_id: &str,
        operation_id: &str,
        verify: F,
    ) -> Result<ReferenceCompletion, JournalError>
    where
        F: FnOnce(&ReferenceOperation) -> Result<ReferenceEvidence, String>,
    {
        match self {
            Self::Project { journal, .. } => {
                journal.complete_reference_operation(home_id, operation_id, verify)
            }
            Self::LegacyPrototype(store) => {
                store.complete_reference_operation(home_id, operation_id, verify)
            }
        }
    }

    pub fn complete_revalidated_reference_operation<F>(
        &mut self,
        home_id: &str,
        operation_id: &str,
        verify: F,
    ) -> Result<ReferenceCompletion, JournalError>
    where
        F: FnOnce(&ReferenceOperation, i64) -> Result<RevalidatedReferenceEvidence, String>,
    {
        match self {
            Self::Project { journal, .. } => {
                journal.complete_revalidated_reference_operation(home_id, operation_id, verify)
            }
            Self::LegacyPrototype(store) => {
                store.complete_revalidated_reference_operation(home_id, operation_id, verify)
            }
        }
    }

    pub fn bind_exact_reference_use<F>(
        &mut self,
        home_id: &str,
        target_store: &str,
        use_key: &str,
        version_id: &str,
        operation_id: &str,
        verify: F,
    ) -> Result<ReferenceUsePin, JournalError>
    where
        F: FnOnce(&ReferenceOperation) -> Result<ReferenceUseEvidence, String>,
    {
        match self {
            Self::Project { journal, product } => {
                let pin = journal.bind_exact_reference_use(
                    home_id,
                    target_store,
                    use_key,
                    version_id,
                    operation_id,
                    verify,
                )?;
                let acknowledged =
                    product.acknowledge_home_reference_use(journal, target_store, use_key)?;
                if acknowledged.pin != pin {
                    return Err(JournalError::Conflict(
                        "Home product acknowledgment differs from the exact use pin",
                    ));
                }
                Ok(pin)
            }
            Self::LegacyPrototype(store) => store.bind_exact_reference_use(
                home_id,
                target_store,
                use_key,
                version_id,
                operation_id,
                verify,
            ),
        }
    }

    pub fn reference_use_pin(
        &self,
        home_id: &str,
        target_store: &str,
        use_key: &str,
    ) -> Result<Option<ReferenceUsePin>, JournalError> {
        match self {
            Self::Project { journal, .. } => {
                journal.reference_use_pin(home_id, target_store, use_key)
            }
            Self::LegacyPrototype(store) => store.reference_use_pin(home_id, target_store, use_key),
        }
    }

    pub fn reference_operations_for_target(
        &self,
        home_id: &str,
        target_store: &str,
    ) -> Result<Vec<ReferenceOperation>, JournalError> {
        match self {
            Self::Project { journal, .. } => {
                journal.reference_operations_for_target(home_id, target_store)
            }
            Self::LegacyPrototype(store) => {
                store.reference_operations_for_target(home_id, target_store)
            }
        }
    }

    pub fn reference_use_pins_for_target(
        &self,
        home_id: &str,
        target_store: &str,
    ) -> Result<Vec<ReferenceUsePin>, JournalError> {
        match self {
            Self::Project { journal, .. } => {
                journal.reference_use_pins_for_target(home_id, target_store)
            }
            Self::LegacyPrototype(store) => {
                store.reference_use_pins_for_target(home_id, target_store)
            }
        }
    }

    pub fn classify_legacy_reference_use_unknown(
        &mut self,
        home_id: &str,
        target_store: &str,
        use_key: &str,
        version_id: &str,
    ) -> Result<ReferenceUsePin, JournalError> {
        match self {
            Self::Project { journal, .. } => journal.classify_legacy_reference_use_unknown(
                home_id,
                target_store,
                use_key,
                version_id,
            ),
            Self::LegacyPrototype(store) => store.classify_legacy_reference_use_unknown(
                home_id,
                target_store,
                use_key,
                version_id,
            ),
        }
    }

    pub fn exact_reference_origin_for_version(
        &self,
        home_id: &str,
        target_store: &str,
        version_id: &str,
    ) -> Result<Option<String>, JournalError> {
        match self {
            Self::Project { journal, .. } => {
                journal.exact_reference_origin_for_version(home_id, target_store, version_id)
            }
            Self::LegacyPrototype(store) => {
                store.exact_reference_origin_for_version(home_id, target_store, version_id)
            }
        }
    }
}
