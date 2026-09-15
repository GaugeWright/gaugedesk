//! Pure account-auth custody, migration, and erasure decisions (ADR 0170).
//!
//! Authentication payloads belong to an independently keyed account scope.
//! The global order records only the opaque coordination events in this module;
//! it never receives an email, credential id, provider subject, verifier,
//! session digest, root, or encrypted copy of one.

use std::collections::BTreeMap;

use gaugedesk_store::{AdmitError, CommandRecordFact, Store};
use serde::{Deserialize, Serialize};

const ACCOUNT_AUTH_SCOPE_PREFIX: &str = "account-auth::account::";
pub const ACCOUNT_AUTH_CUSTODY_KIND: &str = "account_auth_custody";

/// The exact erasable scope for one person's authentication payloads.
pub fn account_auth_scope(account_id: &str) -> Result<String, CustodyRejection> {
    let account_id = required(account_id)?;
    Ok(format!("{ACCOUNT_AUTH_SCOPE_PREFIX}{account_id}"))
}

/// Migration standing for one account's authentication payloads.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum MigrationStanding {
    #[default]
    Legacy,
    Copying {
        operation_id: String,
        source_basis: String,
    },
    Migrated {
        operation_id: String,
        source_basis: String,
        destination_basis: String,
        evidence_id: String,
    },
}

/// Independently admitted progress for the composed erasure operation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum ErasureStanding {
    #[default]
    Available,
    Fenced {
        operation_id: String,
        authorization_id: String,
        review_id: String,
        bearers_evicted: bool,
        related_scopes_erased: bool,
        auth_key_destroyed: bool,
        directory_retracted: bool,
    },
    Erased {
        operation_id: String,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountAuthCustody {
    pub migration: MigrationStanding,
    pub erasure: ErasureStanding,
}

/// One globally ordered, non-identifying custody event for an exact random
/// account id. This envelope is the only custody payload admitted to the legacy
/// global order after ADR 0170; the nested event shape contains coordination
/// identities and causal bases only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountAuthCustodyRecord {
    pub account_id: String,
    pub event: OpaqueCustodyEvent,
}

impl AccountAuthCustodyRecord {
    pub fn new(account_id: &str, event: OpaqueCustodyEvent) -> Result<Self, CustodyRejection> {
        Ok(Self {
            account_id: required(account_id)?,
            event,
        })
    }

    pub fn command_record_fact(&self) -> Result<CommandRecordFact, AdmitError> {
        Ok(CommandRecordFact {
            scope_id: crate::account_auth::ACCOUNT_AUTH_SCOPE.to_owned(),
            kind: ACCOUNT_AUTH_CUSTODY_KIND.to_owned(),
            payload: serde_json::to_string(self)?,
        })
    }
}

/// Rebuildable non-secret catalog used to find migrated account scopes and
/// resumable erasure work. It contains no authentication lookup key.
#[derive(Clone, Debug, Default)]
pub struct AccountAuthCustodyCatalog {
    accounts: BTreeMap<String, AccountAuthCustody>,
}

impl AccountAuthCustodyCatalog {
    pub fn rebuild(store: &Store) -> Result<Self, AdmitError> {
        let mut catalog = Self::default();
        for row in store.records(
            crate::account_auth::ACCOUNT_AUTH_SCOPE,
            ACCOUNT_AUTH_CUSTODY_KIND,
        )? {
            let record: AccountAuthCustodyRecord = serde_json::from_str(&row)?;
            evolve(
                catalog.accounts.entry(record.account_id).or_default(),
                &record.event,
            );
        }
        Ok(catalog)
    }

    pub fn account(&self, account_id: &str) -> AccountAuthCustody {
        self.accounts.get(account_id).cloned().unwrap_or_default()
    }

    pub fn migrated_account_ids(&self) -> Vec<&str> {
        self.accounts
            .iter()
            .filter_map(|(account_id, state)| state.is_migrated().then_some(account_id.as_str()))
            .collect()
    }

    /// Accounts whose independently keyed scope is authoritative. `Copying`
    /// starts with an atomic copy, so readers and writers cut over at that
    /// marker rather than waiting for the later verification receipt.
    pub fn account_scoped_account_ids(&self) -> Vec<&str> {
        self.accounts
            .iter()
            .filter_map(|(account_id, state)| {
                matches!(
                    state.migration,
                    MigrationStanding::Copying { .. } | MigrationStanding::Migrated { .. }
                )
                .then_some(account_id.as_str())
            })
            .collect()
    }

    /// Account scopes that may still participate in authentication. The
    /// erasure fence is the cut-off: payloads remain decryptable until key
    /// destruction, but no login, refresh, or Account projection may observe
    /// them after the globally ordered fence wins.
    pub fn authenticatable_account_scoped_account_ids(&self) -> Vec<&str> {
        self.accounts
            .iter()
            .filter_map(|(account_id, state)| {
                (matches!(
                    state.migration,
                    MigrationStanding::Copying { .. } | MigrationStanding::Migrated { .. }
                ) && state.may_authenticate())
                .then_some(account_id.as_str())
            })
            .collect()
    }

    pub fn pending_erasure_account_ids(&self) -> Vec<&str> {
        self.accounts
            .iter()
            .filter_map(|(account_id, state)| {
                matches!(state.erasure, ErasureStanding::Fenced { .. })
                    .then_some(account_id.as_str())
            })
            .collect()
    }
}

/// Apply a pure command and encode its opaque events for atomic record
/// admission. The caller may place the returned global facts in the same
/// transaction as encrypted account-scoped facts.
pub fn command_record_facts(
    account_id: &str,
    state: &AccountAuthCustody,
    command: CustodyCommand,
) -> Result<Vec<CommandRecordFact>, AdmitError> {
    let events = decide(state, command)
        .map_err(|rejection| AdmitError::Codec(format!("account-auth custody: {rejection:?}")))?;
    events
        .into_iter()
        .map(|event| {
            AccountAuthCustodyRecord::new(account_id, event)
                .map_err(|_| AdmitError::Codec("invalid account-auth catalog identity".into()))?
                .command_record_fact()
        })
        .collect()
}

impl AccountAuthCustody {
    /// Authentication fails closed as soon as the erasure fence is admitted.
    pub fn may_authenticate(&self) -> bool {
        matches!(self.erasure, ErasureStanding::Available)
    }

    pub fn is_migrated(&self) -> bool {
        matches!(self.migration, MigrationStanding::Migrated { .. })
    }
}

/// Commands carry only opaque identities and causal bases. The imperative
/// shell validates copy evidence, fresh WebAuthn authorization, review, and
/// external-effect receipts before submitting the corresponding command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CustodyCommand {
    BeginMigration {
        operation_id: String,
        source_basis: String,
    },
    CompleteMigration {
        operation_id: String,
        destination_basis: String,
        evidence_id: String,
    },
    FenceErasure {
        operation_id: String,
        authorization_id: String,
        review_id: String,
        blocking_organization_ids: Vec<String>,
    },
    RecordBearersEvicted {
        operation_id: String,
    },
    RecordRelatedScopesErased {
        operation_id: String,
    },
    RecordAuthKeyDestroyed {
        operation_id: String,
    },
    RecordDirectoryRetracted {
        operation_id: String,
    },
    CompleteErasure {
        operation_id: String,
    },
}

/// These are the only account-auth custody events permitted in the global
/// order. Their closed shape is deliberately incapable of carrying an
/// authentication value or encrypted authentication payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "kebab-case")]
pub enum OpaqueCustodyEvent {
    MigrationStarted {
        operation_id: String,
        source_basis: String,
    },
    MigrationCompleted {
        operation_id: String,
        source_basis: String,
        destination_basis: String,
        evidence_id: String,
    },
    ErasureFenced {
        operation_id: String,
        authorization_id: String,
        review_id: String,
    },
    BearersEvicted {
        operation_id: String,
    },
    RelatedScopesErased {
        operation_id: String,
    },
    AuthKeyDestroyed {
        operation_id: String,
    },
    DirectoryRetracted {
        operation_id: String,
    },
    ErasureCompleted {
        operation_id: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CustodyRejection {
    InvalidIdentity,
    MigrationAlreadyStarted,
    MigrationNotStarted,
    MigrationNotComplete,
    OperationMismatch,
    BlockingOrganizationOwnership,
    ErasureAlreadyStarted,
    ErasureNotStarted,
    BearersNotEvicted,
    RelatedScopesNotErased,
    AuthKeyNotDestroyed,
    DirectoryNotRetracted,
}

pub fn decide(
    state: &AccountAuthCustody,
    command: CustodyCommand,
) -> Result<Vec<OpaqueCustodyEvent>, CustodyRejection> {
    use CustodyCommand::*;
    use ErasureStanding::*;
    use MigrationStanding::*;

    match command {
        BeginMigration {
            operation_id,
            source_basis,
        } => match &state.migration {
            Legacy => Ok(vec![OpaqueCustodyEvent::MigrationStarted {
                operation_id: required(&operation_id)?,
                source_basis: required(&source_basis)?,
            }]),
            Copying {
                operation_id: existing,
                source_basis: existing_basis,
            } if existing == &operation_id && existing_basis == &source_basis => Ok(Vec::new()),
            _ => Err(CustodyRejection::MigrationAlreadyStarted),
        },
        CompleteMigration {
            operation_id,
            destination_basis,
            evidence_id,
        } => match &state.migration {
            Copying {
                operation_id: existing,
                source_basis,
            } if existing == &operation_id => Ok(vec![OpaqueCustodyEvent::MigrationCompleted {
                operation_id: existing.clone(),
                source_basis: source_basis.clone(),
                destination_basis: required(&destination_basis)?,
                evidence_id: required(&evidence_id)?,
            }]),
            Migrated {
                operation_id: existing,
                destination_basis: existing_destination,
                evidence_id: existing_evidence,
                ..
            } if existing == &operation_id
                && existing_destination == &destination_basis
                && existing_evidence == &evidence_id =>
            {
                Ok(Vec::new())
            }
            Legacy => Err(CustodyRejection::MigrationNotStarted),
            _ => Err(CustodyRejection::OperationMismatch),
        },
        FenceErasure {
            operation_id,
            authorization_id,
            review_id,
            blocking_organization_ids,
        } => {
            if !blocking_organization_ids.is_empty() {
                return Err(CustodyRejection::BlockingOrganizationOwnership);
            }
            if !state.is_migrated() {
                return Err(CustodyRejection::MigrationNotComplete);
            }
            match &state.erasure {
                Available => Ok(vec![OpaqueCustodyEvent::ErasureFenced {
                    operation_id: required(&operation_id)?,
                    authorization_id: required(&authorization_id)?,
                    review_id: required(&review_id)?,
                }]),
                Fenced {
                    operation_id: existing,
                    authorization_id: existing_authorization,
                    review_id: existing_review,
                    ..
                } if existing == &operation_id
                    && existing_authorization == &authorization_id
                    && existing_review == &review_id =>
                {
                    Ok(Vec::new())
                }
                _ => Err(CustodyRejection::ErasureAlreadyStarted),
            }
        }
        RecordBearersEvicted { operation_id } => progress_event(
            &state.erasure,
            &operation_id,
            |bearers, _, _, _| bearers,
            |operation_id| OpaqueCustodyEvent::BearersEvicted { operation_id },
        ),
        RecordRelatedScopesErased { operation_id } => progress_event(
            &state.erasure,
            &operation_id,
            |_, related, _, _| related,
            |operation_id| OpaqueCustodyEvent::RelatedScopesErased { operation_id },
        ),
        RecordAuthKeyDestroyed { operation_id } => match &state.erasure {
            Fenced {
                operation_id: existing,
                bearers_evicted,
                related_scopes_erased,
                auth_key_destroyed,
                ..
            } if existing == &operation_id => {
                if !bearers_evicted {
                    Err(CustodyRejection::BearersNotEvicted)
                } else if !related_scopes_erased {
                    Err(CustodyRejection::RelatedScopesNotErased)
                } else if *auth_key_destroyed {
                    Ok(Vec::new())
                } else {
                    Ok(vec![OpaqueCustodyEvent::AuthKeyDestroyed { operation_id }])
                }
            }
            Fenced { .. } | Erased { .. } => Err(CustodyRejection::OperationMismatch),
            Available => Err(CustodyRejection::ErasureNotStarted),
        },
        RecordDirectoryRetracted { operation_id } => progress_event(
            &state.erasure,
            &operation_id,
            |_, _, _, directory| directory,
            |operation_id| OpaqueCustodyEvent::DirectoryRetracted { operation_id },
        ),
        CompleteErasure { operation_id } => match &state.erasure {
            Fenced {
                operation_id: existing,
                auth_key_destroyed,
                directory_retracted,
                ..
            } if existing == &operation_id => {
                if !auth_key_destroyed {
                    Err(CustodyRejection::AuthKeyNotDestroyed)
                } else if !directory_retracted {
                    Err(CustodyRejection::DirectoryNotRetracted)
                } else {
                    Ok(vec![OpaqueCustodyEvent::ErasureCompleted { operation_id }])
                }
            }
            Erased {
                operation_id: existing,
            } if existing == &operation_id => Ok(Vec::new()),
            Fenced { .. } | Erased { .. } => Err(CustodyRejection::OperationMismatch),
            Available => Err(CustodyRejection::ErasureNotStarted),
        },
    }
}

fn progress_event(
    standing: &ErasureStanding,
    operation_id: &str,
    already_done: impl FnOnce(bool, bool, bool, bool) -> bool,
    event: impl FnOnce(String) -> OpaqueCustodyEvent,
) -> Result<Vec<OpaqueCustodyEvent>, CustodyRejection> {
    match standing {
        ErasureStanding::Fenced {
            operation_id: existing,
            bearers_evicted,
            related_scopes_erased,
            auth_key_destroyed,
            directory_retracted,
            ..
        } if existing == operation_id => {
            if already_done(
                *bearers_evicted,
                *related_scopes_erased,
                *auth_key_destroyed,
                *directory_retracted,
            ) {
                Ok(Vec::new())
            } else {
                Ok(vec![event(required(operation_id)?)])
            }
        }
        ErasureStanding::Fenced { .. } | ErasureStanding::Erased { .. } => {
            Err(CustodyRejection::OperationMismatch)
        }
        ErasureStanding::Available => Err(CustodyRejection::ErasureNotStarted),
    }
}

pub fn evolve(state: &mut AccountAuthCustody, event: &OpaqueCustodyEvent) {
    use ErasureStanding::*;
    use MigrationStanding::*;
    use OpaqueCustodyEvent::*;

    match event {
        MigrationStarted {
            operation_id,
            source_basis,
        } => {
            state.migration = Copying {
                operation_id: operation_id.clone(),
                source_basis: source_basis.clone(),
            };
        }
        MigrationCompleted {
            operation_id,
            source_basis,
            destination_basis,
            evidence_id,
        } => {
            state.migration = Migrated {
                operation_id: operation_id.clone(),
                source_basis: source_basis.clone(),
                destination_basis: destination_basis.clone(),
                evidence_id: evidence_id.clone(),
            };
        }
        ErasureFenced {
            operation_id,
            authorization_id,
            review_id,
        } => {
            state.erasure = Fenced {
                operation_id: operation_id.clone(),
                authorization_id: authorization_id.clone(),
                review_id: review_id.clone(),
                bearers_evicted: false,
                related_scopes_erased: false,
                auth_key_destroyed: false,
                directory_retracted: false,
            };
        }
        BearersEvicted { operation_id } => {
            if let Fenced {
                operation_id: existing,
                bearers_evicted,
                ..
            } = &mut state.erasure
            {
                if existing == operation_id {
                    *bearers_evicted = true;
                }
            }
        }
        RelatedScopesErased { operation_id } => {
            if let Fenced {
                operation_id: existing,
                related_scopes_erased,
                ..
            } = &mut state.erasure
            {
                if existing == operation_id {
                    *related_scopes_erased = true;
                }
            }
        }
        AuthKeyDestroyed { operation_id } => {
            if let Fenced {
                operation_id: existing,
                auth_key_destroyed,
                ..
            } = &mut state.erasure
            {
                if existing == operation_id {
                    *auth_key_destroyed = true;
                }
            }
        }
        DirectoryRetracted { operation_id } => {
            if let Fenced {
                operation_id: existing,
                directory_retracted,
                ..
            } = &mut state.erasure
            {
                if existing == operation_id {
                    *directory_retracted = true;
                }
            }
        }
        ErasureCompleted { operation_id } => {
            state.erasure = Erased {
                operation_id: operation_id.clone(),
            };
        }
    }
}

fn required(value: &str) -> Result<String, CustodyRejection> {
    let value = value.trim();
    if value.is_empty() {
        Err(CustodyRejection::InvalidIdentity)
    } else {
        Ok(value.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apply(state: &mut AccountAuthCustody, command: CustodyCommand) {
        for event in decide(state, command).unwrap() {
            evolve(state, &event);
        }
    }

    fn migrated() -> AccountAuthCustody {
        let mut state = AccountAuthCustody::default();
        apply(
            &mut state,
            CustodyCommand::BeginMigration {
                operation_id: "migration-random".into(),
                source_basis: "legacy-basis".into(),
            },
        );
        apply(
            &mut state,
            CustodyCommand::CompleteMigration {
                operation_id: "migration-random".into(),
                destination_basis: "account-basis".into(),
                evidence_id: "copy-proof".into(),
            },
        );
        state
    }

    #[test]
    fn migration_is_monotone_idempotent_and_required_before_erasure() {
        let state = AccountAuthCustody::default();
        assert_eq!(
            decide(
                &state,
                CustodyCommand::FenceErasure {
                    operation_id: "erase".into(),
                    authorization_id: "fresh-passkey".into(),
                    review_id: "review".into(),
                    blocking_organization_ids: Vec::new(),
                }
            ),
            Err(CustodyRejection::MigrationNotComplete)
        );

        let state = migrated();
        assert!(state.is_migrated());
        assert_eq!(
            decide(
                &state,
                CustodyCommand::CompleteMigration {
                    operation_id: "migration-random".into(),
                    destination_basis: "account-basis".into(),
                    evidence_id: "copy-proof".into(),
                }
            )
            .unwrap(),
            Vec::new()
        );
    }

    #[test]
    fn organization_blocker_refuses_without_fencing_authentication() {
        let state = migrated();
        assert_eq!(
            decide(
                &state,
                CustodyCommand::FenceErasure {
                    operation_id: "erase".into(),
                    authorization_id: "fresh-passkey".into(),
                    review_id: "review".into(),
                    blocking_organization_ids: vec!["sole-owner-org".into()],
                }
            ),
            Err(CustodyRejection::BlockingOrganizationOwnership)
        );
        assert!(state.may_authenticate());
        assert_eq!(state.erasure, ErasureStanding::Available);
    }

    #[test]
    fn fence_blocks_auth_before_any_continuation_and_retries_exactly() {
        let mut state = migrated();
        let command = CustodyCommand::FenceErasure {
            operation_id: "erase-random".into(),
            authorization_id: "fresh-passkey".into(),
            review_id: "review".into(),
            blocking_organization_ids: Vec::new(),
        };
        apply(&mut state, command.clone());
        assert!(!state.may_authenticate());
        assert_eq!(decide(&state, command).unwrap(), Vec::new());

        assert_eq!(
            decide(
                &state,
                CustodyCommand::RecordAuthKeyDestroyed {
                    operation_id: "erase-random".into(),
                }
            ),
            Err(CustodyRejection::BearersNotEvicted)
        );
    }

    #[test]
    fn erasure_completes_only_after_local_destruction_and_directory_retraction() {
        let mut state = migrated();
        apply(
            &mut state,
            CustodyCommand::FenceErasure {
                operation_id: "erase-random".into(),
                authorization_id: "fresh-passkey".into(),
                review_id: "review".into(),
                blocking_organization_ids: Vec::new(),
            },
        );
        apply(
            &mut state,
            CustodyCommand::RecordDirectoryRetracted {
                operation_id: "erase-random".into(),
            },
        );
        apply(
            &mut state,
            CustodyCommand::RecordBearersEvicted {
                operation_id: "erase-random".into(),
            },
        );
        apply(
            &mut state,
            CustodyCommand::RecordRelatedScopesErased {
                operation_id: "erase-random".into(),
            },
        );
        apply(
            &mut state,
            CustodyCommand::RecordAuthKeyDestroyed {
                operation_id: "erase-random".into(),
            },
        );
        apply(
            &mut state,
            CustodyCommand::CompleteErasure {
                operation_id: "erase-random".into(),
            },
        );
        assert_eq!(
            state.erasure,
            ErasureStanding::Erased {
                operation_id: "erase-random".into()
            }
        );
        assert!(!state.may_authenticate());
    }

    #[test]
    fn global_event_shape_contains_no_authentication_payload_field() {
        let event = OpaqueCustodyEvent::ErasureFenced {
            operation_id: "opaque-operation".into(),
            authorization_id: "opaque-authorization".into(),
            review_id: "opaque-review".into(),
        };
        let json = serde_json::to_string(&event).unwrap();
        for forbidden in [
            "email",
            "credential_id",
            "issuer",
            "subject",
            "verifier",
            "session_digest",
            "sealed",
            "root",
        ] {
            assert!(!json.contains(forbidden));
        }
    }

    #[test]
    fn account_scope_is_exact_and_rejects_an_empty_identity() {
        assert_eq!(
            account_auth_scope("person-random").unwrap(),
            "account-auth::account::person-random"
        );
        assert_eq!(
            account_auth_scope("  "),
            Err(CustodyRejection::InvalidIdentity)
        );
    }

    #[test]
    fn global_catalog_rebuilds_migration_and_pending_erasure_without_auth_values() {
        let mut store = Store::open_in_memory().unwrap();
        let state = AccountAuthCustody::default();
        let started = command_record_facts(
            "random-account-id",
            &state,
            CustodyCommand::BeginMigration {
                operation_id: "random-migration-id".into(),
                source_basis: "legacy-position-7".into(),
            },
        )
        .unwrap();
        let started_refs: Vec<(&str, &str, &str)> = started
            .iter()
            .map(|fact| {
                (
                    fact.scope_id.as_str(),
                    fact.kind.as_str(),
                    fact.payload.as_str(),
                )
            })
            .collect();
        store.append_records_atomically(&started_refs).unwrap();

        let copying = AccountAuthCustodyCatalog::rebuild(&store).unwrap();
        assert!(matches!(
            copying.account("random-account-id").migration,
            MigrationStanding::Copying { .. }
        ));

        let completed = command_record_facts(
            "random-account-id",
            &copying.account("random-account-id"),
            CustodyCommand::CompleteMigration {
                operation_id: "random-migration-id".into(),
                destination_basis: "account-position-4".into(),
                evidence_id: "random-copy-observation".into(),
            },
        )
        .unwrap();
        let completed_refs: Vec<(&str, &str, &str)> = completed
            .iter()
            .map(|fact| {
                (
                    fact.scope_id.as_str(),
                    fact.kind.as_str(),
                    fact.payload.as_str(),
                )
            })
            .collect();
        store.append_records_atomically(&completed_refs).unwrap();

        let migrated = AccountAuthCustodyCatalog::rebuild(&store).unwrap();
        assert_eq!(migrated.migrated_account_ids(), vec!["random-account-id"]);
        assert!(migrated.pending_erasure_account_ids().is_empty());

        for row in store
            .records(
                crate::account_auth::ACCOUNT_AUTH_SCOPE,
                ACCOUNT_AUTH_CUSTODY_KIND,
            )
            .unwrap()
        {
            for forbidden in [
                "email",
                "credential_id",
                "issuer",
                "subject",
                "verifier",
                "session_digest",
                "sealed",
                "root",
            ] {
                assert!(!row.contains(forbidden));
            }
        }
    }
}
