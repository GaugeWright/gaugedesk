//! Deriving the envelope set a federated run is governed by (ADR 0139 §1 —
//! SUPPLY-1, the shell half of WhippleScript DR-0063 §6).
//!
//! The pure law — the roster/record cross-check and the root-signing rule — is
//! [`gaugedesk_core::envelope_supply`]. What lives here is the part that must
//! read persisted records: *which* authorities have a stake in this run.
//!
//! > the union of the persisted `ResourceRecord.stakeholders` of every handle in
//! > the run's authenticated pre-run input set, together with the engagement's
//! > accumulated `boundary::taint`, the **host** authority whose home admits the
//! > run, and the **executor's** authority where that is not the host.
//!
//! **Both stakeholder terms are needed and neither subsumes the other.** The
//! pre-run set is the only term carrying a resource this run reads for the first
//! time, because the read record that feeds taint does not exist until the turn
//! has run — supplying from taint alone would omit exactly the owner of a newly
//! granted resource, and a missing stakeholder is a *wider* meet. Taint is the
//! only term carrying a resource an earlier turn read and this run no longer
//! names, which still taints everything the run can observe of engagement state
//! (ADR 0026's engagement-scoped soundness). The union is the conservative
//! answer, and conservative is the only safe direction here.
//!
//! **Nothing here reads the submission.** The handles are the home's: the
//! pre-run input set is [`resource_store::granted_context`] — the context
//! resources the home admits this turn to read — and the stakeholders come from
//! the persisted record, not from any list the submitter attached. A set the
//! submitter names is a set the submitter can shorten.

use std::collections::{BTreeMap, BTreeSet};

use gaugedesk_core::boundary::Authority;
use gaugedesk_core::envelope_supply::{EnvelopeSupply, SuppliedEnvelope};
use gaugedesk_core::ids::PublicKey;
use gaugedesk_store::{AdmitError, Store};

use crate::resource_store;

/// Why the envelope set could not be derived. Every variant refuses the run:
/// ADR 0139 §1 is explicit that an unresolvable handle refuses rather than
/// contributing an empty stakeholder set, because resolution reads the persisted
/// record — which survives revoke and tombstone — so a stake does not disappear
/// when a payload does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DerivationRefusal {
    /// A handle in the run's admitted input set has no persisted record in the
    /// home's resource scope, so its owner is unknown.
    UnresolvedHandle(String),
    /// A resource the engagement read has no persisted record, so the taint term
    /// cannot be completed. The advancement path tolerates this with an
    /// `"<unresolved>"` sentinel; governance must not, because a sentinel would
    /// enter the roster as an authority that cannot supply an envelope and
    /// cannot be told apart from one that declined to.
    UnresolvedRead(String),
    /// The engagement's records could not be read at all.
    Store(String),
}

impl std::fmt::Display for DerivationRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnresolvedHandle(h) => write!(
                f,
                "the admitted input handle {h} resolves to no record in this home's scope"
            ),
            Self::UnresolvedRead(h) => write!(
                f,
                "the engagement read {h}, which resolves to no record in this home's scope"
            ),
            Self::Store(e) => write!(
                f,
                "the engagement's resource records could not be read: {e}"
            ),
        }
    }
}

impl std::error::Error for DerivationRefusal {}

impl From<AdmitError> for DerivationRefusal {
    fn from(error: AdmitError) -> Self {
        Self::Store(format!("{error:?}"))
    }
}

/// The authorities whose envelopes govern a run placed on this home.
///
/// `engagement` is the target chat when the run drives an existing engagement,
/// and `None` for a legacy isolated run — which has no read history and no
/// granted context, so its set is the executing authorities alone.
///
/// `executor` is the authority that runs the code. Today the host executes its
/// own admitted runs so the two coincide and the set absorbs the duplicate;
/// once execution is leased off-box they do not, and the authority running the
/// code is a stakeholder in what it can observe.
pub fn derive_stakeholders(
    store: &Store,
    engagement: Option<&str>,
    host: &Authority,
    executor: &Authority,
) -> Result<BTreeSet<Authority>, DerivationRefusal> {
    let mut set = BTreeSet::from([host.clone(), executor.clone()]);
    let Some(engagement) = engagement else {
        return Ok(set);
    };

    // Owners and stakeholders resolved from every persisted record, tombstoned
    // ones included, so a past read still resolves after the resource is
    // revoked or erased (ADR 0026).
    let records = resource_store::list(store, engagement)?;
    let by_id: BTreeMap<String, &gaugedesk_core::resource::ResourceRecord> = records
        .iter()
        .map(|r| (r.resource.id.as_str().to_string(), r))
        .collect();

    // (a) The authenticated pre-run input set — what this run is admitted to
    //     read, including anything granted since the last turn.
    for id in resource_store::granted_context(store, engagement)? {
        let record = by_id
            .get(id.as_str())
            .ok_or_else(|| DerivationRefusal::UnresolvedHandle(id.as_str().to_string()))?;
        set.extend(record.stakeholders.iter().cloned());
    }

    // (b) The engagement's accumulated taint — what earlier turns already read,
    //     including anything this run no longer names. Totality is checked
    //     before the fold so an unresolvable read refuses instead of entering
    //     the roster as a sentinel authority.
    let reads = resource_store::engagement_reads(store, engagement)?;
    for item in reads.items() {
        if !by_id.contains_key(item.as_str()) {
            return Err(DerivationRefusal::UnresolvedRead(item.clone()));
        }
    }
    set.extend(
        reads
            .taint(|item| {
                by_id
                    .get(item)
                    .map(|r| r.resource.owner.as_str().to_string())
                    .unwrap_or_default()
            })
            .into_iter()
            .map(Authority::new),
    );

    Ok(set)
}

// --- SUPPLY-3: binding an authority id to a governance root key -------------

/// Resolve an authority to the governance **root** key its envelopes must be
/// signed by (ADR 0139 §3), or `None` when this home holds no binding for it.
///
/// Under ADR 0039's Model A a long-lived root signs short-lived device-subkey
/// delegations, and each *crossing* is signed by a subkey. A policy envelope is
/// not a crossing: a crossing is per-act and high-frequency, which is what makes
/// a short-lived subkey right for it, while a policy revision is rare,
/// load-bearing, and precisely the artifact a compromised device must not be
/// able to author. So the binding is to the root, and
/// [`gaugedesk_core::envelope_supply::assemble`] refuses anything else — a
/// subkey is by construction not the root, so no separate subkey test is needed.
///
/// The pin already exists for every paired peer: it is the same
/// `source_authority_root_pubkey` a crossing's delegation chain is checked
/// against, so governance and transport cannot come to disagree about which key
/// is an authority's root.
pub fn root_key_of(
    fed: Option<&crate::federation::Federation>,
    host: &Authority,
    host_root: &PublicKey,
    authority: &Authority,
) -> Option<PublicKey> {
    if authority == host {
        return Some(host_root.clone());
    }
    fed?.grant_for(authority.as_str())
        .map(|grant| grant.source_authority_root_pubkey)
}

// --- The registered envelopes a project's runs are checked under ------------

/// The record kind under which a supplied policy envelope is stored.
const ENVELOPE_KIND: &str = "envelope";

/// The project-scoped store scope holding supplied policy envelopes.
fn project_envelope_scope(project: &str) -> String {
    format!("project::{project}::envelopes")
}

/// A policy envelope registered on this home, for one authority.
///
/// The envelope *document* is not stored here and is never parsed on this side —
/// supply carries what identifies and authenticates it, and composition is the
/// checker's (ADR 0139 §6).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EnvelopeRecord {
    pub authority: Authority,
    pub envelope_hash: String,
    pub envelope_version: u32,
    pub epoch: u64,
    /// The key that signed the `:v2` preimage.
    pub signer: PublicKey,
}

/// Register (or revise) an authority's policy envelope for a project.
pub fn register_envelope(
    store: &mut Store,
    project: &str,
    record: &EnvelopeRecord,
) -> Result<(), AdmitError> {
    let payload = serde_json::to_string(record).unwrap_or_default();
    store.append_record(&project_envelope_scope(project), ENVELOPE_KIND, &payload)?;
    Ok(())
}

/// The envelopes registered for a project, folded latest-wins per authority — a
/// revision supersedes rather than accumulating, so this side never offers two
/// envelopes for one authority and never has to choose between them.
pub fn registered_envelopes(store: &Store, project: &str) -> Vec<SuppliedEnvelope> {
    let mut by_authority: BTreeMap<Authority, SuppliedEnvelope> = BTreeMap::new();
    for payload in store
        .records(&project_envelope_scope(project), ENVELOPE_KIND)
        .unwrap_or_default()
    {
        let Ok(record) = serde_json::from_str::<EnvelopeRecord>(&payload) else {
            continue;
        };
        by_authority.insert(
            record.authority.clone(),
            SuppliedEnvelope {
                authority: record.authority,
                envelope_hash: record.envelope_hash,
                envelope_version: record.envelope_version,
                epoch: record.epoch,
                signer: record.signer,
            },
        );
    }
    by_authority.into_values().collect()
}

// --- Evidence: what the run was checked under -------------------------------

/// The record kind under which a run's assembled supply is stored.
const SUPPLY_KIND: &str = "supply";

fn run_supply_scope(correlation: &str) -> String {
    format!("run::{correlation}::supply")
}

/// Persist the pair a run was admitted with, so "which policies was this checked
/// under" is answerable after the fact rather than reconstructed, and the roster
/// beside it answers "who had a stake and did not govern".
pub fn record_supply(
    store: &mut Store,
    correlation: &str,
    supply: &EnvelopeSupply,
) -> Result<(), AdmitError> {
    let payload = serde_json::to_string(supply).unwrap_or_default();
    store.append_record(&run_supply_scope(correlation), SUPPLY_KIND, &payload)?;
    Ok(())
}

/// The supply a run was admitted with, for its evidence.
pub fn supply_for(store: &Store, correlation: &str) -> Option<EnvelopeSupply> {
    store
        .records(&run_supply_scope(correlation), SUPPLY_KIND)
        .unwrap_or_default()
        .last()
        .and_then(|payload| serde_json::from_str(payload).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gaugedesk_core::resource::{
        ContentLocator, Resource, ResourceId, ResourceKind, ResourceRecord,
    };

    fn store() -> Store {
        Store::open_in_memory().expect("in-memory store")
    }

    fn authority(name: &str) -> Authority {
        Authority::new(name)
    }

    fn locator(id: &str) -> ContentLocator {
        ContentLocator::Workspace {
            path: id.into(),
            commit: "c1".into(),
        }
    }

    /// Persist `record` and take it all the way to granted, so it lands in the
    /// pre-run input set.
    fn grant(store: &mut Store, engagement: &str, record: &ResourceRecord) {
        let id = record.resource.id.clone();
        let owner = record.resource.owner.clone();
        resource_store::put(store, engagement, record).expect("put");
        resource_store::request_access(store, engagement, &id, BTreeSet::from([owner.clone()]))
            .expect("request");
        resource_store::approve_access(store, engagement, &id, owner).expect("approve");
    }

    fn grant_context(store: &mut Store, engagement: &str, id: &str, owner: &str) {
        let resource = Resource::input(
            ResourceId::new(id),
            ResourceKind::context(),
            authority(owner),
        );
        let record = ResourceRecord::new(resource, locator(id), |_| authority(owner));
        grant(store, engagement, &record);
    }

    #[test]
    fn an_isolated_run_is_governed_by_the_executing_authorities_alone() {
        let store = store();
        let set = derive_stakeholders(&store, None, &authority("host"), &authority("host"))
            .expect("derives");
        assert_eq!(set, BTreeSet::from([authority("host")]));
    }

    /// The executor clause is written now and bites later: today it coincides
    /// with the host and the set absorbs it.
    #[test]
    fn a_distinct_executor_is_a_stakeholder() {
        let store = store();
        let set = derive_stakeholders(&store, None, &authority("host"), &authority("lessee"))
            .expect("derives");
        assert_eq!(
            set,
            BTreeSet::from([authority("host"), authority("lessee")])
        );
    }

    /// The failure ADR 0139 names: taint holds *prior* turns' reads, so a run
    /// consuming a newly granted resource for the first time would govern itself
    /// without that resource's owner if the pre-run term were dropped.
    #[test]
    fn a_first_read_is_governed_before_any_turn_records_it() {
        let mut store = store();
        grant_context(&mut store, "eng", "ctx-newly-granted", "partner");
        // Nothing has been read yet — taint is empty by construction.
        let reads = resource_store::engagement_reads(&store, "eng").expect("reads");
        assert!(reads.items().is_empty());

        let set = derive_stakeholders(&store, Some("eng"), &authority("host"), &authority("host"))
            .expect("derives");
        assert!(
            set.contains(&authority("partner")),
            "the pre-run input set is the only term that carries a first read"
        );
    }

    /// The other direction: a resource an earlier turn read and this run no
    /// longer names still governs, because the run can observe engagement state
    /// derived from it.
    #[test]
    fn a_past_read_still_governs_after_its_grant_is_revoked() {
        let mut store = store();
        grant_context(&mut store, "eng", "ctx-past", "partner");
        resource_store::record_reads(&mut store, "eng", &[ResourceId::new("ctx-past")])
            .expect("record read");
        resource_store::revoke_access(&mut store, "eng", &ResourceId::new("ctx-past"))
            .expect("revoke");

        // The pre-run set is now empty — the grant is gone.
        assert!(resource_store::granted_context(&store, "eng")
            .expect("granted")
            .is_empty());

        let set = derive_stakeholders(&store, Some("eng"), &authority("host"), &authority("host"))
            .expect("derives");
        assert!(
            set.contains(&authority("partner")),
            "taint is the only term that carries a read this run no longer names"
        );
    }

    /// Governance must not inherit the advancement path's `"<unresolved>"`
    /// sentinel: an authority that cannot supply an envelope would be
    /// indistinguishable from one that declined to.
    #[test]
    fn an_unresolvable_read_refuses_rather_than_rostering_a_sentinel() {
        let mut store = store();
        resource_store::record_reads(&mut store, "eng", &[ResourceId::new("ctx-ghost")])
            .expect("record read");
        assert_eq!(
            derive_stakeholders(&store, Some("eng"), &authority("host"), &authority("host")),
            Err(DerivationRefusal::UnresolvedRead("ctx-ghost".into()))
        );
    }

    /// A derived resource's stakeholders are its own owner together with the
    /// owners of its provenance, and the whole set governs — not just the owner.
    #[test]
    fn a_derived_resources_provenance_owners_all_govern() {
        let mut store = store();
        grant_context(&mut store, "eng", "ctx-a", "alpha");
        // A context resource *with* provenance — readable by the turn (so it is
        // in the pre-run input set) and carrying someone else's stake.
        let derived = Resource {
            id: ResourceId::new("ctx-derived"),
            kind: ResourceKind::context(),
            owner: authority("beta"),
            provenance: BTreeSet::from([ResourceId::new("ctx-a")]),
        };
        let record = ResourceRecord::new(derived, locator("ctx-derived"), |id| {
            if id.as_str() == "ctx-a" {
                authority("alpha")
            } else {
                authority("beta")
            }
        });
        grant(&mut store, "eng", &record);

        let set = derive_stakeholders(&store, Some("eng"), &authority("host"), &authority("host"))
            .expect("derives");
        assert_eq!(
            set,
            BTreeSet::from([authority("host"), authority("alpha"), authority("beta")])
        );
    }
}
