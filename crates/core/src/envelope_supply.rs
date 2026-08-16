//! Envelope **supply** — the two cross-checked lists a multi-party run travels
//! with (ADR 0139 §2/§3, discharging WhippleScript DR-0063 §4's embedder half).
//!
//! DR-0063 governs a run by a *set* of signed policy envelopes whose effective
//! policy is their meet. That record owns **composition**; this module owns
//! **supply**: given the stakeholder set derived at admission (ADR 0139 §1,
//! assembled in the shell because it reads persisted records) and the envelopes
//! actually offered, produce the pair of lists the checker is handed — and
//! refuse rather than repair when they disagree.
//!
//! Nothing here intersects, filters, reorders, or pre-evaluates policy. A check
//! that does not run inside `whip check` is advisory, and two definitions of
//! legal composition in two repositories is exactly what the shared
//! cross-repository-artifact rule exists to prevent (ADR 0139 §6).
//!
//! **Why two lists rather than one.** DR-0063 §4's composition record is the set
//! the run was actually *checked under*, and its witness (`recOnlyPresent`)
//! refuses an entry naming an authority the envelope set does not hold. An
//! ungoverned stakeholder has no hash, no version, and no epoch, so admitting it
//! there as a nullable entry would weaken the exactness that stops a run citing
//! evidence for a set it was not checked under. But dropping it entirely would
//! make an absent constituent indistinguishable from a set that was never
//! assembled — the omission that record exists to prevent. So it appears in the
//! roster, marked ungoverned, contributing no restriction: which is what having
//! no policy means.

use std::collections::{BTreeMap, BTreeSet};

use crate::boundary::Authority;
use crate::ids::PublicKey;

/// One constituent of the set the run was actually checked under — DR-0063 §4's
/// composition record entry.
///
/// Every field is present or the entry does not exist. An authority that
/// supplied no envelope is a [`RosterEntry`] with `governed: false`, never an
/// entry here with empty fields.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct CompositionEntry {
    /// The governance **root** id whose policy this is (ADR 0139 §3).
    pub authority: Authority,
    /// The hash of the canonical envelope document the signature covers.
    pub envelope_hash: String,
    /// The envelope's declared policy version.
    pub envelope_version: u32,
    /// The policy epoch the `:v2` preimage binds.
    pub epoch: u64,
}

/// One derived stakeholder, and whether it supplied policy.
///
/// The roster is the set derived at admission from records the home holds — it
/// answers "who had a stake", including the parties that did not govern.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct RosterEntry {
    pub authority: Authority,
    /// `false` when this stakeholder supplied no envelope. It contributes no
    /// restriction, and its absence is visible here and in the guarantee report
    /// rather than being silently indistinguishable from never having a stake.
    pub governed: bool,
}

/// An envelope offered for one authority, as this side receives it.
///
/// The envelope document itself passes through opaquely — supply never parses
/// policy. What this side must know is who it claims to speak for, what it
/// commits to, and which key signed it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuppliedEnvelope {
    pub authority: Authority,
    pub envelope_hash: String,
    pub envelope_version: u32,
    pub epoch: u64,
    /// The key that signed the `:v2` preimage. Checked against the authority's
    /// governance root, never against a device subkey (ADR 0139 §3).
    pub signer: PublicKey,
}

/// The pair handed to the checker, assembled and cross-checked.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EnvelopeSupply {
    /// Every derived stakeholder, governed or not, sorted by authority.
    pub roster: Vec<RosterEntry>,
    /// The constituents of the checked set, sorted by authority.
    pub record: Vec<CompositionEntry>,
}

impl EnvelopeSupply {
    /// The stakeholders that supplied no policy. Reported, never refused —
    /// refusing would hand every party a veto over every engagement by simply
    /// declining to have a policy (ADR 0139 §2).
    pub fn ungoverned(&self) -> Vec<&Authority> {
        self.roster
            .iter()
            .filter(|e| !e.governed)
            .map(|e| &e.authority)
            .collect()
    }
}

/// Why supply refused. Every variant is fail-closed: none of them is repaired by
/// dropping the offending envelope, because a dropped envelope is a wider meet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SupplyRefusal {
    /// An envelope names an authority the derived roster does not hold. This
    /// side's derivation and its supply disagree about who has a stake, and the
    /// one that can be influenced from outside is the supply (ADR 0139 §2).
    NotAStakeholder(Authority),
    /// Two envelopes claim the same authority. Which one governs is then a
    /// choice, and a choice between policies is composition — not supply's to
    /// make, and the wrong pick widens the meet.
    DuplicateAuthority(Authority),
    /// No governance root key is bound to this authority, so nothing
    /// authenticates the envelope. Refuse rather than accept it unverified.
    UnboundAuthority(Authority),
    /// The envelope was signed by a key that is not the authority's governance
    /// root — a device subkey under ADR 0039's Model A, or an unrelated key.
    /// A policy revision is not a crossing (ADR 0139 §3).
    NotRootSigned {
        authority: Authority,
        signer: PublicKey,
    },
}

impl std::fmt::Display for SupplyRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAStakeholder(a) => write!(
                f,
                "envelope supplied for {a}, which is not a derived stakeholder of this run"
            ),
            Self::DuplicateAuthority(a) => {
                write!(f, "more than one envelope supplied for {a}")
            }
            Self::UnboundAuthority(a) => {
                write!(f, "no governance root key is bound to {a}")
            }
            Self::NotRootSigned { authority, signer } => write!(
                f,
                "the envelope for {authority} is signed by {signer}, not by that authority's \
                 governance root — a device subkey does not author policy"
            ),
        }
    }
}

impl std::error::Error for SupplyRefusal {}

/// Assemble the roster and the composition record from the derived stakeholder
/// set and the envelopes offered, refusing on any disagreement between them.
///
/// `root_key_of` resolves an authority to its pinned governance root key, and
/// returns `None` when this home has no binding for it — which is a refusal, not
/// an ungoverned stakeholder: an unbound authority *offered* an envelope, and an
/// envelope nothing authenticates is not policy.
///
/// The cross-check runs both ways, and the two directions are deliberately not
/// symmetric:
///
/// - in the record but not the roster → [`SupplyRefusal::NotAStakeholder`],
///   fail-closed;
/// - in the roster but not the record → ungoverned, reported.
pub fn assemble(
    stakeholders: &BTreeSet<Authority>,
    supplied: &[SuppliedEnvelope],
    root_key_of: impl Fn(&Authority) -> Option<PublicKey>,
) -> Result<EnvelopeSupply, SupplyRefusal> {
    let mut by_authority: BTreeMap<Authority, CompositionEntry> = BTreeMap::new();
    for envelope in supplied {
        if !stakeholders.contains(&envelope.authority) {
            return Err(SupplyRefusal::NotAStakeholder(envelope.authority.clone()));
        }
        let Some(root) = root_key_of(&envelope.authority) else {
            return Err(SupplyRefusal::UnboundAuthority(envelope.authority.clone()));
        };
        if envelope.signer != root {
            return Err(SupplyRefusal::NotRootSigned {
                authority: envelope.authority.clone(),
                signer: envelope.signer.clone(),
            });
        }
        let entry = CompositionEntry {
            authority: envelope.authority.clone(),
            envelope_hash: envelope.envelope_hash.clone(),
            envelope_version: envelope.envelope_version,
            epoch: envelope.epoch,
        };
        if by_authority
            .insert(envelope.authority.clone(), entry)
            .is_some()
        {
            return Err(SupplyRefusal::DuplicateAuthority(
                envelope.authority.clone(),
            ));
        }
    }
    let roster = stakeholders
        .iter()
        .map(|authority| RosterEntry {
            authority: authority.clone(),
            governed: by_authority.contains_key(authority),
        })
        .collect();
    Ok(EnvelopeSupply {
        roster,
        record: by_authority.into_values().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn authority(name: &str) -> Authority {
        Authority::new(name)
    }

    fn root_of(authority: &Authority) -> PublicKey {
        PublicKey::new(format!("04root-{}", authority.as_str()))
    }

    fn envelope(name: &str) -> SuppliedEnvelope {
        let authority = authority(name);
        SuppliedEnvelope {
            envelope_hash: format!("hash-{name}"),
            envelope_version: 1,
            epoch: 7,
            signer: root_of(&authority),
            authority,
        }
    }

    /// Every authority in the record is in the roster, and marked governed —
    /// the direction DR-0063 §4's `recOnlyPresent` witness enforces.
    #[test]
    fn the_record_is_a_governed_subset_of_the_roster() {
        let stakeholders = BTreeSet::from([authority("a"), authority("b"), authority("c")]);
        let supply = assemble(&stakeholders, &[envelope("a"), envelope("c")], |a| {
            Some(root_of(a))
        })
        .expect("assembles");
        assert_eq!(
            supply
                .record
                .iter()
                .map(|e| e.authority.as_str())
                .collect::<Vec<_>>(),
            ["a", "c"]
        );
        for entry in &supply.record {
            let rostered = supply
                .roster
                .iter()
                .find(|r| r.authority == entry.authority)
                .expect("every record entry is rostered");
            assert!(rostered.governed);
        }
    }

    /// A stakeholder with no envelope is present and marked, not dropped: an
    /// absent constituent must not look like a set that was never assembled.
    #[test]
    fn an_ungoverned_stakeholder_is_rostered_not_omitted() {
        let stakeholders = BTreeSet::from([authority("a"), authority("b")]);
        let supply =
            assemble(&stakeholders, &[envelope("a")], |a| Some(root_of(a))).expect("assembles");
        assert_eq!(supply.roster.len(), 2);
        assert_eq!(supply.ungoverned(), vec![&authority("b")]);
        assert_eq!(supply.record.len(), 1);
    }

    /// The submitter-influenced direction fails closed.
    #[test]
    fn an_envelope_for_a_non_stakeholder_refuses() {
        let stakeholders = BTreeSet::from([authority("a")]);
        assert_eq!(
            assemble(&stakeholders, &[envelope("b")], |a| Some(root_of(a))),
            Err(SupplyRefusal::NotAStakeholder(authority("b")))
        );
    }

    /// ADR 0139 §3: a subkey signs crossings, never policy. This is the whole
    /// tooth — a stolen device must not be a policy author for its authority.
    #[test]
    fn a_subkey_signed_envelope_refuses() {
        let stakeholders = BTreeSet::from([authority("a")]);
        let mut subkey_signed = envelope("a");
        subkey_signed.signer = PublicKey::new("04subkey-a");
        assert_eq!(
            assemble(&stakeholders, &[subkey_signed], |a| Some(root_of(a))),
            Err(SupplyRefusal::NotRootSigned {
                authority: authority("a"),
                signer: PublicKey::new("04subkey-a"),
            })
        );
    }

    /// An envelope nothing authenticates is not policy, and is not an ungoverned
    /// stakeholder either — the authority did offer one.
    #[test]
    fn an_unbound_authority_refuses_rather_than_passing_ungoverned() {
        let stakeholders = BTreeSet::from([authority("a")]);
        assert_eq!(
            assemble(&stakeholders, &[envelope("a")], |_| None),
            Err(SupplyRefusal::UnboundAuthority(authority("a")))
        );
    }

    #[test]
    fn two_envelopes_for_one_authority_refuse() {
        let stakeholders = BTreeSet::from([authority("a")]);
        let mut second = envelope("a");
        second.envelope_hash = "hash-a-prime".into();
        assert_eq!(
            assemble(&stakeholders, &[envelope("a"), second], |a| Some(root_of(
                a
            ))),
            Err(SupplyRefusal::DuplicateAuthority(authority("a")))
        );
    }

    prop_compose! {
        fn arb_authorities()(
            names in prop::collection::btree_set("[a-e]", 0..5)
        ) -> BTreeSet<Authority> {
            names.iter().map(|n| authority(n)).collect()
        }
    }

    proptest! {
        /// The roster is exactly the derived set — supply never adds a
        /// stakeholder and never drops one, whatever is offered.
        #[test]
        fn the_roster_is_exactly_the_derived_set(
            stakeholders in arb_authorities(),
            offered in prop::collection::btree_set("[a-e]", 0..5),
        ) {
            let supplied: Vec<_> = offered.iter().map(|n| envelope(n)).collect();
            if let Ok(supply) = assemble(&stakeholders, &supplied, |a| Some(root_of(a))) {
                let rostered: BTreeSet<Authority> =
                    supply.roster.iter().map(|e| e.authority.clone()).collect();
                prop_assert_eq!(rostered, stakeholders);
            }
        }

        /// Whenever supply succeeds, the record's authorities are precisely the
        /// governed half of the roster — the cross-check holds in both
        /// directions at once, so neither list can be read without the other.
        #[test]
        fn record_and_governed_roster_agree(
            stakeholders in arb_authorities(),
            offered in prop::collection::btree_set("[a-e]", 0..5),
        ) {
            let supplied: Vec<_> = offered.iter().map(|n| envelope(n)).collect();
            if let Ok(supply) = assemble(&stakeholders, &supplied, |a| Some(root_of(a))) {
                let recorded: BTreeSet<Authority> =
                    supply.record.iter().map(|e| e.authority.clone()).collect();
                let governed: BTreeSet<Authority> = supply
                    .roster
                    .iter()
                    .filter(|e| e.governed)
                    .map(|e| e.authority.clone())
                    .collect();
                prop_assert_eq!(recorded, governed);
            }
        }

        /// Supply succeeds exactly when every offered envelope names a
        /// stakeholder. With root-signing and uniqueness held fixed, that is the
        /// only remaining reason to refuse — no silent third condition.
        #[test]
        fn success_is_exactly_offered_subset_of_derived(
            stakeholders in arb_authorities(),
            offered in prop::collection::btree_set("[a-e]", 0..5),
        ) {
            let supplied: Vec<_> = offered.iter().map(|n| envelope(n)).collect();
            let offered_authorities: BTreeSet<Authority> =
                offered.iter().map(|n| authority(n)).collect();
            let assembled = assemble(&stakeholders, &supplied, |a| Some(root_of(a)));
            prop_assert_eq!(
                assembled.is_ok(),
                offered_authorities.is_subset(&stakeholders)
            );
        }
    }
}
