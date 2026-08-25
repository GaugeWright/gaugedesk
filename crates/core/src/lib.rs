//! gaugewright core — the pure, verified heart.
//!
//! Domain types and lifecycle reducers, with **no I/O**: reducers are the
//! `(decide, evolve)` pairs of ADR 0004, ported from the Quint models in
//! `specs/models/` and property-tested against the same invariants. The
//! imperative shell (store / boundary / pi-bridge / api / app) materializes all
//! non-determinism and authority before these reducers run.
//!
//! Contracts at the boundary (`principles.md`): identities are newtypes,
//! commands/events/states are enums — illegal states are unrepresentable, and
//! the core trusts its types rather than re-validating strings.

pub mod abac;
pub mod agent_release;
pub mod agent_version;
pub mod attestation;
pub mod billing;
pub mod boundary;
pub mod boundary_lifecycle;
pub mod bridge_grant;
pub mod content_erasure;
pub mod delegation;
pub mod deployment_entitlement;
pub mod device_enrollment;
pub mod envelope_supply;
pub mod federated_delivery;
pub mod federated_envelope;
pub mod federation;
pub mod freshness;
pub mod handoff;
pub mod ids;
pub mod instance;
pub mod key_release;
pub mod managed_machine_execution;
pub mod merge;
pub mod mobile_machine_session;
pub mod mobile_wake;
pub mod package_distribution;
pub mod pinned_tls;
pub mod protected_profile;
pub mod rbac;
pub mod recovery;
pub mod remote_call;
pub mod remote_session;
pub mod resource;
pub mod resource_access;
pub mod resource_export;
pub mod review;
pub mod revocation;
pub mod run;
pub mod runtime_session;
pub mod signature;
pub mod taint;
pub mod workstream;

/// A `decide` rejection. A rejected command produces no events and no state
/// change — commands are requests, not facts (`INV-2`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rejection {
    pub reason: &'static str,
}

/// The common shape of every lifecycle reducer (ADR 0004): a `(decide, evolve)`
/// pair over a default-initial state, tagged with a `KIND` discriminator so the
/// imperative shell can keep distinct lifecycles in one append-only log.
///
/// This is the seam the store folds and admits through — one generic spine
/// instead of one `admit_*` per reducer. Events are serde so they round-trip
/// through the log; state is reconstructed solely by folding them (`INV-8`).
pub trait Lifecycle {
    type State: Default;
    type Command;
    type Event: serde::Serialize + serde::de::DeserializeOwned + Clone;

    /// The log discriminator for this lifecycle's events within a scope.
    const KIND: &'static str;

    fn decide(state: &Self::State, command: Self::Command) -> Result<Vec<Self::Event>, Rejection>;
    fn evolve(state: &Self::State, event: Self::Event) -> Self::State;
}

/// Resolve which authority owns a scope, by convention from the scope string.
///
/// Scopes are named `scope:<authority>:<rest>` (ADR 0005), so the owning
/// authority is the second `:`-delimited segment. This is the seam the
/// imperative shell uses to decide which authority's keyset governs a scope for
/// permission checks (D-REMOTE). If the string doesn't match the convention we
/// fall back to treating the whole string as the authority rather than failing —
/// the caller is the shell, which would otherwise have to re-validate.
///
/// **Fail-closed contract (CONF-19).** This is a naming helper, **not** an admission
/// gate, and its malformed-input fallback is deliberately non-authoritative: it
/// returns *some* `AuthorityId` but never grants anything. Every permission path
/// that consumes the result MUST fail closed on an unrecognized authority — e.g.
/// `net_server::GovernanceAuth::authenticate` looks the returned id up in its
/// registered-key map and rejects (`UnknownAuthority`) if absent, so a malformed
/// scope cannot authenticate. The only other consumer (`engine` output minting)
/// resolves system-constructed, well-formed scopes. A stricter `Option`-returning
/// signature is the eventual hardening (folded into the CORE-4 rename sweep), but is
/// not load-bearing today because the gate already fails closed.
pub fn determine_scope_authority(scope: &str) -> ids::AuthorityId {
    match scope.split(':').nth(1) {
        Some(authority) if !authority.is_empty() => ids::AuthorityId::new(authority),
        _ => ids::AuthorityId::new(scope),
    }
}

#[cfg(test)]
mod scope {
    use super::*;

    #[test]
    fn well_formed_scope_yields_second_segment() {
        assert_eq!(
            determine_scope_authority("scope:A:run-1"),
            ids::AuthorityId::new("A"),
        );
        assert_eq!(
            determine_scope_authority("scope:peach:x"),
            ids::AuthorityId::new("peach"),
        );
    }

    #[test]
    fn malformed_scope_falls_back_to_whole_string() {
        // No `:` at all — nothing to split on, so the whole string is the authority.
        assert_eq!(
            determine_scope_authority("lonely"),
            ids::AuthorityId::new("lonely"),
        );
        // An empty second segment is not a usable authority — fall back too.
        assert_eq!(
            determine_scope_authority("scope::run-1"),
            ids::AuthorityId::new("scope::run-1"),
        );
    }
}
