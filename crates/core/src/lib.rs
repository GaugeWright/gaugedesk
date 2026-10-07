//! gaugewright core — the pure, verified heart.
//!
//! Domain types and lifecycle reducers, with **no I/O**: reducers are the
//! `(decide, evolve)` pairs of ADR 0004, ported from the Quint models in
//! `specs/models/` and property-tested against the same invariants. The
//! imperative shell (store / boundary / harness / api / app) materializes all
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
pub mod gaugevault;
pub mod gaugevault_namespace;
pub mod handoff;
pub mod host_action_admission;
pub mod ids;
pub mod instance;
pub mod key_release;
pub mod managed_machine_execution;
pub mod merge;
pub mod mobile_machine_session;
pub mod mobile_wake;
pub mod model_connection;
pub mod package_distribution;
pub mod pinned_tls;
pub mod plan;
pub mod project_home_handoff;
pub mod project_host_export;
pub mod project_host_registration;
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
pub mod target_settlement;
pub mod whip_pricing;
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

    /// How the store may checkpoint this lifecycle's folded state (SCALE-1).
    ///
    /// `None` — the default — keeps the lifecycle a pure full replay. A
    /// lifecycle whose state round-trips through serde may return
    /// [`SnapshotCodec::serde`], and the store then folds from its newest
    /// checkpoint plus the events after it. Events stay the authority: a
    /// checkpoint is derived, rebuildable data, and any doubt about one is a
    /// full replay.
    fn snapshot_codec() -> Option<SnapshotCodec<Self::State>> {
        None
    }
}

/// A persistent encoding of a lifecycle's folded state (SCALE-1).
///
/// `version` names the meaning of a stored checkpoint: raise it whenever
/// `evolve`, the state's shape, or its serialized form changes, so a checkpoint
/// folded under the old reducer is never resumed by the new one. The store keys
/// checkpoints on `(scope, kind, lifecycle, version)`, so a raised version
/// simply finds none and replays the full history.
pub struct SnapshotCodec<S> {
    /// Stable identity of the reducer, distinct from its log `KIND` because two
    /// reducers may fold one kind.
    pub lifecycle: &'static str,
    pub version: u32,
    /// Checkpoint once this many of the lifecycle's events follow the last one.
    pub every: u32,
    pub encode: fn(&S) -> Option<String>,
    pub decode: fn(&str) -> Option<S>,
}

/// The reducer build a checkpoint was folded by. The store keys checkpoints on
/// it beside [`SnapshotCodec::version`], so every release replays each scope
/// once rather than trusting that no reducer changed without a version raise.
pub const SNAPSHOT_REDUCER_BUILD: &str = env!("CARGO_PKG_VERSION");

/// Events folded between checkpoints unless a lifecycle chooses otherwise.
pub const DEFAULT_SNAPSHOT_INTERVAL: u32 = 64;

impl<S: serde::Serialize + serde::de::DeserializeOwned> SnapshotCodec<S> {
    /// The serde codec (hex-encoded CBOR, the core's own wire format),
    /// available only to a state that is fully serde.
    pub fn serde(lifecycle: &'static str, version: u32) -> Self {
        Self {
            lifecycle,
            version,
            every: DEFAULT_SNAPSHOT_INTERVAL,
            encode: |state| {
                let mut bytes = Vec::new();
                ciborium::into_writer(state, &mut bytes).ok()?;
                Some(hex::encode(bytes))
            },
            decode: |text| ciborium::from_reader(hex::decode(text).ok()?.as_slice()).ok(),
        }
    }
}

impl<S> SnapshotCodec<S> {
    /// Checkpoint after `every` events instead of the default interval.
    pub fn every(mut self, every: u32) -> Self {
        self.every = every.max(1);
        self
    }
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
