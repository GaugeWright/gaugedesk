//! `IdentityProvider` — the seam mapping a real principal onto an [[authority]] and
//! its attribute claims (ADR 0032 step 3). Mirrors the `Harness` seam of ADR 0031
//! and the [`crate::key_store::KeyStore`] seam: the pure core stays
//! **identity-agnostic** — it speaks only [`AuthorityId`] +
//! [`AuthorityAttributes`](gaugewright_core::abac::AuthorityAttributes) — and Okta/Entra
//! (OIDC+SCIM), AD/LDAP, or a custom directory are interchangeable adapters behind
//! this trait. The first adapter is a loopback/dev in-memory directory; a real IdP
//! implements the same trait with **no change** to the ABAC evaluation path
//! ([`gaugewright_core::abac`]). No IdP is pinned (per the ADR) — the seam is.

use std::collections::BTreeMap;

use gaugewright_core::abac::AuthorityAttributes;
use gaugewright_core::ids::{AuthorityId, HomeId};

use crate::Workbench;

/// The authority GaugeDesk authenticated for the current request. Product auth
/// middleware places this in request extensions after verification; downstream
/// runtime adapters may attribute actions to it but must never authenticate it
/// again or substitute the workspace owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedActor(pub AuthorityId);

impl Workbench {
    /// Apply the optional local authority override used by self-operated
    /// federation/dev deployments. Empty values are ignored so a mis-set env var
    /// does not erase the local single-user default.
    pub(crate) fn activate_configured_authority(&mut self) {
        if let Some(authority) = gaugewright_store::process_env::var("AUTHORITY") {
            if !authority.is_empty() {
                self.authority = AuthorityId::new(authority);
                self.home_id = HomeId::new(format!("home:{}", self.authority.as_str()));
            }
        }
        if let Some(home) = gaugewright_store::process_env::var("HOME_ID") {
            if !home.is_empty() {
                self.home_id = HomeId::new(home);
            }
        }
    }

    /// This control plane's own authority identity — the owner of locally-minted
    /// context and the signer of its pairing tickets / federated envelopes.
    pub fn authority(&self) -> &AuthorityId {
        &self.authority
    }

    /// This control plane's stable logical Home identity (`HOME-1`). It is not
    /// derived from a browser session, process id, VM, or Durable Object.
    pub fn home_id(&self) -> &HomeId {
        &self.home_id
    }

    /// Bind a hosted/registered composition to its provisioned Home identity.
    /// The local default remains `home:<authority>`.
    pub fn with_home_id(mut self, home_id: HomeId) -> Self {
        self.home_id = home_id;
        self
    }

    /// Bind this workbench to the private hosted-Home authorization posture.
    /// The managed Home router calls this during composition; local/Hub/Public
    /// workbenches retain their distinct defaults.
    pub fn enable_hosted_home_mode(&mut self) {
        self.hosted_home_mode = true;
    }

    pub(crate) fn hosted_home_mode(&self) -> bool {
        self.hosted_home_mode
    }

    pub(crate) fn configured_home_id() -> HomeId {
        if let Some(home) = gaugewright_store::process_env::var("HOME_ID") {
            if !home.is_empty() {
                return HomeId::new(home);
            }
        }
        let authority = gaugewright_store::process_env::var("AUTHORITY")
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| crate::LOCAL_AUTHORITY.to_string());
        HomeId::new(format!("home:{authority}"))
    }
}

/// Resolve principals → authorities and authorities → attribute claims. Two jobs,
/// per ADR 0032: **(i)** authenticate a presented credential to a durable,
/// accountable [`AuthorityId`] (`INV-1`; authenticity is the actor-authenticity
/// substrate, `INV-21`); **(ii)** supply the attribute claims (roles / clearance /
/// affiliation / region) the ABAC evaluator reads. Both **fail closed** (`INV-20`):
/// an unauthenticated credential yields no authority, and an unknown authority
/// yields the most-restrictive default attributes (no roles), never an error a
/// caller might quietly treat as "allow".
pub trait IdentityProvider {
    /// Authenticate a presented `credential` (an opaque bearer token / signed
    /// assertion the adapter verifies) to the authority it speaks for, or `None` if
    /// it cannot be authenticated.
    fn authenticate(&self, credential: &str) -> Option<AuthorityId>;

    /// The attribute claims for `authority`, materialized from IdP claims. An
    /// unknown authority gets [`AuthorityAttributes::default`] — fail-closed (no
    /// roles, the most-protected defaults), so a missing mapping never widens access.
    fn claims(&self, authority: &AuthorityId) -> AuthorityAttributes;
}

/// Loopback/dev `IdentityProvider`: an in-memory directory. Enroll credentials →
/// authorities and authorities → claims, then resolve. The first adapter (like
/// [`crate::key_store::LoopbackKeyStore`]); **not secure** — credentials are plain
/// map keys, not verified assertions, so anyone holding the string is the authority.
/// A real OIDC/SCIM or LDAP adapter implements the same trait with verified claims.
#[derive(Default, Clone)]
pub struct LoopbackIdentityProvider {
    credentials: BTreeMap<String, AuthorityId>,
    claims: BTreeMap<AuthorityId, AuthorityAttributes>,
}

impl LoopbackIdentityProvider {
    pub fn new() -> Self {
        Self::default()
    }

    /// Enroll a principal: `credential` authenticates to `authority`, which carries
    /// `attrs`. Builder-style (consumes and returns `self`) for terse dev/test wiring.
    pub fn enroll(
        mut self,
        credential: impl Into<String>,
        authority: AuthorityId,
        attrs: AuthorityAttributes,
    ) -> Self {
        self.claims.insert(authority.clone(), attrs);
        self.credentials.insert(credential.into(), authority);
        self
    }
}

impl IdentityProvider for LoopbackIdentityProvider {
    fn authenticate(&self, credential: &str) -> Option<AuthorityId> {
        self.credentials.get(credential).cloned()
    }

    fn claims(&self, authority: &AuthorityId) -> AuthorityAttributes {
        self.claims.get(authority).cloned().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gaugewright_core::abac::{
        permitted_with_policy, Action, AuthorityAttributes, Classification, Context, Decision,
        Policy, Region, ResourceAttributes, Role,
    };

    fn attrs(roles: &[Role], region: &str) -> AuthorityAttributes {
        AuthorityAttributes {
            roles: roles.iter().cloned().collect(),
            region: Some(Region::new(region)),
            ..Default::default()
        }
    }

    #[test]
    fn authenticate_resolves_enrolled_principal() {
        let idp = LoopbackIdentityProvider::new().enroll(
            "alice-token",
            AuthorityId::new("alice"),
            attrs(&[Role::member()], "eu"),
        );
        assert_eq!(
            idp.authenticate("alice-token"),
            Some(AuthorityId::new("alice"))
        );
    }

    #[test]
    fn unknown_credential_does_not_authenticate() {
        // Fail-closed (INV-20): an unenrolled credential yields no authority.
        let idp = LoopbackIdentityProvider::new();
        assert_eq!(idp.authenticate("nobody"), None);
    }

    #[test]
    fn unknown_authority_gets_default_claims() {
        // Fail-closed: no roles, no region — never a widening default.
        let idp = LoopbackIdentityProvider::new();
        let claims = idp.claims(&AuthorityId::new("ghost"));
        assert_eq!(claims, AuthorityAttributes::default());
        assert!(claims.roles.is_empty());
    }

    #[test]
    fn claims_carry_enrolled_attributes() {
        let idp = LoopbackIdentityProvider::new().enroll(
            "alice-token",
            AuthorityId::new("alice"),
            attrs(&[Role::viewer()], "eu"),
        );
        let claims = idp.claims(&AuthorityId::new("alice"));
        assert!(claims.roles.contains(&Role::viewer()));
        assert_eq!(claims.region, Some(Region::new("eu")));
    }

    #[test]
    fn seam_feeds_the_abac_evaluator_end_to_end() {
        // The seam's whole point: a real principal resolves to an authority + its
        // claims, which the ABAC evaluator then reads. Here a `viewer` principal is
        // denied an export the floor would otherwise allow (coarse role = no export),
        // proving identity → attributes → policy composes.
        let idp = LoopbackIdentityProvider::new().enroll(
            "alice-token",
            AuthorityId::new("alice"),
            attrs(&[Role::viewer()], "eu"),
        );

        let authority = idp.authenticate("alice-token").expect("enrolled");
        let actor = idp.claims(&authority);

        let decision = Decision {
            actor,
            resource: ResourceAttributes {
                classification: Classification::Internal,
                region: Some(Region::new("eu")),
                purpose: Default::default(),
            },
            action: Action::Export,
            context: Context {
                ceiling_attested: true,
            },
        };

        // The floor said yes (baseline = true); the enterprise policy narrows it.
        assert!(!permitted_with_policy(
            true,
            &Policy::enterprise_example(),
            &decision
        ));
    }
}
