//! Enterprise attribute-based permissions (ABAC) over the protection floor —
//! [ADR 0032](../../../specs/decisions/0032-enterprise-data-permissions.md),
//! ported from `specs/models/abac.qnt`.
//!
//! The organization-facing policy layer is a **filter** on the already-verified
//! protection floor (conjunctive consent + boundary ceiling): it may only
//! *remove* options the floor already allowed, never grant one it denied. That
//! restrict-only law — `ABAC_MONOTONE`: `permitted_with_policy ⊆ permitted_baseline`
//! — is what lets a rich enterprise policy attach **without re-opening any existing
//! protection proof**: `INV-13`/`INV-22` are untouched, because ABAC sits strictly
//! inside the floor.
//!
//! [`evaluate`] is a pure `(policy, resource_attrs, actor_attrs, context) →
//! Constraints`. The floor's verdict (`baseline`) is computed elsewhere
//! (resource-access / derived-output / boundary) and only **AND-combined** here by
//! [`permitted_with_policy`]; this module never recomputes it. Roles fall out as
//! *coarse* ABAC — admin/member/viewer is just an attribute profile evaluated by
//! the same engine (`role = viewer ⇒ no export`), not a parallel permission system.
//!
//! This is a noun-with-a-law (like [`crate::resource`]), not a `(decide, evolve)`
//! lifecycle: types plus the pure monotone evaluator. The imperative shell maps a
//! real principal → an [`crate::boundary::Authority`] and its attributes via the
//! `IdentityProvider` adapter, materializes the floor's `baseline`, and admits
//! under the combined verdict.

use std::collections::BTreeSet;

// --- attributes (the `data.md` record extension of ADR 0032 step 1) -------------

/// A resource's data classification (`public < internal < pii < regulated`). An
/// **open** vocabulary in spirit (regulatory mappings are an open question in the
/// ADR), modeled as a closed enum here for the verified core; the shell may carry
/// customer labels that resolve to one of these for policy evaluation.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    Public,
    Internal,
    Pii,
    /// The safe default: the most-protected class, so an unlabeled resource is
    /// never *less* constrained than an explicitly-labeled one (fail-closed,
    /// `INV-20`).
    #[default]
    Regulated,
}

/// A data-residency region tag (e.g. `eu`, `us`). A newtype, not a closed enum, so
/// a new region is not a breaking change (mirrors [`crate::resource::ResourceKind`]).
#[derive(
    Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct Region(String);

impl Region {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A purpose tag constraining why data may be used (open vocabulary).
#[derive(
    Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct Purpose(String);

impl Purpose {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A coarse role carried as an authority attribute. Roles are coarse ABAC: a role
/// is just an attribute the same evaluator reads (`admin`/`member`/`viewer` and any
/// custom role). Open vocabulary, like [`Region`].
#[derive(
    Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct Role(String);

impl Role {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    /// The break-glass account; enforce-SSO can never lock out the last `owner`
    /// (ID-5). May do everything.
    pub fn owner() -> Self {
        Self("owner".into())
    }
    pub fn admin() -> Self {
        Self("admin".into())
    }
    pub fn member() -> Self {
        Self("member".into())
    }
    pub fn viewer() -> Self {
        Self("viewer".into())
    }
    /// Sees only the billing surface (B16). Billing is never run/access authority
    /// (`INV-18`).
    pub fn billing() -> Self {
        Self("billing".into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A tenant / affiliation tag (which organization the authority belongs to).
#[derive(
    Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct Tenant(String);

impl Tenant {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A clearance level (higher dominates). Carried from IdP claims; not read by the
/// example rules but part of the attribute vocabulary ABAC rules may condition on.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct Clearance(pub u8);

impl Clearance {
    /// The clearance a directory role implies on its own.
    ///
    /// An IdP that asserts no clearance claim leaves [`Clearance::default()`],
    /// which clears only `classification:public`. Since an unlabeled resource
    /// is [`Classification::Regulated`] — fail-closed, the most protected —
    /// default-actor against default-resource could never read, so an agent
    /// turn over an ordinary project was refused for a reason no operator had
    /// chosen. A role is the authorization fact the directory *does* carry, so
    /// it supplies the floor.
    ///
    /// The mapping follows what each role already means elsewhere: `owner` is
    /// documented as "may do everything" and `admin` administers the same
    /// directory, so both reach `Regulated`; a `member` works with the org's
    /// material but is not its administrator, so it stops below `Regulated`;
    /// `viewer` is read-only; and `billing` "is never run/access authority"
    /// (`INV-18`), so it implies nothing. An unrecognized role implies nothing
    /// — a role invented later must be granted deliberately, not inherit the
    /// most permissive branch by falling through.
    pub fn implied_by(role: &Role) -> Self {
        match role.as_str() {
            "owner" | "admin" => Self(3),
            "member" => Self(2),
            "viewer" => Self(1),
            _ => Self(0),
        }
    }
}

impl AuthorityAttributes {
    /// The clearance to evaluate this authority at: the highest of what the IdP
    /// asserted and what any of its roles implies.
    ///
    /// A **floor**, deliberately, not a replacement. An IdP that asserts a
    /// higher clearance than the role implies keeps it, so an organization can
    /// grant above the default; the role can only raise an authority that
    /// arrived with nothing. The alternative — letting the claim replace the
    /// role — would mean an IdP silently omitting the claim downgrades every
    /// authority to `public`, which is the failure this exists to end.
    pub fn effective_clearance(&self) -> Clearance {
        self.roles
            .iter()
            .map(Clearance::implied_by)
            .chain(std::iter::once(self.clearance))
            .max()
            .unwrap_or_default()
    }
}

/// Attributes carried on a **resource** record (`data.md` extension): beyond
/// stakeholders/provenance, a resource has a classification, a residency region,
/// and purpose tags.
#[derive(Clone, Debug, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct ResourceAttributes {
    pub classification: Classification,
    pub region: Option<Region>,
    pub purpose: BTreeSet<Purpose>,
}

/// Attributes carried on an **authority** (mapped from IdP claims by the
/// `IdentityProvider` adapter): clearance, affiliation/tenant, roles, and the
/// authority's home region.
#[derive(Clone, Debug, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct AuthorityAttributes {
    pub clearance: Clearance,
    pub affiliation: Option<Tenant>,
    pub roles: BTreeSet<Role>,
    pub region: Option<Region>,
}

// --- the request under evaluation -----------------------------------------------

/// The kind of decision ABAC gates — the points where the floor already admits or
/// denies (resource-access grant, run admission, egress/export). ABAC may further
/// constrain any of them.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Access,
    Run,
    Export,
}

/// The execution/egress context of the decision. `ceiling_attested` mirrors
/// [`crate::boundary_lifecycle::Placement::method_secret`] (ADR 0040): the proposed
/// boundary ceiling is host-blind. A rule may *require* it (tighten the ceiling).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Context {
    pub ceiling_attested: bool,
}

/// A complete request the evaluator decides over: who (actor attrs), what (resource
/// attrs), which action, in what context.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Decision {
    pub actor: AuthorityAttributes,
    pub resource: ResourceAttributes,
    pub action: Action,
    pub context: Context,
}

// --- the policy (a structured rule set: *data, not code*) -----------------------

/// A rule condition over the request's attributes. Structured data (ADR 0032's
/// recommended policy surface) so policy is itself admittable and auditable.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Condition {
    /// Always applies.
    Always,
    /// The resource carries exactly this classification.
    ClassificationIs(Classification),
    /// The actor carries this role.
    ActorHasRole(Role),
}

/// The constraint a rule imposes when its condition holds. Every variant only ever
/// *removes* options — there is no "permit" constraint, which is what makes the
/// evaluator monotone by construction.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Constraint {
    /// Require the boundary ceiling to be attested (host-blind).
    RequireAttestedCeiling,
    /// Require the resource's region to match the actor's region.
    RequireResourceRegionMatchesActor,
    /// Forbid this action outright.
    DenyAction(Action),
}

/// A single `condition ⇒ constraint` rule.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Rule {
    pub when: Condition,
    pub require: Constraint,
}

/// An ABAC policy: an ordered set of rules. Restrict-only because [`Constraint`]
/// has no granting variant.
#[derive(Clone, Debug, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct Policy {
    pub rules: Vec<Rule>,
}

impl Policy {
    /// The worked enterprise example of ADR 0032: a `pii` resource may be reached
    /// only at an attested ceiling and in the actor's own region; a `viewer` may
    /// not export. Coarse roles and fine attribute rules under one evaluator.
    pub fn enterprise_example() -> Self {
        Self {
            rules: vec![
                Rule {
                    when: Condition::ClassificationIs(Classification::Pii),
                    require: Constraint::RequireAttestedCeiling,
                },
                Rule {
                    when: Condition::ClassificationIs(Classification::Pii),
                    require: Constraint::RequireResourceRegionMatchesActor,
                },
                Rule {
                    when: Condition::ActorHasRole(Role::viewer()),
                    require: Constraint::DenyAction(Action::Export),
                },
            ],
        }
    }
}

/// The constraints a policy imposes on a specific request — the accumulated effect
/// of every rule whose condition held. Computed by [`evaluate`], checked by
/// [`constraints_satisfied`].
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Constraints {
    pub require_attested: bool,
    pub require_actor_region: bool,
    pub denied_actions: BTreeSet<Action>,
}

fn condition_holds(cond: &Condition, d: &Decision) -> bool {
    match cond {
        Condition::Always => true,
        Condition::ClassificationIs(k) => d.resource.classification == *k,
        Condition::ActorHasRole(r) => d.actor.roles.contains(r),
    }
}

/// Evaluate `policy` against decision `d`, accumulating every applicable rule's
/// constraint. Pure: no I/O, no floor recomputation.
pub fn evaluate(policy: &Policy, d: &Decision) -> Constraints {
    let mut c = Constraints::default();
    for rule in &policy.rules {
        if condition_holds(&rule.when, d) {
            match &rule.require {
                Constraint::RequireAttestedCeiling => c.require_attested = true,
                Constraint::RequireResourceRegionMatchesActor => c.require_actor_region = true,
                Constraint::DenyAction(a) => {
                    c.denied_actions.insert(*a);
                }
            }
        }
    }
    c
}

/// Whether decision `d` satisfies the computed `constraints`. A required-but-absent
/// region fails closed (no region ⇒ cannot prove a match; `INV-20`).
pub fn constraints_satisfied(constraints: &Constraints, d: &Decision) -> bool {
    if constraints.require_attested && !d.context.ceiling_attested {
        return false;
    }
    if constraints.require_actor_region {
        match (&d.resource.region, &d.actor.region) {
            (Some(rr), Some(ar)) if rr == ar => {}
            _ => return false,
        }
    }
    if constraints.denied_actions.contains(&d.action) {
        return false;
    }
    true
}

/// The combined permit: the floor's `baseline` verdict **and** the policy's
/// constraints. Restrict-only by construction — ABAC can only narrow `baseline`,
/// never widen it (`ABAC_MONOTONE`).
pub fn permitted_with_policy(baseline: bool, policy: &Policy, d: &Decision) -> bool {
    baseline && constraints_satisfied(&evaluate(policy, d), d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn roles(names: &[&str]) -> BTreeSet<Role> {
        names.iter().map(|s| Role::new(*s)).collect()
    }

    fn attributes(claimed: u8, role_names: &[&str]) -> AuthorityAttributes {
        AuthorityAttributes {
            clearance: Clearance(claimed),
            roles: roles(role_names),
            ..Default::default()
        }
    }

    #[test]
    fn each_role_implies_its_own_clearance() {
        assert_eq!(Clearance::implied_by(&Role::owner()), Clearance(3));
        assert_eq!(Clearance::implied_by(&Role::admin()), Clearance(3));
        assert_eq!(Clearance::implied_by(&Role::member()), Clearance(2));
        assert_eq!(Clearance::implied_by(&Role::viewer()), Clearance(1));
        // Billing is never run/access authority (INV-18), so it implies nothing.
        assert_eq!(Clearance::implied_by(&Role::billing()), Clearance(0));
        // A role invented later must be granted deliberately rather than
        // inherit the most permissive branch by falling through.
        assert_eq!(Clearance::implied_by(&Role::new("auditor")), Clearance(0));
    }

    /// The case the production wiring canary hit: an OIDC actor carrying no
    /// clearance claim, acting on an unlabeled — therefore `Regulated` —
    /// project it owns. Before the role floor this cleared only `public`, so
    /// the agent turn was refused for a reason no operator had chosen.
    #[test]
    fn an_owner_with_no_clearance_claim_reaches_regulated() {
        assert_eq!(
            attributes(0, &["owner"]).effective_clearance(),
            Clearance(3)
        );
    }

    #[test]
    fn the_role_is_a_floor_the_claim_can_raise_but_not_lower() {
        // A claim above the floor stands: an org may grant beyond the role.
        assert_eq!(
            attributes(3, &["viewer"]).effective_clearance(),
            Clearance(3)
        );
        // A claim below the floor does not pull the role down — otherwise an
        // IdP that simply omits the claim silently downgrades everyone.
        assert_eq!(
            attributes(0, &["member"]).effective_clearance(),
            Clearance(2)
        );
        // The highest role wins when an authority holds several.
        assert_eq!(
            attributes(0, &["billing", "owner"]).effective_clearance(),
            Clearance(3),
        );
    }

    #[test]
    fn no_role_and_no_claim_still_clears_nothing() {
        // The fail-closed default is unchanged: this only lifts authorities the
        // directory has actually placed in a role.
        assert_eq!(attributes(0, &[]).effective_clearance(), Clearance(0));
        assert_eq!(
            AuthorityAttributes::default().effective_clearance(),
            Clearance(0),
        );
        // An unrecognized role is not a grant.
        assert_eq!(
            attributes(0, &["auditor"]).effective_clearance(),
            Clearance(0)
        );
    }

    /// A decision builder for the readable unit tests.
    fn decision(
        cls: Classification,
        res_region: Option<&str>,
        actor_region: Option<&str>,
        actor_roles: &[&str],
        action: Action,
        ceiling_attested: bool,
    ) -> Decision {
        Decision {
            actor: AuthorityAttributes {
                clearance: Clearance::default(),
                affiliation: None,
                roles: roles(actor_roles),
                region: actor_region.map(Region::new),
            },
            resource: ResourceAttributes {
                classification: cls,
                region: res_region.map(Region::new),
                purpose: BTreeSet::new(),
            },
            action,
            context: Context { ceiling_attested },
        }
    }

    // --- readable scenarios (mirror the abac.qnt deterministic runs) ------------

    #[test]
    fn pii_blocked_when_unattested() {
        // abac.qnt::piiBlockedWhenUnattested — the floor allowed it (baseline),
        // but policy narrows: a pii resource at an unattested ceiling is blocked.
        let d = decision(
            Classification::Pii,
            Some("eu"),
            Some("eu"),
            &["member"],
            Action::Run,
            false,
        );
        assert!(!permitted_with_policy(
            true,
            &Policy::enterprise_example(),
            &d
        ));
    }

    #[test]
    fn pii_allowed_when_attested_same_region() {
        let d = decision(
            Classification::Pii,
            Some("eu"),
            Some("eu"),
            &["member"],
            Action::Run,
            true,
        );
        assert!(permitted_with_policy(
            true,
            &Policy::enterprise_example(),
            &d
        ));
    }

    #[test]
    fn pii_blocked_cross_region_even_when_attested() {
        let d = decision(
            Classification::Pii,
            Some("us"),
            Some("eu"),
            &["member"],
            Action::Run,
            true,
        );
        assert!(!permitted_with_policy(
            true,
            &Policy::enterprise_example(),
            &d
        ));
    }

    #[test]
    fn viewer_export_blocked() {
        // abac.qnt::viewerExportBlocked — coarse role: a viewer never exports.
        let d = decision(
            Classification::Internal,
            Some("eu"),
            Some("eu"),
            &["viewer"],
            Action::Export,
            true,
        );
        assert!(!permitted_with_policy(
            true,
            &Policy::enterprise_example(),
            &d
        ));
    }

    #[test]
    fn viewer_may_still_access() {
        let d = decision(
            Classification::Internal,
            Some("eu"),
            Some("eu"),
            &["viewer"],
            Action::Access,
            true,
        );
        assert!(permitted_with_policy(
            true,
            &Policy::enterprise_example(),
            &d
        ));
    }

    #[test]
    fn policy_never_grants_what_floor_denied() {
        // abac.qnt::policyNeverGrants — baseline false ⇒ never permitted, whatever
        // the attributes.
        let d = decision(
            Classification::Public,
            Some("eu"),
            Some("eu"),
            &["admin"],
            Action::Access,
            true,
        );
        assert!(!permitted_with_policy(
            false,
            &Policy::enterprise_example(),
            &d
        ));
    }

    // --- proptest generators ----------------------------------------------------

    fn arb_classification() -> impl Strategy<Value = Classification> {
        prop_oneof![
            Just(Classification::Public),
            Just(Classification::Internal),
            Just(Classification::Pii),
            Just(Classification::Regulated),
        ]
    }
    fn arb_region() -> impl Strategy<Value = Option<Region>> {
        prop_oneof![
            Just(None),
            Just(Some(Region::new("eu"))),
            Just(Some(Region::new("us"))),
        ]
    }
    fn arb_role() -> impl Strategy<Value = Role> {
        prop_oneof![
            Just(Role::admin()),
            Just(Role::member()),
            Just(Role::viewer()),
        ]
    }
    fn arb_roles() -> impl Strategy<Value = BTreeSet<Role>> {
        prop::collection::btree_set(arb_role(), 0..3)
    }
    fn arb_action() -> impl Strategy<Value = Action> {
        prop_oneof![
            Just(Action::Access),
            Just(Action::Run),
            Just(Action::Export),
        ]
    }
    fn arb_decision() -> impl Strategy<Value = Decision> {
        (
            arb_region(),
            arb_roles(),
            arb_classification(),
            arb_region(),
            arb_action(),
            any::<bool>(),
        )
            .prop_map(
                |(actor_region, actor_roles, classification, res_region, action, ceiling)| {
                    Decision {
                        actor: AuthorityAttributes {
                            clearance: Clearance::default(),
                            affiliation: None,
                            roles: actor_roles,
                            region: actor_region,
                        },
                        resource: ResourceAttributes {
                            classification,
                            region: res_region,
                            purpose: BTreeSet::new(),
                        },
                        action,
                        context: Context {
                            ceiling_attested: ceiling,
                        },
                    }
                },
            )
    }
    fn arb_condition() -> impl Strategy<Value = Condition> {
        prop_oneof![
            Just(Condition::Always),
            arb_classification().prop_map(Condition::ClassificationIs),
            arb_role().prop_map(Condition::ActorHasRole),
        ]
    }
    fn arb_constraint() -> impl Strategy<Value = Constraint> {
        prop_oneof![
            Just(Constraint::RequireAttestedCeiling),
            Just(Constraint::RequireResourceRegionMatchesActor),
            arb_action().prop_map(Constraint::DenyAction),
        ]
    }
    fn arb_policy() -> impl Strategy<Value = Policy> {
        prop::collection::vec(
            (arb_condition(), arb_constraint()).prop_map(|(when, require)| Rule { when, require }),
            0..6,
        )
        .prop_map(|rules| Policy { rules })
    }

    proptest! {
        /// ABAC_MONOTONE (abac.qnt): `permitted_with_policy ⊆ permitted_baseline`.
        /// For ANY policy, decision, and floor verdict, the policy can only remove
        /// — whatever it permits, the floor already permitted. This is the property
        /// that lets the enterprise layer attach without re-proving the floor.
        #[test]
        fn policy_is_monotone(
            policy in arb_policy(),
            d in arb_decision(),
            baseline in any::<bool>(),
        ) {
            if permitted_with_policy(baseline, &policy, &d) {
                prop_assert!(baseline, "policy granted a request the floor denied");
            }
        }

        /// PII_REQUIRES_ATTESTED_SAMEREGION (abac.qnt): under the enterprise policy,
        /// a permitted `pii` request is necessarily at an attested ceiling and in
        /// the actor's region.
        #[test]
        fn pii_requires_attested_same_region(d in arb_decision(), baseline in any::<bool>()) {
            let policy = Policy::enterprise_example();
            if d.resource.classification == Classification::Pii
                && permitted_with_policy(baseline, &policy, &d)
            {
                prop_assert!(d.context.ceiling_attested);
                prop_assert!(d.resource.region.is_some());
                prop_assert_eq!(d.resource.region.as_ref(), d.actor.region.as_ref());
            }
        }

        /// VIEWER_CANNOT_EXPORT (abac.qnt): roles are coarse ABAC — a `viewer` is
        /// never permitted to export under the enterprise policy, regardless of the
        /// floor's verdict.
        #[test]
        fn viewer_cannot_export(d in arb_decision(), baseline in any::<bool>()) {
            let policy = Policy::enterprise_example();
            if d.action == Action::Export && d.actor.roles.contains(&Role::viewer()) {
                prop_assert!(!permitted_with_policy(baseline, &policy, &d));
            }
        }
    }

    // --- teeth: each tooth from abac.qnt, shown load-bearing --------------------

    /// The buggy combinator behind `POLICY_CAN_GRANT`: OR-ing the floor with the
    /// policy instead of AND-ing. Off ⇒ the real, monotone combinator.
    fn permitted_buggy(
        baseline: bool,
        policy: &Policy,
        d: &Decision,
        policy_can_grant: bool,
    ) -> bool {
        let sat = constraints_satisfied(&evaluate(policy, d), d);
        if policy_can_grant {
            baseline || sat
        } else {
            baseline && sat
        }
    }

    #[test]
    fn policy_can_grant_tooth_bites() {
        // A request the floor DENIES (baseline=false) whose constraints are
        // vacuously satisfied (public, no viewer). The sound combinator denies; the
        // OR tooth grants past the floor — violating ABAC_MONOTONE.
        let policy = Policy::enterprise_example();
        let d = decision(
            Classification::Public,
            Some("eu"),
            Some("eu"),
            &["member"],
            Action::Access,
            false,
        );
        assert!(
            !permitted_buggy(false, &policy, &d, false),
            "sound: the floor denied, so the combined verdict must deny"
        );
        assert!(
            permitted_buggy(false, &policy, &d, true),
            "tooth: OR-combining grants a request the floor denied"
        );
    }

    #[test]
    fn pii_rule_off_tooth_bites() {
        // pii resource, unattested ceiling, floor allows. With the classification
        // rule present it is blocked; dropping it (the tooth) leaks pii to an
        // unattested ceiling.
        let d = decision(
            Classification::Pii,
            Some("eu"),
            Some("eu"),
            &["member"],
            Action::Run,
            false,
        );
        assert!(!permitted_with_policy(
            true,
            &Policy::enterprise_example(),
            &d
        ));
        let without_pii_rule = Policy {
            rules: vec![Rule {
                when: Condition::ActorHasRole(Role::viewer()),
                require: Constraint::DenyAction(Action::Export),
            }],
        };
        assert!(
            permitted_with_policy(true, &without_pii_rule, &d),
            "tooth: without the pii rule, a pii resource is reached at an unattested ceiling"
        );
    }

    #[test]
    fn viewer_may_export_tooth_bites() {
        // viewer + export, all else satisfiable. The viewer rule blocks it; dropping
        // it (the tooth) lets a viewer export.
        let d = decision(
            Classification::Internal,
            Some("eu"),
            Some("eu"),
            &["viewer"],
            Action::Export,
            true,
        );
        assert!(!permitted_with_policy(
            true,
            &Policy::enterprise_example(),
            &d
        ));
        let without_viewer_rule = Policy {
            rules: vec![
                Rule {
                    when: Condition::ClassificationIs(Classification::Pii),
                    require: Constraint::RequireAttestedCeiling,
                },
                Rule {
                    when: Condition::ClassificationIs(Classification::Pii),
                    require: Constraint::RequireResourceRegionMatchesActor,
                },
            ],
        };
        assert!(
            permitted_with_policy(true, &without_viewer_rule, &d),
            "tooth: without the viewer rule, a viewer exports"
        );
    }
}
