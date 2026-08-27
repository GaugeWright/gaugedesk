//! Coarse RBAC for the **admin-console surface** — the workspace-administration
//! capability matrix (M3 `RBAC-3`, [ADR 0043](../../../specs/decisions/0043-enterprise-readiness-mid-market.md) §2,
//! separated into owner / admin / auditor / billing duties by
//! [ADR 0149](../../../specs/decisions/0149-the-org-console-separates-owner-admin-and-auditor-duties.md)).
//!
//! Two distinct role mechanisms live under "roles are coarse ABAC" (ADR 0032), and
//! they have **opposite default polarity** on purpose:
//!
//! - The **resource-floor** rules in [`crate::abac`] are *restrict-only*: they narrow
//!   a protection-floor `baseline` the floor already computed (`role = viewer ⇒ no
//!   export`). They can only *remove* a permission the floor granted.
//! - The **admin-console** matrix here is *positive, default-deny*: there is no
//!   protection floor behind "may this role invite a member" — the action either is
//!   or is not within the role's standing. So [`role_can`] grants only what the fixed
//!   matrix lists and denies everything else, including any unrecognized role
//!   (fail-closed, `INV-20`). This is the right shape for admin authorization; using
//!   the restrict-only evaluator (default-allow-then-narrow) would fail *open*.
//!
//! Both are "roles as attributes", not a parallel permission system: the fixed roles
//! are the same `owner`/`admin`/`auditor`/`member`/`viewer`/`billing` set, and custom
//! roles + a policy-authoring surface (and a finer `security-admin` tier, ADR 0149 §5)
//! stay upmarket (ADR 0043 §3).
//!
//! ADR 0149 breaks the privileged tier apart: `owner` ⊋ `admin` (the two owner-only
//! capabilities [`Capability::ManageOrgLifecycle`] and [`Capability::GrantPrivilegedRoles`]
//! are removed from `admin`), `admin` loses [`Capability::ManageBilling`], the read-only
//! `auditor` holds only [`Capability::ViewAudit`], and `billing` stays spend-only.
//!
//! See [`specs/primitives/organization.md`](../../../specs/primitives/organization.md)
//! and [`specs/models/rbac.qnt`](../../../specs/models/rbac.qnt) (the Quint oracle).

use crate::abac::Role;

/// A governed admin-console action, mapped to its surface (B10–B16). Default-deny:
/// a role holds a capability only if [`role_can`] lists it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Capability {
    /// Delete/terminate the org or transfer ownership (ADR 0149 §1). **Owner-only** —
    /// an operational admin cannot end or hand off the tenant.
    ManageOrgLifecycle,
    /// Assign the `owner` or `admin` role — grant a *privileged* role (ADR 0149 §1).
    /// **Owner-only.** `admin`'s [`Capability::ManageMembers`] covers assigning the
    /// non-privileged roles; elevating a principal to `owner`/`admin` requires this,
    /// closing self- and lateral-escalation by an admin.
    GrantPrivilegedRoles,
    /// Edit org profile / verified domains / default region (B10).
    EditOrgSettings,
    /// Invite / assign-role / deactivate members (B11) — the **non-privileged** roles
    /// only (`member`/`viewer`/`billing`/`auditor`). Elevating to `owner`/`admin`
    /// requires [`Capability::GrantPrivilegedRoles`] (ADR 0149 §1); the target-role
    /// gate lives in the assign-role handler.
    ManageMembers,
    /// Connect an IdP, run test-connection, toggle enforce-SSO (B12).
    ConfigureSso,
    /// Issue/rotate SCIM tokens, map groups → roles (B13).
    ConfigureProvisioning,
    /// Read the per-actor audit timeline / export it (B14).
    ViewAudit,
    /// Org security controls: MFA, session lifetime, residency default (B15).
    ConfigureSecurity,
    /// Plan/tier, seats, invoices (B16).
    ManageBilling,
}

impl Capability {
    /// Every capability — the iteration surface the model/tests quantify over.
    pub const ALL: [Capability; 9] = [
        Capability::ManageOrgLifecycle,
        Capability::GrantPrivilegedRoles,
        Capability::EditOrgSettings,
        Capability::ManageMembers,
        Capability::ConfigureSso,
        Capability::ConfigureProvisioning,
        Capability::ViewAudit,
        Capability::ConfigureSecurity,
        Capability::ManageBilling,
    ];

    /// Stable transport name used by capability discovery. These names are part
    /// of the enterprise client/server contract, not UI labels.
    pub const fn as_str(self) -> &'static str {
        match self {
            Capability::ManageOrgLifecycle => "manage_org_lifecycle",
            Capability::GrantPrivilegedRoles => "grant_privileged_roles",
            Capability::EditOrgSettings => "edit_org_settings",
            Capability::ManageMembers => "manage_members",
            Capability::ConfigureSso => "configure_sso",
            Capability::ConfigureProvisioning => "configure_provisioning",
            Capability::ViewAudit => "view_audit",
            Capability::ConfigureSecurity => "configure_security",
            Capability::ManageBilling => "manage_billing",
        }
    }
}

/// Whether `role` may perform `cap`. The fixed matrix (ADR 0149 §4, admin-console.md):
///
/// - `owner` — every capability (the full console; `owner` ⊋ `admin`).
/// - `admin` — everything **except** the two owner-only capabilities
///   ([`Capability::ManageOrgLifecycle`], [`Capability::GrantPrivilegedRoles`]) **and**
///   [`Capability::ManageBilling`]: it operates the org but cannot end/hand it off,
///   elevate a principal to `owner`/`admin`, or control spend.
/// - `auditor` — only [`Capability::ViewAudit`] (the read-only separation-of-duties
///   reader; no write capability of any kind).
/// - `billing` — only [`Capability::ManageBilling`] (B16; spend-only).
/// - `member` / `viewer` — none (no console at all).
/// - any other / unknown role — none (fail-closed, `INV-20`).
pub fn role_can(role: &Role, cap: Capability) -> bool {
    use Capability::*;
    match role.as_str() {
        "owner" => true,
        // admin holds the full console minus the owner-only lifecycle/grant duties and
        // billing (ADR 0149 §1, §2): default-deny, so only the listed capabilities.
        "admin" => matches!(
            cap,
            EditOrgSettings
                | ManageMembers
                | ConfigureSso
                | ConfigureProvisioning
                | ConfigureSecurity
                | ViewAudit
        ),
        // The read-only auditor (ADR 0149 §3): audit read/export, nothing else.
        "auditor" => cap == ViewAudit,
        "billing" => cap == ManageBilling,
        // member, viewer, and every unrecognized role: no admin capabilities.
        _ => false,
    }
}

/// Whether `role` may open the admin console at all — i.e. holds *some* capability.
/// `member`/`viewer`/unknown see no console; `billing` sees only its billing surface;
/// `auditor` sees only the audit surface.
pub fn can_access_console(role: &Role) -> bool {
    Capability::ALL.iter().any(|&cap| role_can(role, cap))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn owner_has_every_capability() {
        let owner = Role::owner();
        for cap in Capability::ALL {
            assert!(role_can(&owner, cap), "owner should hold {cap:?}");
        }
    }

    #[test]
    fn admin_has_everything_except_owner_only_and_billing() {
        // ADR 0149 §1/§2: admin loses ManageOrgLifecycle, GrantPrivilegedRoles, and
        // ManageBilling; it keeps the operational configuration + audit-read set.
        let admin = Role::admin();
        let denied = [
            Capability::ManageOrgLifecycle,
            Capability::GrantPrivilegedRoles,
            Capability::ManageBilling,
        ];
        for cap in Capability::ALL {
            assert_eq!(
                role_can(&admin, cap),
                !denied.contains(&cap),
                "admin holds {cap:?}?"
            );
        }
        // Explicit: the separation-of-duties reductions ADR 0149 turns on.
        assert!(!role_can(&admin, Capability::ManageBilling));
        assert!(!role_can(&admin, Capability::ManageOrgLifecycle));
        assert!(!role_can(&admin, Capability::GrantPrivilegedRoles));
        assert!(role_can(&admin, Capability::ManageMembers));
        assert!(role_can(&admin, Capability::ViewAudit));
        assert!(can_access_console(&admin));
    }

    #[test]
    fn auditor_holds_only_view_audit() {
        // ADR 0149 §3: the read-only separation-of-duties reader.
        let auditor = Role::auditor();
        for cap in Capability::ALL {
            assert_eq!(role_can(&auditor, cap), cap == Capability::ViewAudit);
        }
        assert!(can_access_console(&auditor));
    }

    #[test]
    fn billing_holds_only_billing() {
        let billing = Role::billing();
        for cap in Capability::ALL {
            assert_eq!(role_can(&billing, cap), cap == Capability::ManageBilling);
        }
        assert!(can_access_console(&billing));
    }

    #[test]
    fn capability_transport_names_are_unique_and_stable() {
        let names: std::collections::BTreeSet<_> = Capability::ALL
            .iter()
            .map(|capability| capability.as_str())
            .collect();
        assert_eq!(names.len(), Capability::ALL.len());
        assert!(names.contains("manage_billing"));
        assert!(names.contains("configure_security"));
        assert!(names.contains("manage_org_lifecycle"));
        assert!(names.contains("grant_privileged_roles"));
    }

    #[test]
    fn member_and_viewer_have_no_console() {
        for role in [Role::member(), Role::viewer()] {
            assert!(!can_access_console(&role));
            for cap in Capability::ALL {
                assert!(!role_can(&role, cap));
            }
        }
    }

    #[test]
    fn unknown_role_is_fail_closed() {
        for name in ["", "superuser", "root", "Owner", "ADMIN"] {
            let role = Role::new(name);
            assert!(
                !can_access_console(&role),
                "{name:?} must hold no capability"
            );
            for cap in Capability::ALL {
                assert!(!role_can(&role, cap));
            }
        }
    }

    proptest! {
        /// The two owner-only capabilities (ADR 0149 §1) are held by `owner` and
        /// nothing else — no arbitrary role string, including `admin`, elevates.
        #[test]
        fn owner_only_caps_are_owner_only(name in "[a-zA-Z]{0,12}") {
            let role = Role::new(&name);
            for cap in [Capability::ManageOrgLifecycle, Capability::GrantPrivilegedRoles] {
                if role_can(&role, cap) {
                    prop_assert_eq!(&name, "owner");
                }
            }
        }

        /// `ManageBilling` is held by `owner` and `billing` only (ADR 0149 §2): admin
        /// no longer holds it, and no arbitrary role string does.
        #[test]
        fn billing_cap_is_owner_or_billing(name in "[a-zA-Z]{0,12}") {
            let role = Role::new(&name);
            if role_can(&role, Capability::ManageBilling) {
                prop_assert!(name == "owner" || name == "billing");
            }
        }

        /// Any role holding a capability is one of the four recognized console roles;
        /// every unrecognized role string is fail-closed (`INV-20`).
        #[test]
        fn only_known_roles_hold_any_capability(name in "[a-zA-Z]{0,12}") {
            let role = Role::new(&name);
            if Capability::ALL.iter().any(|&c| role_can(&role, c)) {
                prop_assert!(
                    matches!(name.as_str(), "owner" | "admin" | "auditor" | "billing")
                );
            }
        }

        /// Console access ⇔ holding some capability (the accessor can't disagree with
        /// the matrix).
        #[test]
        fn console_access_iff_some_capability(name in "[a-zA-Z]{0,12}") {
            let role = Role::new(&name);
            let any = Capability::ALL.iter().any(|&c| role_can(&role, c));
            prop_assert_eq!(can_access_console(&role), any);
        }
    }
}
