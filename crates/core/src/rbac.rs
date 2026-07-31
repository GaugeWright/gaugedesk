//! Coarse RBAC for the **admin-console surface** — the workspace-administration
//! capability matrix (M3 `RBAC-3`, [ADR 0043](../../../specs/decisions/0043-enterprise-readiness-mid-market.md) §2).
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
//! are the same `owner`/`admin`/`member`/`viewer`/`billing` set, and custom roles +
//! a policy-authoring surface stay upmarket (ADR 0043 §3).
//!
//! See [`specs/primitives/organization.md`](../../../specs/primitives/organization.md)
//! and [`specs/models/rbac.qnt`](../../../specs/models/rbac.qnt) (the Quint oracle).

use crate::abac::Role;

/// A governed admin-console action, mapped to its surface (B10–B16). Default-deny:
/// a role holds a capability only if [`role_can`] lists it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Capability {
    /// Edit org profile / verified domains / default region (B10).
    EditOrgSettings,
    /// Invite / assign-role / deactivate members (B11).
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
    pub const ALL: [Capability; 7] = [
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

/// Whether `role` may perform `cap`. The fixed matrix (admin-console.md):
///
/// - `owner` / `admin` — all capabilities (the full console).
/// - `billing` — only [`Capability::ManageBilling`] (B16).
/// - `member` / `viewer` — none (no console at all).
/// - any other / unknown role — none (fail-closed, `INV-20`).
pub fn role_can(role: &Role, cap: Capability) -> bool {
    match role.as_str() {
        "owner" | "admin" => true,
        "billing" => cap == Capability::ManageBilling,
        // member, viewer, and every unrecognized role: no admin capabilities.
        _ => false,
    }
}

/// Whether `role` may open the admin console at all — i.e. holds *some* capability.
/// `member`/`viewer`/unknown see no console; `billing` sees only its billing surface.
pub fn can_access_console(role: &Role) -> bool {
    Capability::ALL.iter().any(|&cap| role_can(role, cap))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn owner_and_admin_have_every_capability() {
        for role in [Role::owner(), Role::admin()] {
            for cap in Capability::ALL {
                assert!(role_can(&role, cap), "{role:?} should hold {cap:?}");
            }
        }
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
        /// No non-owner/admin role ever holds a non-billing capability (no privilege
        /// escalation through an arbitrary role string).
        #[test]
        fn only_owner_admin_get_non_billing_caps(name in "[a-zA-Z]{0,12}") {
            let role = Role::new(&name);
            for cap in Capability::ALL {
                if cap != Capability::ManageBilling && role_can(&role, cap) {
                    prop_assert!(name == "owner" || name == "admin");
                }
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
