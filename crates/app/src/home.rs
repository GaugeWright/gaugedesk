//! Home identity and fact jurisdiction (`HOME-1`, ADR 0084).
//!
//! The account hub and a project Home are deliberately different services. The
//! hub owns identity/routing/commercial metadata and stays blind to work; the
//! Home owns GaugeDesk project truth and admission; WhippleScript owns runtime
//! evidence bodies. This module makes that ownership map executable so route and
//! storage composition can test it instead of relying on deployment convention.

use gaugedesk_core::ids::{AuthorityId, HomeId};
use serde::{Deserialize, Serialize};

pub use gaugedesk_directory_protocol::{
    shared_home_route_verifies, sign_home_route, OpaqueHomeRoute, OpaqueRelayLocator,
};

/// Where a Home is operated. This is operational placement behind one product
/// identity; changing a process/VM does not change the [`HomeId`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HomeKind {
    /// The desktop/local Home on the owner's machine.
    #[default]
    Local,
    /// A tenant-registered machine running its Home.
    Registered,
    /// GaugeWright's paid tenant-level Cloud Home facility.
    Cloud,
}

/// Stable identity/configuration for one logical Home.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HomeRecord {
    pub id: HomeId,
    /// Tenant billed for and governing this Home. A local solo Home uses the
    /// owning authority until it joins a named tenant.
    pub tenant_id: String,
    pub kind: HomeKind,
    /// The tenant facility that provides this Home, when applicable. A local
    /// Home exists without a hosted facility.
    #[serde(default)]
    pub facility_id: Option<String>,
}

impl HomeRecord {
    /// The stable local Home for an authority.
    pub fn local(authority: &AuthorityId) -> Self {
        Self {
            id: HomeId::new(format!("home:{}", authority.as_str())),
            tenant_id: authority.as_str().to_string(),
            kind: HomeKind::Local,
            facility_id: None,
        }
    }
}

/// Durable/operational fact classes whose owner must never be inferred from
/// physical co-location (`HOME-1`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FactClass {
    AccountIdentity,
    TenantMembership,
    Invitation,
    Facility,
    Billing,
    OpaqueHomeRoute,
    ProjectEvent,
    ProjectContent,
    ProjectGrant,
    Schedule,
    AdmittedCommandPointer,
    RuntimeEvent,
    RuntimeInstance,
    RuntimeEffect,
    RuntimeReceipt,
}

/// The one jurisdiction authoritative for a fact class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FactJurisdiction {
    Hub,
    Home,
    WhippleScript,
}

/// The executable one-owner-per-fact table from ADR 0084.
pub const fn fact_jurisdiction(class: FactClass) -> FactJurisdiction {
    match class {
        FactClass::AccountIdentity
        | FactClass::TenantMembership
        | FactClass::Invitation
        | FactClass::Facility
        | FactClass::Billing
        | FactClass::OpaqueHomeRoute => FactJurisdiction::Hub,
        FactClass::ProjectEvent
        | FactClass::ProjectContent
        | FactClass::ProjectGrant
        | FactClass::Schedule
        | FactClass::AdmittedCommandPointer => FactJurisdiction::Home,
        FactClass::RuntimeEvent
        | FactClass::RuntimeInstance
        | FactClass::RuntimeEffect
        | FactClass::RuntimeReceipt => FactJurisdiction::WhippleScript,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_home_identity_is_stable_and_not_a_session() {
        let authority = AuthorityId::new("alice");
        assert_eq!(HomeRecord::local(&authority), HomeRecord::local(&authority));
        assert_eq!(HomeRecord::local(&authority).id.as_str(), "home:alice");
    }

    #[test]
    fn one_owner_per_fact_keeps_hub_blind_and_runtime_bodies_out_of_home() {
        for class in [
            FactClass::AccountIdentity,
            FactClass::TenantMembership,
            FactClass::Invitation,
            FactClass::Facility,
            FactClass::Billing,
            FactClass::OpaqueHomeRoute,
        ] {
            assert_eq!(fact_jurisdiction(class), FactJurisdiction::Hub);
        }
        for class in [
            FactClass::ProjectEvent,
            FactClass::ProjectContent,
            FactClass::ProjectGrant,
            FactClass::Schedule,
            FactClass::AdmittedCommandPointer,
        ] {
            assert_eq!(fact_jurisdiction(class), FactJurisdiction::Home);
        }
        for class in [
            FactClass::RuntimeEvent,
            FactClass::RuntimeInstance,
            FactClass::RuntimeEffect,
            FactClass::RuntimeReceipt,
        ] {
            assert_eq!(fact_jurisdiction(class), FactJurisdiction::WhippleScript);
        }
    }
}
