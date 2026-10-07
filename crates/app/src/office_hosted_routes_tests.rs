use std::collections::BTreeSet;

use axum::http::Method;
use gaugedesk_store::Store;

use super::*;
use crate::account::account_scope;
use crate::tenancy::{TenantRef, TENANT_REF_KIND};

fn index_tenant(store: &mut Store, person: &str, tenant: &str) {
    let tenant_ref = TenantRef {
        id: tenant.into(),
        op: RecordOp::Upsert,
        display_name: tenant.into(),
        role: "member".into(),
        personal: false,
    };
    store
        .append_record(
            &account_scope(person),
            TENANT_REF_KIND,
            &serde_json::to_string(&tenant_ref).unwrap(),
        )
        .unwrap();
}

#[test]
fn the_inventory_names_every_family_exactly_once_with_its_disposition() {
    let listed: Vec<_> = INVENTORY.iter().map(|entry| entry.family).collect();
    let unique: BTreeSet<_> = listed.iter().copied().collect();
    assert_eq!(listed.len(), unique.len(), "a family is listed twice");
    assert_eq!(
        unique,
        HostedRouteFamily::ALL.into_iter().collect::<BTreeSet<_>>(),
        "every family the profile names has an inventory line"
    );
    for entry in INVENTORY {
        assert_eq!(
            entry.disposition,
            entry.family.disposition(),
            "{:?}",
            entry.family
        );
        match (entry.disposition, entry.enforcement) {
            (Disposition::Conditional, Enforcement::NotRefused) => {}
            (Disposition::Conditional, other) => {
                panic!("{:?} is conditional but claims {other:?}", entry.family)
            }
            (Disposition::Refused, Enforcement::NotRefused) => {
                panic!("{:?} is refused but listed as not refused", entry.family)
            }
            (Disposition::Refused, _) => {}
        }
    }
    // Sign-in and updates stay available; everything else is refused.
    assert_eq!(
        HostedRouteFamily::ALL
            .into_iter()
            .filter(|family| family.disposition() == Disposition::Conditional)
            .collect::<Vec<_>>(),
        vec![
            HostedRouteFamily::AccountSignIn,
            HostedRouteFamily::SoftwareUpdate
        ]
    );
}

#[test]
fn every_enforced_family_classifies_its_documented_paths() {
    let cases: &[(Method, &str, HostedRouteFamily, Option<&str>)] = &[
        (
            Method::POST,
            "/product-analytics/events",
            HostedRouteFamily::ProductAnalytics,
            None,
        ),
        (
            Method::POST,
            "/account/dictation/entitlement",
            HostedRouteFamily::Dictation,
            None,
        ),
        (
            Method::POST,
            "/account/dictation/transcribe",
            HostedRouteFamily::Dictation,
            None,
        ),
        (
            Method::GET,
            "/account/tenants/clinic/cloud-home",
            HostedRouteFamily::HostedHome,
            Some("clinic"),
        ),
        (
            Method::POST,
            "/account/tenants/clinic/cloud-home/export",
            HostedRouteFamily::HostedHome,
            Some("clinic"),
        ),
        (
            Method::GET,
            "/account/tenants/clinic/backups",
            HostedRouteFamily::HostedBackup,
            Some("clinic"),
        ),
        (
            Method::POST,
            "/account/tenants/clinic/backups/points/p/restore-material/r",
            HostedRouteFamily::HostedBackup,
            Some("clinic"),
        ),
        (
            Method::GET,
            "/projects/p1/organization-model-options",
            HostedRouteFamily::ManagedInference,
            None,
        ),
        (
            Method::POST,
            "/projects/p1/organization-model-invocations",
            HostedRouteFamily::ManagedInference,
            None,
        ),
        (
            Method::POST,
            "/gaugeapps/administration/model-providers/intake",
            HostedRouteFamily::CredentialBroker,
            None,
        ),
        (
            Method::POST,
            "/gaugeapps/administration/model-providers/verify",
            HostedRouteFamily::CredentialBroker,
            None,
        ),
    ];
    let mut seen = BTreeSet::new();
    for (method, path, family, tenant) in cases {
        let request = classify(method, path).unwrap_or_else(|| panic!("{path} is unclassified"));
        assert_eq!(request.family, *family, "{path}");
        assert_eq!(
            request.tenant,
            tenant.map(|tenant| PathTenant::Named(tenant.into())),
            "{path}"
        );
        seen.insert(*family);
    }
    let enforced: BTreeSet<_> = INVENTORY
        .iter()
        .filter(|entry| matches!(entry.enforcement, Enforcement::HubAdmission(_)))
        .map(|entry| entry.family)
        .collect();
    assert_eq!(
        seen, enforced,
        "each Hub-enforced family has a path case here"
    );
}

#[test]
fn sign_in_policy_reads_and_unrelated_routes_are_not_classified() {
    for (method, path) in [
        (Method::GET, "/product-analytics/policy"),
        (Method::GET, "/account/tenants"),
        (Method::GET, "/account/tenants/clinic/hosts"),
        (Method::GET, "/account/tenants/clinic/facilities"),
        (Method::GET, "/account/tenants//backups"),
        (Method::GET, "/account/hub-session"),
        (Method::POST, "/auth/account/authorization/start"),
        (Method::GET, "/admin/software-policy"),
        (Method::GET, "/gaugewright-release.json"),
        (Method::GET, "/projects/p1/chats"),
        (Method::GET, "/account/tenants/clinic/backupsx"),
    ] {
        assert_eq!(classify(&method, path), None, "{method} {path}");
    }
}

#[test]
fn enrollment_is_one_way_and_idempotent() {
    let mut store = Store::open_in_memory().unwrap();
    assert!(!tenant_enrolled(&store, "clinic").unwrap());
    let first = enroll(&mut store, "clinic", "clinic-home", "operator", 10).unwrap();
    assert!(tenant_enrolled(&store, "clinic").unwrap());
    let again = enroll(&mut store, "clinic", "clinic-home", "someone-else", 20).unwrap();
    assert_eq!(first, again, "a second enrollment keeps the first");
    assert_eq!(
        store
            .records(&tenant_scope("clinic"), OFFICE_PROFILE_KIND)
            .unwrap()
            .len(),
        1
    );

    // A tombstone — written by a stale tool, a restore, or a changed setting —
    // cannot take the organization back out.
    let tombstone = OfficeProfileRecord {
        op: RecordOp::Tombstone,
        ..first.clone()
    };
    store
        .append_record(
            &tenant_scope("clinic"),
            OFFICE_PROFILE_KIND,
            &serde_json::to_string(&tombstone).unwrap(),
        )
        .unwrap();
    assert!(tenant_enrolled(&store, "clinic").unwrap());
    assert!(!tenant_enrolled(&store, "other").unwrap());
}

#[test]
fn a_path_naming_a_tenant_is_refused_only_for_that_tenant() {
    let mut store = Store::open_in_memory().unwrap();
    enroll(&mut store, "clinic", "clinic-home", "operator", 1).unwrap();
    let refused = refusal(
        &store,
        &Method::GET,
        "/account/tenants/clinic/backups",
        "org",
        Some(&account_scope("doc")),
    );
    assert_eq!(
        refused,
        Some(OfficeProfileRefusal {
            family: HostedRouteFamily::HostedBackup
        })
    );
    // The doctor's personal tenant is not the office; its backups are its own.
    index_tenant(&mut store, "doc", "clinic");
    assert_eq!(
        refusal(
            &store,
            &Method::GET,
            "/account/tenants/personal:doc/backups",
            "org",
            Some(&account_scope("doc")),
        ),
        None
    );
}

#[test]
fn a_person_level_route_is_refused_for_any_member_of_an_enrolled_organization() {
    let mut store = Store::open_in_memory().unwrap();
    enroll(&mut store, "clinic", "clinic-home", "operator", 1).unwrap();
    index_tenant(&mut store, "doc", "personal:doc");
    index_tenant(&mut store, "doc", "clinic");
    index_tenant(&mut store, "rae", "personal:rae");

    let dictation = |person: &str, scope: &str| {
        refusal(
            &store,
            &Method::POST,
            "/account/dictation/transcribe",
            scope,
            Some(&account_scope(person)),
        )
    };
    // A stale client sends no tenant header; membership still refuses it.
    assert!(dictation("doc", "org").is_some());
    // The organization header alone refuses it too.
    assert!(dictation("rae", &tenant_scope("clinic")).is_some());
    // An ordinary person is unaffected.
    assert!(dictation("rae", "org").is_none());
    // Analytics events, likewise.
    assert!(refusal(
        &store,
        &Method::POST,
        "/product-analytics/events",
        "org",
        Some(&account_scope("doc"))
    )
    .is_some());
}

#[test]
fn conditional_and_unclassified_routes_are_never_refused() {
    let mut store = Store::open_in_memory().unwrap();
    enroll(&mut store, "clinic", "clinic-home", "operator", 1).unwrap();
    let scope = tenant_scope("clinic");
    for path in [
        "/admin/software-policy",
        "/account/tenants",
        "/product-analytics/policy",
    ] {
        assert_eq!(
            refusal(&store, &Method::GET, path, &scope, None),
            None,
            "{path}"
        );
    }
}

#[test]
fn an_unreadable_enrollment_refuses() {
    let mut store = Store::open_in_memory().unwrap();
    store
        .append_record(&tenant_scope("clinic"), OFFICE_PROFILE_KIND, "not json")
        .unwrap();
    assert!(refusal(
        &store,
        &Method::GET,
        "/account/tenants/clinic/cloud-home",
        "org",
        None
    )
    .is_some());
}

/// The shipping client addresses a generated organization tenant with
/// `encodeURIComponent`, so the path carries `organization%3A<hex>` while the
/// router's `Path` extractor hands the handler `organization:<hex>`. The
/// refusal must look up the decoded id, or every enrolled organization's
/// hosted Home and backups stay reachable by encoding one character.
#[test]
fn an_encoded_tenant_segment_is_decoded_before_the_enrollment_lookup() {
    let tenant = "organization:5f3a9c";
    let mut store = Store::open_in_memory().unwrap();
    enroll(&mut store, tenant, "clinic-home", "operator", 1).unwrap();
    for path in [
        "/account/tenants/organization%3A5f3a9c/cloud-home",
        "/account/tenants/organization%3a5f3a9c/backups",
        "/account/tenants/%6Frganization%3A5f3a9c/backups/points",
        "/account/tenants/organization:5f3a9c/backups",
    ] {
        let request = classify(&Method::GET, path).unwrap();
        assert_eq!(
            request.tenant,
            Some(PathTenant::Named(tenant.into())),
            "{path}"
        );
        assert!(
            refusal(&store, &Method::GET, path, "org", None).is_some(),
            "{path} must be refused"
        );
    }
    // Another organization, encoded the same way, is untouched.
    assert_eq!(
        refusal(
            &store,
            &Method::GET,
            "/account/tenants/organization%3A000000/backups",
            "org",
            None
        ),
        None
    );
}

#[test]
fn a_segment_that_does_not_decode_to_utf8_refuses() {
    let store = Store::open_in_memory().unwrap();
    let path = "/account/tenants/organization%FF/backups";
    assert_eq!(
        classify(&Method::GET, path).unwrap().tenant,
        Some(PathTenant::Undecodable)
    );
    assert!(refusal(&store, &Method::GET, path, "org", None).is_some());
}

#[test]
fn malformed_escapes_stay_literal_as_the_router_leaves_them() {
    assert_eq!(decode_segment("a%2"), Some("a%2".into()));
    assert_eq!(decode_segment("a%zz%"), Some("a%zz%".into()));
    assert_eq!(decode_segment("a+b"), Some("a+b".into()));
    assert_eq!(decode_segment("%41%42"), Some("AB".into()));
}

/// A Home's own binding (`office_profile`, DR-0371) and the Hub's enrollment
/// are one record kind in one scope, so each must read the other's record.
#[test]
fn the_hub_and_a_home_read_one_binding_record() {
    let mut store = Store::open_in_memory().unwrap();
    let written = enroll(&mut store, ORG_ID, "home-1", "admin", 7).unwrap();
    let rows = store
        .records(crate::org::ORG_SCOPE, OFFICE_PROFILE_KIND)
        .unwrap();
    assert_eq!(
        crate::office_profile::fold_office_profile(rows).unwrap(),
        Some(written)
    );
    assert!(tenant_enrolled(&store, ORG_ID).unwrap());
}
