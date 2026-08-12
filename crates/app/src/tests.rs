use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};

use axum::Router;
use gaugedesk_core::instance::InstanceState;
use gaugedesk_store::Store;
use gaugedesk_workspace::Instance;

use super::*;
use crate::test_support::fake_agent_env;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use gaugedesk_core::instance::InstanceCommand;
use http_body_util::BodyExt;
use tower::ServiceExt;

#[test]
fn context_attributes_map_labels_and_fail_closed_on_unknown() {
    use gaugedesk_core::abac::{Classification, Region};
    // SECAUD-5: known labels map; region is carried.
    let a = resource_store::context_attributes(Some("pii"), Some("eu"));
    assert_eq!(a.classification, Classification::Pii);
    assert_eq!(a.region, Some(Region::new("eu")));
    assert_eq!(
        resource_store::context_attributes(Some("public"), None).classification,
        Classification::Public
    );
    assert_eq!(
        resource_store::context_attributes(Some("internal"), None).classification,
        Classification::Internal
    );
    // Unknown / typo / absent ⇒ fail-closed most-protected, never under-protect.
    assert_eq!(
        resource_store::context_attributes(Some("seekrit"), None).classification,
        Classification::Regulated
    );
    assert_eq!(
        resource_store::context_attributes(None, None).classification,
        Classification::Regulated
    );
    // Blank region is dropped (not an empty-string tag).
    assert_eq!(
        resource_store::context_attributes(Some("pii"), Some("   ")).region,
        None
    );
}

#[test]
fn authorize_resource_export_enforces_pii_classification_on_egress() {
    // SECAUD-5 / CORE-6: the live export gate denies a PII-labeled resource at an
    // unattested ceiling, lets an unlabeled (Regulated) resource through, and is
    // ungated in solo mode.
    use crate::identity::LoopbackIdentityProvider;
    use crate::library::RecordOp;
    use crate::org::{MembershipRecord, MembershipStatus, ORG_SCOPE};
    use gaugedesk_core::abac::{AuthorityAttributes, Classification, Region, ResourceAttributes};
    use gaugedesk_core::ids::AuthorityId;

    let idp = LoopbackIdentityProvider::new().enroll(
        "member-token",
        AuthorityId::new("member-auth"),
        AuthorityAttributes::default(),
    );
    let mut wb =
        Workbench::new(Store::open_in_memory().unwrap()).with_identity_provider(Arc::new(idp));
    // Provision an active member so the gate engages (past bootstrap).
    let member = MembershipRecord {
        id: "member-auth".into(),
        op: RecordOp::Upsert,
        org_id: "org".into(),
        authority: "member-auth".into(),
        email: "m@e.com".into(),
        role: "member".into(),
        status: MembershipStatus::Active,
        managed_by_scim: false,
        team: None,
    };
    wb.store_mut()
        .append_record(
            ORG_SCOPE,
            "membership",
            &serde_json::to_string(&member).unwrap(),
        )
        .unwrap();

    let pii = resource_store::mint_context_with(
        wb.store_mut(),
        "eng",
        "client",
        "pii-doc",
        "c1",
        ResourceAttributes {
            classification: Classification::Pii,
            region: Some(Region::new("eu")),
            purpose: Default::default(),
        },
    )
    .unwrap();
    let plain =
        resource_store::mint_context(wb.store_mut(), "eng", "client", "plain-doc", "c1").unwrap();

    // PII at an unattested ceiling is refused egress...
    let err = wb
        .authorize_resource_export(Some("member-token"), "eng", &pii.resource.id)
        .unwrap_err();
    assert_eq!(err.0, StatusCode::FORBIDDEN);
    // ...the unlabeled (Regulated) resource exports freely (policy constrains only PII).
    assert!(wb
        .authorize_resource_export(Some("member-token"), "eng", &plain.resource.id)
        .is_ok());

    // CORE-6: the same floor gates a resource-access *grant* — the PII resource is refused,
    // the unlabeled one is allowed.
    assert_eq!(
        wb.authorize_resource_access(Some("member-token"), "eng", &pii.resource.id)
            .unwrap_err()
            .0,
        StatusCode::FORBIDDEN,
        "PII access grant refused at an unattested ceiling",
    );
    assert!(
        wb.authorize_resource_access(Some("member-token"), "eng", &plain.resource.id)
            .is_ok(),
        "unlabeled resource access is allowed",
    );

    // Solo (no IdP) is ungated — PII included.
    let mut solo = Workbench::new(Store::open_in_memory().unwrap());
    let pii2 = resource_store::mint_context_with(
        solo.store_mut(),
        "eng",
        "client",
        "pii-doc",
        "c1",
        ResourceAttributes {
            classification: Classification::Pii,
            region: None,
            purpose: Default::default(),
        },
    )
    .unwrap();
    assert!(solo
        .authorize_resource_export(Some("member-token"), "eng", &pii2.resource.id)
        .is_ok());
    assert!(
        solo.authorize_resource_access(Some("member-token"), "eng", &pii2.resource.id)
            .is_ok(),
        "solo resource-access grant is ungated (the operator's own workspace)",
    );
}

#[test]
fn content_vault_wired_into_the_store_encrypts_transcripts_and_crypto_erases() {
    // SECAUD-9/6 end-to-end at the workbench: with the vault as the store codec,
    // transcript content round-trips (encrypted at rest), and crypto_erase_content
    // makes a chat's transcript unrecoverable while leaving another chat's intact.
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(content_vault::ContentVault::new(
        dir.path().join("ckeys"),
        Box::new(at_rest::LoopbackKeyWrap::new([3u8; 32])),
    ));
    let store = Store::open_in_memory().unwrap().with_codec(vault.clone());
    let mut wb = Workbench::new(store).with_content_vault(vault);

    wb.store_mut()
        .append_record("chat-1", "transcript", r#"{"line":"private"}"#)
        .unwrap();
    wb.store_mut()
        .append_record("chat-2", "transcript", r#"{"line":"keep"}"#)
        .unwrap();
    // Reads decrypt transparently.
    assert_eq!(
        wb.store_ref().records("chat-1", "transcript").unwrap(),
        vec![r#"{"line":"private"}"#]
    );

    // Deleting chat-1 crypto-erases its content; chat-2 is untouched (per-unit keys).
    assert!(wb.crypto_erase_content("chat-1"));
    assert!(
        wb.store_ref()
            .records("chat-1", "transcript")
            .unwrap()
            .is_empty(),
        "erased transcript is unrecoverable"
    );
    assert_eq!(
        wb.store_ref().records("chat-2", "transcript").unwrap(),
        vec![r#"{"line":"keep"}"#],
        "another chat's content is intact"
    );
}

/// ENTSEC-7: every control-plane response carries an HSTS header, so a browser that reaches
/// it over HTTPS will refuse a later plain-HTTP downgrade. Asserted on the always-open
/// `/health` route (no auth/state needed).
#[tokio::test]
async fn responses_carry_an_hsts_header() {
    let (_dir, wb) = workbench();
    let app = open_control_plane(wb);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let hsts = resp
        .headers()
        .get(axum::http::header::STRICT_TRANSPORT_SECURITY)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(hsts.contains("max-age="), "HSTS header present: {hsts:?}");
    assert!(hsts.contains("includeSubDomains"));
}

/// ADR 0065 gate: the cross-authority federation surface is PARKED off by default. A workbench
/// with no federation configured (the single-authority product shape) mounts **none** of the
/// `/federation/*` relay routes — they 404, not 503 — so the unauthenticated relay surface is
/// genuinely absent, not merely dormant.
#[tokio::test]
async fn federation_routes_are_absent_when_federation_is_off() {
    let (_dir, wb) = workbench(); // with_target → no federation attached
    let app = open_control_plane(wb);
    for path in [
        "/federation/peers",
        "/federation/handoff/incoming",
        "/federation/run/queue",
    ] {
        let resp = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "{path} must be unmounted when federation is off"
        );
    }
    // A product route (always mounted) still answers — the gate removed only federation.
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

/// RF-A4: a handler that panics while holding the workbench lock poisons
/// the mutex; `lock_unpoisoned` recovers it so the next request still
/// works, instead of every later lock panicking too.
#[test]
fn a_poisoned_lock_recovers_instead_of_cascading() {
    let m = Arc::new(Mutex::new(0_i32));
    let m2 = Arc::clone(&m);
    let _ = std::thread::spawn(move || {
        let _guard = m2.lock().unwrap();
        panic!("simulated handler panic while holding the lock");
    })
    .join();
    assert!(m.is_poisoned(), "the panic poisoned the mutex");
    *m.lock_unpoisoned() += 1;
    assert_eq!(*m.lock_unpoisoned(), 1);
}

fn workbench() -> (tempfile::TempDir, SharedWorkbench) {
    let dir = tempfile::tempdir().unwrap();
    let instance = Instance::init(dir.path().join("repo"), dir.path().join("wt")).unwrap();
    let store = Store::open_in_memory().unwrap();
    (
        dir,
        Arc::new(Mutex::new(Workbench::with_target(
            "inst-test",
            instance,
            store,
        ))),
    )
}

#[tokio::test]
async fn console_review_count_is_actor_scoped_and_contains_no_review_metadata() {
    use std::collections::BTreeSet;

    use gaugedesk_core::boundary::Authority;
    use gaugedesk_core::resource::{ContentLocator, Resource, ResourceId, ResourceRecord};

    let _fake_agent = fake_agent_env();
    let (_dir, wb) = workbench();
    let app = open_control_plane(Arc::clone(&wb));
    let (status, _) = send(&app, "POST", "/chats", Some(r#"{"id":"review-count"}"#)).await;
    assert_eq!(status, StatusCode::CREATED);

    {
        let mut workbench = wb.lock_unpoisoned();
        let output = ResourceRecord {
            resource: Resource::derived(
                ResourceId::new("out-review-count"),
                Authority::from("owner"),
                BTreeSet::new(),
            ),
            stakeholders: BTreeSet::from([Authority::from(LOCAL_AUTHORITY)]),
            locator: ContentLocator::Workspace {
                path: String::new(),
                commit: "c1".into(),
            },
            tombstoned: false,
            attributes: Default::default(),
        };
        resource_store::put(workbench.store_mut(), "review-count", &output).unwrap();
        workbench
            .admit_resource_review("review-count", &output.resource.id)
            .unwrap()
            .expect("output exists");
    }

    let (status, body) = send(&app, "GET", "/console/review-count", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, r#"{"review_count":1}"#);
    assert!(
        !body.contains("review-count"),
        "the count projection exposes no review identity"
    );
}

async fn send(app: &Router, method: &str, uri: &str, body: Option<&str>) -> (StatusCode, String) {
    static REQUEST_KEY: AtomicU64 = AtomicU64::new(1);
    let key = format!(
        "test-request-{}",
        REQUEST_KEY.fetch_add(1, Ordering::Relaxed)
    );
    send_with_key(app, method, uri, body, &key).await
}

async fn send_with_key(
    app: &Router,
    method: &str,
    uri: &str,
    body: Option<&str>,
    key: &str,
) -> (StatusCode, String) {
    let mut builder = Request::builder().method(method).uri(uri);
    if method != "GET" && method != "HEAD" && method != "OPTIONS" {
        builder = builder.header("idempotency-key", key);
    }
    let b = match body {
        Some(body) => builder
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let resp = app.clone().oneshot(b).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

async fn send_as(
    app: &Router,
    method: &str,
    uri: &str,
    body: Option<&str>,
    bearer: &str,
) -> (StatusCode, String) {
    static REQUEST_KEY: AtomicU64 = AtomicU64::new(1);
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {bearer}"));
    if method != "GET" && method != "HEAD" && method != "OPTIONS" {
        builder = builder.header(
            "idempotency-key",
            format!(
                "authenticated-test-request-{}",
                REQUEST_KEY.fetch_add(1, Ordering::Relaxed)
            ),
        );
    }
    let request = match body {
        Some(body) => builder
            .header("content-type", "application/json")
            .body(Body::from(body.to_owned()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

/// `send` for GETs, also returning the `x-workspace-cut` header — the
/// addressable base a cut-carrying save sends back (SUB-6 §12).
async fn send_with_cut(app: &Router, uri: &str) -> (StatusCode, Option<String>, String) {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let cut = resp
        .headers()
        .get("x-workspace-cut")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, cut, String::from_utf8(bytes.to_vec()).unwrap())
}

#[tokio::test]
async fn transcript_is_durable_across_a_fresh_read() {
    let _fake_agent = fake_agent_env();
    let (_d, wb) = workbench();
    let app = open_control_plane(wb);
    send(&app, "POST", "/chats", Some(r#"{"id":"t1"}"#)).await;
    send(
        &app,
        "POST",
        "/chats/t1/task",
        Some(r#"{"prompt":"do the thing"}"#),
    )
    .await;

    // a *fresh* GET (no client state) rebuilds the chat from durable records.
    let (s, body) = send(&app, "GET", "/chats/t1/transcript", None).await;
    assert_eq!(s, StatusCode::OK, "got {body}");
    assert!(
        body.contains(r#""type":"user""#) && body.contains("do the thing"),
        "user msg: {body}"
    );
    assert!(
        body.contains(r#""type":"assistant""#),
        "assistant msg: {body}"
    );
    assert!(body.contains(r#""entry_id":"#), "stable entry ids: {body}");
    assert!(
        body.contains(r#""type":"admitted""#) && body.contains("run → Completed"),
        "run: {body}"
    );
}

#[tokio::test]
async fn point_fork_rejects_an_unmapped_transcript_entry() {
    let (_d, wb) = workbench();
    let app = open_control_plane(wb);
    send(&app, "POST", "/chats", Some(r#"{"id":"point-source"}"#)).await;
    let (status, body) = send(&app, "POST", "/chats/point-source/fork/999", Some("{}")).await;
    assert_eq!(status, StatusCode::CONFLICT, "got {body}");
    assert!(body.contains("not a durable fork point"), "got {body}");
}

#[tokio::test]
async fn explicit_resource_access_request_approve_revoke_routes() {
    // CORE-3: the multi-party request → approve → grant → revoke lifecycle over HTTP.
    let (_dir, wb) = workbench();
    let app = open_control_plane(Arc::clone(&wb));
    send(&app, "POST", "/chats", Some(r#"{"id":"c1"}"#)).await;
    {
        use gaugedesk_core::boundary::Authority;
        use gaugedesk_core::resource::{
            ContentLocator, Resource, ResourceId, ResourceKind, ResourceRecord,
        };

        let resource = ResourceRecord::new(
            Resource::input(
                ResourceId::new("doc-1"),
                ResourceKind::context(),
                Authority::from(LOCAL_AUTHORITY),
            ),
            ContentLocator::Workspace {
                path: "doc-1".into(),
                commit: "seed".into(),
            },
            |_| Authority::from(LOCAL_AUTHORITY),
        );
        resource_store::put(wb.lock_unpoisoned().store_mut(), "c1", &resource).unwrap();
    }

    // The server derives the durable resource owner as the required approver.
    let (s, b) = send(
        &app,
        "POST",
        "/chats/c1/resources/doc-1/access/request",
        Some(r#"{"required":["mallory"]}"#),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "got {b}");
    assert!(
        b.contains(r#""phase":"Requested""#),
        "request → Requested: {b}"
    );

    // The read route reflects the pending request (payload not yet accessible).
    let (_, b) = send(&app, "GET", "/chats/c1/resources/doc-1/access", None).await;
    assert!(b.contains(r#""phase":"Requested""#), "read: {b}");

    // A caller-supplied identity is ignored: the local authenticated actor
    // approves as itself, satisfying the resource-derived owner requirement.
    let (s, b) = send(
        &app,
        "POST",
        "/chats/c1/resources/doc-1/access/approve",
        Some(r#"{"approver":"mallory"}"#),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "got {b}");
    assert!(b.contains(r#""phase":"Granted""#), "approve → Granted: {b}");

    // Revoke the grant (INV-18, future-only) → Revoked.
    let (s, b) = send(
        &app,
        "POST",
        "/chats/c1/resources/doc-1/access/revoke",
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "got {b}");
    assert!(b.contains(r#""phase":"Revoked""#), "revoke → Revoked: {b}");

    let (s, _) = send(
        &app,
        "POST",
        "/chats/c1/resources/missing/access/request",
        Some("{}"),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::NOT_FOUND,
        "a request cannot mint a ghost resource lifecycle"
    );
}

#[tokio::test]
async fn resource_access_approval_is_bound_to_the_authenticated_stakeholder() {
    use crate::identity::LoopbackIdentityProvider;
    use crate::org::{MembershipRecord, MembershipStatus, ORG_SCOPE};
    use gaugedesk_core::abac::AuthorityAttributes;
    use gaugedesk_core::boundary::Authority;
    use gaugedesk_core::ids::AuthorityId;
    use gaugedesk_core::resource::{
        ContentLocator, Resource, ResourceId, ResourceKind, ResourceRecord,
    };

    let (_dir, wb) = workbench();
    {
        let mut workbench = wb.lock_unpoisoned();
        for (authority, role) in [("owner-auth", "owner"), ("member-auth", "member")] {
            let member = MembershipRecord {
                id: authority.into(),
                op: crate::org::RecordOp::Upsert,
                org_id: crate::org::ORG_ID.into(),
                authority: authority.into(),
                email: String::new(),
                role: role.into(),
                status: MembershipStatus::Active,
                managed_by_scim: false,
                team: None,
            };
            workbench
                .store_mut()
                .append_record(
                    ORG_SCOPE,
                    "membership",
                    &serde_json::to_string(&member).unwrap(),
                )
                .unwrap();
        }
        let idp = LoopbackIdentityProvider::new()
            .enroll(
                "owner-token",
                AuthorityId::new("owner-auth"),
                AuthorityAttributes::default(),
            )
            .enroll(
                "member-token",
                AuthorityId::new("member-auth"),
                AuthorityAttributes::default(),
            );
        workbench.set_identity_provider(Some(Arc::new(idp)));
        assert!(
            workbench
                .create_default_engagement("consent-chat".into(), "consent chat".into())
                .is_ok(),
            "test chat is created",
        );
        let resource = ResourceRecord::new(
            Resource::input(
                ResourceId::new("owned-context"),
                ResourceKind::context(),
                Authority::from("owner-auth"),
            ),
            ContentLocator::Workspace {
                path: "owned.txt".into(),
                commit: "seed".into(),
            },
            |_| Authority::from("owner-auth"),
        );
        resource_store::put(workbench.store_mut(), "consent-chat", &resource).unwrap();
    }
    let app = open_control_plane(wb);
    let (status, body) = send_as(
        &app,
        "POST",
        "/chats/consent-chat/resources/owned-context/access/request",
        Some(r#"{"required":["member-auth"]}"#),
        "owner-token",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "request: {body}");

    let (status, body) = send_as(
        &app,
        "POST",
        "/chats/consent-chat/resources/owned-context/access/approve",
        Some(r#"{"approver":"owner-auth"}"#),
        "member-token",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "impersonation: {body}");

    let (status, body) = send_as(
        &app,
        "POST",
        "/chats/consent-chat/resources/owned-context/access/approve",
        Some(r#"{"approver":"member-auth"}"#),
        "owner-token",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "owner approval: {body}");
    assert!(body.contains(r#""phase":"Granted""#));
}

#[tokio::test]
async fn resource_review_and_export_decisions_derive_scope_and_authenticated_actor() {
    use crate::identity::LoopbackIdentityProvider;
    use crate::org::{MembershipRecord, MembershipStatus, ORG_SCOPE};
    use gaugedesk_core::abac::AuthorityAttributes;
    use gaugedesk_core::boundary::Authority;
    use gaugedesk_core::ids::AuthorityId;
    use gaugedesk_core::resource::{
        ContentLocator, Resource, ResourceId, ResourceKind, ResourceRecord,
    };

    let (_dir, wb) = workbench();
    {
        let mut workbench = wb.lock_unpoisoned();
        for (authority, role) in [("owner-auth", "owner"), ("other-auth", "admin")] {
            let member = MembershipRecord {
                id: authority.into(),
                op: crate::org::RecordOp::Upsert,
                org_id: crate::org::ORG_ID.into(),
                authority: authority.into(),
                email: String::new(),
                role: role.into(),
                status: MembershipStatus::Active,
                managed_by_scim: false,
                team: None,
            };
            workbench
                .store_mut()
                .append_record(
                    ORG_SCOPE,
                    "membership",
                    &serde_json::to_string(&member).unwrap(),
                )
                .unwrap();
        }
        workbench.set_identity_provider(Some(Arc::new(
            LoopbackIdentityProvider::new()
                .enroll(
                    "owner-token",
                    AuthorityId::new("owner-auth"),
                    AuthorityAttributes::default(),
                )
                .enroll(
                    "other-token",
                    AuthorityId::new("other-auth"),
                    AuthorityAttributes::default(),
                ),
        )));
        assert!(workbench
            .create_default_engagement("bound-chat".into(), "bound chat".into())
            .is_ok());
        let output = ResourceRecord::new(
            Resource::input(
                ResourceId::new("bound-output"),
                ResourceKind::output(),
                Authority::from("owner-auth"),
            ),
            ContentLocator::Workspace {
                path: "deliverable.txt".into(),
                commit: "seed".into(),
            },
            |_| Authority::from("owner-auth"),
        );
        resource_store::put(workbench.store_mut(), "bound-chat", &output).unwrap();
    }
    let app = open_control_plane(wb);

    for path in ["review", "export"] {
        let (status, response) = send_as(
            &app,
            "POST",
            &format!("/chats/bound-chat/resources/bound-output/{path}"),
            None,
            "owner-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{path} proposal: {response}");
    }

    for action in ["consent", "reject", "revoke", "release"] {
        let (status, response) = send_as(
            &app,
            "POST",
            "/chats/bound-chat/resources/bound-output/review/command",
            Some(&format!(r#"{{"action":"{action}"}}"#)),
            "other-token",
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "non-stakeholder review {action}: {response}"
        );
    }
    let (_, review) = send_as(
        &app,
        "GET",
        "/chats/bound-chat/resources/bound-output/review",
        None,
        "owner-token",
    )
    .await;
    assert!(
        review.contains(r#""phase":"Proposed""#),
        "review unchanged: {review}"
    );

    for action in ["consent", "reject", "revoke"] {
        let (status, response) = send_as(
            &app,
            "POST",
            "/chats/bound-chat/resources/bound-output/export/command",
            Some(&format!(r#"{{"action":"{action}"}}"#)),
            "other-token",
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "non-stakeholder export {action}: {response}"
        );
    }
    let (_, export) = send_as(
        &app,
        "GET",
        "/chats/bound-chat/resources/bound-output/export",
        None,
        "owner-token",
    )
    .await;
    assert!(
        export.contains(r#""phase":"Requested""#),
        "export unchanged: {export}"
    );

    let (status, review) = send_as(
        &app,
        "POST",
        "/chats/bound-chat/resources/bound-output/review/command",
        Some(r#"{"action":"consent"}"#),
        "owner-token",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "owner review consent: {review}");
    assert!(review.contains(r#""phase":"Cleared""#));

    let (status, export) = send_as(
        &app,
        "POST",
        "/chats/bound-chat/resources/bound-output/export/command",
        Some(r#"{"action":"consent"}"#),
        "owner-token",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "owner export consent: {export}");
    assert!(export.contains(r#""source_consented":["owner-auth"]"#));

    let (status, _) = send_as(
        &app,
        "POST",
        "/chats/bound-chat/resources/bound-output/review/command",
        Some(r#"{"action":"release","authority":"owner-auth"}"#),
        "owner-token",
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    for path in [
        "/scopes/bound-review/review/command",
        "/scopes/bound-export/export/command",
    ] {
        let (status, _) = send_as(
            &app,
            "POST",
            path,
            Some(r#"{"action":"consent"}"#),
            "owner-token",
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "raw route retired: {path}");
    }
    for path in ["/scopes/bound-review/review", "/scopes/bound-export/export"] {
        let (status, _) = send_as(&app, "GET", path, None, "owner-token").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "raw route retired: {path}");
    }
}

#[tokio::test]
async fn opening_a_folder_mints_a_granted_context_resource() {
    let (dir, wb) = workbench();
    let app = open_control_plane(wb);
    send(&app, "POST", "/chats", Some(r#"{"id":"c1"}"#)).await;

    // a real folder to open as context
    let src = dir.path().join("docs");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("notes.txt"), "secret-bytes").unwrap();
    let body = serde_json::json!({ "path": src.to_str().unwrap() }).to_string();
    let (s, b) = send(&app, "POST", "/chats/c1/context", Some(&body)).await;
    assert_eq!(s, StatusCode::OK, "got {b}");
    assert!(
        b.contains(r#""resource":"ctx-"#),
        "returns the minted handle: {b}"
    );

    // a fresh GET (no client state) rebuilds the resources projection from the
    // store: a granted `context` handle owned by the local authority…
    let (s, b) = send(&app, "GET", "/chats/c1/resources", None).await;
    assert_eq!(s, StatusCode::OK, "got {b}");
    assert!(b.contains(r#""kind":"context""#), "context kind: {b}");
    assert!(
        b.contains(r#""access":"Granted""#),
        "auto-granted (trust-by-default): {b}"
    );
    assert!(b.contains(r#""owner":"local-user""#), "local owner: {b}");
    assert!(b.contains(r#""tombstoned":false"#), "not tombstoned: {b}");
    // …rendering metadata only — the payload bytes never enter the projection (INV-10).
    assert!(
        !b.contains("secret-bytes"),
        "payload not in the projection: {b}"
    );
}

#[tokio::test]
async fn content_resolves_through_a_granted_handle_then_tombstone_blocks_it() {
    let (dir, wb) = workbench();
    let app = open_control_plane(wb);
    send(&app, "POST", "/chats", Some(r#"{"id":"c2"}"#)).await;

    let src = dir.path().join("docs");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("notes.txt"), "secret-bytes").unwrap();
    let body = serde_json::json!({ "path": src.to_str().unwrap() }).to_string();
    send(&app, "POST", "/chats/c2/context", Some(&body)).await;
    let rid = resource_store::context_id(src.to_str().unwrap());
    let rid = rid.as_str();

    // the manifest resolves through the granted handle…
    let (s, b) = send(
        &app,
        "GET",
        &format!("/chats/c2/resources/{rid}/content"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "manifest resolves: {b}");
    assert!(
        b.contains("notes.txt"),
        "manifest lists the ingested file: {b}"
    );
    // …and so do the file's bytes.
    let (s, b) = send(
        &app,
        "GET",
        &format!("/chats/c2/resources/{rid}/content?path=notes.txt"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        b, "secret-bytes",
        "payload bytes resolve for a granted handle"
    );

    // tombstone the payload → future resolution is GONE (INV-18)…
    let (s, _) = send(
        &app,
        "POST",
        &format!("/chats/c2/resources/{rid}/tombstone"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = send(
        &app,
        "GET",
        &format!("/chats/c2/resources/{rid}/content?path=notes.txt"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::GONE, "tombstoned payload no longer resolves");
    // …while the handle/record survive in the projection, marked tombstoned (INV-6).
    let (_, b) = send(&app, "GET", "/chats/c2/resources", None).await;
    assert!(
        b.contains(r#""tombstoned":true"#),
        "handle/record remain: {b}"
    );
}

#[tokio::test]
async fn export_source_required_is_derived_from_the_resource_stakeholders() {
    let _fake_agent = fake_agent_env();
    let (dir, wb) = workbench();
    let app = open_control_plane(wb);
    send(&app, "POST", "/chats", Some(r#"{"id":"x1"}"#)).await;

    // open a context folder (owner = local authority), then run a turn: the
    // engine mints the derived output resource, tainted by the granted context.
    let src = dir.path().join("docs");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("notes.txt"), "data").unwrap();
    let body = serde_json::json!({ "path": src.to_str().unwrap() }).to_string();
    send(&app, "POST", "/chats/x1/context", Some(&body)).await;
    send(&app, "POST", "/chats/x1/task", Some(r#"{"prompt":"go"}"#)).await;

    let out = resource_store::output_id("x1");
    let out = out.as_str();
    let (_, b) = send(&app, "GET", "/chats/x1/resources", None).await;
    assert!(
        b.contains(out) && b.contains(r#""kind":"output""#),
        "output resource minted: {b}"
    );

    // propose export — source_required comes from the RESOURCE, not the caller.
    let (s, b) = send(
        &app,
        "POST",
        &format!("/chats/x1/resources/{out}/export"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "got {b}");
    assert!(b.contains(r#""phase":"Requested""#), "export proposed: {b}");
    assert!(
        b.contains("local-user"),
        "source_required derived from the resource owner: {b}"
    );

    // The resource stakeholder may consent only through the resource-bound
    // route. Target admission and the final crossing are not caller commands.
    let uri = format!("/chats/x1/resources/{out}/export/command");
    let (s, b) = send(&app, "POST", &uri, Some(r#"{"action":"consent"}"#)).await;
    assert_eq!(s, StatusCode::OK, "got {b}");
    assert!(
        b.contains(r#""phase":"Requested""#)
            && b.contains(r#""source_consented":["local-user"]"#)
            && b.contains(r#""target_admitted":false"#),
        "source consent still waits for a real target: {b}"
    );
}

/// RF-A9: export-to-disk supplies target admission, writes the resolved bytes,
/// and only then records the lifecycle as `Exported`.
#[tokio::test]
async fn export_to_disk_is_gated_then_writes_bytes_and_records_egress() {
    let _fake_agent = fake_agent_env();
    let (dir, wb) = workbench();
    let app = open_control_plane(wb);
    send(&app, "POST", "/chats", Some(r#"{"id":"d1"}"#)).await;
    // A turn produces the engagement's output (the fake agent writes a note).
    send(&app, "POST", "/chats/d1/task", Some(r#"{"prompt":"go"}"#)).await;

    let out = resource_store::output_id("d1");
    let out = out.as_str();
    let dest = dir.path().join("delivered");
    std::fs::create_dir_all(&dest).unwrap();
    let dest_body = serde_json::json!({ "dest": dest.to_str().unwrap() }).to_string();

    // Before the export lifecycle clears, export-to-disk fails closed.
    let (s, b) = send(
        &app,
        "POST",
        &format!("/chats/d1/resources/{out}/export-to-disk"),
        Some(&dest_body),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::CONFLICT,
        "must fail closed before Exported: {b}"
    );
    assert!(
        std::fs::read_dir(&dest).unwrap().next().is_none(),
        "nothing leaves before the export is cleared"
    );

    // Propose the export. This fixture has no source stakeholders, so the real
    // directory selection may supply target admission and perform the crossing.
    send(
        &app,
        "POST",
        &format!("/chats/d1/resources/{out}/export"),
        None,
    )
    .await;
    // The egress handler admits the target, writes, and records the crossing.
    let (s, b) = send(
        &app,
        "POST",
        &format!("/chats/d1/resources/{out}/export-to-disk"),
        Some(&dest_body),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "exports once cleared: {b}");
    assert!(
        b.contains("agent-note.txt"),
        "the deliverable file is reported: {b}"
    );
    assert!(
        dest.join("agent-note.txt").exists(),
        "the bytes actually landed on disk"
    );
    let (_, state) = send(
        &app,
        "GET",
        &format!("/chats/d1/resources/{out}/export"),
        None,
    )
    .await;
    assert!(
        state.contains(r#""phase":"Exported""#) && state.contains(r#""target_admitted":true"#),
        "the lifecycle records the real crossing: {state}"
    );
}

#[tokio::test]
async fn review_required_is_derived_from_the_resource_stakeholders() {
    let _fake_agent = fake_agent_env();
    let (dir, wb) = workbench();
    let app = open_control_plane(wb);
    send(&app, "POST", "/chats", Some(r#"{"id":"r2"}"#)).await;

    let src = dir.path().join("docs");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("notes.txt"), "data").unwrap();
    let body = serde_json::json!({ "path": src.to_str().unwrap() }).to_string();
    send(&app, "POST", "/chats/r2/context", Some(&body)).await;
    send(&app, "POST", "/chats/r2/task", Some(r#"{"prompt":"go"}"#)).await;
    let out = resource_store::output_id("r2");
    let out = out.as_str();

    // propose review — `required` comes from the resource, not the caller.
    let (s, b) = send(
        &app,
        "POST",
        &format!("/chats/r2/resources/{out}/review"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "got {b}");
    assert!(b.contains(r#""phase":"Proposed""#), "review proposed: {b}");
    assert!(
        b.contains("local-user"),
        "required derived from the resource stakeholder: {b}"
    );

    // The body carries no authority or scope; the request actor is materialized.
    let uri = format!("/chats/r2/resources/{out}/review/command");
    let (_, b) = send(&app, "POST", &uri, Some(r#"{"action":"consent"}"#)).await;
    assert!(
        b.contains(r#""phase":"Cleared""#),
        "clears once the stakeholder consents: {b}"
    );
    let (_, b) = send(&app, "POST", &uri, Some(r#"{"action":"release"}"#)).await;
    assert!(b.contains(r#""phase":"Released""#), "released: {b}");
}

#[tokio::test]
async fn unconsumed_package_http_facades_are_absent() {
    let (_d, wb) = workbench();
    let app = open_control_plane(wb);

    // Package construction, distribution, entitlement, and readiness remain
    // package-owned reducer/store operations. No production client consumed
    // these local HTTP facades, so exposing them made backend-only API BDD look
    // like product wiring. Keep every former method/path explicitly absent.
    for (method, path) in [
        ("GET", "/packages"),
        ("POST", "/packages"),
        ("POST", "/packages/p1/entitle?context=ctx"),
        ("POST", "/packages/p1/install"),
        ("GET", "/packages/p1/readiness?context=ctx"),
        ("POST", "/packages/p1/withdraw"),
    ] {
        let (status, body) = send(&app, method, path, None).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "retired {method} {path}: {body}"
        );
    }
}

#[tokio::test]
async fn merge_lifecycle_advances_then_integrates_to_mainline() {
    let _fake_agent = fake_agent_env();
    let (_d, wb) = workbench();
    let app = open_control_plane(wb);

    send(&app, "POST", "/chats", Some(r#"{"id":"m1"}"#)).await;
    // A clean turn settles itself — there is no hold to admit past (ADR 0136).
    let (s, body) = send(&app, "POST", "/chats/m1/task", Some(r#"{"prompt":"go"}"#)).await;
    assert_eq!(s, StatusCode::OK, "got {body}");

    let (_, body) = send(&app, "GET", "/chats/m1/merge", None).await;
    assert!(body.contains("\"phase\":\"Advanced\""), "got {body}");

    // WS-1: integrate the advanced workstream into the shared mainline. The hop
    // admits the boundary command then integrates — MAINLINE_INTEGRATION_REQUIRES_
    // BOUNDARY, driven live (the reducer proptest verifies the gate).
    let (s, body) = send(
        &app,
        "POST",
        "/chats/m1/merge/command",
        Some(r#"{"action":"integrate"}"#),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "got {body}");
    assert!(body.contains("\"phase\":\"Integrated\""), "got {body}");
}

#[tokio::test]
async fn revert_discards_chat_work() {
    let _fake_agent = fake_agent_env();
    let (_d, wb) = workbench();
    let app = open_control_plane(wb);

    send(&app, "POST", "/chats", Some(r#"{"id":"rv1"}"#)).await;
    // a fake turn leaves work awaiting review (Clean).
    let (s, body) = send(
        &app,
        "POST",
        "/chats/rv1/task",
        Some(r#"{"prompt":"go","review":true}"#),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "got {body}");
    assert!(body.contains("\"merge_phase\":\"Clean\""), "got {body}");

    // revert (UX-5) discards it.
    let (s, body) = send(&app, "POST", "/chats/rv1/revert", None).await;
    assert_eq!(s, StatusCode::OK, "got {body}");
    assert!(body.contains("\"reverted\":true"), "got {body}");

    // an unknown chat fails closed (404).
    let (s, _) = send(&app, "POST", "/chats/nope/revert", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn end_to_end_run_command_flow() {
    let (_d, wb) = workbench();
    let app = open_control_plane(wb);

    for cmd in ["\"RequestRun\"", "\"AdmitRun\"", "\"StartRun\""] {
        let (s, _) = send(&app, "POST", "/scopes/run-1/run/command", Some(cmd)).await;
        assert_eq!(s, StatusCode::OK);
    }
    let (s, body) = send(&app, "GET", "/scopes/run-1/run", None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains("Running"), "got {body}");

    // INV-11: start without admission is rejected (409), no fact appended.
    let (_, _) = send(
        &app,
        "POST",
        "/scopes/run-2/run/command",
        Some("\"RequestRun\""),
    )
    .await;
    let (s, body) = send(
        &app,
        "POST",
        "/scopes/run-2/run/command",
        Some("\"StartRun\""),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert!(body.contains("rejected"), "got {body}");
    let (_, body) = send(&app, "GET", "/scopes/run-2/run", None).await;
    assert!(body.contains("Requested"), "got {body}");
}

/// MOB-012: the projection shim wraps the folded value in a `ProjectionCarriage`
/// (mirrors `web/src/api/projection-carriage.ts`) — a default read is `live`,
/// a declared non-live read carries its caveat + a repair hint, and an unknown
/// kind is a 404. The basis grows as truth is admitted (the append-only clock).
#[tokio::test]
async fn fork_tree_route_returns_a_forest() {
    // UX-8: the fork-forest projection is reachable (and the router builds — no route
    // conflict with /chats/*).
    let (_d, wb) = workbench();
    let app = open_control_plane(wb);
    let (s, body) = send(&app, "GET", "/fork-tree", None).await;
    assert_eq!(s, StatusCode::OK, "got {body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(v["forest"].is_array(), "forest is an array: {body}");
}

#[tokio::test]
async fn merge_projection_has_freshness_carriage() {
    // UX-13: the `merge` kind now has a carriage read like run/review/export/boundary.
    let (_d, wb) = workbench();
    let app = open_control_plane(wb);
    let (s, body) = send(&app, "GET", "/projections/m-9/merge", None).await;
    assert_eq!(s, StatusCode::OK, "got {body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["freshness"]["marker"], "live", "got {body}");
    assert!(
        v["value"].is_object(),
        "value is the folded merge projection: {body}"
    );
    // an unknown kind still fails closed with a 404.
    let (s, _) = send(&app, "GET", "/projections/m-9/bogus", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn health_probe_is_a_fixed_ok() {
    // The readiness probe the SERVE-2 sandbox warm-check (and any host) polls: a 200
    // once the control plane is serving, no store access. It reports migrations
    // current (getHealth, local-api-contract.md) — honest without a store read
    // because Store::open applies every pending migration before the router
    // serves and fails closed on a newer schema (DR-0054 Phase B/C).
    let (_d, wb) = workbench();
    let app = open_control_plane(wb);
    let (s, body) = send(&app, "GET", "/health", None).await;
    assert_eq!(s, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["migrations"], "current");
    assert_eq!(
        v["schema_version"],
        gaugedesk_store::SUPPORTED_SCHEMA_VERSION
    );
}

#[tokio::test]
async fn project_home_rolls_up_runs_outputs_and_audit() {
    // UX-2: the project-home rollup aggregates the project's work chats' run/merge/audit
    // state from data (INV-5), across all its placements; 404 on an unknown project.
    use library::{Admission, ChatRecord, InstanceKind, InstanceRecord, ProjectRecord, RecordOp};
    let (_d, wb) = workbench();
    {
        let mut g = wb.lock_unpoisoned();
        g.write_project_record(ProjectRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: "proj-1".into(),
            op: RecordOp::Upsert,
            name: "Acme".into(),
            is_default: false,
            home_id: gaugedesk_core::ids::HomeId::new("home:local-user"),
            network_isolated: false,
            run_purpose: None,
            deployment_mode: None,
        });
        g.write_instance_record(InstanceRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: "inst-1".into(),
            op: RecordOp::Upsert,
            kind: InstanceKind::Using,
            agent_id: "a1".into(),
            project_id: Some("proj-1".into()),
            version: 1,
            admission: Admission::Active,
        });
        g.write_chat_record(ChatRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: "chat-1".into(),
            op: RecordOp::Upsert,
            instance_id: "inst-1".into(),
            title: "Build the landing page".into(),
            created_position: 1,
            forked_from: None,
            forked_from_entry: None,
        });
    }
    let app = open_control_plane(wb);

    let (s, body) = send(&app, "GET", "/projects/proj-1/home", None).await;
    assert_eq!(s, StatusCode::OK, "got {body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["project_id"], "proj-1");
    assert_eq!(v["audit"]["placements"], 1);
    assert_eq!(v["audit"]["chats"], 1);
    // The work chat appears in recent_runs, derived from its (fresh) RunState — never run.
    let runs = v["recent_runs"].as_array().unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0]["chat"], "chat-1");
    assert_eq!(runs[0]["title"], "Build the landing page");
    assert_eq!(runs[0]["ran"], false);
    // No live merge ⇒ no output/review summary yet.
    assert!(v["outputs"].as_array().unwrap().is_empty());

    // Fail-closed on an unknown project.
    let (s, _) = send(&app, "GET", "/projects/nope/home", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn projection_shim_wraps_every_read_in_a_freshness_carriage() {
    let (_d, wb) = workbench();
    let app = open_control_plane(wb);

    // Nothing admitted yet: a live carriage over an empty run projection, basis 0.
    let (s, body) = send(&app, "GET", "/projections/run-9/run", None).await;
    assert_eq!(s, StatusCode::OK, "got {body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        v["freshness"]["marker"], "live",
        "default read is live: {body}"
    );
    assert_eq!(
        v["freshness"]["generated_at"], 0,
        "empty scope basis is 0: {body}"
    );
    assert!(
        v["freshness"]["repair_hint"].is_null(),
        "live carries no hint: {body}"
    );
    assert!(v["client_request_id"].is_null(), "no reconcile id: {body}");
    assert!(
        v["value"].is_object(),
        "value is the folded projection: {body}"
    );

    // Admit some run truth — the basis (last admitted position) advances.
    for cmd in ["\"RequestRun\"", "\"AdmitRun\"", "\"StartRun\""] {
        let (s, _) = send(&app, "POST", "/scopes/run-9/run/command", Some(cmd)).await;
        assert_eq!(s, StatusCode::OK);
    }
    let (_, body) = send(&app, "GET", "/projections/run-9/run", None).await;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(body.contains("Running"), "wraps the live run state: {body}");
    assert!(
        v["freshness"]["generated_at"].as_u64().unwrap() > 0,
        "basis advanced as truth was admitted: {body}"
    );

    // A declared non-live read keeps its caveat + a repair hint (never silently live).
    let (s, body) = send(&app, "GET", "/projections/run-9/run?freshness=stale", None).await;
    assert_eq!(s, StatusCode::OK, "got {body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        v["freshness"]["marker"], "stale",
        "honours the declared marker: {body}"
    );
    assert!(
        v["freshness"]["repair_hint"].is_string(),
        "stale carries a repair hint: {body}"
    );

    // An unknown marker is a client error, not a silent fallback to live.
    let (s, _) = send(&app, "GET", "/projections/run-9/run?freshness=bogus", None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "unknown marker rejected");

    // An unknown kind is a 404, not an empty carriage.
    let (s, _) = send(&app, "GET", "/projections/run-9/nope", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "unknown kind is 404");

    // The shim projects the other admission-spine kinds too (e.g. boundary).
    let (s, body) = send(&app, "GET", "/projections/run-9/boundary", None).await;
    assert_eq!(s, StatusCode::OK, "got {body}");
    assert!(
        body.contains("ceiling"),
        "boundary carriage carries its ceiling: {body}"
    );

    // The duplicate chat-shaped boundary projection had no production client.
    // Boundary consumers use the canonical freshness carriage or pairing status.
    let (s, _) = send(&app, "GET", "/chats/run-9/boundary", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "retired boundary read is absent");
}

#[tokio::test]
async fn engagement_lifecycle_over_http() {
    let (_d, wb) = workbench();
    let app = open_control_plane(wb);

    let (s, body) = send(&app, "POST", "/chats", Some(r#"{"id":"e1"}"#)).await;
    assert_eq!(s, StatusCode::CREATED, "got {body}");
    assert!(body.contains("engagement/e1"), "branch in response: {body}");

    // duplicate id is a conflict
    let (s, _) = send(&app, "POST", "/chats", Some(r#"{"id":"e1"}"#)).await;
    assert_eq!(s, StatusCode::CONFLICT);

    let (s, body) = send(&app, "GET", "/chats", None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains("e1"));

    // a fresh engagement has an empty diff against main
    let (s, body) = send(&app, "GET", "/chats/e1/diff", None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(body.contains("\"diff\""), "got {body}");
}

#[tokio::test]
async fn agent_authoring_config_round_trips_and_rejects_garbage() {
    let (_d, wb) = workbench();
    let app = open_control_plane(wb);
    send(&app, "POST", "/chats", Some(r#"{"id":"a1"}"#)).await;

    // empty config initially
    let (s, body) = send(&app, "GET", "/chats/a1/config", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body.trim(), "{}");

    // valid config is parsed-then-persisted
    let cfg = r#"{"provider":"openai-codex","model":"gpt-5.5","thinking":"high"}"#;
    let (s, _) = send(&app, "PUT", "/chats/a1/config", Some(cfg)).await;
    assert_eq!(s, StatusCode::OK);
    let (_, body) = send(&app, "GET", "/chats/a1/config", None).await;
    assert!(body.contains("openai-codex"), "got {body}");

    // Package capabilities cannot be smuggled back into host runtime settings.
    let (s, body) = send(
        &app,
        "PUT",
        "/chats/a1/config",
        Some(r#"{"policy":{"block_tools":["bash"]}}"#),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(body.contains("package-owned"), "got {body}");

    // malformed config is rejected at the boundary, not written
    let (s, _) = send(&app, "PUT", "/chats/a1/config", Some("{ not json")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn lifecycle_commands_materialize_caller_keys_and_replay_at_most_once() {
    let (_d, wb) = workbench();
    let inspect = Arc::clone(&wb);
    let app = open_control_plane(wb);
    let uri = "/scopes/idempotent-run/run/command";

    // A command endpoint never invents identity for an unkeyed caller.
    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(r#""RequestRun""#))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // The first keyed call applies; an identical replay returns the current fold
    // without appending the lifecycle event a second time.
    let (status, first) = send_with_key(
        &app,
        "POST",
        uri,
        Some(r#""RequestRun""#),
        "stable-run-command",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {first}");
    let (status, replay) = send_with_key(
        &app,
        "POST",
        uri,
        Some(r#""RequestRun""#),
        "stable-run-command",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {replay}");
    assert_eq!(first, replay);

    {
        let guard = inspect.lock_unpoisoned();
        let run_events = guard
            .store_ref()
            .events("idempotent-run")
            .unwrap()
            .into_iter()
            .filter(|(_, kind, _)| kind == "run")
            .count();
        assert_eq!(run_events, 1, "the caller key admits at most once");
        let command = guard
            .store_ref()
            .command_for_key("idempotent-run", "stable-run-command")
            .unwrap()
            .expect("materialized command row");
        assert_eq!(command.status, "applied");
        assert!(command.snapshot_json.contains("RequestRun"));
    }

    // Reusing the key for a different body cannot replace that first snapshot.
    let (status, body) = send_with_key(
        &app,
        "POST",
        uri,
        Some(r#""AdmitRun""#),
        "stable-run-command",
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "got {body}");
    assert!(body.contains("idempotency key reused"), "got {body}");
}

#[tokio::test]
async fn every_mutating_route_is_guarded_without_storing_request_secrets() {
    use sha2::{Digest, Sha256};

    let (_d, wb) = workbench();
    let inspect = Arc::clone(&wb);
    let app = open_control_plane(wb);
    let key = "stable-create-chat";
    let body = r#"{"id":"idempotent-chat"}"#;

    let (status, first) = send_with_key(&app, "POST", "/chats", Some(body), key).await;
    assert_eq!(status, StatusCode::CREATED, "got {first}");
    let (status, replay) = send_with_key(&app, "POST", "/chats", Some(body), key).await;
    assert_eq!(status, StatusCode::CONFLICT, "got {replay}");
    assert!(replay.contains("command already applied"), "got {replay}");

    // Same key, widened input is distinctly refused and never replaces the hash
    // snapshot of the first user intent.
    let (status, mismatch) = send_with_key(
        &app,
        "POST",
        "/chats",
        Some(r#"{"id":"different-chat"}"#),
        key,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "got {mismatch}");
    assert!(mismatch.contains("key-reused-with-different-input"));

    let (_, listed) = send(&app, "GET", "/chats", None).await;
    assert_eq!(listed.matches("idempotent-chat").count(), 1);
    assert!(!listed.contains("different-chat"));

    let caller_hash: String = Sha256::digest(b"\n\n")
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let scope = format!("http-command:POST:/chats:{caller_hash}");
    let receipt = inspect
        .lock_unpoisoned()
        .store_ref()
        .command_for_key(&scope, key)
        .unwrap()
        .expect("outer command receipt");
    assert_eq!(receipt.status, "applied");
    assert!(receipt.snapshot_json.contains("body_sha256"));
    assert!(
        !receipt.snapshot_json.contains("idempotent-chat"),
        "the command row stores a digest, not caller payload"
    );
}

/// A workbench seeded like the live server (builder agent + authoring instance)
/// so the library routes have an instance to work against.
fn seeded_workbench() -> (tempfile::TempDir, SharedWorkbench) {
    let dir = tempfile::tempdir().unwrap();
    let wb = open_workbench(dir.path()).unwrap();
    (dir, wb)
}

#[test]
fn startup_persists_the_agent_ability_hard_cutover_and_reconciles_frozen_refs() {
    let (dir, wb) = seeded_workbench();
    let original_ref = {
        let guard = wb.lock_unpoisoned();
        let original_ref = guard.library.agents[DEFAULT_AGENT].versions[&1]
            .package_ref
            .clone();
        let target_id = library_state::authoring_target_id(DEFAULT_AGENT);
        let workspace = guard.targets.get(&target_id).unwrap();
        let engagement_id = library::gen_id("legacy-abilities");
        let edit = workspace.create_engagement(&engagement_id).unwrap();
        for package_root in [".whipple/draft", ".whipple/versions/1"] {
            let manifest_path = format!("{package_root}/package.json");
            let mut manifest: serde_json::Value =
                serde_json::from_str(&edit.read_file(&manifest_path).unwrap()).unwrap();
            manifest.as_object_mut().unwrap().remove("agent_abilities");
            manifest["capabilities"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!("human.ask"));
            edit.write_file(
                &manifest_path,
                &format!("{}\n", serde_json::to_string_pretty(&manifest).unwrap()),
            )
            .unwrap();

            let source_path = format!("{package_root}/method.whip");
            let source = edit
                .read_file(&source_path)
                .unwrap()
                .replace(
                    "\"command.run\"]",
                    "\"command.run\", \"human.ask\"]",
                )
                .replace(
                    "\n      \"Run the selected GaugeDesk method.\"",
                    "\n      with access to human {\n        ask\n      }\n      \"Run the selected GaugeDesk method.\"",
                );
            edit.write_file(&source_path, &source).unwrap();
        }
        for discipline_root in [
            ".whipple/discipline/draft",
            ".whipple/discipline/versions/1",
        ] {
            let path = format!("{discipline_root}/discipline.json");
            let mut manifest: serde_json::Value =
                serde_json::from_str(&edit.read_file(&path).unwrap()).unwrap();
            manifest["capabilities"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!("human.ask"));
            edit.write_file(
                &path,
                &format!("{}\n", serde_json::to_string_pretty(&manifest).unwrap()),
            )
            .unwrap();
        }
        edit.commit_turn("restore pre-ABIL package shape").unwrap();
        assert_eq!(
            edit.merge_into_main().unwrap(),
            gaugedesk_workspace::MergeOutcome::Clean
        );
        workspace.remove_engagement(&engagement_id).unwrap();
        original_ref
    };
    drop(wb);

    let migrated = open_workbench(dir.path()).expect("legacy package migrates once");
    let migrated_ref = {
        let guard = migrated.lock_unpoisoned();
        assert_eq!(
            guard.archetype_abilities(DEFAULT_AGENT).unwrap(),
            vec![
                "workspace.read".to_owned(),
                "workspace.write".to_owned(),
                "command.run".to_owned(),
            ]
        );
        let target_id = library_state::authoring_target_id(DEFAULT_AGENT);
        let workspace = guard.targets.get(&target_id).unwrap();
        let engagement_id = library::gen_id("verify-abilities");
        let read = workspace.create_engagement(&engagement_id).unwrap();
        for root in [".whipple/draft", ".whipple/versions/1"] {
            assert!(!read
                .read_file(&format!("{root}/method.whip"))
                .unwrap()
                .contains("human.ask"));
        }
        workspace.remove_engagement(&engagement_id).unwrap();
        guard.library.agents[DEFAULT_AGENT].versions[&1]
            .package_ref
            .clone()
    };
    assert_ne!(migrated_ref, original_ref);
    drop(migrated);

    let reopened = open_workbench(dir.path()).expect("migrated package remains strict");
    assert_eq!(
        reopened.lock_unpoisoned().library.agents[DEFAULT_AGENT].versions[&1].package_ref,
        migrated_ref
    );
}

#[test]
fn placement_project_lookup_returns_only_the_exact_using_binding() {
    let (_dir, wb) = seeded_workbench();
    let guard = wb.lock_unpoisoned();
    assert_eq!(
        guard.placement_project_id(DEFAULT_PLACEMENT),
        Some(DEFAULT_PROJECT)
    );
    assert_eq!(guard.placement_project_id(DEFAULT_INSTANCE), None);
    assert_eq!(guard.placement_project_id("missing-placement"), None);
}

#[test]
fn published_agent_release_contains_the_runtime_closure_and_verifies_offline() {
    use std::collections::BTreeSet;

    use gaugedesk_core::agent_release::{
        AttributionPolicy, PanelManifest, ProviderPolicy, PublicDoRuntimeSupport, ReleaseFile,
        RetentionPolicy,
    };

    let (_dir, wb) = seeded_workbench();
    let signed = wb
        .lock_unpoisoned()
        .build_agent_release(
            DEFAULT_PLACEMENT,
            crate::agent_release::ReleasePublishSpec {
                published_at_unix_ms: 1_800_000_000_000,
                panels: PanelManifest {
                    components: BTreeSet::from(["gw-chat".to_owned(), "gw-viewer".to_owned()]),
                    default_component: "gw-chat".to_owned(),
                    attribution: AttributionPolicy::GaugeWright,
                },
                provider: ProviderPolicy {
                    provider: "openai".to_owned(),
                    model: "gpt-5.1".to_owned(),
                    base_url: "https://api.openai.com".to_owned(),
                    credential_class: "managed-openai".to_owned(),
                    max_input_tokens: None,
                    max_output_tokens: None,
                },
                retention: RetentionPolicy {
                    idle_ttl_seconds: 86_400,
                    absolute_ttl_seconds: 2_592_000,
                    transcript_retained: true,
                    workspace_retained: true,
                },
                initial_workspace: vec![ReleaseFile::new(
                    "workspace/brief.md",
                    "text/markdown",
                    b"Published session brief".to_vec(),
                )],
                collection: None,
            },
        )
        .unwrap();

    drop(wb);
    assert_eq!(
        signed.verify(&PublicDoRuntimeSupport {
            host_protocol: crate::agent_release::PUBLIC_SESSION_HOST_PROTOCOL.to_owned(),
            runtime_abi: crate::agent_release::WHIPPLESCRIPT_DO_RUNTIME_ABI.to_owned(),
            host_capabilities: BTreeSet::from([
                crate::agent_release::DIRECT_PROVIDER_STREAM.to_owned(),
                crate::agent_release::HIBERNATABLE_WEBSOCKET.to_owned(),
            ]),
            providers: BTreeSet::from(["openai".to_owned()]),
            panel_components: BTreeSet::from([
                "gw-chat".to_owned(),
                "gw-viewer".to_owned(),
                "gw-files".to_owned(),
            ]),
        }),
        Ok(())
    );
    assert!(signed
        .payload
        .package
        .files
        .iter()
        .any(|file| file.path == "package/package.json"));
    assert!(signed
        .payload
        .persona
        .instructions
        .iter()
        .any(|file| file.path == "discipline/discipline.json"));
    assert_eq!(
        signed.payload.initial_workspace[0].bytes,
        b"Published session brief"
    );
    let admitted = gaugedesk_whip_runtime::AdmittedPolicyEpoch::verify_with(
        gaugedesk_whip_runtime::PolicyEpoch::new(signed.payload.host_policy.epoch).unwrap(),
        &signed.payload.host_policy.signed_envelope,
        &gaugedesk_whip_runtime::GovernanceRootVerifier::new(
            gaugedesk_core::ids::AuthorityId::new(
                signed.payload.host_policy.expected_signer.clone(),
            ),
            gaugedesk_core::ids::PublicKey::new(
                signed.payload.host_policy.signer_public_key_hex.clone(),
            ),
        ),
    )
    .unwrap();
    assert_eq!(
        admitted.signer(),
        signed.payload.host_policy.expected_signer
    );
}

/// Seed the org's archetype-approval policy (`APPROVE-1`, ADR 0064) — the record the
/// ee Admin Console writes — directly into the org scope before the control plane opens.
fn seed_require_archetype_approval(wb: &SharedWorkbench) {
    use crate::org::{ArchetypeApprovalPolicyRecord, ORG_SCOPE};
    let mut guard = wb.lock_unpoisoned();
    let rec = ArchetypeApprovalPolicyRecord {
        id: String::new(),
        op: crate::library::RecordOp::Upsert,
        require_approval: true,
    };
    guard
        .store_mut()
        .append_record(
            ORG_SCOPE,
            "archetype_approval",
            &serde_json::to_string(&rec).unwrap(),
        )
        .unwrap();
}

/// Find a placement's projected JSON in `GET /workspace` by its instance id.
async fn placement_json(app: &Router, iid: &str) -> Option<serde_json::Value> {
    let (_, body) = send(app, "GET", "/workspace", None).await;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    for project in v["projects"].as_array()? {
        for placement in project["placements"].as_array()? {
            if placement["placement_id"] == iid {
                return Some(placement.clone());
            }
        }
    }
    None
}

/// APPROVE-1 (ADR 0064): under an approval-required policy an explicitly-added
/// archetype's placement lands **pending** — it can't host a work chat and is flagged in
/// the nav — until the owner **accepts** it, whereupon it goes active and hosts chats.
#[tokio::test]
async fn approval_policy_holds_a_placement_pending_until_the_owner_accepts() {
    let (_d, wb) = seeded_workbench();
    seed_require_archetype_approval(&wb);
    let app = open_control_plane(wb);

    // an archetype to place, and a project (its built-in general placement stays active).
    let (_, body) = send(&app, "POST", "/archetypes", Some(r#"{"name":"reviewer"}"#)).await;
    let agent_id = serde_json::from_str::<serde_json::Value>(&body).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (_, body) = send(&app, "POST", "/projects", Some(r#"{"name":"acme"}"#)).await;
    let project: serde_json::Value = serde_json::from_str(&body).unwrap();
    let pid = project["id"].as_str().unwrap().to_string();
    let target_id = project["target_id"].as_str().unwrap().to_string();

    // explicitly add the archetype → a *pending* placement under the policy.
    let (s, body) = send(
        &app,
        "POST",
        &format!("/projects/{pid}/placements"),
        Some(&format!(r#"{{"agent_id":"{agent_id}"}}"#)),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "bound: {body}");
    let iid = serde_json::from_str::<serde_json::Value>(&body).unwrap()["instance_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        placement_json(&app, &iid).await.expect("in workspace")["pending"],
        true,
        "an explicitly-added placement starts pending under the policy",
    );

    // a work chat can't root on a pending placement — fail closed with an actionable reason.
    let (s, body) = send(
        &app,
        "POST",
        &format!("/projects/{pid}/placements/{iid}/chats"),
        Some(&format!(r#"{{"title":"go","target_id":"{target_id}"}}"#)),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "refused: {body}");
    assert!(
        body.contains("pending approval"),
        "actionable reason: {body}"
    );

    // the owner's second act accepts it → active.
    let (s, body) = send(&app, "POST", &format!("/placements/{iid}/accept"), None).await;
    assert_eq!(s, StatusCode::OK, "accepted: {body}");
    assert_eq!(
        placement_json(&app, &iid).await.unwrap()["pending"],
        false,
        "accepted placement is active",
    );

    // now a work chat is allowed.
    let (s, body) = send(
        &app,
        "POST",
        &format!("/projects/{pid}/placements/{iid}/chats"),
        Some(&format!(r#"{{"title":"go","target_id":"{target_id}"}}"#)),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::CREATED,
        "active placement hosts a chat: {body}"
    );
}

/// APPROVE-1: the default (frictionless) policy admits an explicitly-added placement
/// **active at once** — no accept step, a chat roots immediately.
#[tokio::test]
async fn frictionless_default_admits_a_placement_active_at_once() {
    let (_d, wb) = seeded_workbench();
    let app = open_control_plane(wb);

    let (_, body) = send(&app, "POST", "/archetypes", Some(r#"{"name":"reviewer"}"#)).await;
    let agent_id = serde_json::from_str::<serde_json::Value>(&body).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (_, body) = send(&app, "POST", "/projects", Some(r#"{"name":"acme"}"#)).await;
    let project: serde_json::Value = serde_json::from_str(&body).unwrap();
    let pid = project["id"].as_str().unwrap().to_string();
    let target_id = project["target_id"].as_str().unwrap().to_string();
    let (s, body) = send(
        &app,
        "POST",
        &format!("/projects/{pid}/placements"),
        Some(&format!(r#"{{"agent_id":"{agent_id}"}}"#)),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "bound: {body}");
    let iid = serde_json::from_str::<serde_json::Value>(&body).unwrap()["instance_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        placement_json(&app, &iid).await.unwrap()["pending"],
        false,
        "frictionless default is active immediately",
    );
    let (s, body) = send(
        &app,
        "POST",
        &format!("/projects/{pid}/placements/{iid}/chats"),
        Some(&format!(r#"{{"title":"go","target_id":"{target_id}"}}"#)),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::CREATED,
        "active placement hosts a chat: {body}"
    );
}

/// A placement id is not independent authority. The project segment and the
/// placement's durable project binding must agree before either chat creation
/// or removal can mutate state.
#[tokio::test]
async fn placement_routes_reject_a_mismatched_project_path_without_mutation() {
    let (_d, wb) = seeded_workbench();
    let app = open_control_plane(wb);

    let (_, first_body) = send(&app, "POST", "/projects", Some(r#"{"name":"first"}"#)).await;
    let first: serde_json::Value = serde_json::from_str(&first_body).unwrap();
    let first_id = first["id"].as_str().unwrap();

    let (_, second_body) = send(&app, "POST", "/projects", Some(r#"{"name":"second"}"#)).await;
    let second: serde_json::Value = serde_json::from_str(&second_body).unwrap();
    let second_id = second["id"].as_str().unwrap();
    let second_placement = second["placement"].as_str().unwrap();
    let second_target = second["target_id"].as_str().unwrap();

    let (status, body) = send(
        &app,
        "POST",
        &format!("/projects/{first_id}/placements/{second_placement}/chats"),
        Some(&format!(
            r#"{{"title":"wrong project","target_id":"{second_target}"}}"#
        )),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "mismatched chat: {body}");

    let (status, body) = send(
        &app,
        "DELETE",
        &format!("/projects/{first_id}/placements/{second_placement}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "mismatched removal: {body}");

    let (_, workspace_body) = send(&app, "GET", "/workspace", None).await;
    let workspace: serde_json::Value = serde_json::from_str(&workspace_body).unwrap();
    let second_project = workspace["projects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|project| project["id"] == second_id)
        .expect("second project remains");
    let placement = second_project["placements"]
        .as_array()
        .unwrap()
        .iter()
        .find(|placement| placement["placement_id"] == second_placement)
        .expect("second placement remains");
    assert!(
        placement["chats"].as_array().unwrap().is_empty(),
        "mismatched project path created a chat: {placement}"
    );
}

/// The mutation response is the same redacted target projection consumed by
/// `GET /workspace`; returning a partial record here makes the shipped
/// `parseWorkTarget` client throw after the durable attach has already happened.
#[tokio::test]
async fn attached_target_response_matches_the_workspace_projection() {
    let (_d, wb) = seeded_workbench();
    let app = open_control_plane(wb);
    let source = tempfile::tempdir().unwrap();
    std::fs::write(source.path().join("work.txt"), "basis\n").unwrap();

    let (_, project_body) = send(
        &app,
        "POST",
        "/projects",
        Some(r#"{"name":"target owner"}"#),
    )
    .await;
    let project: serde_json::Value = serde_json::from_str(&project_body).unwrap();
    let project_id = project["id"].as_str().unwrap();
    let attach_body = serde_json::json!({
        "name": "Existing folder",
        "kind": "external-folder",
        "path": source.path(),
        "path_scope": ["."],
    })
    .to_string();
    let (status, attached_body) = send(
        &app,
        "POST",
        &format!("/projects/{project_id}/targets"),
        Some(&attach_body),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "attached: {attached_body}");
    let attached: serde_json::Value = serde_json::from_str(&attached_body).unwrap();
    assert_eq!(attached["owner_kind"], "project");
    assert_eq!(attached["owner_id"], project_id);
    assert_eq!(attached["concurrency"], "compare-before-write-weak");
    assert!(attached["current_basis"].is_string());
    assert!(
        !attached_body.contains(&source.path().display().to_string()),
        "native path escaped in mutation projection: {attached_body}"
    );

    let (_, workspace_body) = send(&app, "GET", "/workspace", None).await;
    let workspace: serde_json::Value = serde_json::from_str(&workspace_body).unwrap();
    let projected = workspace["projects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|candidate| candidate["id"] == project_id)
        .unwrap()["targets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|target| target["id"] == attached["id"])
        .expect("attached target is projected");
    assert_eq!(&attached, projected);
}

/// ENTSEC-5: context can be ingested from an **upload** (not just a server-local path) — the
/// enterprise thin-client's context-in. The uploaded file lands in the engagement worktree
/// and a context resource is minted.
#[tokio::test]
async fn context_upload_ingests_files_into_the_engagement() {
    let (_d, wb) = seeded_workbench();
    let app = open_control_plane(wb);

    // a live work chat (an engagement with a worktree).
    let (s, _) = send(&app, "POST", "/chats", Some(r#"{"id":"up-chat"}"#)).await;
    assert_eq!(s, StatusCode::CREATED);

    // upload context files.
    let (s, body) = send(
        &app,
        "POST",
        "/chats/up-chat/context/upload",
        Some(r##"{"files":[{"name":"brief.md","content":"# the brief"}],"classification":"internal"}"##),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "upload accepted: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["ingested"], 1);
    assert!(
        v["resource"].as_str().is_some(),
        "a resource was minted: {body}"
    );

    // the uploaded file is now in the engagement worktree.
    let (_, tree) = send(&app, "GET", "/chats/up-chat/tree", None).await;
    assert!(
        tree.contains("brief.md"),
        "uploaded file present in the tree: {tree}"
    );
}

#[tokio::test]
async fn workspace_seeds_built_in_archetypes_and_official_office_skills() {
    let (d, wb) = seeded_workbench();
    let app = open_control_plane(wb);

    for archetype in app_support::builtin_archetypes() {
        assert!(d
            .path()
            .join("targets")
            .join(library_state::authoring_target_id(archetype.id))
            .is_dir());
    }
    assert!(d
        .path()
        .join("targets")
        .join(library_state::managed_project_target_id(DEFAULT_PROJECT))
        .is_dir());
    assert!(!d.path().join("targets").join(DEFAULT_PLACEMENT).exists());
    assert!(!d.path().join("instances").exists());

    let package = gaugedesk_whip_runtime::AuthoredAgentPackage::load(
        d.path()
            .join("targets")
            .join(library_state::authoring_target_id(DEFAULT_AGENT))
            .join("repo/.whipple/versions/1"),
    )
    .expect("seeded version is a native WhippleScript package");
    assert!(package.version_ref().starts_with("whip:agent-package:"));

    // A fresh root exposes all three ordinary library archetypes.
    let (s, body) = send(&app, "GET", "/workspace", None).await;
    assert_eq!(s, StatusCode::OK, "got {body}");
    for name in ["Default", "Software engineer", "Office worker"] {
        assert!(body.contains(name), "built-in {name} seeded: {body}");
    }
    assert!(body.contains("\"is_default\":true"), "got {body}");
    assert!(body.contains("\"work_targets\""), "got {body}");
    assert!(
        !body.contains("locator_handle"),
        "protected locator leaked: {body}"
    );

    let office_root = d
        .path()
        .join("targets")
        .join(library_state::authoring_target_id(
            app_support::OFFICE_WORKER_AGENT,
        ))
        .join("repo/.whipple/discipline/versions/1");
    let office_manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(office_root.join("discipline.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(office_manifest["skills"].as_array().unwrap().len(), 4);
    let office_bundle =
        discipline::load(&office_root, package.capabilities().iter().cloned()).unwrap();
    for skill in official_skills::catalog() {
        assert!(office_manifest["skills"]
            .as_array()
            .unwrap()
            .iter()
            .any(|reference| reference == skill.reference));
        assert!(office_bundle.files.iter().any(|(path, guide)| {
            path == &official_skills::asset_path(skill) && guide == skill.guide
        }));
    }
    for id in [DEFAULT_AGENT, app_support::SOFTWARE_ENGINEER_AGENT] {
        let manifest: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(
                d.path()
                    .join("targets")
                    .join(library_state::authoring_target_id(id))
                    .join("repo/.whipple/discipline/versions/1/discipline.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(manifest["skills"].as_array().unwrap().is_empty());
    }

    // The catalog is package-owned and consumed directly while the immutable
    // discipline bundle above is built. Its unconsumed HTTP facades are retired
    // so a route cannot masquerade as a shipped product surface.
    for path in ["/skills/official", "/skills/official/docx"] {
        let (status, _) = send(&app, "GET", path, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "retired route: {path}");
    }

    // create an agent → it shows up.
    let (s, body) = send(&app, "POST", "/archetypes", Some(r#"{"name":"reviewer"}"#)).await;
    assert_eq!(s, StatusCode::CREATED, "got {body}");
    let agent_id = serde_json::from_str::<serde_json::Value>(&body).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    // new chat under that agent → appears under it + in recent.
    let (s, body) = send(
        &app,
        "POST",
        &format!("/archetypes/{agent_id}/chats"),
        Some(r#"{"title":"first chat"}"#),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "got {body}");
    let chat_id = serde_json::from_str::<serde_json::Value>(&body).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let (_, body) = send(&app, "GET", "/workspace", None).await;
    assert!(
        body.contains("reviewer") && body.contains("first chat"),
        "got {body}"
    );

    // UX-12: a reference-only chat event resolves to a freshness-carried narrow
    // projection: its current parent + recent row, with global ordering by id but
    // without retransmitting unrelated archetype content.
    let (s, delta) = send(
        &app,
        "GET",
        &format!("/projections/library/workspace/chat/{chat_id}?freshness=live"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "got {delta}");
    let delta: serde_json::Value = serde_json::from_str(&delta).unwrap();
    assert_eq!(delta["freshness"]["marker"], "live");
    assert_eq!(delta["value"]["archetypes"].as_array().unwrap().len(), 1);
    assert_eq!(delta["value"]["recent"].as_array().unwrap().len(), 1);
    assert_eq!(delta["value"]["recent"][0]["id"], chat_id);
    assert!(delta["value"]["order"]["recent"]
        .as_array()
        .unwrap()
        .iter()
        .any(|id| id.as_str() == Some(chat_id.as_str())));

    // the chat is a real engagement: it can be tasked/diffed.
    let (s, _) = send(&app, "GET", &format!("/chats/{chat_id}/diff"), None).await;
    assert_eq!(s, StatusCode::OK);

    // delete the chat → tombstoned, gone from the workspace.
    let (s, _) = send(&app, "DELETE", &format!("/chats/{chat_id}"), None).await;
    assert_eq!(s, StatusCode::OK);
    let (_, body) = send(&app, "GET", "/workspace", None).await;
    assert!(!body.contains("first chat"), "deleted chat is gone: {body}");
}

#[tokio::test]
async fn placements_share_project_targets_and_cross_project_targets_are_rejected() {
    let (_dir, wb) = seeded_workbench();
    let app = open_control_plane(wb);

    let (status, project_body) = send(&app, "POST", "/projects", Some(r#"{"name":"Acme"}"#)).await;
    assert_eq!(status, StatusCode::CREATED, "{project_body}");
    let project: serde_json::Value = serde_json::from_str(&project_body).unwrap();
    let project_id = project["id"].as_str().unwrap();
    let target_id = project["target_id"].as_str().unwrap();
    let general = project["placement"].as_str().unwrap();

    let (status, archetype_body) =
        send(&app, "POST", "/archetypes", Some(r#"{"name":"Reviewer"}"#)).await;
    assert_eq!(status, StatusCode::CREATED, "{archetype_body}");
    let archetype: serde_json::Value = serde_json::from_str(&archetype_body).unwrap();
    let archetype_id = archetype["id"].as_str().unwrap();
    let (status, placement_body) = send(
        &app,
        "POST",
        &format!("/projects/{project_id}/placements"),
        Some(&format!(r#"{{"agent_id":"{archetype_id}"}}"#)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{placement_body}");
    let placement: serde_json::Value = serde_json::from_str(&placement_body).unwrap();
    let placement_id = placement["instance_id"].as_str().unwrap();

    let (_, workspace_body) = send(&app, "GET", "/workspace", None).await;
    let workspace: serde_json::Value = serde_json::from_str(&workspace_body).unwrap();
    let projected = workspace["projects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|project| project["id"] == project_id)
        .unwrap();
    for placement in projected["placements"].as_array().unwrap() {
        assert_eq!(placement["target_ids"], serde_json::json!([target_id]));
    }

    let (status, other_body) = send(&app, "POST", "/projects", Some(r#"{"name":"Other"}"#)).await;
    assert_eq!(status, StatusCode::CREATED, "{other_body}");
    let other: serde_json::Value = serde_json::from_str(&other_body).unwrap();
    let other_target = other["target_id"].as_str().unwrap();
    let (status, error) = send(
        &app,
        "POST",
        &format!("/projects/{project_id}/placements/{placement_id}/chats"),
        Some(&format!(
            r#"{{"title":"wrong target","target_id":"{other_target}"}}"#
        )),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");

    let (status, chat_body) = send(
        &app,
        "POST",
        &format!("/projects/{project_id}/placements/{general}/chats"),
        Some(&format!(
            r#"{{"title":"right target","target_id":"{target_id}"}}"#
        )),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{chat_body}");
    let chat: serde_json::Value = serde_json::from_str(&chat_body).unwrap();
    assert_eq!(chat["target_id"], target_id);
    assert!(chat["basis"]
        .as_str()
        .is_some_and(|basis| !basis.is_empty()));
}

#[tokio::test]
async fn target_binding_basis_and_candidate_survive_restart() {
    let dir = tempfile::tempdir().unwrap();
    let (chat_id, target_id, basis) = {
        let wb = open_workbench(dir.path()).unwrap();
        let app = open_control_plane(wb);
        let (status, project_body) =
            send(&app, "POST", "/projects", Some(r#"{"name":"Restart"}"#)).await;
        assert_eq!(status, StatusCode::CREATED, "{project_body}");
        let project: serde_json::Value = serde_json::from_str(&project_body).unwrap();
        let project_id = project["id"].as_str().unwrap();
        let placement_id = project["placement"].as_str().unwrap();
        let target_id = project["target_id"].as_str().unwrap();
        let (status, chat_body) = send(
            &app,
            "POST",
            &format!("/projects/{project_id}/placements/{placement_id}/chats"),
            Some(&format!(
                r#"{{"title":"restart","target_id":"{target_id}"}}"#
            )),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{chat_body}");
        let chat: serde_json::Value = serde_json::from_str(&chat_body).unwrap();
        let chat_id = chat["id"].as_str().unwrap().to_owned();
        let basis = chat["basis"].as_str().unwrap().to_owned();
        let (status, body) = send(
            &app,
            "PUT",
            &format!("/chats/{chat_id}/file?path=candidate.md"),
            Some("candidate survives"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        (chat_id, target_id.to_owned(), basis)
    };

    let app = open_control_plane(open_workbench(dir.path()).unwrap());
    let (status, workspace_body) = send(&app, "GET", "/workspace", None).await;
    assert_eq!(status, StatusCode::OK, "{workspace_body}");
    let workspace: serde_json::Value = serde_json::from_str(&workspace_body).unwrap();
    let chat = workspace["recent"]
        .as_array()
        .unwrap()
        .iter()
        .find(|chat| chat["id"] == chat_id)
        .unwrap();
    assert_eq!(chat["target_id"], target_id);
    assert_eq!(chat["target_basis"], basis);
    let (status, diff) = send(&app, "GET", &format!("/chats/{chat_id}/diff"), None).await;
    assert_eq!(status, StatusCode::OK, "{diff}");
    assert!(diff.contains("candidate.md"), "{diff}");
}

#[tokio::test]
async fn publish_atomically_freezes_package_and_discipline_without_copying_them_to_targets() {
    let (dir, wb) = seeded_workbench();
    let edit_draft = |wb: &SharedWorkbench, body: &str| {
        let guard = wb.lock_unpoisoned();
        let target_id = library_state::authoring_target_id(DEFAULT_AGENT);
        let workspace = guard.targets.get(&target_id).expect("authoring workspace");
        let id = library::gen_id("test-edit");
        let edit = workspace.create_engagement(&id).expect("edit engagement");
        edit.write_file(".whipple/draft/persona.md", body)
            .expect("edit persona");
        edit.commit_turn("edit package draft")
            .expect("commit draft");
        assert_eq!(
            edit.merge_into_main().expect("merge draft"),
            gaugedesk_workspace::MergeOutcome::Clean
        );
        workspace.remove_engagement(&id).expect("remove edit");
    };
    edit_draft(&wb, "published persona");
    {
        let guard = wb.lock_unpoisoned();
        let target_id = library_state::authoring_target_id(DEFAULT_AGENT);
        let workspace = guard.targets.get(&target_id).expect("authoring workspace");
        let id = library::gen_id("test-discipline-edit");
        let edit = workspace.create_engagement(&id).expect("edit engagement");
        edit.write_file(
            ".whipple/discipline/draft/discipline.json",
            &serde_json::json!({
                "schema": "gaugedesk.discipline.v1",
                "skills": ["skill://review"],
                "capabilities": ["workspace.read", "workspace.write", "command.run"],
                "assets": [{"path": "checks/verify.sh", "treatment": "managed"}],
                "target_rules": ["requires README.md"]
            })
            .to_string(),
        )
        .unwrap();
        edit.write_file(
            ".whipple/discipline/draft/checks/verify.sh",
            "#!/bin/sh\nexit 0\n",
        )
        .unwrap();
        edit.commit_turn("edit discipline draft").unwrap();
        assert_eq!(
            edit.merge_into_main().unwrap(),
            gaugedesk_workspace::MergeOutcome::Clean
        );
        workspace.remove_engagement(&id).unwrap();
    }

    let app = open_control_plane(wb.clone());
    let (status, body) = send(
        &app,
        "POST",
        &format!("/archetypes/{DEFAULT_AGENT}/publish"),
        Some("{}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "publish: {body}");
    assert!(body.contains("\"version\":2"), "publish: {body}");

    let frozen_root = dir
        .path()
        .join("targets")
        .join(library_state::authoring_target_id(DEFAULT_AGENT))
        .join("repo/.whipple/versions/2");
    let frozen =
        gaugedesk_whip_runtime::AuthoredAgentPackage::load(&frozen_root).expect("frozen package");
    let frozen_ref = frozen.version_ref().to_owned();
    let frozen_discipline = dir
        .path()
        .join("targets")
        .join(library_state::authoring_target_id(DEFAULT_AGENT))
        .join("repo/.whipple/discipline/versions/2");
    assert_eq!(
        std::fs::read_to_string(frozen_discipline.join("checks/verify.sh")).unwrap(),
        "#!/bin/sh\nexit 0\n"
    );
    let discipline_ref =
        crate::discipline::load(&frozen_discipline, frozen.capabilities().iter().cloned())
            .unwrap()
            .reference;
    {
        let guard = wb.lock_unpoisoned();
        let version = &guard.library.agents[DEFAULT_AGENT].versions[&2];
        assert_eq!(version.package_ref, frozen_ref);
        assert_eq!(version.discipline_ref, discipline_ref);
    }
    assert_eq!(
        std::fs::read_to_string(frozen_root.join("persona.md")).unwrap(),
        "published persona"
    );

    // Further draft work cannot mutate version 2 or its content address.
    edit_draft(&wb, "unpublished persona");
    assert_eq!(
        gaugedesk_whip_runtime::AuthoredAgentPackage::load(&frozen_root)
            .unwrap()
            .version_ref(),
        frozen_ref
    );

    let (status, body) = send(
        &app,
        "POST",
        &format!("/placements/{DEFAULT_PLACEMENT}/upgrade"),
        Some("{}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "upgrade: {body}");
    let guard = wb.lock_unpoisoned();
    assert_eq!(
        guard.library.instances[DEFAULT_PLACEMENT].version, 2,
        "the placement pins the immutable authoring-target package"
    );
    let project_target = library_state::managed_project_target_id(DEFAULT_PROJECT);
    let acts = guard.target_acts(&project_target).unwrap();
    let upgrade_proposal = acts
        .iter()
        .find(|act| {
            act.act == crate::target_adapter::TargetActKind::Propose
                && act
                    .reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains("upgrade 1 -> 2"))
        })
        .expect("upgrade creates a target proposal");
    assert_eq!(
        upgrade_proposal.candidate.as_deref(),
        Some(discipline_ref.as_str())
    );
    assert!(upgrade_proposal
        .checks
        .iter()
        .any(|change| change.contains("Managed:checks/verify.sh")));
    assert!(
        !dir.path()
            .join("targets")
            .join(&project_target)
            .join("repo/.whipple/versions/2")
            .exists(),
        "the package is not copied into the project target"
    );
    assert!(
        !dir.path()
            .join("targets")
            .join(project_target)
            .join("repo/.whipple/discipline/versions/2")
            .exists(),
        "the discipline is not copied into the project target"
    );
}

#[tokio::test]
async fn publish_rejects_discipline_capability_drift_without_advancing_version() {
    let (dir, wb) = seeded_workbench();
    {
        let guard = wb.lock_unpoisoned();
        let target_id = library_state::authoring_target_id(DEFAULT_AGENT);
        let workspace = guard.targets.get(&target_id).unwrap();
        let id = library::gen_id("bad-discipline");
        let edit = workspace.create_engagement(&id).unwrap();
        edit.write_file(
            ".whipple/discipline/draft/discipline.json",
            &serde_json::json!({
                "schema": "gaugedesk.discipline.v1",
                "skills": [],
                "capabilities": ["workspace.read"],
                "assets": [],
                "target_rules": []
            })
            .to_string(),
        )
        .unwrap();
        edit.commit_turn("introduce capability drift").unwrap();
        assert_eq!(
            edit.merge_into_main().unwrap(),
            gaugedesk_workspace::MergeOutcome::Clean
        );
        workspace.remove_engagement(&id).unwrap();
    }
    let app = open_control_plane(wb.clone());
    let (status, body) = send(
        &app,
        "POST",
        &format!("/archetypes/{DEFAULT_AGENT}/publish"),
        Some("{}"),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(body.contains("capabilities"), "{body}");
    assert_eq!(
        wb.lock_unpoisoned().library.agents[DEFAULT_AGENT].current_version,
        1
    );
    assert!(!dir
        .path()
        .join("targets")
        .join(library_state::authoring_target_id(DEFAULT_AGENT))
        .join("repo/.whipple/versions/2")
        .exists());
}

#[tokio::test]
async fn base_carrying_save_merges_concurrent_edits_and_folds_conflicts() {
    // SUB-6: the editor's save carries the content it loaded (the
    // three-way base). Concurrent disjoint edits merge through whip's
    // token-level engine; overlapping rewrites 409 with the fold payload
    // and write nothing; the merge fact reaches the transcript while the
    // piece-level provenance lands on the audit plane.
    let (_dir, wb) = seeded_workbench();
    let app = open_control_plane(wb);
    let (status, body) = send(&app, "POST", "/chats", Some(r#"{"id":"sub6"}"#)).await;
    assert_eq!(status, StatusCode::CREATED, "chat: {body}");
    let base = "The quick brown fox jumps over the lazy dog tonight.";
    let (status, _) = send(&app, "PUT", "/chats/sub6/file?path=notes.md", Some(base)).await;
    assert_eq!(status, StatusCode::OK);
    // An "agent" write moves the file (legacy unconditional PUT stands in
    // for the turn's mediated write).
    let (status, _) = send(
        &app,
        "PUT",
        "/chats/sub6/file?path=notes.md",
        Some("The swift brown fox jumps over the lazy dog tonight."),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // The editor saves a draft based on the ORIGINAL content, editing a
    // distant word: the save merges, keeping both edits.
    let save = serde_json::json!({
        "content": "The quick brown fox jumps over the lazy dog today.",
        "base_content": base,
    })
    .to_string();
    let (status, body) = send(&app, "PUT", "/chats/sub6/file?path=notes.md", Some(&save)).await;
    assert_eq!(status, StatusCode::OK, "merged save: {body}");
    let merged: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(merged["merged"], true);
    assert_eq!(
        merged["content"],
        "The swift brown fox jumps over the lazy dog today."
    );
    let (_, file) = send(&app, "GET", "/chats/sub6/file?path=notes.md", None).await;
    assert_eq!(file, "The swift brown fox jumps over the lazy dog today.");
    // Provenance is audit evidence; the transcript states only the fact.
    let (_, audit) = send(&app, "GET", "/chats/sub6/audit", None).await;
    assert!(audit.contains("save_merged"), "audit provenance: {audit}");
    let (_, transcript) = send(&app, "GET", "/chats/sub6/transcript", None).await;
    assert!(
        transcript.contains("merged with concurrent changes"),
        "the fact reaches the conversation: {transcript}"
    );
    // Overlapping rewrites: 409 with the fold payload, nothing written.
    let head = "The swift brown fox jumps over the lazy dog today.";
    let (status, _) = send(
        &app,
        "PUT",
        "/chats/sub6/file?path=notes.md",
        Some("The swift brown fox jumps over the lazy TIGER today."),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let save = serde_json::json!({
        "content": "The swift brown fox jumps over the lazy LION today.",
        "base_content": head,
    })
    .to_string();
    let (status, body) = send(&app, "PUT", "/chats/sub6/file?path=notes.md", Some(&save)).await;
    assert_eq!(status, StatusCode::CONFLICT, "fold payload: {body}");
    let conflict: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(conflict["conflict"], true);
    assert!(
        conflict["pieces"]
            .as_array()
            .unwrap()
            .iter()
            .any(|piece| piece["kind"] == "conflict"),
        "structured regions: {body}"
    );
    let (_, file) = send(&app, "GET", "/chats/sub6/file?path=notes.md", None).await;
    assert_eq!(
        file, "The swift brown fox jumps over the lazy TIGER today.",
        "a conflicted save writes nothing"
    );
}

#[tokio::test]
async fn cut_carrying_saves_mint_region_memory_and_preview_folds() {
    // The §12 endgame over HTTP: GET names the state it serves
    // (x-workspace-cut), the save carries that cut back, a fold-settled
    // region rides the resolve as durable memory, and the SAME divergence
    // in ANOTHER file later folds cleanly through the read-only preview —
    // resolved provenance, no re-ask.
    let (_dir, wb) = seeded_workbench();
    let app = open_control_plane(wb);
    let (status, body) = send(&app, "POST", "/chats", Some(r#"{"id":"cut1"}"#)).await;
    assert_eq!(status, StatusCode::CREATED, "chat: {body}");
    let base = "Alpha beta gamma delta epsilon zeta eta theta.";
    let agent = "Alpha beta AGENT-GAMMA delta epsilon zeta eta theta.";
    let editor = "Alpha beta EDITOR-GAMMA delta epsilon zeta eta theta.";

    send(&app, "PUT", "/chats/cut1/file?path=one.md", Some(base)).await;
    let (status, cut, body) = send_with_cut(&app, "/chats/cut1/file?path=one.md").await;
    assert_eq!(status, StatusCode::OK, "read: {body}");
    let cut = cut.expect("the read names its cut");
    // The agent moves the file; the editor saves an overlapping draft
    // against the cut it loaded → 409, structured regions, re-save base.
    send(&app, "PUT", "/chats/cut1/file?path=one.md", Some(agent)).await;
    let save = serde_json::json!({ "content": editor, "base_cut": cut }).to_string();
    let (status, body) = send(&app, "PUT", "/chats/cut1/file?path=one.md", Some(&save)).await;
    assert_eq!(status, StatusCode::CONFLICT, "fold payload: {body}");
    let conflict: serde_json::Value = serde_json::from_str(&body).unwrap();
    let resave_cut = conflict["current_cut"]
        .as_str()
        .expect("re-save base")
        .to_owned();
    let pieces = conflict["pieces"].as_array().unwrap().clone();
    let region = pieces
        .iter()
        .find(|piece| piece["kind"] == "conflict")
        .expect("a conflict region")
        .clone();
    // The user settles the region; the composed document re-saves with
    // the settled triple riding along.
    let composed: String = pieces
        .iter()
        .map(|piece| {
            if piece["kind"] == "merged" {
                piece["text"].as_str().unwrap().to_owned()
            } else {
                "SETTLED-GAMMA".to_owned()
            }
        })
        .collect();
    let resolve = serde_json::json!({
        "content": composed,
        "base_cut": resave_cut,
        "resolutions": [{
            "base_text": region["base_text"],
            "ours_text": region["ours_text"],
            "theirs_text": region["theirs_text"],
            "resolution_text": "SETTLED-GAMMA",
        }],
    })
    .to_string();
    let (status, body) = send(&app, "PUT", "/chats/cut1/file?path=one.md", Some(&resolve)).await;
    assert_eq!(status, StatusCode::OK, "resolved save: {body}");
    let saved: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(saved["cut"].is_string(), "the save names its cut: {body}");
    let (_, file) = send(&app, "GET", "/chats/cut1/file?path=one.md", None).await;
    assert!(
        file.contains("SETTLED-GAMMA"),
        "settled text landed: {file}"
    );
    // Minted memory is audit-plane evidence.
    let (_, audit) = send(&app, "GET", "/chats/cut1/audit", None).await;
    assert!(
        audit.contains("region_resolutions_recorded"),
        "memory minting is recorded: {audit}"
    );

    // Pay-forward through the read-only preview: same divergence, other
    // file — folds clean with resolved provenance, nothing moves.
    send(&app, "PUT", "/chats/cut1/file?path=two.md", Some(base)).await;
    let (_, cut2, _) = send_with_cut(&app, "/chats/cut1/file?path=two.md").await;
    let cut2 = cut2.expect("second read names its cut");
    send(&app, "PUT", "/chats/cut1/file?path=two.md", Some(agent)).await;
    let preview =
        serde_json::json!({ "path": "two.md", "draft": editor, "base_cut": cut2 }).to_string();
    let (status, body) = send(&app, "POST", "/chats/cut1/merge-preview", Some(&preview)).await;
    assert_eq!(status, StatusCode::OK, "preview: {body}");
    let preview: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(preview["known_base"], true, "known base: {body}");
    assert_eq!(preview["clean"], true, "memory folds it clean: {body}");
    assert!(
        preview["merged"]
            .as_str()
            .unwrap()
            .contains("SETTLED-GAMMA"),
        "the fold carries the remembered text: {body}"
    );
    assert!(
        preview["pieces"]
            .as_array()
            .unwrap()
            .iter()
            .any(|piece| piece["provenance"] == "resolved"),
        "remembered regions are honestly tagged: {body}"
    );
    // Preview moved nothing: the file still holds the agent's body.
    let (_, file) = send(&app, "GET", "/chats/cut1/file?path=two.md", None).await;
    assert_eq!(file, agent, "read-only preview");
}

#[tokio::test]
async fn file_edits_respect_draft_version_and_host_control_ownership() {
    let (_dir, wb) = seeded_workbench();
    let app = open_control_plane(wb);
    let (status, body) = send(
        &app,
        "POST",
        &format!("/archetypes/{DEFAULT_AGENT}/chats"),
        Some(r#"{"title":"edit package"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "edit chat: {body}");
    let edit_id = serde_json::from_str::<serde_json::Value>(&body).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let (status, _) = send(
        &app,
        "PUT",
        &format!("/chats/{edit_id}/file?path=.whipple%2Fdraft%2Fpersona.md"),
        Some("new draft"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = send(
        &app,
        "PUT",
        &format!("/chats/{edit_id}/file?path=.whipple%2Fversions%2F1%2Fpersona.md"),
        Some("tamper"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "frozen write: {body}");
    let (status, body) = send(
        &app,
        "PUT",
        &format!("/chats/{edit_id}/file?path=.agent-config.json"),
        Some("{}"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "host config write: {body}");

    let (status, body) = send(&app, "POST", "/chats", Some("{}")).await;
    assert_eq!(status, StatusCode::CREATED);
    let work_id = serde_json::from_str::<serde_json::Value>(&body).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let (status, body) = send(
        &app,
        "PUT",
        &format!("/chats/{work_id}/file?path=.whipple%2Fdraft%2Fpersona.md"),
        Some("tamper"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "work package write: {body}");
}

/// The All-chats "+ new chat" quick-start: `POST /chats` with no id mints one
/// server-side and roots on the hidden Personal default placement (a work chat).
#[tokio::test]
async fn post_chats_without_id_mints_a_work_chat_on_the_default_placement() {
    let (_d, wb) = seeded_workbench();
    let app = open_control_plane(wb);

    // No id in the body ⇒ the server mints one (the UI never mints ids).
    let (s, body) = send(&app, "POST", "/chats", Some("{}")).await;
    assert_eq!(s, StatusCode::CREATED, "got {body}");
    let v = serde_json::from_str::<serde_json::Value>(&body).unwrap();
    let id = v["id"].as_str().unwrap().to_string();
    assert!(id.starts_with("chat-"), "minted a chat id: {id}");

    // It is a real engagement (diffable) rooted on the default placement, and it
    // carries the "new chat" placeholder title so the nav renders it "Untitled".
    let (s, _) = send(&app, "GET", &format!("/chats/{id}/diff"), None).await;
    assert_eq!(s, StatusCode::OK);
    let (_, body) = send(&app, "GET", "/workspace", None).await;
    assert!(
        body.contains(&id) && body.contains("\"new chat\""),
        "got {body}"
    );
    let workspace: serde_json::Value = serde_json::from_str(&body).unwrap();
    let chat = workspace["recent"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["id"] == id))
        .expect("new Personal chat in recent");
    assert_eq!(
        chat["rehome_blocked"], false,
        "a fresh chat has no collaborative candidate: {chat}"
    );

    // The explicit Personal-project action must name the exact target; runtime
    // config/discipline remain outside its candidate diff.
    let personal = workspace["projects"]
        .as_array()
        .and_then(|projects| {
            projects
                .iter()
                .find(|project| project["is_personal"] == true)
        })
        .expect("Personal project");
    let project_id = personal["id"].as_str().unwrap();
    let placement_id = personal["placements"][0]["placement_id"].as_str().unwrap();
    let target_id = personal["targets"][0]["id"].as_str().unwrap();
    let (_, placed_body) = send(
        &app,
        "POST",
        &format!("/projects/{project_id}/placements/{placement_id}/chats"),
        Some(&format!(
            r#"{{"title":"placed fresh","target_id":"{target_id}"}}"#
        )),
    )
    .await;
    let placed_id = serde_json::from_str::<serde_json::Value>(&placed_body).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (_, placed_diff) = send(&app, "GET", &format!("/chats/{placed_id}/diff"), None).await;
    let (_, placed_workspace) = send(&app, "GET", "/workspace", None).await;
    let placed_workspace: serde_json::Value = serde_json::from_str(&placed_workspace).unwrap();
    let placed_chat = placed_workspace["recent"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["id"] == placed_id))
        .expect("placement-created Personal chat");
    assert_eq!(
        placed_chat["rehome_blocked"], false,
        "runtime state is not a target candidate: {placed_chat}; diff={placed_diff}"
    );

    // A second quick-start mints a distinct id — no collision, no client id.
    let (s, body2) = send(&app, "POST", "/chats", Some("{}")).await;
    assert_eq!(s, StatusCode::CREATED, "got {body2}");
    let id2 = serde_json::from_str::<serde_json::Value>(&body2).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(id, id2, "each quick-start gets its own id");
}

/// ADR 0104: only the exact untouched default projection migrates. Non-library
/// state and legacy workspace bytes remain intact, and reopening is idempotent.
#[tokio::test]
async fn exact_pre_target_defaults_migrate_additively() {
    use library::{
        Admission, AgentRecord, InstanceKind, InstanceRecord, ProjectRecord, RecordOp,
        LIBRARY_SCOPE,
    };
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let legacy_dir = root.join("instances").join(DEFAULT_INSTANCE);
    std::fs::create_dir_all(&legacy_dir).unwrap();
    std::fs::write(legacy_dir.join("rollback-evidence.txt"), "preserve me").unwrap();

    {
        let mut store = Store::open(root.join("gaugewright.db").to_str().unwrap()).unwrap();
        let agent = AgentRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: DEFAULT_AGENT.into(),
            op: RecordOp::Upsert,
            name: "assistant".into(),
            instance_id: DEFAULT_INSTANCE.into(),
            config: "{}".into(),
            current_version: 1,
            versions: Default::default(),
            auto_upgrade: false,
            forked_from: None,
        };
        let project = ProjectRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: DEFAULT_PROJECT.into(),
            op: RecordOp::Upsert,
            name: "Personal".into(),
            is_default: false,
            home_id: gaugedesk_core::ids::HomeId::new(""),
            network_isolated: false,
            run_purpose: None,
            deployment_mode: None,
        };
        let authoring = InstanceRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: DEFAULT_INSTANCE.into(),
            op: RecordOp::Upsert,
            kind: InstanceKind::Authoring,
            agent_id: DEFAULT_AGENT.into(),
            project_id: None,
            version: 1,
            admission: Admission::Active,
        };
        let placement = InstanceRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: DEFAULT_PLACEMENT.into(),
            op: RecordOp::Upsert,
            kind: InstanceKind::Using,
            agent_id: DEFAULT_AGENT.into(),
            project_id: Some(DEFAULT_PROJECT.into()),
            version: 1,
            admission: Admission::Active,
        };
        for (kind, payload) in [
            ("agent", serde_json::to_string(&agent).unwrap()),
            ("project", serde_json::to_string(&project).unwrap()),
            ("instance", serde_json::to_string(&authoring).unwrap()),
            ("instance", serde_json::to_string(&placement).unwrap()),
        ] {
            store.append_record(LIBRARY_SCOPE, kind, &payload).unwrap();
        }
        store
            .append_record("account:preserved", "marker", r#"{"kept":true}"#)
            .unwrap();
    }

    let wb = open_workbench(root).unwrap();
    {
        let w = wb.lock_unpoisoned();
        assert_eq!(w.library.work_targets.len(), 4);
        assert_eq!(w.library.placement_targets.len(), 3);
        assert_eq!(
            w.store_ref()
                .records("account:preserved", "marker")
                .unwrap(),
            vec![r#"{"kept":true}"#.to_owned()]
        );
        assert_eq!(
            w.store_ref().records(LIBRARY_SCOPE, "agent").unwrap().len(),
            5,
            "legacy migration plus the two missing built-in archetype seeds"
        );
    }
    drop(wb);

    assert_eq!(
        std::fs::read_to_string(legacy_dir.join("rollback-evidence.txt")).unwrap(),
        "preserve me"
    );
    assert!(root
        .join("targets")
        .join(library_state::authoring_target_id(DEFAULT_AGENT))
        .exists());

    let reopened = open_workbench(root).unwrap();
    assert_eq!(
        reopened
            .lock_unpoisoned()
            .store_ref()
            .records(LIBRARY_SCOPE, "agent")
            .unwrap()
            .len(),
        5,
        "reopen must not rerun migration or duplicate built-ins"
    );
}

/// TARGET-1 hard cutover: any non-exact pre-target placement-owned state is
/// rejected with actionable reset guidance; it is never guessed into a target.
#[tokio::test]
async fn pre_target_store_is_rejected_instead_of_self_healed() {
    use library::{Admission, AgentRecord, InstanceKind, InstanceRecord, RecordOp, LIBRARY_SCOPE};
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let targets_dir = root.join("targets");
    std::fs::create_dir_all(&targets_dir).unwrap();

    // Lay down a *legacy* store: the default agent/instance records exist and the
    // instance repo is seeded, but the instance was never activated.
    {
        let mut store = Store::open(root.join("gaugewright.db").to_str().unwrap()).unwrap();
        let inst = Instance::init_at(targets_dir.join(DEFAULT_INSTANCE)).unwrap();
        inst.seed_main(&[
            (".pi/SYSTEM.md", app_support::DEFAULT_AGENT_SYSTEM_MD),
            ("AGENTS.md", app_support::DEFAULT_AGENT_AGENTS_MD),
        ])
        .unwrap();
        let inst_rec = InstanceRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: DEFAULT_INSTANCE.into(),
            op: RecordOp::Upsert,
            kind: InstanceKind::Authoring,
            agent_id: DEFAULT_AGENT.into(),
            project_id: None,
            version: 1,
            admission: Admission::Active,
        };
        store
            .append_record(
                LIBRARY_SCOPE,
                "instance",
                &serde_json::to_string(&inst_rec).unwrap(),
            )
            .unwrap();
        let agent = AgentRecord {
            schema: crate::library::LIBRARY_RECORD_SCHEMA,
            extra: Default::default(),
            id: DEFAULT_AGENT.into(),
            op: RecordOp::Upsert,
            name: "assistant".into(),
            instance_id: DEFAULT_INSTANCE.into(),
            config: "{}".into(),
            current_version: 1,
            versions: Default::default(),
            auto_upgrade: false,
            forked_from: None,
        };
        store
            .append_record(
                LIBRARY_SCOPE,
                "agent",
                &serde_json::to_string(&agent).unwrap(),
            )
            .unwrap();
        // No activate_instance — this is exactly the bug we heal.
        assert!(
            !store
                .fold::<InstanceState>(DEFAULT_INSTANCE)
                .map(|s| s.runnable)
                .unwrap_or(false),
            "precondition: legacy default instance is not runnable"
        );
    }

    let error = match open_workbench(root) {
        Ok(_) => panic!("pre-target state must not open"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(error
        .to_string()
        .contains("reset this pre-release state root"));
}

/// The heal is narrow: a *deliberately* suspended default instance (pinned, then
/// suspended) must stay suspended across a reopen — never silently auto-resumed.
#[tokio::test]
async fn reopening_a_suspended_default_instance_is_not_auto_resumed() {
    let dir = tempfile::tempdir().unwrap();
    {
        let wb = open_workbench(dir.path()).unwrap(); // seeds + activates
        let mut w = wb.lock_unpoisoned();
        w.store_mut()
            .admit::<InstanceState>(DEFAULT_INSTANCE, InstanceCommand::Suspend)
            .unwrap();
        assert!(
            !w.store_ref()
                .fold::<InstanceState>(DEFAULT_INSTANCE)
                .unwrap()
                .runnable,
            "suspended"
        );
    }
    // Reopen: pinned_version is Some, so the heal skips it — the suspend stands.
    let wb = open_workbench(dir.path()).unwrap();
    let w = wb.lock_unpoisoned();
    let st = w
        .store_ref()
        .fold::<InstanceState>(DEFAULT_INSTANCE)
        .unwrap();
    assert!(
        !st.runnable,
        "a deliberately suspended instance is not auto-resumed on reopen"
    );
    assert_eq!(st.phase, gaugedesk_core::instance::InstancePhase::Suspended);
}

/// Archetype fork (ADR 0035/0038): copies the source's config + method into a
/// fresh, independent archetype that is itself usable.
#[tokio::test]
async fn forking_an_archetype_copies_config_and_is_independent() {
    let (_d, wb) = seeded_workbench();
    let app = open_control_plane(wb);
    // a distinctive config on the source so we can prove the copy
    let (s, _) = send(
        &app,
        "PUT",
        &format!("/archetypes/{DEFAULT_AGENT}"),
        Some(r#"{"config":"{\"model\":\"src-model\"}"}"#),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    // fork it
    let (s, body) = send(
        &app,
        "POST",
        &format!("/archetypes/{DEFAULT_AGENT}/fork"),
        Some(r#"{"name":"forked"}"#),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "fork: {body}");
    let fork_id = serde_json::from_str::<serde_json::Value>(&body).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    // the fork carries the copied config
    let (_, fb) = send(&app, "GET", &format!("/archetypes/{fork_id}"), None).await;
    assert!(fb.contains("src-model"), "fork copied the config: {fb}");
    // independence: reconfigure the fork, the source is untouched
    let _ = send(
        &app,
        "PUT",
        &format!("/archetypes/{fork_id}"),
        Some(r#"{"config":"{\"model\":\"fork-model\"}"}"#),
    )
    .await;
    let (_, srcb) = send(&app, "GET", &format!("/archetypes/{DEFAULT_AGENT}"), None).await;
    assert!(
        srcb.contains("src-model") && !srcb.contains("fork-model"),
        "source unchanged: {srcb}"
    );
    // the fork is a real, runnable archetype: it can host an edit chat
    let (s, _) = send(
        &app,
        "POST",
        &format!("/archetypes/{fork_id}/chats"),
        Some(r#"{"title":"edit the fork"}"#),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
}

#[tokio::test]
async fn archetype_abilities_update_only_the_draft_manifest() {
    let (_d, wb) = seeded_workbench();
    let read_draft = |path: &str| {
        let guard = wb.lock_unpoisoned();
        let target_id = library_state::authoring_target_id(DEFAULT_AGENT);
        let workspace = guard.targets.get(&target_id).expect("authoring workspace");
        let id = library::gen_id("abilities-inspect");
        let engagement = workspace.create_engagement(&id).expect("engagement");
        let body = engagement.read_file(path).expect("draft file");
        workspace.remove_engagement(&id).expect("remove engagement");
        body
    };
    let source_before = read_draft(".whipple/draft/method.whip");
    let app = open_control_plane(wb.clone());

    let (status, body) = send(
        &app,
        "PUT",
        &format!("/archetypes/{DEFAULT_AGENT}/abilities"),
        Some(r#"{"abilities":[]}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = send(
        &app,
        "GET",
        &format!("/archetypes/{DEFAULT_AGENT}/abilities"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["abilities"],
        serde_json::json!([])
    );
    assert_eq!(read_draft(".whipple/draft/method.whip"), source_before);
    let manifest: serde_json::Value =
        serde_json::from_str(&read_draft(".whipple/draft/package.json")).unwrap();
    assert_eq!(manifest["agent_abilities"], serde_json::json!([]));

    let (status, body) = send(
        &app,
        "GET",
        &format!("/placements/{DEFAULT_PLACEMENT}/abilities"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["abilities"],
        serde_json::json!(["command.run", "workspace.read", "workspace.write"]),
        "the deployment surface must report the immutable published version, not the draft"
    );
}

/// Chat fork (ADR 0038): clone a chat into a linked new chat that inherits the
/// parent's worktree files. Runtime thread continuity is covered by the
/// WhippleScript adapter and the @live real-model fork scenario.
#[tokio::test]
async fn forking_a_chat_links_it_and_inherits_the_parent_worktree() {
    let (_d, wb) = seeded_workbench();
    let app = open_control_plane(wb);
    // a work chat (back-compat path roots it on the default placement)
    let (s, _) = send(&app, "POST", "/chats", Some(r#"{"id":"fork-src"}"#)).await;
    assert_eq!(s, StatusCode::CREATED);
    // a distinctive file in the parent's worktree
    let (s, _) = send(
        &app,
        "PUT",
        "/chats/fork-src/file?path=note.txt",
        Some("parent work"),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    // fork it
    let (s, body) = send(&app, "POST", "/chats/fork-src/fork", None).await;
    assert_eq!(s, StatusCode::CREATED, "fork: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let fork_id = v["id"].as_str().unwrap().to_string();
    assert_eq!(v["forked_from"], "fork-src", "the fork records its parent");
    // the fork's worktree inherited the parent's file
    let (s, fb) = send(
        &app,
        "GET",
        &format!("/chats/{fork_id}/file?path=note.txt"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        fb.contains("parent work"),
        "fork inherited the parent's worktree: {fb}"
    );
    // and the projection surfaces the fork lineage
    let (_, ws) = send(&app, "GET", "/workspace", None).await;
    assert!(
        ws.contains("\"forked_from\":\"fork-src\""),
        "projection shows forked_from: {ws}"
    );
}

#[tokio::test]
async fn stop_is_a_no_op_when_nothing_is_running() {
    let (_d, wb) = seeded_workbench();
    let app = open_control_plane(wb);
    let (_, body) = send(
        &app,
        "POST",
        "/archetypes/agent-default/chats",
        Some(r#"{"title":"s"}"#),
    )
    .await;
    let chat = serde_json::from_str::<serde_json::Value>(&body).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    // no turn running → stop is a clean no-op.
    let (s, body) = send(&app, "POST", &format!("/chats/{chat}/stop"), None).await;
    assert_eq!(s, StatusCode::OK, "got {body}");
    assert!(body.contains("\"stopped\":false"), "got {body}");
}

#[tokio::test]
async fn edit_chat_tasks_run_without_a_project_binding() {
    let _fake_agent = fake_agent_env();
    let (_d, wb) = seeded_workbench();
    let app = open_control_plane(wb);
    let (status, body) = send(
        &app,
        "POST",
        "/archetypes/agent-default/chats",
        Some(r#"{"title":"edit the method"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "edit chat: {body}");
    let chat = serde_json::from_str::<serde_json::Value>(&body).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let (status, body) = send(
        &app,
        "POST",
        &format!("/chats/{chat}/task"),
        Some(r#"{"prompt":"make a change","review":true}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "edit task: {body}");
    assert!(
        body.contains("agent-note.txt"),
        "fake edit turn ran: {body}"
    );
}

#[test]
fn running_turn_registry_round_trips() {
    // the out-of-band registry the Stop route reads (no workbench lock): the
    // registered interrupt handle comes back invokable, and clear removes it.
    let fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = fired.clone();
    engine::register_running_turn(
        "eng-x",
        std::sync::Arc::new(move || flag.store(true, std::sync::atomic::Ordering::SeqCst)),
    );
    let interrupt = engine::running_turn_interrupt("eng-x").expect("handle registered");
    interrupt();
    assert!(fired.load(std::sync::atomic::Ordering::SeqCst));
    engine::clear_running_turn("eng-x");
    assert!(engine::running_turn_interrupt("eng-x").is_none());
}

#[tokio::test]
async fn workstream_sync_route_is_clean_with_nothing_to_pull() {
    let (_d, wb) = seeded_workbench();
    let app = open_control_plane(wb);
    let (_, body) = send(
        &app,
        "POST",
        "/archetypes/agent-default/chats",
        Some(r#"{"title":"w"}"#),
    )
    .await;
    let chat = serde_json::from_str::<serde_json::Value>(&body).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    // syncing with nothing promoted to main is a clean no-op (WC-1 route).
    let (s, body) = send(&app, "POST", &format!("/chats/{chat}/sync"), None).await;
    assert_eq!(s, StatusCode::OK, "got {body}");
    assert!(body.contains("\"conflict\":false"), "got {body}");
}

#[tokio::test]
async fn unbinding_a_placement_tombstones_its_workstream_roots() {
    let (_d, wb) = seeded_workbench();
    let app = open_control_plane(wb.clone());
    let target_id = library_state::managed_project_target_id(DEFAULT_PROJECT);
    let (status, body) = send(
        &app,
        "POST",
        &format!("/placements/{DEFAULT_PLACEMENT}/workstreams"),
        Some(
            &serde_json::json!({
                "name": "retired with placement",
                "target_id": target_id,
            })
            .to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create workstream: {body}");
    let workstream_id = serde_json::from_str::<serde_json::Value>(&body).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let (status, body) = send(
        &app,
        "DELETE",
        &format!("/projects/{DEFAULT_PROJECT}/placements/{DEFAULT_PLACEMENT}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unbind placement: {body}");

    let guard = wb.lock_unpoisoned();
    assert!(!guard.library.workstreams.contains_key(&workstream_id));
    assert!(!guard.library.workstream_roots.contains_key(&workstream_id));
    let rebuilt = crate::library::Library::rebuild(guard.store_ref()).expect("rebuild library");
    assert!(!rebuilt.workstreams.contains_key(&workstream_id));
    assert!(!rebuilt.workstream_roots.contains_key(&workstream_id));
}

#[tokio::test]
async fn instance_lifecycle_suspend_blocks_new_chats_then_resume_allows() {
    let (_d, wb) = seeded_workbench();
    let app = open_control_plane(wb);

    // the seeded instance is active (pinned) and runnable.
    let (s, body) = send(&app, "GET", "/placements/inst-default", None).await;
    assert_eq!(s, StatusCode::OK, "got {body}");
    assert!(
        body.contains("\"runnable\":true") && body.contains("\"phase\":\"active\""),
        "got {body}"
    );

    // suspend → a new chat is rejected (SUSPEND_BLOCKS_RUN)…
    let (s, _) = send(
        &app,
        "POST",
        "/placements/inst-default/command",
        Some(r#""Suspend""#),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, body) = send(
        &app,
        "POST",
        "/archetypes/agent-default/chats",
        Some(r#"{"title":"nope"}"#),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::INTERNAL_SERVER_ERROR,
        "suspended instance rejects: {body}"
    );

    // …resume → chats work again.
    send(
        &app,
        "POST",
        "/placements/inst-default/command",
        Some(r#""Resume""#),
    )
    .await;
    let (s, _) = send(
        &app,
        "POST",
        "/archetypes/agent-default/chats",
        Some(r#"{"title":"ok"}"#),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);

    // double-pin is rejected (PIN_IMMUTABLE).
    let (s, body) = send(
        &app,
        "POST",
        "/placements/inst-default/command",
        Some(r#"{"PinVersion":"v9"}"#),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "re-pin rejected: {body}");
}

#[tokio::test]
async fn placement_config_rejects_unreadable_json_without_replacing_the_last_good_value() {
    let (_d, wb) = seeded_workbench();
    let app = open_control_plane(wb);

    let valid = r#"{"SetLocalConfig":{"config":"{\"model\":\"wiring\"}","notes":"kept"}}"#;
    let (status, body) = send(
        &app,
        "POST",
        "/placements/inst-default/command",
        Some(valid),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "valid config: {body}");

    let invalid = r#"{"SetLocalConfig":{"config":"{not json","notes":"lost"}}"#;
    let (status, body) = send(
        &app,
        "POST",
        "/placements/inst-default/command",
        Some(invalid),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "invalid config: {body}");
    assert!(body.contains("invalid placement config"), "got {body}");

    let (status, body) = send(&app, "GET", "/placements/inst-default", None).await;
    assert_eq!(status, StatusCode::OK, "placement readback: {body}");
    let placement: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(placement["local_config"], r#"{"model":"wiring"}"#);
    assert_eq!(placement["notes"], "kept");

    let notes_only = r#"{"SetLocalConfig":{"config":"","notes":"notes only"}}"#;
    let (status, body) = send(
        &app,
        "POST",
        "/placements/inst-default/command",
        Some(notes_only),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "notes-only config: {body}");
}

#[tokio::test]
async fn project_credential_override_pins_seals_and_lists() {
    // LLM-2 (ADR 0062): the per-project credential surface pins a sealed BYOK token
    // in the project scope, lists provider+linked only (never the token), and unpins.
    let (_d, wb) = seeded_workbench();
    let app = open_control_plane(wb.clone());

    let (_, body) = send(&app, "POST", "/projects", Some(r#"{"name":"client-site"}"#)).await;
    let project: serde_json::Value = serde_json::from_str(&body).unwrap();
    let pid = project["id"].as_str().unwrap().to_string();

    // No pins yet.
    let (s, body) = send(&app, "GET", &format!("/projects/{pid}/credentials"), None).await;
    assert_eq!(s, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        v["credentials"].as_array().unwrap().len(),
        0,
        "starts empty: {body}"
    );

    // Pin a provider for the project.
    let (s, _) = send(
        &app,
        "POST",
        &format!("/projects/{pid}/credentials"),
        Some(r#"{"provider":"openai","token":"proj-secret"}"#),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    {
        let g = wb.lock_unpoisoned();
        let record = crate::account::credentials_in_scope(
            g.store_ref(),
            &crate::account::project_scope(&pid),
        )
        .remove("openai")
        .unwrap();
        assert!(
            g.unseal_account_secret(&record.sealed_token).is_none(),
            "a project credential is not encrypted to the current owner's account key"
        );
        assert_eq!(
            g.unseal_project_secret(&pid, &record.sealed_token)
                .as_deref(),
            Some("proj-secret")
        );
    }

    // It lists the provider but NEVER the token (sealed at rest, INV-10).
    let (_, body) = send(&app, "GET", &format!("/projects/{pid}/credentials"), None).await;
    assert!(
        !body.contains("proj-secret"),
        "sealed token must never be returned: {body}"
    );
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["credentials"][0]["provider"], "openai", "got {body}");

    // Unpin → empty again (fall back to the account default).
    let (s, _) = send(
        &app,
        "DELETE",
        &format!("/projects/{pid}/credentials/openai"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (_, body) = send(&app, "GET", &format!("/projects/{pid}/credentials"), None).await;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        v["credentials"].as_array().unwrap().len(),
        0,
        "unpinned: {body}"
    );
}

#[tokio::test]
async fn project_creation_binds_the_serving_home_and_refuses_a_foreign_home() {
    let (_d, wb) = seeded_workbench();
    let app = open_control_plane(wb);

    let (status, body) = send(
        &app,
        "POST",
        "/projects",
        Some(r#"{"name":"wrong-home","home_id":"home:elsewhere"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    let (status, body) = send(&app, "POST", "/projects", Some(r#"{"name":"right-home"}"#)).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let created: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(created["home_id"], "home:local-user");

    let (_, workspace) = send(&app, "GET", "/workspace", None).await;
    let workspace: serde_json::Value = serde_json::from_str(&workspace).unwrap();
    let project = workspace["projects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|project| project["id"] == created["id"])
        .unwrap();
    assert_eq!(project["home_id"], "home:local-user");
    assert!(!workspace.to_string().contains("wrong-home"));
}

#[test]
fn startup_rejects_a_project_without_a_home_bound_target() {
    let dir = tempfile::tempdir().unwrap();
    let wb = open_workbench(dir.path()).unwrap();
    wb.lock_unpoisoned()
        .store_mut()
        .append_record(
            crate::library::LIBRARY_SCOPE,
            "project",
            r#"{"id":"legacy","op":"upsert","name":"Legacy","is_default":false}"#,
        )
        .unwrap();
    drop(wb);

    let error = match open_workbench(dir.path()) {
        Ok(_) => panic!("project without a Home-bound target must not open"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(error
        .to_string()
        .contains("reset this pre-release state root"));
}

#[tokio::test]
async fn project_binds_an_agent_and_hosts_a_chat() {
    let (_d, wb) = seeded_workbench();
    let app = open_control_plane(wb);

    let (_, body) = send(&app, "POST", "/projects", Some(r#"{"name":"client-site"}"#)).await;
    let project: serde_json::Value = serde_json::from_str(&body).unwrap();
    let pid = project["id"].as_str().unwrap().to_string();
    let target_id = project["target_id"].as_str().unwrap().to_string();

    // bind the default agent into the project → a using instance.
    let (s, body) = send(
        &app,
        "POST",
        &format!("/projects/{pid}/placements"),
        Some(r#"{"agent_id":"agent-default"}"#),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "got {body}");
    let iid = serde_json::from_str::<serde_json::Value>(&body).unwrap()["instance_id"]
        .as_str()
        .unwrap()
        .to_string();

    // chat under the binding.
    let (s, _) = send(
        &app,
        "POST",
        &format!("/projects/{pid}/placements/{iid}/chats"),
        Some(&format!(
            r#"{{"title":"triage","target_id":"{target_id}"}}"#
        )),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    let (_, body) = send(&app, "GET", "/workspace", None).await;
    assert!(
        body.contains("client-site") && body.contains("triage"),
        "got {body}"
    );

    // deleting the project cascades the using instance + its chats.
    let (s, _) = send(&app, "DELETE", &format!("/projects/{pid}"), None).await;
    assert_eq!(s, StatusCode::OK);
    let (_, body) = send(&app, "GET", "/workspace", None).await;
    assert!(
        !body.contains("client-site") && !body.contains("triage"),
        "got {body}"
    );
}

#[tokio::test]
async fn delete_agent_refuses_default_and_survives_restart_rehydration() {
    let (dir, wb) = seeded_workbench();
    let app = open_control_plane(wb);

    // the seed default agent can't be deleted.
    let (s, body) = send(&app, "DELETE", "/archetypes/agent-default", None).await;
    assert_eq!(s, StatusCode::CONFLICT, "got {body}");

    // create an agent + a chat, then reopen the workbench from disk.
    let (_, body) = send(&app, "POST", "/archetypes", Some(r#"{"name":"persisted"}"#)).await;
    let agent_id = serde_json::from_str::<serde_json::Value>(&body).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    send(
        &app,
        "POST",
        &format!("/archetypes/{agent_id}/chats"),
        Some(r#"{"title":"durable"}"#),
    )
    .await;

    let wb2 = open_workbench(dir.path()).unwrap();
    let app2 = open_control_plane(wb2);
    let (_, body) = send(&app2, "GET", "/workspace", None).await;
    assert!(
        body.contains("persisted") && body.contains("durable"),
        "rehydrated: {body}"
    );
}

/// ADR 0136 §3: a clean turn queues nothing. This replaces the review lifecycle
/// this test used to walk (hold → queued `review` task → keep clears it); the
/// point now is that the queue stays out of it entirely, which is the behaviour
/// the retired signal would otherwise creep back into.
#[tokio::test]
async fn a_clean_turn_queues_no_task() {
    let _fake_agent = fake_agent_env();
    let (_d, wb) = seeded_workbench();
    let app = open_control_plane(wb);
    send(&app, "POST", "/chats", Some(r#"{"id":"q1"}"#)).await;

    // A fresh workbench seeds onboarding `issue` tasks (ADR 0075); this is about
    // what a *turn* contributes.
    let (s, before) = send(&app, "GET", "/tasks", None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(!before.contains(r#""id":"q1""#), "no task yet: {before}");

    send(&app, "POST", "/chats/q1/task", Some(r#"{"prompt":"go"}"#)).await;

    let (_, after) = send(&app, "GET", "/tasks", None).await;
    assert!(
        !after.contains(r#""id":"q1""#),
        "a clean turn settles itself and asks for nothing: {after}"
    );
    let (_, merge) = send(&app, "GET", "/chats/q1/merge", None).await;
    assert!(merge.contains("Advanced"), "and it advanced: {merge}");
}

/// ADR 0096 as amended by ADR 0136: every clean turn auto-syncs, whether or not
/// it changed a file. There is no per-change hold to opt out with.
#[tokio::test]
async fn every_clean_turn_auto_advances_without_queuing() {
    let _fake_agent = fake_agent_env();
    let (_d, wb) = seeded_workbench();
    let app = open_control_plane(wb);
    send(&app, "POST", "/chats", Some(r#"{"id":"noop1"}"#)).await;

    // A no-op turn (`[no-write]` keeps the fake agent's hands off the worktree):
    // no review task; the merge advanced without a human.
    send(
        &app,
        "POST",
        "/chats/noop1/task",
        Some(r#"{"prompt":"[no-write] just think"}"#),
    )
    .await;
    let (_, body) = send(&app, "GET", "/tasks", None).await;
    assert!(
        !body.contains(r#""kind":"review""#),
        "no review for a no-op turn: {body}"
    );
    let (_, merge) = send(&app, "GET", "/chats/noop1/merge", None).await;
    assert!(merge.contains("Advanced"), "auto-advanced: {merge}");

    let (_, transcript) = send(&app, "GET", "/chats/noop1/transcript", None).await;
    assert!(
        transcript.contains("synced into Main"),
        "the shared-line settlement is visible: {transcript}"
    );

    // A file-changing turn also auto-syncs by default.
    send(
        &app,
        "POST",
        "/chats/noop1/task",
        Some(r#"{"prompt":"now write"}"#),
    )
    .await;
    let (_, body) = send(&app, "GET", "/tasks", None).await;
    assert!(
        !body.contains(r#""kind":"review""#),
        "a normal change auto-syncs: {body}"
    );
}

/// ADR 0137 §3: a message composed once runs at most once, however many times
/// it is submitted.
///
/// The composer mints an outbox id when a message is *composed* and sends it as
/// the turn's `Idempotency-Key`. A client that dies between handing the message
/// to the transport and hearing back can therefore resend it: the command
/// envelope recognises the key and refuses, rather than the client having to
/// choose between losing the message and running the turn twice.
///
/// Reading the transcript is the assertion that matters. A refused *request* is
/// only evidence about HTTP; one user line in durable truth is evidence about
/// what actually happened to the chat.
#[tokio::test]
async fn a_message_resent_under_its_composed_id_runs_exactly_one_turn() {
    let _fake_agent = fake_agent_env();
    let (_d, wb) = seeded_workbench();
    let app = open_control_plane(wb);
    send(&app, "POST", "/chats", Some(r#"{"id":"idem1"}"#)).await;

    let composed = "outbox-9f2c";
    let body = r#"{"prompt":"[no-write] book the room"}"#;
    let (first, first_body) =
        send_with_key(&app, "POST", "/chats/idem1/task", Some(body), composed).await;
    assert_eq!(
        first,
        StatusCode::OK,
        "the first submission runs: {first_body}"
    );

    // The resend after an uncertain dispatch. Same composed id, same bytes.
    let (second, second_body) =
        send_with_key(&app, "POST", "/chats/idem1/task", Some(body), composed).await;
    assert_eq!(
        second,
        StatusCode::CONFLICT,
        "a resend under the composed id must be refused, not run: {second_body}"
    );
    assert!(
        second_body.contains(r#""command_status":"applied""#),
        "the refusal has to say the turn already ran — `applied` is what lets the \
         composer clear the message instead of setting it aside: {second_body}"
    );

    let (_, transcript) = send(&app, "GET", "/chats/idem1/transcript", None).await;
    assert_eq!(
        transcript.matches("book the room").count(),
        1,
        "one composed message, one user line in durable truth: {transcript}"
    );

    // A *different* composed message is a different command and still runs.
    let (other, other_body) = send_with_key(
        &app,
        "POST",
        "/chats/idem1/task",
        Some(r#"{"prompt":"[no-write] and the projector"}"#),
        "outbox-4a11",
    )
    .await;
    assert_eq!(
        other,
        StatusCode::OK,
        "dedupe is per composed id, not a lock on the chat: {other_body}"
    );
}

/// ADR 0082 §2: each chat task is typed by its **ask** — a conflicted merge
/// queues `repair` (not `review`), and a turn suspended on a human question
/// queues `answer` (outranking merge state).
#[tokio::test]
async fn task_queue_types_asks_repair_and_answer() {
    let _fake_agent = fake_agent_env();
    let (_d, wb) = seeded_workbench();
    let wb2 = std::sync::Arc::clone(&wb);
    let app = open_control_plane(wb);

    // Two chats cut from the same base. rb runs first and its clean turn settles
    // itself into Main; ra then writes the same file from the stale base, so ra's
    // own auto-sync hits the add/add race and ra owns the repair. (Before ADR 0136
    // this was staged by holding rb for review — with no hold left, the ordinary
    // settle order produces the same race.)
    send(&app, "POST", "/chats", Some(r#"{"id":"ra"}"#)).await;
    send(&app, "POST", "/chats", Some(r#"{"id":"rb"}"#)).await;
    send(&app, "POST", "/chats/rb/task", Some(r#"{"prompt":"beta"}"#)).await;
    send(
        &app,
        "POST",
        "/chats/ra/task",
        Some(r#"{"prompt":"alpha"}"#),
    )
    .await;
    // Put ra's merge into the conflicted state directly. Before ADR 0136 this test
    // manufactured the add/add race by holding rb's candidate for review, which
    // stopped rb auto-pulling; with every clean turn settling itself there is no
    // lever to stage that race from the outside. The subject here is ask *typing*
    // — which durable state produces which task kind — so the state is admitted
    // the same way the open question below is.
    {
        let mut guard = wb2.lock_unpoisoned();
        let store = guard.store_mut();
        store
            .admit::<gaugedesk_core::merge::MergeState>(
                "ra",
                gaugedesk_core::merge::MergeCommand::StartMerge,
            )
            .expect("re-enter the merge lifecycle");
        store
            .admit::<gaugedesk_core::merge::MergeState>(
                "ra",
                gaugedesk_core::merge::MergeCommand::WorkspaceConflict,
            )
            .expect("the workspace reports a conflict");
    }
    let (_, body) = send(&app, "GET", "/tasks", None).await;
    assert!(
        body.contains(r#""id":"ra""#) && body.contains(r#""kind":"repair""#),
        "conflicted chat queues repair: {body}"
    );

    // An agent's open question outranks the chat's merge state (ADR 0111: the
    // question is a tracker item now, not a parked run phase).
    wb2.lock_unpoisoned()
        .ask_question("ra", "Which environment?", &[], None, false)
        .expect("the agent asks");
    let (_, body) = send(&app, "GET", "/tasks", None).await;
    assert!(
        body.contains(r#""kind":"answer""#),
        "an open question queues answer: {body}"
    );
    assert!(
        !body.contains(r#""kind":"repair""#),
        "answer outranks repair for the same chat: {body}"
    );
}

/// ATTN-2 (ADR 0082 §3): the operator's attention rules re-shape the queue —
/// muting `changes` drops the review task *and* its nav badge, while opting
/// `turn-settled` into the queue raises the `reply` ask the defaults never show
/// (the muted signal falls through; it does not silence the chat).
#[tokio::test]
async fn attention_rules_reshape_queue_and_badges() {
    let _fake_agent = fake_agent_env();
    let (_d, wb) = seeded_workbench();
    let wb2 = std::sync::Arc::clone(&wb);
    let app = open_control_plane(wb);
    send(&app, "POST", "/chats", Some(r#"{"id":"at1"}"#)).await;
    send(&app, "POST", "/chats/at1/task", Some(r#"{"prompt":"go"}"#)).await;
    // Conflict is the signal this exercises now that `changes` is retired
    // (ADR 0136 §3). Admitted directly: the point is the rules, not the race.
    {
        let mut guard = wb2.lock_unpoisoned();
        let store = guard.store_mut();
        store
            .admit::<gaugedesk_core::merge::MergeState>(
                "at1",
                gaugedesk_core::merge::MergeCommand::StartMerge,
            )
            .expect("re-enter the merge lifecycle");
        store
            .admit::<gaugedesk_core::merge::MergeState>(
                "at1",
                gaugedesk_core::merge::MergeCommand::WorkspaceConflict,
            )
            .expect("the workspace reports a conflict");
    }

    // Defaults: the conflict queues `repair`; no `reply` pill.
    let (_, body) = send(&app, "GET", "/tasks", None).await;
    assert!(
        body.contains(r#""kind":"repair""#) && !body.contains(r#""kind":"reply""#),
        "defaults hold: {body}"
    );

    // Mute `conflict`, opt `turn-settled` into the queue.
    let rules = serde_json::json!({
        "value": r#"{"version":1,"rules":[{"signal":"conflict","attention":"mute"},{"signal":"turn-settled","attention":"queue"}]}"#
    })
    .to_string();
    let (s, _) = send(
        &app,
        "PUT",
        "/account/settings/attention.rules",
        Some(&rules),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    let (_, body) = send(&app, "GET", "/tasks", None).await;
    assert!(!body.contains(r#""kind":"repair""#), "repair muted: {body}");
    assert!(
        body.contains(r#""id":"at1""#) && body.contains(r#""kind":"reply""#),
        "reply queued via fall-through: {body}"
    );

    // The muted signal's nav badge goes with it (badge surface, same rules).
    let (_, ws) = send(&app, "GET", "/workspace", None).await;
    let v: serde_json::Value = serde_json::from_str(&ws).unwrap();
    let chat = v["recent"]
        .as_array()
        .and_then(|chats| chats.iter().find(|c| c["id"] == "at1"))
        .expect("at1 in recent")
        .clone();
    assert_eq!(
        chat["conflict"], false,
        "muted conflict shows no badge: {chat}"
    );
}

/// ADR 0096 supersedes the old default-hold posture: advancement policy may not
/// turn an explicit per-change review back into an automatic advance.
#[tokio::test]
async fn advancement_rules_auto_advance_covered_turns_only() {
    let _fake_agent = fake_agent_env();
    let (_d, wb) = seeded_workbench();
    let app = open_control_plane(wb);

    // A rule covering the fake agent's write (`agent-note.txt` at the root).
    let rules = serde_json::json!({
        "value": r#"{"version":1,"rules":[{"advance":"writes-within","paths":["*.txt"]}]}"#
    })
    .to_string();
    send(
        &app,
        "PUT",
        "/account/settings/advancement.rules",
        Some(&rules),
    )
    .await;

    send(&app, "POST", "/chats", Some(r#"{"id":"adv1"}"#)).await;
    send(&app, "POST", "/chats/adv1/task", Some(r#"{"prompt":"go"}"#)).await;
    let (_, merge) = send(&app, "GET", "/chats/adv1/merge", None).await;
    assert!(
        merge.contains("Advanced"),
        "covered turn auto-advanced: {merge}"
    );
    let (_, body) = send(&app, "GET", "/tasks", None).await;
    assert!(
        !body.contains(r#""kind":"review""#),
        "no review queued: {body}"
    );
    // Narrowing the old policy also does not change the new auto-sync default.
    let rules = serde_json::json!({
        "value": r#"{"version":1,"rules":[{"advance":"writes-within","paths":["docs/**"]}]}"#
    })
    .to_string();
    send(
        &app,
        "PUT",
        "/account/settings/advancement.rules",
        Some(&rules),
    )
    .await;
    send(&app, "POST", "/chats", Some(r#"{"id":"adv2"}"#)).await;
    send(&app, "POST", "/chats/adv2/task", Some(r#"{"prompt":"go"}"#)).await;
    let (_, merge) = send(&app, "GET", "/chats/adv2/merge", None).await;
    assert!(
        merge.contains("Advanced"),
        "ordinary turn auto-syncs: {merge}"
    );
}

#[tokio::test]
async fn admitted_run_events_reach_the_live_stream() {
    let (_d, wb) = workbench();
    // Subscribe before driving commands (as an SSE client would).
    let mut rx = wb.lock_unpoisoned().sender("eng-stream").subscribe();
    let app = open_control_plane(wb);

    for cmd in ["\"RequestRun\"", "\"AdmitRun\"", "\"StartRun\""] {
        let (s, _) = send(&app, "POST", "/scopes/eng-stream/run/command", Some(cmd)).await;
        assert_eq!(s, StatusCode::OK);
    }

    // Each admitted command published an `admitted` event in order.
    let mut phases = Vec::new();
    for _ in 0..3 {
        match rx.recv().await.unwrap() {
            ServerEvent::Admitted { text, .. } => phases.push(text),
            other => panic!("expected admitted, got {other:?}"),
        }
    }
    assert!(phases[0].contains("Requested"));
    assert!(phases[1].contains("Admitted"));
    assert!(phases[2].contains("Running"));
}

/// The onboarding checklist (ADR 0075 Phase 2/3) is seeded on a fresh workbench,
/// surfaces as `issue` tasks in the unified `/tasks` projection, and advances
/// when the matching app event fires — here, connecting an LLM credential closes
/// the "credential" step end-to-end through the HTTP surface.
#[tokio::test]
async fn onboarding_checklist_appears_and_advances_on_credential() {
    // Onboarding is gated off under the fake agent; pin the real runtime (and
    // serialize against fake-agent tests) so the checklist actually seeds.
    let _real = crate::test_support::real_agent_env();
    let dir = tempfile::tempdir().unwrap();
    let wb = crate::workbench_state::build_workbench(dir.path()).unwrap();
    let app = open_control_plane(Arc::new(Mutex::new(wb)));

    // The seeded onboarding steps show up as `issue` tasks, each with an assignee.
    let (status, body) = send(&app, "GET", "/tasks", None).await;
    assert_eq!(status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let tasks = v["tasks"].as_array().unwrap();
    let issue_titles = |v: &serde_json::Value| -> Vec<String> {
        v["tasks"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|t| t["kind"] == "issue")
            .filter_map(|t| t["title"].as_str().map(str::to_owned))
            .collect()
    };
    let titles = issue_titles(&v);
    assert!(
        titles.iter().any(|t| t == "Connect a model"),
        "expected the credential onboarding step, got {titles:?}"
    );
    assert!(titles.iter().any(|t| t == "Create a project"));
    assert!(
        tasks.iter().all(|t| t["assignee"].is_string()),
        "every task carries an assignee authority (ADR 0075 §4)"
    );

    // Connecting a credential fires app.credential_connected, which closes the step.
    let (status, _) = send(
        &app,
        "POST",
        "/account/credentials",
        Some(r#"{"provider":"anthropic","token":"sk-test-xyz"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (_, body) = send(&app, "GET", "/tasks", None).await;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let titles = issue_titles(&v);
    assert!(
        !titles.iter().any(|t| t == "Connect a model"),
        "the credential step should be closed after linking, got {titles:?}"
    );
    assert!(
        titles.iter().any(|t| t == "Create a project"),
        "unrelated onboarding steps stay open"
    );
}

/// Every project has a gate from creation, and it is review-by-hand.
///
/// ADR 0117 §7. This asserts the seeding — that the two files land in the
/// project's *target mainline*, so every chat rooted there sees the same gate
/// and changing it is an ordinary diff (ADR 0110 §5).
///
/// It asserts `gate::admit` too, not just that two files exist: two files pass
/// on any two files, while what makes a gate a gate is that it compiles and its
/// flows satisfy its own envelope. That assertion was impossible until
/// WhippleScript DR-0051 gave a person's decision an integrity crossing.
#[tokio::test]
async fn every_project_is_created_with_the_default_gate() {
    let (d, wb) = seeded_workbench();
    let app = open_control_plane(wb);

    // The project every account starts with.
    let personal = d
        .path()
        .join("targets")
        .join(library_state::managed_project_target_id(DEFAULT_PROJECT))
        .join("repo");
    assert_eq!(
        std::fs::read_to_string(personal.join(crate::gate::GATE_PROGRAM_PATH)).unwrap(),
        crate::gate::REVIEW_BY_HAND_GATE,
        "Personal is seeded with the default gate",
    );
    crate::gate::admit_installed(&personal)
        .expect("Personal's seeded gate compiles and satisfies its envelope");

    // And one created through the ordinary route.
    let (status, body) = send(
        &app,
        "POST",
        "/projects",
        Some(&serde_json::json!({ "name": "Field research" }).to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "project created: {body}");
    let created: serde_json::Value = serde_json::from_str(&body).unwrap();
    let target = created["target_id"].as_str().expect("a files target");
    let seeded = d.path().join("targets").join(target).join("repo");
    assert_eq!(
        std::fs::read_to_string(seeded.join(crate::gate::GATE_PROGRAM_PATH)).unwrap(),
        crate::gate::REVIEW_BY_HAND_GATE,
        "a new project is seeded with the default gate",
    );
    crate::gate::admit_installed(&seeded)
        .expect("a new project's seeded gate compiles and satisfies its envelope");
}

/// `GATE-3f`: `assigned_to` is a roster authority, and assignment stays advisory.
///
/// The advisory half is the decision the row asked for, and it is enforced here
/// rather than only documented: WhippleScript kept assignment advisory because it
/// lacks an authority model, GaugeDesk *has* one and still does not gate claiming.
/// Enforcing "only the assignee may claim" turns an away assignee into stuck work,
/// which inverts the premise of a shared queue. Exclusivity is `claim`'s job, and
/// it is earned by taking the work rather than granted by being named.
#[tokio::test]
async fn assignment_binds_to_the_roster_and_never_gates_a_claim() {
    let (_dir, wb) = workbench();
    let boundary = crate::workbench_state::ACCOUNT_GLOBAL_BOUNDARY;

    let (owner, filed) = {
        let mut guard = wb.lock_unpoisoned();
        let owner = guard.authority().as_str().to_owned();
        let tracker = guard.tracker_for_boundary(boundary).expect("tracker opens");
        let item = tracker
            .file_item(
                crate::onboarding::ONBOARDING_QUEUE,
                "Someone should look at this",
                "",
                &[],
                &serde_json::Value::Null,
                Some("agent"),
            )
            .expect("the issue files");
        (owner, item.id)
    };

    // A name nobody on the roster answers to is refused, and the refusal names
    // who could have been chosen.
    let refusal = wb
        .lock_unpoisoned()
        .assign_work_item(boundary, &filed, Some("nobody@example.com"))
        .expect_err("an off-roster assignee is refused");
    assert!(
        matches!(refusal, crate::roster::AssignError::NotOnRoster { .. }),
        "refused for being off-roster: {refusal}",
    );
    assert!(
        refusal.to_string().contains(&owner),
        "names the roster: {refusal}"
    );

    // The acting authority is on it, so assigning to them resolves to an
    // authority rather than storing whatever string arrived.
    let assigned = wb
        .lock_unpoisoned()
        .assign_work_item(boundary, &filed, Some(&owner))
        .expect("the owner is on the roster");
    assert_eq!(assigned.as_deref(), Some(owner.as_str()));
    let projected = wb.lock_unpoisoned().task_queue_value();
    assert_eq!(projected["tasks"][0]["id"], filed);
    assert_eq!(projected["tasks"][0]["boundary"], boundary);
    assert_eq!(projected["tasks"][0]["assignee"], owner);

    // ...and somebody else can still claim it. This is the load-bearing
    // assertion: the assignment is a recommendation, not a lock.
    let outcome = wb
        .lock_unpoisoned()
        .tracker_for_boundary(boundary)
        .expect("tracker opens")
        .claim_item(&filed, "someone-else", None)
        .expect("a claim is admitted");
    // `Claimed` is the claim being taken. A refused one reports the existing
    // holder or a conflict instead — so this asserts the claim went through for
    // somebody the item was not assigned to.
    assert_eq!(
        format!("{outcome:?}"),
        "Claimed",
        "a non-assignee may claim",
    );

    // Clearing it means "whoever has access" — the inbox default, not an error.
    let cleared = wb
        .lock_unpoisoned()
        .assign_work_item(boundary, &filed, None)
        .expect("clearing is allowed");
    assert_eq!(cleared, None);
    assert!(
        wb.lock_unpoisoned().task_queue_value()["tasks"][0]["assignee"].is_null(),
        "the task projection must read admitted assignment, not synthesize the acting owner",
    );
}

/// CMP-17 reproduction under instrumentation.
///
/// Chats on one placement share a target workspace, so their turns contend on a
/// single `branches.sqlite` / `content.sqlite`. A steer is `task → stop → task`,
/// which puts one turn's workspace commit against the next turn's materialize.
/// This drives that shape hard and records the wall time of anything that fails,
/// because the timing is what distinguishes the two candidate mechanisms:
/// a `busy_timeout` of 5 s expiring looks like a ~5 s failure, and an immediate
/// `SQLITE_BUSY` (no handler, or a deadlock SQLite refuses to wait on) looks like
/// a fast one.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "CMP-17: reproduces an upstream defect and fails until it is fixed; \
            run with `--ignored` to reproduce or to check"]
async fn cmp17_busy_under_steer_pressure() {
    let _fake_agent = fake_agent_env();
    let (_d, wb) = seeded_workbench();
    let app = open_control_plane(wb);

    const CHATS: usize = 6;
    const ROUNDS: usize = 4;

    let mut chats = Vec::new();
    for n in 0..CHATS {
        let (status, body) = send(
            &app,
            "POST",
            "/chats",
            Some(&format!(r#"{{"id":"busy{n}"}}"#)),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "create busy{n}: {body}");
        chats.push(format!("busy{n}"));
    }

    let failures = std::sync::Arc::new(std::sync::Mutex::new(Vec::<(String, u128, String)>::new()));
    for round in 0..ROUNDS {
        let mut handles = Vec::new();
        for chat in &chats {
            let app = app.clone();
            let chat = chat.clone();
            let failures = std::sync::Arc::clone(&failures);
            handles.push(tokio::spawn(async move {
                let record =
                    |what: &str, started: std::time::Instant, status: StatusCode, body: String| {
                        if status != StatusCode::OK && status != StatusCode::CREATED {
                            failures.lock().unwrap().push((
                                format!("{what} r{round}"),
                                started.elapsed().as_millis(),
                                body,
                            ));
                        }
                    };
                // A turn that holds itself open, so the stop lands mid-flight.
                let slow = tokio::spawn({
                    let app = app.clone();
                    let chat = chat.clone();
                    async move {
                        let at = std::time::Instant::now();
                        let (s, b) = send(
                            &app,
                            "POST",
                            &format!("/chats/{chat}/task"),
                            Some(r#"{"prompt":"[slow] original"}"#),
                        )
                        .await;
                        (at, s, b)
                    }
                });
                tokio::time::sleep(std::time::Duration::from_millis(400)).await;
                let at = std::time::Instant::now();
                let (s, b) = send(&app, "POST", &format!("/chats/{chat}/stop"), None).await;
                record("stop", at, s, b);

                let (at, s, b) = slow.await.unwrap();
                record("slow-task", at, s, b);

                // The steered message: lands while the stopped turn is settling.
                let at = std::time::Instant::now();
                let (s, b) = send(
                    &app,
                    "POST",
                    &format!("/chats/{chat}/task"),
                    Some(r#"{"prompt":"redirect"}"#),
                )
                .await;
                record("steered-task", at, s, b);
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }
    }

    let failures = failures.lock().unwrap();
    let busy: Vec<_> = failures
        .iter()
        .filter(|(_, _, body)| body.contains("DatabaseBusy"))
        .collect();
    assert!(
        failures.is_empty(),
        "{} request(s) failed, {} of them SQLITE_BUSY:\n{}",
        failures.len(),
        busy.len(),
        failures
            .iter()
            .map(|(what, ms, body)| format!(
                "  {what} after {ms}ms: {}",
                body.chars().take(160).collect::<String>()
            ))
            .collect::<Vec<_>>()
            .join("\n"),
    );
}
