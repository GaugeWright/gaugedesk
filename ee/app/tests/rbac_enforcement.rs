//! Live-route RBAC enforcement (M3 `RBAC-5`). With an `IdentityProvider` wired
//! (enterprise mode) and the org directory provisioned, the `/admin/*` routes are
//! gated by the actor's directory role: an `owner`/`admin` token is admitted, a
//! `member` token is forbidden, an unauthenticated/garbage token is unauthorized.
//! Single-user local mode (no IdP) stays ungated — covered by `org_admin.rs`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

use gaugedesk_app::identity::LoopbackIdentityProvider;
use gaugedesk_app::library::{
    Admission, ChatRecord, ChatTargetBindingRecord, InstanceKind, InstanceRecord,
    PlacementTargetsRecord, ProjectRecord, RecordOp, TargetCapabilities, LIBRARY_SCOPE,
};
use gaugedesk_app::org::{
    tenant_scope, MembershipRecord, MembershipStatus, RecordOp as OrgRecordOp, ORG_ID, ORG_SCOPE,
};
use gaugedesk_app::{resource_store, Workbench};
use gaugedesk_core::abac::AuthorityAttributes;
use gaugedesk_core::boundary::Authority;
use gaugedesk_core::ids::AuthorityId;
use gaugedesk_core::resource::{
    ContentLocator, Resource, ResourceId, ResourceKind, ResourceRecord,
};
use gaugedesk_ee::org_routes::enterprise_control_plane;
use gaugedesk_store::Store;
use gaugedesk_workspace::Instance;

mod support;
use support::{administration_command, administration_document};

fn active_member(authority: &str, role: &str, team: Option<&str>) -> MembershipRecord {
    MembershipRecord {
        id: authority.into(),
        op: OrgRecordOp::Upsert,
        org_id: ORG_ID.into(),
        authority: authority.into(),
        email: format!("{authority}@example.test"),
        role: role.into(),
        status: MembershipStatus::Active,
        managed_by_scim: false,
        team: team.map(str::to_owned),
    }
}

fn seed_members(store: &mut Store, members: &[(&str, &str, Option<&str>)]) {
    for (authority, role, team) in members {
        store
            .append_record(
                ORG_SCOPE,
                "membership",
                &serde_json::to_string(&active_member(authority, role, *team)).unwrap(),
            )
            .unwrap();
    }
}

fn workbench_with_idp() -> (tempfile::TempDir, Router) {
    let (dir, app, _workbench) = workbench_with_idp_shared();
    (dir, app)
}

fn workbench_with_idp_shared() -> (tempfile::TempDir, Router, Arc<Mutex<Workbench>>) {
    let dir = tempfile::tempdir().unwrap();
    let instance = Instance::init(dir.path().join("repo"), dir.path().join("wt")).unwrap();
    let mut store = Store::open_in_memory().unwrap();
    seed_members(
        &mut store,
        &[
            ("owner-auth", "owner", None),
            ("member-auth", "member", None),
            ("viewer-auth", "viewer", None),
            ("admin-a", "admin", Some("A")),
            ("auditor-auth", "auditor", None),
            ("billing-auth", "billing", None),
            ("alice", "member", Some("A")),
            ("bob", "member", Some("B")),
        ],
    );
    // The IdP only authenticates a token → authority; the *role* is read from the
    // directory (Org::role_of), so default attributes are fine here.
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
        )
        .enroll(
            "viewer-token",
            AuthorityId::new("viewer-auth"),
            AuthorityAttributes::default(),
        )
        .enroll(
            "admin-a-token",
            AuthorityId::new("admin-a"),
            AuthorityAttributes::default(),
        )
        .enroll(
            "auditor-token",
            AuthorityId::new("auditor-auth"),
            AuthorityAttributes::default(),
        )
        .enroll(
            "billing-token",
            AuthorityId::new("billing-auth"),
            AuthorityAttributes::default(),
        )
        .enroll(
            "outsider-token",
            AuthorityId::new("outsider-auth"),
            AuthorityAttributes::default(),
        );
    let wb =
        Workbench::with_target("inst-test", instance, store).with_identity_provider(Arc::new(idp));
    let shared = Arc::new(Mutex::new(wb));
    (dir, enterprise_control_plane(Arc::clone(&shared)), shared)
}

/// A workbench (enterprise mode) whose library already holds a project `proj-acme` with a
/// placement `i-acme` and a chat `chat-acme` on it — so the ENTSEC-2 path resolver can map a
/// `/chats/chat-acme/*` or `/projects/proj-acme/*` request to its project. Enrolls an owner plus
/// two plain consultants (`consultant-a`, `consultant-b`) in the IdP.
fn workbench_with_scoped_project() -> (tempfile::TempDir, Router) {
    workbench_with_scoped_project_cfg(false)
}

/// As [`workbench_with_scoped_project`], with `audit_reads` controlling SECAUD-4
/// sensitive-read auditing (off in the default harness).
fn workbench_with_scoped_project_cfg(audit_reads: bool) -> (tempfile::TempDir, Router) {
    let dir = tempfile::tempdir().unwrap();
    let instance = Instance::init(dir.path().join("repo"), dir.path().join("wt")).unwrap();
    let mut store = Store::open_in_memory().unwrap();
    seed_members(
        &mut store,
        &[
            ("owner-auth", "owner", None),
            ("consultant-a", "member", None),
            ("consultant-b", "member", None),
        ],
    );
    // Seed the library: a project, a using-instance bound into it, and a chat on that instance.
    let project = ProjectRecord {
        schema: gaugedesk_app::library::LIBRARY_RECORD_SCHEMA,
        extra: Default::default(),
        id: "proj-acme".into(),
        op: RecordOp::Upsert,
        name: "Acme".into(),
        is_default: false,
        home_id: gaugedesk_core::ids::HomeId::new("home:local-user"),
        network_isolated: false,
        run_purpose: None,
        deployment_mode: None,
    };
    let placement = InstanceRecord {
        schema: gaugedesk_app::library::LIBRARY_RECORD_SCHEMA,
        extra: Default::default(),
        id: "i-acme".into(),
        op: RecordOp::Upsert,
        kind: InstanceKind::Using,
        placement_kind: gaugedesk_app::library::PlacementKind::Work,
        agent_id: "a1".into(),
        project_id: Some("proj-acme".into()),
        version: 1,
        admission: Admission::Active,
        collection_recipient: None,
    };
    let chat = ChatRecord {
        schema: gaugedesk_app::library::LIBRARY_RECORD_SCHEMA,
        extra: Default::default(),
        id: "chat-acme".into(),
        op: RecordOp::Upsert,
        instance_id: "i-acme".into(),
        title: "Acme work".into(),
        created_position: 1,
        forked_from: None,
        forked_from_entry: None,
        forked_from_cut: None,
    };
    store
        .append_record(
            LIBRARY_SCOPE,
            "project",
            &serde_json::to_string(&project).unwrap(),
        )
        .unwrap();
    store
        .append_record(
            LIBRARY_SCOPE,
            "instance",
            &serde_json::to_string(&placement).unwrap(),
        )
        .unwrap();
    store
        .append_record(
            LIBRARY_SCOPE,
            "chat",
            &serde_json::to_string(&chat).unwrap(),
        )
        .unwrap();
    store
        .append_record(
            LIBRARY_SCOPE,
            "placement_targets",
            &serde_json::to_string(&PlacementTargetsRecord {
                schema: gaugedesk_app::library::LIBRARY_RECORD_SCHEMA,
                extra: Default::default(),
                placement_id: "i-acme".into(),
                op: RecordOp::Upsert,
                target_ids: vec!["inst-test".into()],
            })
            .unwrap(),
        )
        .unwrap();
    store
        .append_record(
            LIBRARY_SCOPE,
            "chat_target",
            &serde_json::to_string(&ChatTargetBindingRecord {
                schema: gaugedesk_app::library::LIBRARY_RECORD_SCHEMA,
                extra: Default::default(),
                chat_id: "chat-acme".into(),
                op: RecordOp::Upsert,
                target_id: "inst-test".into(),
                basis: "test-basis".into(),
                path_scope: vec![".".into()],
                capabilities: TargetCapabilities::managed_default(),
            })
            .unwrap(),
        )
        .unwrap();
    let idp = LoopbackIdentityProvider::new()
        .enroll(
            "owner-token",
            AuthorityId::new("owner-auth"),
            AuthorityAttributes::default(),
        )
        .enroll(
            "a-token",
            AuthorityId::new("consultant-a"),
            AuthorityAttributes::default(),
        )
        .enroll(
            "b-token",
            AuthorityId::new("consultant-b"),
            AuthorityAttributes::default(),
        );
    let mut wb = Workbench::with_target("inst-test", instance, store)
        .with_identity_provider(Arc::new(idp))
        .with_audit_reads(audit_reads);
    wb.rebuild_library(); // fold the seeded library records into the projection
    (dir, enterprise_control_plane(Arc::new(Mutex::new(wb))))
}

async fn send(
    app: &Router,
    method: &str,
    uri: &str,
    body: Option<&str>,
    token: Option<&str>,
) -> (StatusCode, Value) {
    send_client(app, method, uri, body, token, None).await
}

async fn send_client(
    app: &Router,
    method: &str,
    uri: &str,
    body: Option<&str>,
    token: Option<&str>,
    client: Option<(&str, u32, &str, &str)>,
) -> (StatusCode, Value) {
    let mut b = Request::builder().method(method).uri(uri);
    static NEXT_KEY: AtomicU64 = AtomicU64::new(1);
    if method != "GET" && method != "HEAD" && method != "OPTIONS" {
        b = b.header(
            "idempotency-key",
            format!("rbac-test-{}", NEXT_KEY.fetch_add(1, Ordering::Relaxed)),
        );
    }
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    if let Some((version, protocol, channel, platform)) = client {
        b = b
            .header("x-gaugedesk-client-version", version)
            .header("x-gaugedesk-client-protocol", protocol)
            .header("x-gaugedesk-client-channel", channel)
            .header("x-gaugedesk-client-platform", platform);
    }
    let req = match body {
        Some(body) => b
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        None => b.body(Body::empty()).unwrap(),
    };
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn admin(
    app: &Router,
    token: Option<&str>,
    document: &str,
    command: &str,
    payload: Value,
) -> (StatusCode, Value) {
    administration_command(app, None, token, document, command, payload).await
}

async fn admin_document(app: &Router, token: &str, document_id: &str) -> (StatusCode, Value) {
    let (status, response) = administration_document(app, None, Some(token), document_id).await;
    (status, response["document"]["content"].clone())
}

async fn admin_document_for_client(
    app: &Router,
    token: &str,
    document_id: &str,
    client: (&str, u32, &str, &str),
) -> (StatusCode, Value) {
    let (status, opened) = send_client(
        app,
        "POST",
        "/environments/administration/sessions",
        Some("{}"),
        Some(token),
        Some(client),
    )
    .await;
    if status != StatusCode::OK {
        return (status, opened);
    }
    let session = &opened["session"];
    let uri = format!(
        "/environments/administration/documents/{document_id}?session={}&scope={}",
        session["id"].as_str().unwrap(),
        session["scope"]["id"].as_str().unwrap(),
    );
    let (status, response) = send_client(app, "GET", &uri, None, Some(token), Some(client)).await;
    (status, response["document"]["content"].clone())
}

async fn update_security(app: &Router, token: &str, patch: Value) -> (StatusCode, Value) {
    let (status, document) =
        administration_document(app, None, Some(token), "administration.policy").await;
    if status != StatusCode::OK {
        return (status, document);
    }
    let mut content = document["document"]["content"].clone();
    if !content["security"].is_object() {
        content["security"] = serde_json::json!({});
    }
    for (key, value) in patch.as_object().unwrap() {
        content["security"][key] = value.clone();
    }
    admin(
        app,
        Some(token),
        "administration.policy",
        "policy.update",
        content,
    )
    .await
}

#[tokio::test]
async fn enterprise_mode_gates_admin_routes_by_role() {
    let (_dir, app) = workbench_with_idp();

    // An enrolled ordinary member reads the placement floor before local
    // pairing admission; this recovery/enforcement read is not console RBAC.
    let (s, policy) = send(
        &app,
        "GET",
        "/admin/placement-policy",
        None,
        Some("member-token"),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "member reads placement floor: {policy}");
    assert_eq!(policy["placement_policy"]["require_attested"], false);

    // The account/tenant provisioner seeded the owner. The owner token may propose
    // and approve a new member invitation through Administration.
    let (s, _) = admin(
        &app,
        Some("owner-token"),
        "administration.access",
        "member.invite",
        serde_json::json!({"authority":"new-member","role":"member"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "owner manages members");

    // A member token lacks ManageMembers → 403.
    let (s, _) = admin(
        &app,
        Some("member-token"),
        "administration.access",
        "member.invite",
        serde_json::json!({"authority":"q","role":"member"}),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "member cannot manage members");

    // No credential → 401.
    let (s, _) = admin(
        &app,
        None,
        "administration.access",
        "member.invite",
        serde_json::json!({"authority":"q","role":"member"}),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::UNAUTHORIZED,
        "anonymous is unauthorized once provisioned"
    );

    // Unrecognized credential → 401 (authentication fails).
    let (s, _) = admin(
        &app,
        Some("bogus-token"),
        "administration.access",
        "member.invite",
        serde_json::json!({"authority":"q","role":"member"}),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "garbage token is unauthorized");

    // Reads need Environment admission: a member sees no Administration document
    // (403), while the owner reads the canonical access projection (200).
    let (s, _) =
        administration_document(&app, None, Some("member-token"), "administration.access").await;
    assert_eq!(s, StatusCode::FORBIDDEN, "member has no console");
    let (s, body) = admin_document(&app, "owner-token", "administration.access").await;
    assert_eq!(s, StatusCode::OK);
    assert!(body["members"].as_array().unwrap().len() >= 2);
}

/// The hosted enterprise router authenticates people into one shared process.
/// Library sync signs and opens with a sovereign account root held by one local
/// Workbench, so mounting it here would let any accepted person operate on the
/// process-default account instead of their own. It is desktop-only until a
/// person-bound custody mechanism exists.
#[tokio::test]
async fn hosted_account_session_cannot_reach_process_default_library_sync_key() {
    let (_dir, app) = workbench_with_idp();
    for path in ["/account/library-sync", "/account/library-sync/pull"] {
        let (status, body) = send(&app, "POST", path, Some("{}"), Some("owner-token")).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{path} reached hosted state: {body}"
        );
        assert_eq!(
            body,
            Value::Null,
            "{path} returned a hosted handler response"
        );
    }
}

#[tokio::test]
async fn capability_discovery_is_tenant_scoped_and_role_derived() {
    let (_dir, app) = workbench_with_idp();

    // The tenant provisioner has already established its owner. Anonymous discovery
    // cannot infer Administration from the route or manifest.
    let (status, body) = send(&app, "GET", "/admin/capabilities", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    let (status, owner) = send(
        &app,
        "GET",
        "/admin/capabilities",
        None,
        Some("owner-token"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // ADR 0149: the matrix grew to nine capabilities; the owner holds every one.
    assert_eq!(owner["capabilities"].as_array().unwrap().len(), 9);
    {
        let owner_caps = owner["capabilities"].as_array().unwrap();
        for expected in [
            "manage_org_lifecycle",
            "grant_privileged_roles",
            "manage_billing",
            "view_audit",
        ] {
            assert!(
                owner_caps.iter().any(|c| c == expected),
                "owner should hold {expected}"
            );
        }
    }
    assert_eq!(owner["agent"]["message_attachments"], false);
    assert_eq!(owner["agent"]["additional_tools"], false);
    assert_eq!(
        owner["agent"]["tools"],
        serde_json::json!([
            "admin.files.list",
            "admin.files.read",
            "admin.homes.query",
            "admin.changes.propose",
            "question.ask"
        ])
    );

    let (status, member) = send(
        &app,
        "GET",
        "/admin/capabilities",
        None,
        Some("member-token"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(member["capabilities"], serde_json::json!([]));
    assert_eq!(member["agent"]["tools"], serde_json::json!([]));

    // ADR 0149 §1/§2: admin operates the console but holds neither the owner-only
    // lifecycle/privileged-grant capabilities nor billing.
    let (status, admin) = send(
        &app,
        "GET",
        "/admin/capabilities",
        None,
        Some("admin-a-token"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let admin_caps = admin["capabilities"].as_array().unwrap();
    for denied in [
        "manage_org_lifecycle",
        "grant_privileged_roles",
        "manage_billing",
    ] {
        assert!(
            !admin_caps.iter().any(|c| c == denied),
            "admin must not hold {denied}"
        );
    }
    for held in ["manage_members", "configure_sso", "view_audit"] {
        assert!(
            admin_caps.iter().any(|c| c == held),
            "admin should hold {held}"
        );
    }

    // ADR 0149 §3: the read-only auditor holds view_audit and nothing else.
    let (status, auditor) = send(
        &app,
        "GET",
        "/admin/capabilities",
        None,
        Some("auditor-token"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(auditor["capabilities"], serde_json::json!(["view_audit"]));

    let (status, billing) = send(
        &app,
        "GET",
        "/admin/capabilities",
        None,
        Some("billing-token"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        billing["capabilities"],
        serde_json::json!(["manage_billing"])
    );
    assert_eq!(billing["agent"]["message_attachments"], false);
    assert_eq!(
        billing["agent"]["tools"],
        serde_json::json!([
            "admin.files.list",
            "admin.files.read",
            "admin.changes.propose",
            "question.ask"
        ])
    );

    let (status, _) = send(&app, "GET", "/admin/capabilities", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// ADR 0149 §1 (SOC 2 F-2.5): granting a privileged role is owner-only. An admin holds
/// `ManageMembers` but not `GrantPrivilegedRoles`, so it can neither seed nor elevate a
/// principal into `owner`/`admin`; the owner can; and SCIM may never map a group into a
/// privileged role. The target-role gate lives in the command planner, so the denial
/// surfaces at submit before any proposal becomes durable.
#[tokio::test]
async fn privileged_role_grants_are_owner_only_and_scim_refuses_them() {
    let (_dir, app) = workbench_with_idp();

    // An admin cannot invite directly into a privileged role…
    let (s, body) = admin(
        &app,
        Some("admin-a-token"),
        "administration.access",
        "member.invite",
        serde_json::json!({"authority": "new-admin", "role": "admin"}),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "admin must not invite an admin: {body}"
    );

    // …nor elevate an existing (team-A) member to a privileged role (self-/lateral
    // escalation is closed even inside the admin's own team scope).
    let (s, body) = admin(
        &app,
        Some("admin-a-token"),
        "administration.access",
        "member.role.set",
        serde_json::json!({"id": "alice", "role": "owner"}),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "admin must not elevate a member to owner: {body}"
    );

    // The owner holds GrantPrivilegedRoles and may assign the admin role.
    let (s, body) = admin(
        &app,
        Some("owner-token"),
        "administration.access",
        "member.role.set",
        serde_json::json!({"id": "member-auth", "role": "admin"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "owner may grant the admin role: {body}");

    // SCIM group→role mapping refuses a privileged target…
    let (s, body) = admin(
        &app,
        Some("owner-token"),
        "administration.identity",
        "group-mapping.set",
        serde_json::json!({"group": "eng-leads", "role": "admin"}),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::UNPROCESSABLE_ENTITY,
        "SCIM must not map a group into admin: {body}"
    );

    // …while a non-privileged mapping is accepted.
    let (s, body) = admin(
        &app,
        Some("owner-token"),
        "administration.identity",
        "group-mapping.set",
        serde_json::json!({"group": "eng", "role": "member"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "SCIM maps a group into member: {body}");
}

#[tokio::test]
async fn team_scoped_admin_cannot_administer_another_team() {
    let (_dir, app) = workbench_with_idp();
    // The tenant provisioner seeded an admin scoped to team A and two members.

    // The team-A admin may change a team-A member's role…
    let (s, _) = admin(
        &app,
        Some("admin-a-token"),
        "administration.access",
        "member.role.set",
        serde_json::json!({"id":"alice","role":"viewer"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "admin administers own team");

    // …but not a team-B member's (outside scope → 403).
    let (s, _) = admin(
        &app,
        Some("admin-a-token"),
        "administration.access",
        "member.role.set",
        serde_json::json!({"id":"bob","role":"viewer"}),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "admin cannot cross teams");

    // The owner is org-wide — may administer team B.
    let (s, _) = admin(
        &app,
        Some("owner-token"),
        "administration.access",
        "member.role.set",
        serde_json::json!({"id":"bob","role":"viewer"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "owner is org-wide");
}

#[tokio::test]
async fn export_is_gated_by_role_policy() {
    // RBAC-6 / RBAC-5 export half: the org policy's `viewer ⇒ no export` rule is
    // enforced at the live export route.
    let (_dir, app, workbench) = workbench_with_idp_shared();
    let (created, _) = send(
        &app,
        "POST",
        "/chats",
        Some(r#"{"id":"eng-1"}"#),
        Some("owner-token"),
    )
    .await;
    assert_eq!(created, StatusCode::CREATED);
    {
        let mut workbench = workbench.lock().unwrap();
        let output = ResourceRecord::new(
            Resource::input(
                ResourceId::new("out-1"),
                ResourceKind::output(),
                Authority::from("owner-auth"),
            ),
            ContentLocator::Workspace {
                path: "deliverable.txt".into(),
                commit: "fixture".into(),
            },
            |_| Authority::from("owner-auth"),
        );
        resource_store::put(workbench.store_mut(), "eng-1", &output).unwrap();
    }

    // A viewer is denied export by the policy → 403 (the gate fires before admit).
    let (s, _) = send(
        &app,
        "POST",
        "/chats/eng-1/resources/out-1/export",
        Some("{}"),
        Some("viewer-token"),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "viewer is denied export");

    // The owner passes the export gate (the admit then proceeds; not a 403).
    let (s, _) = send(
        &app,
        "POST",
        "/chats/eng-1/resources/out-1/export",
        Some("{}"),
        Some("owner-token"),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "owner passes the export gate");
}

#[tokio::test]
async fn enterprise_mode_gates_data_routes_for_active_members() {
    // ENTSEC-1 (ADR 0065): in enterprise mode the DATA routes — not just /admin/* — require an
    // authenticated active member; solo mode (no IdP) stays open (covered by the other suites,
    // which never attach an IdP). /health is exempt.
    let (_dir, app) = workbench_with_idp();

    // /health is exempt — open even before provisioning, without a token.
    let (s, _) = send(&app, "GET", "/health", None, None).await;
    assert_eq!(s, StatusCode::OK, "health is always open");

    // The provisioned tenant gates GET /workspace (a data route).
    let (s, _) = send(&app, "GET", "/workspace", None, None).await;
    assert_eq!(
        s,
        StatusCode::UNAUTHORIZED,
        "anonymous cannot read the workspace once provisioned"
    );

    let (s, _) = send(&app, "GET", "/workspace", None, Some("bogus-token")).await;
    assert_eq!(
        s,
        StatusCode::UNAUTHORIZED,
        "a garbage token is unauthorized"
    );

    // An authenticated authority that is NOT an active member → 403 (enrolled in the IdP but
    // never provisioned into the directory).
    let (s, _) = send(&app, "GET", "/workspace", None, Some("outsider-token")).await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "an authenticated non-member is forbidden"
    );

    // A plain member (no console capability) CAN read the data routes — unlike /admin/*.
    let (s, _) = send(&app, "GET", "/workspace", None, Some("member-token")).await;
    assert_eq!(s, StatusCode::OK, "an active member reads the workspace");

    // /health stays exempt even when provisioned.
    let (s, _) = send(&app, "GET", "/health", None, None).await;
    assert_eq!(s, StatusCode::OK, "health stays exempt");

    // Administration admission is unchanged: a member still has no console access.
    let (s, _) =
        administration_document(&app, None, Some("member-token"), "administration.access").await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "member has no console access (admin gate intact)"
    );
}

#[tokio::test]
async fn entsec2_scopes_data_routes_to_granted_projects() {
    // ENTSEC-2 (ADR 0065): a plain member sees only the projects granted to them; owner/admin
    // bypass; a non-granted member is forbidden the project's data routes, fail-closed.
    let (_dir, app) = workbench_with_scoped_project();

    // Grant consultant-a access to proj-acme (owner administers grants).
    let (s, _) = admin(
        &app,
        Some("owner-token"),
        "administration.access",
        "grant.add",
        serde_json::json!({"authority":"consultant-a","project_id":"proj-acme"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "owner grants a member a project");

    // The grant shows up in the canonical access document.
    let (s, grants) = admin_document(&app, "owner-token", "administration.access").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(grants["grants"].as_array().unwrap().len(), 1);

    // A non-granted member is forbidden the project's data routes (scope gate, fail-closed).
    let (s, _) = send(
        &app,
        "GET",
        "/projects/proj-acme/home",
        None,
        Some("b-token"),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "ungranted member is out of scope for the project"
    );
    let (s, _) = send(
        &app,
        "GET",
        "/chats/chat-acme/transcript",
        None,
        Some("b-token"),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "ungranted member cannot read the project's chat"
    );

    // The granted member reaches the project's data routes (200 on the project-home rollup).
    let (s, _) = send(
        &app,
        "GET",
        "/projects/proj-acme/home",
        None,
        Some("a-token"),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "granted member reads their project");
    let (s, _) = send(
        &app,
        "GET",
        "/chats/chat-acme/transcript",
        None,
        Some("a-token"),
    )
    .await;
    assert_ne!(
        s,
        StatusCode::FORBIDDEN,
        "granted member passes the scope gate for the chat"
    );

    // The owner bypasses scoping — sees the project with no grant of its own.
    let (s, _) = send(
        &app,
        "GET",
        "/projects/proj-acme/home",
        None,
        Some("owner-token"),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "owner bypasses project scoping");

    // The workspace nav is membership-gated (200 for any active member), but its *content*
    // is now visibility-scoped (ENTSEC-2, see `entsec2_scopes_the_workspace_nav_content`).
    let (s, _) = send(&app, "GET", "/workspace", None, Some("b-token")).await;
    assert_eq!(
        s,
        StatusCode::OK,
        "the workspace nav is reachable by any member"
    );

    // Revoke consultant-a's grant → access is withdrawn (INV-18 future-only revocation).
    let (s, _) = admin(
        &app,
        Some("owner-token"),
        "administration.access",
        "grant.revoke",
        serde_json::json!({"authority":"consultant-a","project_id":"proj-acme"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = send(
        &app,
        "GET",
        "/projects/proj-acme/home",
        None,
        Some("a-token"),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "a revoked grant withdraws access");
}

#[tokio::test]
async fn secaud4_audits_sensitive_reads_when_enabled() {
    // SECAUD-4 (CC7.2): with read-auditing on, a granted member's GET of project-scoped
    // data is recorded in the org audit trail ("who read this client's data"); the
    // workspace nav (not project-scoped) is not. The default harness (off) records no read.
    let (_dir, app) = workbench_with_scoped_project_cfg(true);
    let (s, _) = admin(
        &app,
        Some("owner-token"),
        "administration.access",
        "grant.add",
        serde_json::json!({"authority":"consultant-a","project_id":"proj-acme"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // The member reads the project's chat transcript (a sensitive GET).
    let (s, _) = send(
        &app,
        "GET",
        "/chats/chat-acme/transcript",
        None,
        Some("a-token"),
    )
    .await;
    assert_ne!(s, StatusCode::FORBIDDEN);
    // ...and reads the non-scoped workspace nav (must NOT be audited — high-volume, not data).
    let (_s, _) = send(&app, "GET", "/workspace", None, Some("a-token")).await;

    let (s, audit) = send(
        &app,
        "GET",
        "/admin/audit?actor=consultant-a",
        None,
        Some("owner-token"),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let entries = audit["entries"].as_array().expect("audit entries");
    assert!(
        entries.iter().any(|e| e["action"]
            .as_str()
            .unwrap_or("")
            .contains("GET /chats/chat-acme/transcript")),
        "the sensitive read is audited: {audit}"
    );
    assert!(
        !entries
            .iter()
            .any(|e| e["action"].as_str().unwrap_or("").contains("/workspace")),
        "the non-scoped nav read is not audited: {audit}"
    );
}

#[tokio::test]
async fn secaud4_reads_are_not_audited_by_default() {
    // SECAUD-4: with read-auditing OFF (the default), a member's sensitive GET leaves no
    // audit entry — the opt-in is genuinely off unless the deployment enables it.
    let (_dir, app) = workbench_with_scoped_project(); // audit_reads = false
    let (s, _) = admin(
        &app,
        Some("owner-token"),
        "administration.access",
        "grant.add",
        serde_json::json!({"authority":"consultant-a","project_id":"proj-acme"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (_s, _) = send(
        &app,
        "GET",
        "/chats/chat-acme/transcript",
        None,
        Some("a-token"),
    )
    .await;

    let (s, audit) = send(
        &app,
        "GET",
        "/admin/audit?actor=consultant-a",
        None,
        Some("owner-token"),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let entries = audit["entries"].as_array().expect("audit entries");
    assert!(
        !entries
            .iter()
            .any(|e| e["action"].as_str().unwrap_or("").starts_with("GET ")),
        "no GET read is audited by default: {audit}"
    );
}

#[tokio::test]
async fn entsec_blocks_export_to_disk_and_audits_member_actions() {
    // ENTSEC-5 + ENTSEC-4 (ADR 0065).
    let (_dir, app) = workbench_with_idp();

    // ENTSEC-5: export-to-disk would write client data to the consultant's endpoint — refused in
    // enterprise mode (the guard fires before any resource resolution).
    let (s, _) = send(
        &app,
        "POST",
        "/chats/eng-1/resources/r1/export-to-disk",
        Some(r#"{"dest":"/tmp/x"}"#),
        Some("member-token"),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "export-to-disk disabled in enterprise mode"
    );

    // ENTSEC-4: a member's mutating data-route action is recorded in the org audit trail.
    let (s, _) = send(
        &app,
        "POST",
        "/projects",
        Some(r#"{"name":"Acme"}"#),
        Some("member-token"),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::CREATED,
        "an active member may create a project"
    );
    let (s, audit) = send(
        &app,
        "GET",
        "/admin/audit?actor=member-auth",
        None,
        Some("owner-token"),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let entries = audit["entries"].as_array().expect("audit entries");
    assert!(
        entries.iter().any(|e| e["action"]
            .as_str()
            .unwrap_or("")
            .contains("POST /projects")
            && e["actor"] == "member-auth"),
        "the member's POST /projects is in the audit trail: {audit}"
    );
}

/// ENTSEC-2 (ADR 0065): the workspace **nav content** is scoped to what the caller may see,
/// not just the per-route access gate. A scoped member sees only their granted projects (and
/// only chats within them) in `GET /workspace`; the owner sees everything; an ungranted
/// member sees no client projects at all — so project/chat *existence* never leaks.
#[tokio::test]
async fn entsec2_scopes_the_workspace_nav_content() {
    let (_dir, app) = workbench_with_scoped_project();

    // The provisioner seeded both consultants; grant only consultant-a → proj-acme.
    let (s, _) = admin(
        &app,
        Some("owner-token"),
        "administration.access",
        "grant.add",
        serde_json::json!({"authority":"consultant-a","project_id":"proj-acme"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // Helpers over GET /workspace: does the nav (for this token) surface the project / chat?
    async fn nav(app: &Router, token: &str) -> Value {
        let (s, body) = send(app, "GET", "/workspace", None, Some(token)).await;
        assert_eq!(s, StatusCode::OK, "nav reachable: {body}");
        body
    }
    let has_project = |v: &Value, id: &str| {
        v["projects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["id"] == id)
    };
    let has_recent_chat = |v: &Value, id: &str| {
        v["recent"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["id"] == id)
    };

    // Owner: bypasses scoping — sees the project and its chat.
    let owner = nav(&app, "owner-token").await;
    assert!(has_project(&owner, "proj-acme"), "owner sees the project");
    assert!(has_recent_chat(&owner, "chat-acme"), "owner sees the chat");

    // Granted member: sees exactly their project and its chat.
    let a = nav(&app, "a-token").await;
    assert!(
        has_project(&a, "proj-acme"),
        "granted member sees their project"
    );
    assert!(
        has_recent_chat(&a, "chat-acme"),
        "granted member sees the chat"
    );

    // Ungranted member: the project and its chat are absent — existence does not leak.
    let b = nav(&app, "b-token").await;
    assert!(
        !has_project(&b, "proj-acme"),
        "ungranted member sees no project: {b}"
    );
    assert!(
        !has_recent_chat(&b, "chat-acme"),
        "ungranted member sees no chat: {b}"
    );

    // The list endpoint (GET /chats) applies the same visibility filter for the ungranted
    // member — it never returns chat-acme as an engagement id.
    let (s, list) = send(&app, "GET", "/chats", None, Some("b-token")).await;
    assert_eq!(s, StatusCode::OK, "chats list reachable: {list}");
    assert!(
        !list["engagements"]
            .as_array()
            .unwrap()
            .iter()
            .any(|id| id == "chat-acme"),
        "ungranted member's chats list excludes the project chat: {list}"
    );
}

/// SEC-2: the org **session idle-timeout** is enforced on data routes. With an
/// `idle_timeout_secs` policy set, an authenticated member's session goes stale after the
/// idle window and the data route refuses it `401` (re-authentication required); the pure
/// timeout logic (lifetime + idle, keying, unset-is-noop) is covered by the
/// `session_activity` unit tests — this proves the live wiring end to end.
#[tokio::test]
async fn sec2_idle_timeout_expires_a_session_on_data_routes() {
    let (_dir, app) = workbench_with_idp();

    // Set a 1-second idle timeout (owner has ConfigureSecurity).
    let (s, _) = update_security(
        &app,
        "owner-token",
        serde_json::json!({"idle_timeout_secs":1}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "owner sets the session policy");

    // First data-route request starts the session — allowed.
    let (s, _) = send(&app, "GET", "/workspace", None, Some("owner-token")).await;
    assert_eq!(s, StatusCode::OK, "the session is fresh");

    // Idle past the timeout → the same token is now refused (re-auth required).
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    let (s, _) = send(&app, "GET", "/workspace", None, Some("owner-token")).await;
    assert_eq!(
        s,
        StatusCode::UNAUTHORIZED,
        "an idle-timed-out session is refused on the data route"
    );
}

/// ENTSEC-5: in enterprise mode the server-local *path* context ingest is disabled (a remote
/// client must not drive the server to read its filesystem) — POST /chats/:id/context is 403
/// for an authenticated member; the client uploads instead. The guard fires before any
/// engagement lookup, so it holds regardless of the chat.
#[tokio::test]
async fn entsec5_path_context_ingest_disabled_in_enterprise() {
    let (_dir, app) = workbench_with_scoped_project();
    let (s, _) = send(
        &app,
        "POST",
        "/chats/chat-acme/context",
        Some(r#"{"path":"/etc"}"#),
        Some("owner-token"),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "server-path context ingest is refused in enterprise mode"
    );
}

/// ITGOV-2: the Administration clients document lists members active on the data
/// routes, is Environment-admission gated, and never exposes a bearer.
#[tokio::test]
async fn itgov2_session_roster_lists_active_members() {
    let (_dir, app) = workbench_with_idp();
    // The member is not on the roster yet (no data-route activity from them).
    let (s, roster) = admin_document(&app, "owner-token", "administration.clients").await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        !roster["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["authority"] == "member-auth"),
        "member absent before their first request: {roster}"
    );

    // The member makes an authenticated data request → they appear in the roster.
    let (s, _) = send(&app, "GET", "/workspace", None, Some("member-token")).await;
    assert_eq!(s, StatusCode::OK);
    let (s, roster) = admin_document(&app, "owner-token", "administration.clients").await;
    assert_eq!(s, StatusCode::OK, "{roster}");
    let sessions = roster["sessions"].as_array().unwrap();
    assert!(
        sessions.iter().any(|r| r["authority"] == "member-auth"),
        "the active member is on the roster: {roster}"
    );
    // The roster never carries a bearer/token field.
    assert!(
        sessions
            .iter()
            .all(|r| r.get("bearer").is_none() && r.get("token").is_none()),
        "no bearer leaks in the roster: {roster}"
    );

    // A plain member has no console access → the roster read is forbidden.
    let (s, _) =
        administration_document(&app, None, Some("member-token"), "administration.clients").await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "member cannot read the IT console"
    );
}

/// ITGOV-4: a Home evaluates reported client compatibility before serving org data. A
/// nonconforming build warns during grace, is blocked after grace, and remains visible to IT.
/// The exact software-policy route remains an authenticated member recovery surface so a
/// blocked desktop updater can discover the policy that it must satisfy.
#[tokio::test]
async fn itgov4_home_enforces_software_policy_and_preserves_recovery() {
    let (_dir, app) = workbench_with_idp();
    let current = ("2.1.0", 2, "stable", "desktop");
    let old = Some(("1.9.0", 1, "stable", "desktop"));

    let grace_policy = serde_json::json!({
        "minimum_version": "2.0.0",
        "minimum_protocol": 2,
        "allowed_channels": ["stable"],
        "grace_until_unix_ms": 4_102_444_800_000_u64
    });
    let (s, body) = admin(
        &app,
        Some("owner-token"),
        "administration.software-policy",
        "software-policy.update",
        grace_policy,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{body}");

    let (s, _) = send_client(&app, "GET", "/workspace", None, Some("member-token"), old).await;
    assert_eq!(s, StatusCode::OK, "grace warns instead of refusing");
    let (s, roster) =
        admin_document_for_client(&app, "owner-token", "administration.clients", current).await;
    assert_eq!(s, StatusCode::OK, "{roster}");
    let member = roster["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["authority"] == "member-auth")
        .unwrap();
    assert_eq!(member["software_status"], "warning", "{roster}");
    assert_eq!(member["client"]["version"], "1.9.0", "{roster}");
    assert_eq!(member["client"]["platform"], "desktop", "{roster}");

    let enforced_policy = serde_json::json!({
        "minimum_version": "2.0.0",
        "minimum_protocol": 2,
        "allowed_channels": ["stable"],
        "grace_until_unix_ms": null
    });
    let (s, _) = admin(
        &app,
        Some("owner-token"),
        "administration.software-policy",
        "software-policy.update",
        enforced_policy,
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    let (s, body) = send_client(&app, "GET", "/workspace", None, Some("member-token"), old).await;
    assert_eq!(s, StatusCode::UPGRADE_REQUIRED, "{body}");
    assert_eq!(
        body["error"],
        "GaugeDesk client does not satisfy organization software policy"
    );

    let (s, policy) = send_client(
        &app,
        "GET",
        "/admin/software-policy",
        None,
        Some("owner-token"),
        old,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "repair route must survive: {policy}");
    assert_eq!(policy["software_policy"]["minimum_version"], "2.0.0");

    let (s, policy) = send_client(
        &app,
        "GET",
        "/admin/software-policy",
        None,
        Some("member-token"),
        old,
    )
    .await;
    assert_eq!(
        s,
        StatusCode::OK,
        "a blocked ordinary member must retain the updater recovery route: {policy}"
    );
    assert_eq!(policy["software_policy"]["minimum_version"], "2.0.0");

    let (s, roster) =
        admin_document_for_client(&app, "owner-token", "administration.clients", current).await;
    assert_eq!(s, StatusCode::OK, "{roster}");
    let member = roster["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["authority"] == "member-auth")
        .unwrap();
    assert_eq!(member["software_status"], "blocked", "{roster}");
    assert!(member["software_reason"]
        .as_str()
        .unwrap()
        .contains("2.0.0"));
}

/// Seed active members into an explicit tenant scope (F-2.3 multi-tenant harness).
fn seed_members_in(store: &mut Store, scope: &str, members: &[(&str, &str, Option<&str>)]) {
    for (authority, role, team) in members {
        store
            .append_record(
                scope,
                "membership",
                &serde_json::to_string(&active_member(authority, role, *team)).unwrap(),
            )
            .unwrap();
    }
}

/// An enterprise workbench whose default `org` scope and the named tenant `acme`
/// hold independent directories — the fixture the F-2.3 tenant-scoped admin-gate
/// test drives. Enrolls the default owner (`owner-token`) and acme's owner
/// (`acme-owner-token`) in the IdP.
fn tenant_workbench(
    default_members: &[(&str, &str, Option<&str>)],
    acme_members: &[(&str, &str, Option<&str>)],
) -> (tempfile::TempDir, Router) {
    let dir = tempfile::tempdir().unwrap();
    let instance = Instance::init(dir.path().join("repo"), dir.path().join("wt")).unwrap();
    let mut store = Store::open_in_memory().unwrap();
    seed_members_in(&mut store, ORG_SCOPE, default_members);
    seed_members_in(&mut store, &tenant_scope("acme"), acme_members);
    let idp = LoopbackIdentityProvider::new()
        .enroll(
            "owner-token",
            AuthorityId::new("owner-auth"),
            AuthorityAttributes::default(),
        )
        .enroll(
            "acme-owner-token",
            AuthorityId::new("acme-owner"),
            AuthorityAttributes::default(),
        );
    let wb =
        Workbench::with_target("inst-test", instance, store).with_identity_provider(Arc::new(idp));
    (dir, enterprise_control_plane(Arc::new(Mutex::new(wb))))
}

async fn send_tenant(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    tenant: Option<&str>,
) -> (StatusCode, Value) {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    if let Some(tenant) = tenant {
        b = b.header("x-gaugewright-tenant", tenant);
    }
    let resp = app
        .clone()
        .oneshot(b.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// F-2.3 (SOC 2 CC6.1): the `/admin/*` capability gate must authorize against the
/// **same** tenant directory the handler reads/writes (resolved from
/// `X-Gaugewright-Tenant`), not the fixed default `org` scope. Before the fix,
/// `deny` folded the default scope while `get_audit_log` served the header's
/// tenant — so a default-scope owner (or, under bootstrap, an unseeded default
/// scope) could reach another tenant's audit/member data.
#[tokio::test]
async fn admin_gate_is_tenant_scoped() {
    // Case 1 — cross-tenant owner. The default scope and acme are both provisioned,
    // with *different* owners. The default-scope owner is not an acme member.
    let (_dir, app) = tenant_workbench(
        &[("owner-auth", "owner", None)],
        &[("acme-owner", "owner", None)],
    );

    // The default-scope owner, carrying acme's header, is refused — the gate now folds
    // acme's directory, where they are not a member (was 200 reading acme's audit log).
    let (s, body) = send_tenant(
        &app,
        "GET",
        "/admin/audit",
        Some("owner-token"),
        Some("acme"),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "a default-scope owner must not administer tenant acme: {body}"
    );

    // Acme's own owner is admitted for acme (the gate and the handler agree on scope).
    let (s, _) = send_tenant(
        &app,
        "GET",
        "/admin/audit",
        Some("acme-owner-token"),
        Some("acme"),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "acme's own owner administers acme");

    // Back-compat: header-absent, the default-scope owner still administers the default
    // tenant (tenant_scope("") == ORG_SCOPE), byte-for-byte unchanged.
    let (s, _) = send_tenant(&app, "GET", "/admin/audit", Some("owner-token"), None).await;
    assert_eq!(
        s,
        StatusCode::OK,
        "the default-scope owner still administers the default tenant"
    );

    // Case 2 — bootstrap passthrough must not cross scopes. The default scope is
    // UNPROVISIONED but acme IS provisioned. A request carrying acme's header must fold
    // acme (provisioned ⇒ require authentication), not be waved through by the empty
    // default scope's bootstrap passthrough.
    let (_dir2, app2) = tenant_workbench(&[], &[("acme-owner", "owner", None)]);
    let (s, body) = send_tenant(&app2, "GET", "/admin/audit", None, Some("acme")).await;
    assert_eq!(
        s,
        StatusCode::UNAUTHORIZED,
        "acme is provisioned: no bootstrap passthrough of the empty default scope: {body}"
    );

    // Sanity: the unprovisioned default tenant itself is still in bootstrap and open —
    // the fix narrows the passthrough to the requested scope, it does not remove it.
    let (s, _) = send_tenant(&app2, "GET", "/admin/audit", None, None).await;
    assert_eq!(
        s,
        StatusCode::OK,
        "the unprovisioned default tenant remains bootstrap-open"
    );
}
