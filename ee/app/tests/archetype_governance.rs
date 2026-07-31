//! Archetype publish/upgrade governance, end to end (UX-9 / ADR 0063). Drives
//! the Administration Environment's reviewed `policy.update` command (the org's
//! `allow_auto_upgrade` policy) alongside the open archetype/placement routes, so
//! it composes the ee enterprise control plane —
//! the test moved here with the enterprise band (SPLIT-1; it lived as a
//! feature-gated unit test in `crates/app/src/tests.rs`).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use tower::ServiceExt;

use gaugewright_app::org::{MembershipRecord, MembershipStatus, RecordOp, ORG_ID, ORG_SCOPE};
use gaugewright_app::{open_workbench, LockUnpoisoned, SharedWorkbench};
use gaugewright_ee::enterprise_control_plane;

/// A workbench seeded like the live server (builder agent + authoring instance)
/// so the library routes have an instance to work against.
fn seeded_workbench() -> (tempfile::TempDir, SharedWorkbench) {
    let dir = tempfile::tempdir().unwrap();
    let wb = open_workbench(dir.path()).unwrap();
    // Administration is not inferred from a configured route. Seed the local
    // authority as this test tenant's owner so the shared Environment admission
    // can issue an exact session and capability set.
    wb.lock_unpoisoned()
        .store_mut()
        .append_record(
            ORG_SCOPE,
            "membership",
            &serde_json::to_string(&MembershipRecord {
                id: "local-user".into(),
                op: RecordOp::Upsert,
                org_id: ORG_ID.into(),
                authority: "local-user".into(),
                email: "owner@example.test".into(),
                role: "owner".into(),
                status: MembershipStatus::Active,
                managed_by_scim: false,
                team: None,
            })
            .unwrap(),
        )
        .unwrap();
    (dir, wb)
}

async fn send(app: &Router, method: &str, uri: &str, body: Option<&str>) -> (StatusCode, String) {
    static NEXT_KEY: AtomicU64 = AtomicU64::new(1);
    let mut builder = Request::builder().method(method).uri(uri);
    if method != "GET" && method != "HEAD" && method != "OPTIONS" {
        builder = builder.header(
            "idempotency-key",
            format!(
                "archetype-test-{}",
                NEXT_KEY.fetch_add(1, Ordering::Relaxed)
            ),
        );
    }
    let req = match body {
        Some(b) => builder
            .header("content-type", "application/json")
            .body(Body::from(b.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

#[tokio::test]
async fn archetype_publish_makes_placements_upgradeable_then_upgrade_advances_them() {
    // UX-9 (ADR 0063): publish bumps the archetype version; placements show "upgrade
    // available" and stay put until upgraded (manual default); auto-upgrade applies only
    // where the owner opts in AND the org allows it. The policy change drives the
    // reviewed Administration command path, so this composes the ee enterprise
    // control plane (SPLIT-1).
    let (_d, wb) = seeded_workbench();
    let app = enterprise_control_plane(wb);

    let parse = |b: &str| serde_json::from_str::<serde_json::Value>(b).unwrap();
    let pid = {
        let (_, b) = send(&app, "POST", "/projects", Some(r#"{"name":"proj"}"#)).await;
        parse(&b)["id"].as_str().unwrap().to_string()
    };
    let aid = {
        let (_, b) = send(&app, "POST", "/archetypes", Some(r#"{"name":"rev"}"#)).await;
        parse(&b)["id"].as_str().unwrap().to_string()
    };
    let iid = {
        let (s, b) = send(
            &app,
            "POST",
            &format!("/projects/{pid}/placements"),
            Some(&format!(r#"{{"agent_id":"{aid}"}}"#)),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "got {b}");
        parse(&b)["instance_id"].as_str().unwrap().to_string()
    };

    // A fresh placement is current (v1): no upgrade available.
    let placement = |ws: &serde_json::Value| -> serde_json::Value {
        ws["projects"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|p| p["placements"].as_array().unwrap().clone())
            .find(|pl| pl["placement_id"] == iid)
            .unwrap()
    };
    let (_, b) = send(&app, "GET", "/workspace", None).await;
    let pl = placement(&parse(&b));
    assert_eq!(pl["version"], 1);
    assert_eq!(pl["upgrade_available"], false);

    // Publish a new version → the placement is now behind (manual default: it stays on v1).
    let (s, b) = send(
        &app,
        "POST",
        &format!("/archetypes/{aid}/publish"),
        Some("{}"),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "got {b}");
    assert_eq!(parse(&b)["version"], 2);
    assert_eq!(
        parse(&b)["auto_upgraded"],
        0,
        "manual: nothing auto-upgrades"
    );
    let (_, b) = send(&app, "GET", "/workspace", None).await;
    let pl = placement(&parse(&b));
    assert_eq!(pl["version"], 1, "stays on v1 until upgraded");
    assert_eq!(pl["current_version"], 2);
    assert_eq!(pl["upgrade_available"], true);

    // Manual upgrade → advances to v2, no longer behind.
    let (s, b) = send(&app, "POST", &format!("/placements/{iid}/upgrade"), None).await;
    assert_eq!(s, StatusCode::OK, "got {b}");
    assert_eq!(parse(&b)["version"], 2);
    let (_, b) = send(&app, "GET", "/workspace", None).await;
    let pl = placement(&parse(&b));
    assert_eq!(pl["version"], 2);
    assert_eq!(pl["upgrade_available"], false);

    // Auto-upgrade: the org must allow it AND the owner must opt in. Allow it, then publish
    // with auto_upgrade → the placement advances automatically.
    let (_, opened) = send(
        &app,
        "POST",
        "/environments/administration/sessions",
        Some("{}"),
    )
    .await;
    let session = parse(&opened)["session"].clone();
    let policy_grant = session["documents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|document| document["id"] == "administration.policy")
        .unwrap();
    let document_uri = format!(
        "/environments/administration/documents/administration.policy?session={}&scope={}",
        session["id"].as_str().unwrap(),
        session["scope"]["id"].as_str().unwrap(),
    );
    let (_, current) = send(&app, "GET", &document_uri, None).await;
    let mut content = parse(&current)["document"]["content"].clone();
    content["security"]["allow_auto_upgrade"] = serde_json::Value::Bool(true);
    let proposal = serde_json::json!({
        "session_id": session["id"],
        "environment": "administration",
        "scope": session["scope"],
        "document_id": "administration.policy",
        "base_revision": policy_grant["revision"],
        "content": content,
        "client": "cli",
    });
    let (s, proposed) = send(
        &app,
        "POST",
        "/environments/administration/changes",
        Some(&proposal.to_string()),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "policy proposal: {proposed}");
    let proposed = parse(&proposed);
    let review_uri = format!(
        "/environments/administration/changes/{}/review",
        proposed["change"]["id"].as_str().unwrap(),
    );
    let review = serde_json::json!({
        "session_id": session["id"],
        "environment": "administration",
        "scope": session["scope"],
        "decision": "accept",
        "client": "cli",
    });
    let (s, reviewed) = send(&app, "POST", &review_uri, Some(&review.to_string())).await;
    assert_eq!(s, StatusCode::OK, "policy review: {reviewed}");
    assert_eq!(parse(&reviewed)["receipt"]["status"], "applied");
    let (s, b) = send(
        &app,
        "POST",
        &format!("/archetypes/{aid}/publish"),
        Some(r#"{"auto_upgrade":true}"#),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "got {b}");
    assert_eq!(parse(&b)["version"], 3);
    assert!(
        parse(&b)["auto_upgraded"].as_u64().unwrap() >= 1,
        "auto-upgraded: {b}"
    );
    let (_, b) = send(&app, "GET", "/workspace", None).await;
    let pl = placement(&parse(&b));
    assert_eq!(pl["version"], 3, "auto-advanced to v3");
    assert_eq!(pl["upgrade_available"], false);
}
use std::sync::atomic::{AtomicU64, Ordering};
