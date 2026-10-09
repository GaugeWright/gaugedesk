//! Real local HTTP creation and synthetic SQLite write faults; no provider runs.
use crate::{
    library::{Library, LIBRARY_SCOPE},
    LockUnpoisoned, SharedWorkbench,
};
use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use tower::ServiceExt;

async fn send(app: &Router, method: &str, uri: &str, value: Option<Value>) -> (StatusCode, String) {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header(
            "idempotency-key",
            format!("chat-rollback-{}", NEXT.fetch_add(1, Ordering::Relaxed)),
        )
        .body(value.map_or_else(Body::empty, |v| Body::from(v.to_string())))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}
async fn setup() -> (tempfile::TempDir, SharedWorkbench, Router, Value) {
    let dir = tempfile::tempdir().unwrap();
    let wb = crate::workbench_state::open_lean_workbench(dir.path()).unwrap();
    let app = crate::open_control_plane(wb.clone());
    let (status, body) = send(&app, "POST", "/projects", Some(json!({"name":"rollback"}))).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    (dir, wb, app, serde_json::from_str(&body).unwrap())
}
fn retained(wb: &SharedWorkbench, targets: &[String]) -> Value {
    let g = wb.lock_unpoisoned();
    let mut chats: Vec<_> = g.library.chats.keys().cloned().collect();
    chats.sort();
    let mut index: Vec<_> = g.engagement_index.keys().cloned().collect();
    index.sort();
    let mut engagements: Vec<_> = g.engagements.keys().cloned().collect();
    engagements.sort();
    let storage = g
        .library
        .project_collaboration_workspaces
        .values()
        .next()
        .unwrap();
    let mut branches = g
        .workspace_by_storage_id(&storage.workspace_id)
        .unwrap()
        .active_engagements()
        .unwrap();
    branches.sort();
    let rows: Vec<_> = ["chat", "chat_target", "chat_target_set"]
        .into_iter()
        .map(|kind| g.store_ref().records(LIBRARY_SCOPE, kind).unwrap())
        .collect();
    let acts: Vec<_> = targets
        .iter()
        .map(|id| {
            g.store_ref()
                .records(&format!("target::{id}::acts"), "target_act")
                .unwrap()
        })
        .collect();
    json!({"chats":chats,"index":index,"engagements":engagements,"branches":branches,"rows":rows,"acts":acts})
}
fn assert_reopened(wb: &SharedWorkbench, before: &Value) {
    let g = wb.lock_unpoisoned();
    let sibling = g.store_ref().sibling().unwrap();
    let rebuilt = Library::rebuild(&sibling).unwrap();
    let mut chats: Vec<_> = rebuilt.chats.keys().cloned().collect();
    chats.sort();
    assert_eq!(
        json!(chats),
        before["chats"],
        "failed chat survived a real Store reopen"
    );
}
#[tokio::test]
async fn failed_chat_package_has_no_navigator_or_owned_branch_residue() {
    let (_dir, wb, app, project) = setup().await;
    let targets = vec![project["target_id"].as_str().unwrap().to_owned()];
    let before = retained(&wb, &targets);
    let package_root = {
        let g = wb.lock_unpoisoned();
        let placement = &g.library.instances[project["placement"].as_str().unwrap()];
        let target = g.library.authoring_target_for(&placement.agent_id).unwrap();
        crate::library_state::published_package_root(
            &g.targets_dir(),
            &target.id,
            placement.version,
        )
    };
    std::fs::remove_dir_all(package_root).unwrap();
    let (status, body) = send(
        &app,
        "POST",
        &format!(
            "/projects/{}/placements/{}/chats",
            project["id"].as_str().unwrap(),
            project["placement"].as_str().unwrap()
        ),
        Some(json!({"title":"failed-go","target_id":targets[0]})),
    )
    .await;
    assert!(status.is_server_error(), "{status}: {body}");
    assert!(body.contains("cannot open agent package"), "{body}");
    let (status, workspace) = send(&app, "GET", "/workspace", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !workspace.contains("failed-go"),
        "failed chat remained in navigator"
    );
    assert_eq!(
        retained(&wb, &targets),
        before,
        "failed chat left owned creation residue"
    );
    assert_reopened(&wb, &before);
}
#[tokio::test]
async fn failed_chat_target_act_rolls_back_single_and_late_multi_target_publication() {
    for multi in [false, true] {
        let (_dir, wb, app, project) = setup().await;
        let mut targets = vec![project["target_id"].as_str().unwrap().to_owned()];
        let folder = tempfile::tempdir().unwrap();
        std::fs::write(folder.path().join("kept.txt"), "unchanged").unwrap();
        if multi {
            let (status, body) = send(&app, "POST", &format!("/projects/{}/targets", project["id"].as_str().unwrap()), Some(json!({"name":"Second target","kind":"external-folder","path":folder.path(),"path_scope":["."]}))).await;
            assert_eq!(status, StatusCode::CREATED, "{body}");
            targets.push(
                serde_json::from_str::<Value>(&body).unwrap()["id"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            );
        }
        let before = retained(&wb, &targets);
        let fault = rusqlite::Connection::open(wb.lock_unpoisoned().store_ref().path()).unwrap();
        let scope = format!("target::{}::acts", targets.last().unwrap());
        // IDs are generated locally, not request SQL. This faults only the last target's INSERT.
        fault.execute_batch(&format!("CREATE TRIGGER refuse_initial_act BEFORE INSERT ON events WHEN NEW.kind='target_act' AND NEW.scope_id='{scope}' BEGIN SELECT RAISE(ABORT,'synthetic late target-act failure'); END")).unwrap();
        let (status, body) = send(
            &app,
            "POST",
            &format!(
                "/projects/{}/placements/{}/chats",
                project["id"].as_str().unwrap(),
                project["placement"].as_str().unwrap()
            ),
            Some(json!({"title":"failed-act","target_ids":targets})),
        )
        .await;
        assert!(status.is_server_error(), "{status}: {body}");
        assert_eq!(
            retained(&wb, &targets),
            before,
            "late target-act failure published partial chat/target acts"
        );
        assert_reopened(&wb, &before);
        assert_eq!(
            std::fs::read_to_string(folder.path().join("kept.txt")).unwrap(),
            "unchanged"
        );
        fault
            .execute_batch("DROP TRIGGER refuse_initial_act")
            .unwrap();
    }
}

#[tokio::test]
async fn valid_chat_creation_keeps_exact_target_manifest_acts_and_authoring_behavior() {
    for multi in [false, true] {
        let (_dir, wb, app, project) = setup().await;
        let project_id = project["id"].as_str().unwrap();
        let mut targets = vec![project["target_id"].as_str().unwrap().to_owned()];
        let folder = tempfile::tempdir().unwrap();
        std::fs::write(folder.path().join("kept.txt"), "unchanged").unwrap();
        if multi {
            let (status, body) = send(&app, "POST", &format!("/projects/{project_id}/targets"), Some(json!({"name":"Second valid target","kind":"external-folder","path":folder.path(),"path_scope":["."]}))).await;
            assert_eq!(status, StatusCode::CREATED, "{body}");
            targets.push(
                serde_json::from_str::<Value>(&body).unwrap()["id"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            );
        }
        wb.lock_unpoisoned()
            .rename_project_target(project_id, &targets[0], "Named on Main")
            .unwrap();
        let (status, body) = send(
            &app,
            "POST",
            &format!(
                "/projects/{project_id}/placements/{}/chats",
                project["placement"].as_str().unwrap()
            ),
            Some(json!({"title":"valid-go","target_ids":targets})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let chat: Value = serde_json::from_str(&body).unwrap();
        let id = chat["id"].as_str().unwrap();
        {
            let g = wb.lock_unpoisoned();
            let eng = g.engagements.get(id).unwrap();
            let manifest: Value = serde_json::from_slice(
                &std::fs::read(
                    eng.path()
                        .join(gaugedesk_boundary::definition::RUNTIME_MOUNT_ROOT)
                        .join("target-set.json"),
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(manifest["targets"].as_array().unwrap().len(), targets.len());
            assert_eq!(manifest["targets"][0]["name"], "Named on Main");
            assert_eq!(manifest["target_set_revision"], 0);
            for (index, target_id) in targets.iter().enumerate() {
                let target = &g.library.work_targets[target_id];
                assert_eq!(
                    manifest["targets"][index]["basis"].as_str(),
                    target.current_basis.as_deref()
                );
                assert_eq!(
                    manifest["targets"][index]["capability_ceiling"],
                    serde_json::to_value(&target.capabilities).unwrap()
                );
                let acts = g.target_acts(target_id).unwrap();
                let acts: Vec<_> = acts
                    .iter()
                    .filter(|act| act.chat_id.as_deref() == Some(id))
                    .collect();
                assert_eq!(acts.len(), 1);
                assert_eq!(
                    acts[0].basis,
                    target.current_basis.as_ref().unwrap().as_str()
                );
                assert_eq!(acts[0].adapter, target.adapter);
                assert_eq!(acts[0].act, crate::target_adapter::TargetActKind::Read);
                assert_eq!(
                    acts[0].status,
                    crate::target_adapter::TargetActStatus::Completed
                );
            }
            let rebuilt = Library::rebuild(&g.store_ref().sibling().unwrap()).unwrap();
            assert!(rebuilt.chats.contains_key(id));
            assert_eq!(
                rebuilt.current_target_set(id),
                g.library.current_target_set(id)
            );
        }
        let (_, workspace) = send(&app, "GET", "/workspace", None).await;
        assert!(workspace.contains("valid-go"));
        let mut g = wb.lock_unpoisoned();
        let authoring = g
            .library
            .instances
            .values()
            .find(|instance| instance.kind == crate::library::InstanceKind::Authoring)
            .unwrap()
            .id
            .clone();
        let edit = g.create_chat_in_instance(&authoring, "valid-edit").unwrap();
        let edit_id = edit["id"].as_str().unwrap();
        let engagement = g.engagements.get(edit_id).unwrap();
        assert!(
            !engagement
                .path()
                .join(gaugedesk_boundary::definition::RUNTIME_MOUNT_ROOT)
                .exists(),
            "Authoring gained an unsolicited runtime mount"
        );
        assert!(Library::rebuild(&g.store_ref().sibling().unwrap())
            .unwrap()
            .chats
            .contains_key(edit_id));
        assert_eq!(
            std::fs::read_to_string(folder.path().join("kept.txt")).unwrap(),
            "unchanged"
        );
    }
}
