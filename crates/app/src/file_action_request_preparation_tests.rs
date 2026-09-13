use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

fn request(intent: &Intent) -> EditorFileSave<'_> {
    EditorFileSave {
        chat_id: &intent.chat_id,
        request_id: &intent.request_id,
        path: &intent.path,
        base_cut: &intent.base_cut,
        content: &intent.content,
    }
}

fn product_rows(wb: &Workbench) -> Vec<i64> {
    let connection = rusqlite::Connection::open(wb.store_ref().path()).unwrap();
    [
        "events",
        "commands",
        "command_receipts",
        "records",
        "content",
    ]
    .map(|table| {
        connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap()
    })
    .into()
}

fn input_bytes(path: &std::path::Path) -> Vec<Option<Vec<u8>>> {
    ["", "-wal"]
        .map(|suffix| std::fs::read(format!("{}{suffix}", path.display())).ok())
        .into()
}

#[test]
fn request_preparation_is_read_only_and_retained_coordinates_recover_a_lost_admission_response() {
    let dir = tempfile::tempdir().unwrap();
    let (shared, intent, token) = setup(dir.path());
    let mut wb = shared.lock_unpoisoned();
    let context = wb.authenticate_action_context(&token).unwrap();
    let before = product_rows(&wb);
    let workspaces = std::mem::take(&mut wb.engagements);
    let original = wb
        .prepare_editor_file_save_request(
            &context,
            &intent.chat_id,
            &intent.path,
            &intent.request_id,
        )
        .unwrap();
    assert_eq!(original, intent.identity);
    assert_eq!(product_rows(&wb), before);
    assert!(wb.engagements.is_empty());
    assert!(!dir.path().join("actions").exists());
    assert!(wb
        .observe_editor_file_save_request(&context, original.as_request())
        .is_err());
    assert_eq!(product_rows(&wb), before);
    wb.engagements = workspaces;
    // This is the caller's persisted value, not a coordinate refreshed after
    // submission. The admission response may be lost completely.
    let retained: EditorFileSaveRequestIdentity =
        serde_json::from_str(&serde_json::to_string(&original).unwrap()).unwrap();
    let inputs = NativeActionInputCustody::open(
        dir.path().join("inputs.sqlite"),
        wb.home_id().as_str(),
        4096,
    )
    .unwrap();
    let admitted = wb
        .admit_editor_file_save(&context, &inputs, &retained, &request(&intent))
        .unwrap();
    assert!(!admitted.replayed);
    let command = admitted.command;
    let after = product_rows(&wb);
    let observed = wb
        .observe_editor_file_save_request(&context, retained.as_request())
        .unwrap();
    assert_eq!(observed.command(), &command);
    assert_eq!(product_rows(&wb), after);
    let replay = wb
        .admit_editor_file_save(&context, &inputs, &retained, &request(&intent))
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.command, command);
}

#[test]
fn request_preparation_substituted_coordinates_refuse_before_policy_or_input_retention() {
    let dir = tempfile::tempdir().unwrap();
    let (shared, intent, token) = setup(dir.path());
    let mut wb = shared.lock_unpoisoned();
    let context = wb.authenticate_action_context(&token).unwrap();
    let input_path = dir.path().join("inputs.sqlite");
    let inputs = NativeActionInputCustody::open(&input_path, wb.home_id().as_str(), 4096).unwrap();
    let rows = product_rows(&wb);
    let bytes = input_bytes(&input_path);
    for field in ["home", "issuer", "scope", "request_id"] {
        let mut original = intent.identity.clone();
        match field {
            "home" => original.home.push_str("-other"),
            "issuer" => original.issuer.push_str("-other"),
            "scope" => original.scope.insert(0, ' '),
            "request_id" => original.request_id.push_str("-other"),
            _ => unreachable!(),
        }
        let error = wb
            .admit_editor_file_save(&context, &inputs, &original, &request(&intent))
            .err()
            .unwrap();
        assert!(error.contains("original file request"), "{field}: {error}");
        assert_eq!(product_rows(&wb), rows, "{field} retained policy or intent");
        assert_eq!(input_bytes(&input_path), bytes, "{field} retained input");
    }
    assert!(wb
        .admit_editor_file_save(&context, &inputs, &intent.identity, &request(&intent))
        .is_ok());
}

#[test]
fn request_preparation_project_move_cannot_rebind_an_unsubmitted_or_lost_response_identity() {
    for submitted in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (shared, intent, token) = setup(dir.path());
        let mut wb = shared.lock_unpoisoned();
        let context = wb.authenticate_action_context(&token).unwrap();
        let input_path = dir.path().join("inputs.sqlite");
        let inputs =
            NativeActionInputCustody::open(&input_path, wb.home_id().as_str(), 4096).unwrap();
        if submitted {
            wb.admit_editor_file_save(&context, &inputs, &intent.identity, &request(&intent))
                .unwrap();
        }
        let library = Library::rebuild(wb.store_ref()).unwrap();
        let chat = &library.chats[&intent.chat_id];
        let mut placement = library.instances[&chat.instance_id].clone();
        let old_project = placement.project_id.clone().unwrap();
        let mut project = library.projects[&old_project].clone();
        project.id = "moved-project".into();
        placement.project_id = Some(project.id.clone());
        let set = library.current_target_set(&intent.chat_id).unwrap();
        let mut target = library.work_targets[&set.members[0].target_id].clone();
        target.owner = WorkTargetOwner::Project {
            project_id: project.id.clone(),
        };
        for (kind, record) in [
            ("project", serde_json::to_string(&project).unwrap()),
            ("instance", serde_json::to_string(&placement).unwrap()),
            ("work_target", serde_json::to_string(&target).unwrap()),
        ] {
            wb.store_mut()
                .append_record(LIBRARY_SCOPE, kind, &record)
                .unwrap();
        }
        // Current authority is otherwise valid. The old in-memory projection
        // and target workspace remain deliberately available to catch fallback.
        assert_eq!(
            current_authority(wb.store_ref(), wb.home_id(), &context, &request(&intent))
                .unwrap()
                .project_id,
            project.id
        );
        let rows = product_rows(&wb);
        let bytes = input_bytes(&input_path);
        let error = wb
            .admit_editor_file_save(&context, &inputs, &intent.identity, &request(&intent))
            .err()
            .unwrap();
        assert!(error.contains("original file request"), "{error}");
        assert_eq!(product_rows(&wb), rows);
        assert_eq!(input_bytes(&input_path), bytes);
        assert!(wb
            .observe_editor_file_save_request(&context, intent.identity.as_request())
            .is_err());
        let fresh = wb
            .prepare_editor_file_save_request(
                &context,
                &intent.chat_id,
                &intent.path,
                "separate-intent",
            )
            .unwrap();
        assert_ne!(fresh.scope, intent.identity.scope);
        assert_ne!(fresh.request_id, intent.identity.request_id);
    }
}

struct ChangeAuthority {
    path: String,
    fired: Arc<AtomicBool>,
    inner: Option<Arc<dyn gaugedesk_store::ContentCodec>>,
}
impl gaugedesk_store::ContentCodec for ChangeAuthority {
    fn encode(&self, scope: &str, kind: &str, payload: &str) -> Result<String, String> {
        match &self.inner {
            Some(inner) => inner.encode(scope, kind, payload),
            None => Ok(payload.into()),
        }
    }
    fn decode(&self, scope: &str, kind: &str, payload: &str) -> Option<String> {
        if kind == "project" && !self.fired.swap(true, Ordering::SeqCst) {
            rusqlite::Connection::open(&self.path).unwrap().execute(
                "INSERT INTO events (scope_id, position, kind, payload) SELECT ?1, COALESCE(MAX(position), -1) + 1, 'request_preparation_stale', '{}' FROM events WHERE scope_id = ?1",
                [ORG_SCOPE],
            ).unwrap();
        }
        match &self.inner {
            Some(inner) => inner.decode(scope, kind, payload),
            None => Some(payload.into()),
        }
    }
}

#[test]
fn request_preparation_fences_publication_against_intervening_authority_change() {
    let dir = tempfile::tempdir().unwrap();
    let (shared, intent, token) = setup(dir.path());
    let mut wb = shared.lock_unpoisoned();
    let context = wb.authenticate_action_context(&token).unwrap();
    let fired = Arc::new(AtomicBool::new(false));
    wb.store = wb
        .store_ref()
        .sibling()
        .unwrap()
        .with_codec(Arc::new(ChangeAuthority {
            path: wb.store_ref().path().into(),
            fired: fired.clone(),
            inner: wb
                .content_vault
                .clone()
                .map(|vault| vault as Arc<dyn gaugedesk_store::ContentCodec>),
        }));
    let error = wb
        .prepare_editor_file_save_request(
            &context,
            &intent.chat_id,
            &intent.path,
            &intent.request_id,
        )
        .unwrap_err();
    assert!(error.contains("file request authority changed"), "{error}");
    assert!(fired.load(Ordering::SeqCst));
    assert_eq!(
        wb.prepare_editor_file_save_request(
            &context,
            &intent.chat_id,
            &intent.path,
            &intent.request_id
        )
        .unwrap(),
        intent.identity
    );
}

#[test]
fn request_preparation_never_survives_revocation_as_save_permission() {
    let dir = tempfile::tempdir().unwrap();
    let (shared, intent, token) = setup(dir.path());
    let mut wb = shared.lock_unpoisoned();
    let context = wb.authenticate_action_context(&token).unwrap();
    wb.revoke_account_session(&token);
    let rows = product_rows(&wb);
    assert!(wb
        .prepare_editor_file_save_request(
            &context,
            &intent.chat_id,
            &intent.path,
            &intent.request_id
        )
        .is_err());
    let input_path = dir.path().join("inputs.sqlite");
    let inputs = NativeActionInputCustody::open(&input_path, wb.home_id().as_str(), 4096).unwrap();
    let bytes = input_bytes(&input_path);
    assert!(wb
        .admit_editor_file_save(&context, &inputs, &intent.identity, &request(&intent))
        .is_err());
    assert_eq!(product_rows(&wb), rows);
    assert_eq!(input_bytes(&input_path), bytes);
}
