use super::*;
use whipplescript_store::{
    content::{ContentBlobs, EraseOutcome},
    text_merge::RegionResolution,
    vcs_resolution_recording::{read_committed_resolution_recording, ResolutionRecordingInput},
};

fn scope(compartment: &str) -> ResolutionMemoryScope {
    ResolutionMemoryScope::new(
        "home".into(),
        "target/path-grant".into(),
        compartment.into(),
    )
    .unwrap()
}
fn body(text: &str) -> String {
    serde_json::to_string(
        &ResolutionRecordingInput::new(vec![RegionResolution {
            base_text: "base".into(),
            ours_text: "ours".into(),
            theirs_text: "theirs".into(),
            resolution_text: text.into(),
        }])
        .unwrap(),
    )
    .unwrap()
}
fn binding(
    body: &str,
    scope: ResolutionMemoryScope,
    operation: &str,
    actor: &str,
) -> ResolutionRecordingBinding {
    ResolutionRecordingBinding::prepare(
        body,
        "input-label",
        scope,
        operation,
        actor,
        "correction",
        "t1",
    )
    .unwrap()
}
fn observe(chat: &Engagement) -> NativeWorkspaceVcs {
    NativeWorkspaceVcs::open_read_only(
        chat.store_root.join("branches.sqlite"),
        chat.store_root.join("content.sqlite"),
    )
    .unwrap()
}

#[test]
fn independent_recording_uses_actual_target_without_a_file_base_or_head_change() {
    let dir = tempfile::tempdir().unwrap();
    let instance = crate::Instance::init_at(dir.path()).unwrap();
    let human = instance.create_engagement("human").unwrap();
    let agent = instance.create_engagement("agent").unwrap();
    let heads = [&human, &agent].map(|chat| observe(chat).get_branch(&chat.branch).unwrap());
    let mut first = None;
    for (chat, actor, text, inserted) in [
        (&human, "human:author", "winner", true),
        (&agent, "agent:author", "later", false),
    ] {
        let target = chat
            .native_resolution_recording_target("note.txt", scope("private"))
            .unwrap();
        assert_eq!(target.path(), "note.txt");
        assert_eq!(target.scope(), &scope("private"));
        let body = body(text);
        let descriptor = binding(&body, scope("private"), actor, actor);
        let mut handler = target.open_recording(descriptor.clone(), &body).unwrap();
        assert_eq!(handler.binding(), &descriptor);
        let receipt = handler.record().unwrap();
        assert_eq!(&receipt.request, descriptor.batch());
        assert!(receipt
            .outcomes
            .iter()
            .all(|entry| entry.inserted == inserted));
        assert_eq!(handler.record().unwrap(), receipt);
        if inserted {
            first = Some(receipt);
        } else {
            assert!(receipt
                .outcomes
                .iter()
                .all(|entry| entry.resolution == first.as_ref().unwrap().outcomes[0].resolution));
        }
        assert!(!chat.path().join("note.txt").exists());
    }
    assert_eq!(
        heads,
        [&human, &agent].map(|chat| observe(chat).get_branch(&chat.branch).unwrap())
    );
    let first = first.unwrap();
    assert_eq!(
        observe(&agent).resolution_receipt("human:author").unwrap(),
        Some(first)
    );
}

#[test]
fn recording_target_refuses_wrong_scope_input_and_unselected_paths() {
    let dir = tempfile::tempdir().unwrap();
    let instance = crate::Instance::init_at(dir.path()).unwrap();
    let mut chat = instance.create_engagement("one").unwrap();
    for path in [
        "",
        "../selected",
        "selected/../escape",
        "selected//file",
        "selected\\file",
        "selected/\0file",
        ".gaugedesk-runtime/private",
    ] {
        assert!(
            chat.native_resolution_recording_target(path, scope("private"))
                .is_err(),
            "{path}"
        );
    }
    chat.sparse_roots = Some(["selected".into()].into_iter().collect());
    assert!(chat
        .native_resolution_recording_target("unselected/file", scope("private"))
        .is_err());
    let body = body("winner");
    let descriptor = binding(&body, scope("private"), "operation", "human:author");
    let target = chat
        .native_resolution_recording_target("selected/file", scope("private"))
        .unwrap();
    assert!(target
        .open_recording(
            binding(&body, scope("foreign"), "operation", "human:author"),
            &body
        )
        .is_err());
    assert!(target
        .open_recording(descriptor.clone(), &self::body("substituted"))
        .is_err());
    assert!(observe(&chat)
        .resolution_receipt("operation")
        .unwrap()
        .is_none());
    let evidence = chat
        .native_resolution_recording_evidence_target("selected/file", scope("foreign"))
        .unwrap();
    let called = std::cell::Cell::new(false);
    assert!(evidence
        .observe(&descriptor, |_| {
            called.set(true);
            Ok(())
        })
        .is_err());
    assert!(!called.get());
    chat.branch = "missing-branch".into();
    let missing_branch = chat
        .native_resolution_recording_target("selected/file", scope("private"))
        .unwrap();
    assert!(missing_branch
        .open_recording(descriptor.clone(), &body)
        .is_err());
    chat.store_root = dir.path().join("absent-store");
    let missing_store = chat
        .native_resolution_recording_target("selected/file", scope("private"))
        .unwrap();
    assert!(missing_store
        .open_recording(descriptor.clone(), &body)
        .is_err());
    let missing_evidence = chat
        .native_resolution_recording_evidence_target("selected/file", scope("private"))
        .unwrap();
    assert!(missing_evidence
        .observe(&descriptor, |_| {
            called.set(true);
            Ok(())
        })
        .is_err());
    assert!(!called.get());
    assert!(!chat.store_root.exists());
}

#[test]
fn recording_evidence_reads_original_batch_after_erasure_without_writes() {
    let dir = tempfile::tempdir().unwrap();
    let instance = crate::Instance::init_at(dir.path()).unwrap();
    let chat = instance.create_engagement("one").unwrap();
    let body = body("winner");
    let descriptor = binding(&body, scope("private"), "operation", "human:author");
    let target = chat
        .native_resolution_recording_target("note.txt", scope("private"))
        .unwrap();
    let receipt = target
        .open_recording(descriptor.clone(), &body)
        .unwrap()
        .record()
        .unwrap();
    let content = ContentStore::open(chat.store_root.join("content.sqlite")).unwrap();
    assert_eq!(content.put_text(&body).unwrap(), descriptor.input_hash());
    for hash in [descriptor.input_hash(), &receipt.outcomes[0].resolution] {
        assert!(matches!(
            content.erase(hash, "t2").unwrap(),
            EraseOutcome::Erased { .. }
        ));
    }
    let evidence = chat
        .native_resolution_recording_evidence_target("note.txt", scope("private"))
        .unwrap();
    let before = observe(&chat).get_branch(&chat.branch).unwrap();
    assert_eq!(
        evidence
            .observe(&descriptor, |workspace| {
                // The locator enforces SQLite read-only access even if a callback asks
                // a storage API to write; it does not authorize callback reads.
                assert!(workspace
                    .content_store()
                    .put_text("forbidden write")
                    .is_err());
                read_committed_resolution_recording(workspace, &descriptor)
            })
            .unwrap(),
        Some(receipt)
    );
    assert_eq!(observe(&chat).get_branch(&chat.branch).unwrap(), before);
    for hash in [
        descriptor.input_hash(),
        &whipplescript_store::stable_hash_hex("winner"),
    ] {
        assert!(content.get(hash).unwrap().is_none());
    }
    let changed = binding(
        &self::body("changed"),
        scope("private"),
        "operation",
        "human:author",
    );
    assert!(evidence
        .observe(&changed, |workspace| read_committed_resolution_recording(
            workspace, &changed
        ))
        .is_err());
}

#[test]
fn external_candidate_cannot_manufacture_native_recording_or_evidence() {
    use crate::Workspace;
    let source = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    std::fs::write(source.path().join("note.txt"), "external source").unwrap();
    let workspace = crate::ExternalWorkspace::open(
        source.path(),
        state.path(),
        crate::ExternalTargetKind::Folder,
    )
    .unwrap();
    let candidate = workspace.create_engagement("chat").unwrap();
    assert!(candidate
        .native_resolution_recording_target("note.txt", scope("private"))
        .is_err());
    assert!(candidate
        .native_resolution_recording_evidence_target("note.txt", scope("private"))
        .is_err());
    assert_eq!(
        std::fs::read_to_string(source.path().join("note.txt")).unwrap(),
        "external source"
    );
    assert_eq!(
        std::fs::read_to_string(candidate.path().join("note.txt")).unwrap(),
        "external source"
    );
    assert!(!state.path().join("branches.sqlite").exists());
    assert!(!state.path().join("content.sqlite").exists());
}
