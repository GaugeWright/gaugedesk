//! Existing coordinates and retained history do not require a projection.
use super::*;
use whipplescript_store::content::{ContentBlobs, ContentStore};

fn databases(instance: &Instance) -> (Vec<u8>, Vec<u8>) {
    (
        std::fs::read(instance.store_root.join("branches.sqlite")).unwrap(),
        std::fs::read(instance.store_root.join("content.sqlite")).unwrap(),
    )
}

#[test]
fn reopening_recorded_coordinates_preserves_history_after_body_and_checkout_erasure() {
    let dir = tempfile::tempdir().unwrap();
    let instance = Instance::init_at(dir.path()).unwrap();
    assert_eq!(instance.current_main_cut().unwrap(), None);
    instance
        .seed_main(&[("selected/note.txt", "retained body")])
        .unwrap();
    let roots = BTreeSet::from(["selected".to_owned()]);
    let chat = instance
        .create_engagement_subset("chat", MAINLINE_BRANCH_ID, &roots)
        .unwrap();
    let head = instance.current_main_cut().unwrap();
    let hash = {
        let vcs = instance.store().unwrap();
        vcs.cut_manifest(head.as_deref().unwrap()).unwrap().unwrap()["selected/note.txt"].clone()
    };
    ContentStore::open(instance.store_root.join("content.sqlite"))
        .unwrap()
        .erase(&hash, "erase retained body")
        .unwrap();
    std::fs::remove_dir_all(chat.path()).unwrap();
    let before = databases(&instance);
    let reopened = instance
        .open_engagement_subset("chat", MAINLINE_BRANCH_ID, &roots)
        .unwrap()
        .unwrap();
    assert_eq!(reopened.branch(), chat.branch());
    assert_eq!(reopened.target(), chat.target());
    assert!(!reopened.path().exists());
    assert_eq!(instance.current_main_cut().unwrap(), head);
    assert!(instance
        .open_engagement_subset("absent", MAINLINE_BRANCH_ID, &roots)
        .unwrap()
        .is_none());
    assert!(instance
        .open_engagement_subset("chat", "absent-home", &roots)
        .is_err());
    assert!(instance
        .open_engagement_subset("../chat", MAINLINE_BRANCH_ID, &roots)
        .is_err());
    assert_eq!(databases(&instance), before);
    assert!(reopened.sync_from_main().is_err());
    assert!(!reopened.path().exists());
    assert!(reopened.write_file("selected/new.txt", "new").is_err());
    assert!(
        ContentStore::open(instance.store_root.join("content.sqlite"))
            .unwrap()
            .get(&hash)
            .unwrap()
            .is_none()
    );
}

#[test]
fn reopening_preserves_unrecorded_edits_and_enforces_selected_paths() {
    let dir = tempfile::tempdir().unwrap();
    let instance = Instance::init_at(dir.path()).unwrap();
    instance
        .seed_main(&[
            ("selected/note.txt", "recorded"),
            ("other/note.txt", "other"),
        ])
        .unwrap();
    let chat = instance.create_engagement("chat").unwrap();
    chat.write_file("selected/note.txt", "unfinished local work")
        .unwrap();
    let before = databases(&instance);
    let roots = BTreeSet::from(["selected".to_owned()]);
    let reopened = instance
        .open_engagement_subset("chat", MAINLINE_BRANCH_ID, &roots)
        .unwrap()
        .unwrap();
    assert_eq!(
        reopened.read_file("selected/note.txt").unwrap(),
        "unfinished local work"
    );
    assert!(reopened.read_file("other/note.txt").is_err());
    assert_eq!(databases(&instance), before);
}

#[test]
fn reading_an_absent_main_ref_does_not_initialize_a_workspace() {
    let dir = tempfile::tempdir().unwrap();
    let instance = Instance::open_at(dir.path().join("missing"));
    assert!(instance.current_main_cut().is_err());
    assert!(!dir.path().join("missing").exists());
}

#[test]
fn missing_projection_is_unavailable_but_materialized_empty_tree_is_empty() {
    let dir = tempfile::tempdir().unwrap();
    let instance = Instance::init_at(dir.path()).unwrap();
    let chat = instance.create_engagement("chat").unwrap();
    assert!(chat.tree().unwrap().is_empty());
    std::fs::remove_dir_all(chat.path()).unwrap();
    let before = databases(&instance);
    assert!(chat.tree().is_err());
    assert_eq!(databases(&instance), before);
    assert!(!chat.path().exists());
}

#[test]
fn direct_mutations_refuse_missing_projection_without_creating_partial_checkout() {
    for operation in [
        "text",
        "bytes",
        "remove",
        "save",
        "ingest",
        "ingest-into",
        "upload",
        "upload-into",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let instance = Instance::init_at(dir.path()).unwrap();
        instance
            .seed_main(&[("selected/kept.txt", "recorded")])
            .unwrap();
        let chat = instance.create_engagement("chat").unwrap();
        let base = instance.current_main_cut().unwrap().unwrap();
        let source = dir.path().join("upload");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("new.txt"), "new").unwrap();
        std::fs::remove_dir_all(chat.path()).unwrap();
        let before = databases(&instance);
        let refused = match operation {
            "text" => chat.write_file("selected/new.txt", "new").is_err(),
            "bytes" => ChatWorkspace::write_file_bytes(&chat, "selected/new.txt", b"new").is_err(),
            "remove" => ChatWorkspace::remove_file(&chat, "selected/kept.txt").is_err(),
            "save" => chat
                .save_file_with_base("selected/kept.txt", "changed", SaveBase::Cut(&base), &[])
                .is_err(),
            "ingest" => chat.ingest(&source).is_err(),
            "ingest-into" => chat.ingest_into("selected", &source).is_err(),
            "upload" => chat
                .ingest_upload(&[("new.txt".into(), "new".into())])
                .is_err(),
            "upload-into" => chat
                .ingest_upload_into("selected", &[("new.txt".into(), "new".into())])
                .is_err(),
            _ => unreachable!(),
        };
        assert!(refused, "{operation}");
        assert!(!chat.path().exists(), "{operation}");
        assert_eq!(databases(&instance), before, "{operation}");
        assert_eq!(chat.current_cut().unwrap(), Some(base), "{operation}");
    }
}
