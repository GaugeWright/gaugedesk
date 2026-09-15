//! Real host encryption at the workspace factory/export boundary. Recipient
//! custody uses actual recipient capsules; product Home admission is separate.
use gaugedesk_app::{
    at_rest::LoopbackKeyWrap,
    content_vault::{ContentVault, LocalFileErasureLedger},
};
use gaugedesk_core::signature::SigningKey;
use gaugedesk_workspace::{
    Instance, WhippleWorkspaceProvider, WorkflowProtection, WorkspaceProvider,
    PROTECTED_EXPORT_FORMAT,
};
use serde_json::json;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use whipplescript_store::{
    log_append::LogAppend,
    tracker_filing::{TrackerFiling, TrackerFilings},
    tracker_result::closing_conformance,
    RuntimeStore,
};

const WORKSPACE: &str = "workspace:personal:alice";
const SCOPE: &str = "project:personal:alice";
fn vault(root: &Path, kek: u8) -> ContentVault {
    ContentVault::new(root, Box::new(LoopbackKeyWrap::new([kek; 32]))).with_ledger(Box::new(
        LocalFileErasureLedger::new(root.join("erased.ledger")),
    ))
}
fn protection(vault: &ContentVault, workspace: &str) -> WorkflowProtection {
    WorkflowProtection::new(workspace, Arc::new(vault.prepare_scope_key(SCOPE).unwrap())).unwrap()
}
fn root(dir: &Path) -> PathBuf {
    dir.join(".repo.whipplescript")
}
fn contains(bytes: &[u8], needle: &str) -> bool {
    bytes
        .windows(needle.len())
        .any(|bytes| bytes == needle.as_bytes())
}

#[test]
fn protected_workspace_relocates_exact_history_with_a_rewrapped_key() {
    let source = tempfile::tempdir().unwrap();
    let keys = source.path().join("keys");
    let source_vault = vault(&keys, 7);
    source_vault.initialize_scope_key(SCOPE).unwrap();
    let p = protection(&source_vault, WORKSPACE);
    let workspace = Instance::init_at(source.path()).unwrap();
    workspace
        .seed_main(&[("tutorials/custom.whip", "ordinary authored source")])
        .unwrap();
    let storage = workspace.native_workflow_storage();
    let mut stores = storage.initialize_protected(&p).unwrap();
    let delivery = closing_conformance::setup(&mut stores.runtime, "lease_expired");
    let instance = delivery.closure.instance_id;
    let events = stores.runtime.list_events(&instance).unwrap();
    let runs = stores.runtime.list_runs(&instance).unwrap();
    let head = stores.runtime.chain_head(&instance).unwrap();
    let filing = TrackerFiling {
        operation_id: "filing:one".into(),
        instance_id: instance.clone(),
        effect_id: "effect:one".into(),
        actor: "person:alice".into(),
        queue: "tutorials".into(),
        title: "private tutorial title".into(),
        body: "private tutorial body".into(),
        labels: vec![],
        metadata: json!({}),
        assigned_to: Some("person:alice".into()),
    };
    let receipt = stores.runtime.items.file_issue_once(&filing).unwrap();
    stores
        .runtime
        .coord
        .append_for_owner(
            WORKSPACE,
            "progress",
            "tutorial",
            "{\"private\":\"coordination payload\"}",
            "person:alice",
            0,
        )
        .unwrap();
    let entries = stores.runtime.coord.list_entries(None, None).unwrap();
    let input = stores.inputs.put_text("private retained input").unwrap();
    assert!(storage.open_existing(WORKSPACE).is_err());
    assert!(workspace.export().is_err());
    let recipient = SigningKey::from_seed(&[3; 32]).unwrap();
    let transfer = source_vault
        .prepare_scope_transfer(SCOPE, &recipient.public_key())
        .unwrap();
    let (export, capsule) = transfer
        .with_retained::<_, std::io::Error>(|key, capsule| {
            let transfer_protection =
                WorkflowProtection::new(WORKSPACE, key.clone()).map_err(std::io::Error::other)?;
            Ok((
                workspace
                    .export_protected_workflow(&transfer_protection)
                    .map_err(std::io::Error::other)?,
                capsule.clone(),
            ))
        })
        .unwrap();
    assert_eq!(&export.0[..8], b"WSVCSEX4");
    for needle in [
        "private tutorial title",
        "private tutorial body",
        "coordination payload",
        "private retained input",
    ] {
        assert!(!contains(&export.0, needle), "export exposed {needle}");
    }
    let target = tempfile::tempdir().unwrap();
    assert!(Instance::from_export_at(target.path(), &export.0).is_err());
    assert!(!root(target.path()).exists());
    // The actual receiver unwraps its recipient capsule and rewraps the same
    // content key under its own KEK; the test never handles raw data-key bytes.
    let target_vault = vault(&target.path().join("keys"), 8);
    let received = target_vault
        .receive_scope_key(SCOPE, &recipient, &capsule)
        .unwrap();
    let target_p = WorkflowProtection::new(WORKSPACE, Arc::new(received)).unwrap();
    let provider = WhippleWorkspaceProvider;
    assert!(provider.accepts_export_format(PROTECTED_EXPORT_FORMAT));
    let imported = provider
        .from_protected_export_at(target.path(), &export.0, &target_p)
        .unwrap();
    let mut relocated = imported
        .native_workflow_storage()
        .unwrap()
        .open_existing_protected(&target_p)
        .unwrap();
    assert_eq!(relocated.runtime.list_events(&instance).unwrap(), events);
    assert_eq!(relocated.runtime.list_runs(&instance).unwrap(), runs);
    assert_eq!(relocated.runtime.chain_head(&instance).unwrap(), head);
    assert_eq!(
        relocated.runtime.items.file_issue_once(&filing).unwrap(),
        receipt
    );
    assert_eq!(
        relocated.runtime.coord.list_entries(None, None).unwrap(),
        entries
    );
    assert_eq!(
        relocated.inputs.get_text(&input).unwrap().text().as_deref(),
        Some("private retained input")
    );
    drop(relocated);
    let reopened = Instance::open_at(target.path());
    let reopened_stores = reopened
        .native_workflow_storage()
        .open_existing_protected(&target_p)
        .unwrap();
    assert_eq!(reopened_stores.runtime.chain_head(&instance).unwrap(), head);
    assert!(Instance::from_protected_export_at(target.path(), &export.0, &target_p).is_ok());
    assert!(Instance::from_export_at(target.path(), &export.0).is_err());
    let later = reopened_stores
        .inputs
        .put_text("later private input")
        .unwrap();
    assert!(Instance::from_protected_export_at(target.path(), &export.0, &target_p).is_err());
    assert_eq!(
        reopened_stores
            .inputs
            .get_text(&later)
            .unwrap()
            .text()
            .as_deref(),
        Some("later private input")
    );
    // Erasing the receiving copy invalidates reads/export there without
    // manufacturing an erasure of the separate source custody fixture.
    target_vault.erase_scope_key(SCOPE).unwrap();
    assert!(Instance::from_protected_export_at(target.path(), &export.0, &target_p).is_err());
    assert!(reopened_stores
        .runtime
        .items
        .get_item(&receipt.item_id)
        .is_err());
    assert!(reopened.export_protected_workflow(&target_p).is_err());
    assert!(storage.open_existing_protected(&p).is_ok());
    let fork_dir = tempfile::tempdir().unwrap();
    let fork = Instance::fork_from_at(fork_dir.path(), &workspace.peer_source()).unwrap();
    assert!(!root(fork_dir.path()).join("workflow").exists());
    assert!(fork
        .native_workflow_storage()
        .open_existing_protected(&p)
        .is_err());
}

#[test]
fn protected_workspace_refuses_foreign_custody_modes_and_damaged_store_sets() {
    let source = tempfile::tempdir().unwrap();
    let v = vault(&source.path().join("keys"), 7);
    v.initialize_scope_key(SCOPE).unwrap();
    let p = protection(&v, WORKSPACE);
    let w = Instance::init_at(source.path()).unwrap();
    assert!(w.export_protected_workflow(&p).is_err());
    let storage = w.native_workflow_storage();
    drop(storage.initialize_protected(&p).unwrap());
    let export = w.export_protected_workflow(&p).unwrap();
    let wrong_root = tempfile::tempdir().unwrap();
    let wrong_vault = vault(wrong_root.path(), 7);
    wrong_vault.initialize_scope_key(SCOPE).unwrap();
    let wrong_key = protection(&wrong_vault, WORKSPACE);
    let wrong_workspace = protection(&v, "workspace:other");
    for wrong in [&wrong_key, &wrong_workspace] {
        assert!(storage.initialize_protected(wrong).is_err());
        assert!(storage.open_existing_protected(wrong).is_err());
        assert!(w.export_protected_workflow(wrong).is_err());
        let target = tempfile::tempdir().unwrap();
        assert!(Instance::from_protected_export_at(target.path(), &export.0, wrong).is_err());
        assert!(!root(target.path()).exists());
        Instance::from_protected_export_at(target.path(), &export.0, &p).unwrap();
    }
    let plain_dir = tempfile::tempdir().unwrap();
    let plain = Instance::init_at(plain_dir.path()).unwrap();
    drop(
        plain
            .native_workflow_storage()
            .initialize(WORKSPACE)
            .unwrap(),
    );
    assert!(plain
        .native_workflow_storage()
        .initialize_protected(&p)
        .is_err());
    assert!(plain.export_protected_workflow(&p).is_err());
    let plain_export = plain.export().unwrap();
    let target = tempfile::tempdir().unwrap();
    assert!(Instance::from_protected_export_at(target.path(), &plain_export.0, &p).is_err());
    assert!(!root(target.path()).exists());
    for index in 0..4 {
        let target = tempfile::tempdir().unwrap();
        let imported = Instance::from_protected_export_at(target.path(), &export.0, &p).unwrap();
        let names = [
            "runtime.sqlite",
            "coord.sqlite",
            "items.sqlite",
            "inputs.sqlite",
        ];
        let file = root(target.path()).join("workflow").join(names[index]);
        std::fs::remove_file(&file).unwrap();
        assert!(imported
            .native_workflow_storage()
            .initialize_protected(&p)
            .is_err());
        assert!(imported.export_protected_workflow(&p).is_err());
        assert!(!file.exists());
    }
    let binding = root(source.path()).join("workflow/workspace.json");
    let mut changed: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&binding).unwrap()).unwrap();
    changed["protected"]["key_check"] = json!([0, 1, 2]);
    std::fs::write(&binding, serde_json::to_vec(&changed).unwrap()).unwrap();
    assert!(storage.open_existing_protected(&p).is_err());
    assert!(w.export_protected_workflow(&p).is_err());
}

fn replace_frame(export: &[u8], index: usize, replacement: &[u8]) -> Vec<u8> {
    let mut result = export[..8].to_vec();
    let mut remaining = &export[8..];
    let mut current = 0;
    while !remaining.is_empty() {
        let len = u64::from_le_bytes(remaining[..8].try_into().unwrap()) as usize;
        let body = if current == index {
            replacement
        } else {
            &remaining[8..8 + len]
        };
        result.extend_from_slice(&(body.len() as u64).to_le_bytes());
        result.extend_from_slice(body);
        remaining = &remaining[8 + len..];
        current += 1;
    }
    assert!(index < current);
    result
}

#[test]
fn damaged_protected_imports_leave_no_published_store_authority() {
    let source = tempfile::tempdir().unwrap();
    let v = vault(&source.path().join("keys"), 7);
    v.initialize_scope_key(SCOPE).unwrap();
    let p = protection(&v, WORKSPACE);
    let w = Instance::init_at(source.path()).unwrap();
    drop(
        w.native_workflow_storage()
            .initialize_protected(&p)
            .unwrap(),
    );
    let export = w.export_protected_workflow(&p).unwrap();
    for frame in 3..8 {
        // Frame 3 is the authenticated workspace binding, followed by four DBs.
        let damaged = replace_frame(&export.0, frame, &[]);
        let target = tempfile::tempdir().unwrap();
        assert!(Instance::from_protected_export_at(target.path(), &damaged, &p).is_err());
        assert!(!root(target.path()).exists());
        Instance::from_protected_export_at(target.path(), &export.0, &p).unwrap();
    }
    let mut downgraded = export.0.clone();
    downgraded[..8].copy_from_slice(b"WSVCSEX3");
    let target = tempfile::tempdir().unwrap();
    assert!(Instance::from_export_at(target.path(), &downgraded).is_err());
    assert!(!root(target.path()).exists());
    let mut binding: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root(source.path()).join("workflow/workspace.json")).unwrap(),
    )
    .unwrap();
    binding["workspace_id"] = json!("workspace:other");
    let damaged = replace_frame(&export.0, 3, &serde_json::to_vec(&binding).unwrap());
    let target = tempfile::tempdir().unwrap();
    assert!(Instance::from_protected_export_at(target.path(), &damaged, &p).is_err());
    assert!(!root(target.path()).exists());
}

struct PublicationProbe {
    key: Arc<gaugedesk_app::content_vault::PreparedScopeKey>,
    vault: Arc<ContentVault>,
    published: PathBuf,
    calls: std::sync::atomic::AtomicUsize,
}
impl whipplescript_store::payload_protection::PayloadCodec for PublicationProbe {
    fn seal(&self, aad: &[u8], body: &[u8]) -> whipplescript_store::StoreResult<Vec<u8>> {
        self.key.seal(aad, body).map_err(Into::into)
    }
    fn open(&self, aad: &[u8], body: &[u8]) -> whipplescript_store::StoreResult<Vec<u8>> {
        self.key.open(aad, body).map_err(Into::into)
    }
    fn retain(
        &self,
        operation: &mut dyn FnMut() -> whipplescript_store::StoreResult<()>,
    ) -> whipplescript_store::StoreResult<()> {
        self.key.retain(|| {
            assert_eq!(
                self.vault.erase_scope_key(SCOPE).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            operation()?;
            assert!(
                self.published.is_file(),
                "key lease ended before final directory publication"
            );
            assert_eq!(
                self.vault.erase_scope_key(SCOPE).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        })
    }
}

#[test]
fn initialization_and_import_retain_the_key_through_final_directory_publication() {
    use std::sync::atomic::Ordering;
    let source = tempfile::tempdir().unwrap();
    let v = Arc::new(vault(&source.path().join("keys"), 7));
    let key = Arc::new(v.initialize_scope_key(SCOPE).unwrap());
    let probe = Arc::new(PublicationProbe {
        key: key.clone(),
        vault: v.clone(),
        published: root(source.path()).join("workflow/inputs.sqlite"),
        calls: 0.into(),
    });
    let p = WorkflowProtection::new(WORKSPACE, probe.clone()).unwrap();
    let w = Instance::init_at(source.path()).unwrap();
    drop(
        w.native_workflow_storage()
            .initialize_protected(&p)
            .unwrap(),
    );
    assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
    let export = w.export_protected_workflow(&p).unwrap();
    assert_eq!(probe.calls.load(Ordering::SeqCst), 2);
    let target = tempfile::tempdir().unwrap();
    let importing = Arc::new(PublicationProbe {
        key,
        vault: v.clone(),
        published: root(target.path()).join("workflow/inputs.sqlite"),
        calls: 0.into(),
    });
    let p = WorkflowProtection::new(WORKSPACE, importing.clone()).unwrap();
    Instance::from_protected_export_at(target.path(), &export.0, &p).unwrap();
    assert_eq!(importing.calls.load(Ordering::SeqCst), 1);
    v.erase_scope_key(SCOPE).unwrap();
    let missing = tempfile::tempdir().unwrap();
    assert!(Instance::from_protected_export_at(missing.path(), &export.0, &p).is_err());
    assert!(!root(missing.path()).exists());
}

#[test]
fn concurrent_protected_initializers_publish_one_complete_store_set() {
    let source = tempfile::tempdir().unwrap();
    let v = vault(&source.path().join("keys"), 7);
    v.initialize_scope_key(SCOPE).unwrap();
    let p = Arc::new(protection(&v, WORKSPACE));
    let workspace = Instance::init_at(source.path()).unwrap();
    let start = Arc::new(std::sync::Barrier::new(5));
    let workers: Vec<_> = (0..4)
        .map(|index| {
            let dir = source.path().to_owned();
            let p = p.clone();
            let start = start.clone();
            std::thread::spawn(move || {
                start.wait();
                let stores = Instance::open_at(dir)
                    .native_workflow_storage()
                    .initialize_protected(&p)
                    .unwrap();
                let body = format!("input from initializer {index}");
                (stores.inputs.put_text(&body).unwrap(), body)
            })
        })
        .collect();
    start.wait();
    let bodies: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    let stores = workspace
        .native_workflow_storage()
        .open_existing_protected(&p)
        .unwrap();
    for (hash, body) in bodies {
        assert_eq!(
            stores.inputs.get_text(&hash).unwrap().text().as_deref(),
            Some(body.as_str())
        );
    }
}
