use super::*;
use crate::at_rest::LoopbackKeyWrap;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc, Barrier,
};
use std::time::Duration;

fn vault(root: &Path) -> Arc<ContentVault> {
    Arc::new(
        ContentVault::new(root, Box::new(LoopbackKeyWrap::new([7; 32]))).with_ledger(Box::new(
            LocalFileErasureLedger::new(root.join("erased.ledger")),
        )),
    )
}

#[test]
fn prepared_scope_keys_require_confirmed_existing_custody_and_authenticate_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(dir.path());
    assert!(v.prepare_scope_key("project").is_err());
    assert!(!v.key_path("project").exists());
    assert!(v.initialize_scope_key("").is_err());
    assert!(v.erase_scope_key("").is_err());
    let no_ledger = ContentVault::new(dir.path(), Box::new(LoopbackKeyWrap::new([7; 32])));
    assert!(no_ledger.initialize_scope_key("project").is_err());
    assert!(no_ledger.erase_scope_key("project").is_err());
    let key = v.initialize_scope_key("project").unwrap();
    assert_eq!(key.scope(), "project");
    let aad = b"workspace/runtime/coordinate";
    let body = b"private\0binary\xffpayload";
    let encrypted = key.seal(aad, body).unwrap();
    assert_ne!(encrypted, body);
    assert_eq!(key.open(aad, &encrypted).unwrap(), body);
    assert!(key.open(b"wrong-coordinate", &encrypted).is_err());
    let fresh = vault(dir.path());
    assert_eq!(
        fresh
            .prepare_scope_key("project")
            .unwrap()
            .open(aad, &encrypted)
            .unwrap(),
        body
    );
    let other = v.initialize_scope_key("other").unwrap();
    assert!(other.open(aad, &encrypted).is_err());
    let wrapped = std::fs::read(v.key_path("project")).unwrap();
    let wrong = ContentVault::new(dir.path(), Box::new(LoopbackKeyWrap::new([8; 32]))).with_ledger(
        Box::new(LocalFileErasureLedger::new(
            dir.path().join("erased.ledger"),
        )),
    );
    assert!(wrong.prepare_scope_key("project").is_err());
    assert!(wrong.initialize_scope_key("project").is_err());
    assert_eq!(std::fs::read(v.key_path("project")).unwrap(), wrapped);
}

#[test]
fn prepared_keys_refuse_missing_or_changed_files_without_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(dir.path());
    let key = v.initialize_scope_key("project").unwrap();
    let ciphertext = key.seal(b"aad", b"private").unwrap();
    let path = v.key_path("project");
    let wrapped = std::fs::read(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    assert!(key.open(b"aad", &ciphertext).is_err());
    assert!(key.seal(b"aad", b"new").is_err());
    assert!(v.prepare_scope_key("project").is_err());
    assert!(!path.exists());
    std::fs::write(&path, b"malformed wrapped key").unwrap();
    assert!(key.open(b"aad", &ciphertext).is_err());
    assert!(v.initialize_scope_key("project").is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"malformed wrapped key");
    // Restoring an unexpectedly missing live file is distinct from erasure.
    std::fs::write(&path, &wrapped).unwrap();
    assert_eq!(key.open(b"aad", &ciphertext).unwrap(), b"private");
    assert!(v.erase_scope_key("project").unwrap());
    std::fs::write(&path, wrapped).unwrap();
    assert!(key.open(b"aad", &ciphertext).is_err());
    assert!(v.prepare_scope_key("project").is_err());
    assert!(v.initialize_scope_key("project").is_err());
}

#[test]
fn legacy_erasure_invalidates_other_vault_caches_and_all_key_creation_paths() {
    let dir = tempfile::tempdir().unwrap();
    let native = vault(dir.path());
    let key = native.initialize_scope_key("project").unwrap();
    let other_cache = vault(dir.path());
    let legacy = other_cache
        .encode("project", "transcript", "private legacy")
        .unwrap();
    let private = other_cache
        .seal_private("project", "private custody")
        .unwrap();
    assert_eq!(
        other_cache.open_private("project", &private).as_deref(),
        Some("private custody")
    );
    let ciphertext = key.seal(b"aad", b"private native").unwrap();
    let wrapped = std::fs::read(native.key_path("project")).unwrap();
    // Even an older caller without an injected ledger participates in local
    // exclusion/tombstones. It cannot leave another vault's cache usable.
    let old = ContentVault::new(dir.path(), Box::new(LoopbackKeyWrap::new([7; 32])));
    assert!(old.crypto_erase("project"));
    assert!(key.open(b"aad", &ciphertext).is_err());
    assert!(other_cache
        .decode("project", "transcript", &legacy)
        .is_none());
    assert!(other_cache.encode("project", "transcript", "new").is_err());
    assert!(native.initialize_scope_key("project").is_err());
    std::fs::write(native.key_path("project"), wrapped).unwrap();
    assert!(vault(dir.path()).prepare_scope_key("project").is_err());
    assert!(old.open_private("project", &private).is_none());
    assert!(native.initialize_scope_key("other").is_ok());
}

#[test]
fn native_and_legacy_initializers_share_one_scope_key_across_instances() {
    let dir = tempfile::tempdir().unwrap();
    let start = Arc::new(Barrier::new(9));
    let mut workers = Vec::new();
    for index in 0..8 {
        let root = dir.path().to_owned();
        let start = start.clone();
        workers.push(std::thread::spawn(move || {
            let v = vault(&root);
            start.wait();
            if index % 2 == 0 {
                v.initialize_scope_key("project")
                    .unwrap()
                    .seal(b"", b"same-key")
                    .unwrap()
            } else {
                hex::decode(v.seal_private("project", "same-key").unwrap()).unwrap()
            }
        }));
    }
    start.wait();
    let ciphertexts: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    let key = vault(dir.path()).prepare_scope_key("project").unwrap();
    for ciphertext in ciphertexts {
        assert_eq!(key.open(b"", &ciphertext).unwrap(), b"same-key");
    }
}

#[test]
fn all_erasers_wait_for_publication_and_nested_use_survives_a_waiting_eraser() {
    for mode in ["confirmed", "legacy", "sweep"] {
        let dir = tempfile::tempdir().unwrap();
        let v = vault(dir.path());
        let key = v.initialize_scope_key("project").unwrap();
        // A different vault and path spelling must share exclusion, not keys.
        let second = vault(&dir.path().join("."));
        let second_key = second.prepare_scope_key("project").unwrap();
        let key_id = crate::org::sha256_hex("project");
        let (started_tx, started_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let mut worker = None;
        key.retain::<_, std::io::Error>(|| {
            if mode == "sweep" {
                LocalFileErasureLedger::new(dir.path().join("erased.ledger"))
                    .record_confirmed(&key_id)?;
            }
            worker = Some(std::thread::spawn(move || {
                started_tx.send(()).unwrap();
                let erased = match mode {
                    "confirmed" => second.erase_scope_key("project").unwrap(),
                    "legacy" => second.crypto_erase("project"),
                    _ => second.reerase_recorded() == 1,
                };
                finished_tx.send(erased).unwrap();
            }));
            started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            assert!(matches!(
                finished_rx.recv_timeout(Duration::from_millis(50)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ));
            let probe = open_lock(&lock_path(dir.path(), &key_id)?)?;
            assert!(matches!(
                probe.try_lock(),
                Err(std::fs::TryLockError::WouldBlock)
            ));
            // These calls happen with an eraser waiting. Re-locking a
            // writer-preferring process RwLock would deadlock here.
            let ciphertext = second_key.seal(b"aad", b"before commit")?;
            assert_eq!(key.open(b"aad", &ciphertext)?, b"before commit");
            assert_eq!(
                v.erase_scope_key("project").unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            assert_eq!(
                finished_rx.try_recv().unwrap_err(),
                mpsc::TryRecvError::Empty
            );
            Ok(())
        })
        .unwrap();
        assert!(finished_rx.recv_timeout(Duration::from_secs(5)).unwrap());
        worker.unwrap().join().unwrap();
        assert!(key.seal(b"aad", b"after erase").is_err());
        assert!(second_key.seal(b"aad", b"after erase").is_err());
    }
}

#[test]
fn failed_or_panicked_publication_releases_its_scope_lease() {
    let dir = tempfile::tempdir().unwrap();
    let v = vault(dir.path());
    let key = v.initialize_scope_key("project").unwrap();
    let error = key
        .retain::<(), std::io::Error>(|| Err(std::io::Error::other("fixture rollback")))
        .unwrap_err();
    assert_eq!(error.to_string(), "fixture rollback");
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = key.retain::<(), std::io::Error>(|| panic!("fixture panic"));
    }))
    .is_err());
    assert!(v.erase_scope_key("project").unwrap());
    assert!(key.seal(b"aad", b"after erase").is_err());
}

#[test]
#[ignore = "invoked by the cross-process retention test"]
fn scope_erasure_child() {
    let root =
        PathBuf::from(std::env::var_os("GAUGEDESK_SCOPE_ERASURE_TEST_ROOT").expect("fixture root"));
    // Report readiness only after observing the parent's actual OS file lock.
    // This proves cross-process exclusion without relying on scheduling delay.
    let probe = open_lock(&lock_path(&root, &crate::org::sha256_hex("project")).unwrap()).unwrap();
    assert!(matches!(
        probe.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    drop(probe);
    std::fs::write(root.join("eraser-ready"), b"ready").unwrap();
    assert!(vault(&root).erase_scope_key("project").unwrap());
    std::fs::write(root.join("eraser-done"), b"done").unwrap();
}

#[test]
fn retained_scope_excludes_an_eraser_in_another_process() {
    use std::process::{Child, Command, Stdio};
    use std::time::Instant;
    struct Worker(Child);
    impl Drop for Worker {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let key = vault(dir.path()).initialize_scope_key("project").unwrap();
    let mut worker = key
        .retain::<_, std::io::Error>(|| {
            let child = Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "content_vault::scope_key::tests::scope_erasure_child",
                    "--ignored",
                ])
                .env("GAUGEDESK_SCOPE_ERASURE_TEST_ROOT", dir.path())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;
            let mut worker = Worker(child);
            let deadline = Instant::now() + Duration::from_secs(10);
            while !dir.path().join("eraser-ready").exists() {
                assert!(Instant::now() < deadline, "child did not start");
                assert!(
                    worker.0.try_wait()?.is_none(),
                    "child exited before erasure"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            std::thread::sleep(Duration::from_millis(50));
            assert!(!dir.path().join("eraser-done").exists());
            assert!(worker.0.try_wait()?.is_none());
            let ciphertext = key.seal(b"aad", b"retained across processes")?;
            assert_eq!(key.open(b"aad", &ciphertext)?, b"retained across processes");
            Ok(worker)
        })
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = worker.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(
            Instant::now() < deadline,
            "child remained blocked after publication"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(dir.path().join("eraser-done").exists());
    assert!(key.seal(b"aad", b"after child erasure").is_err());
}

#[derive(Default)]
struct LedgerState {
    unavailable: AtomicBool,
    refuse_record: AtomicBool,
    confirmations: AtomicUsize,
    ids: Mutex<Vec<String>>,
}
struct Ledger(Arc<LedgerState>);
impl ErasureLedger for Ledger {
    fn record(&self, id: &str) -> std::io::Result<()> {
        self.0.ids.lock().unwrap().push(id.into());
        Ok(())
    }
    fn recorded(&self) -> std::io::Result<Vec<String>> {
        Ok(self.0.ids.lock().unwrap().clone())
    }
    fn record_confirmed(&self, id: &str) -> std::io::Result<()> {
        if self.0.refuse_record.load(Ordering::SeqCst) {
            return Err(std::io::Error::other("fixture unconfirmed"));
        }
        self.record(id)
    }
    fn recorded_confirmed(&self) -> std::io::Result<Vec<String>> {
        self.0.confirmations.fetch_add(1, Ordering::SeqCst);
        if self.0.unavailable.load(Ordering::SeqCst) {
            return Err(std::io::Error::other("fixture unavailable"));
        }
        self.recorded()
    }
}
struct Wrap {
    unavailable: Arc<AtomicBool>,
    inner: LoopbackKeyWrap,
}
impl KeyWrap for Wrap {
    fn wrap(&self, key: &[u8; 32]) -> Result<Vec<u8>, crate::at_rest::AtRestError> {
        self.inner.wrap(key)
    }
    fn unwrap(&self, bytes: &[u8]) -> Result<[u8; 32], crate::at_rest::AtRestError> {
        assert!(
            !self.unavailable.load(Ordering::SeqCst),
            "KMS used inside publication"
        );
        self.inner.unwrap(bytes)
    }
}

#[test]
fn prepared_publication_uses_no_remote_custody_and_failed_confirmation_stays_erased() {
    let dir = tempfile::tempdir().unwrap();
    let state = Arc::new(LedgerState::default());
    let no_kms = Arc::new(AtomicBool::new(false));
    let v = ContentVault::new(
        dir.path(),
        Box::new(Wrap {
            unavailable: no_kms.clone(),
            inner: LoopbackKeyWrap::new([7; 32]),
        }),
    )
    .with_ledger(Box::new(Ledger(state.clone())));
    let key = v.initialize_scope_key("project").unwrap();
    let confirmations = state.confirmations.load(Ordering::SeqCst);
    no_kms.store(true, Ordering::SeqCst);
    state.unavailable.store(true, Ordering::SeqCst);
    key.retain::<_, std::io::Error>(|| {
        let ciphertext = key.seal(b"aad", b"retained local authority")?;
        assert_eq!(key.open(b"aad", &ciphertext)?, b"retained local authority");
        Ok(())
    })
    .unwrap();
    assert_eq!(state.confirmations.load(Ordering::SeqCst), confirmations);
    assert!(v.prepare_scope_key("project").is_err());
    state.unavailable.store(false, Ordering::SeqCst);
    state.refuse_record.store(true, Ordering::SeqCst);
    assert!(v.erase_scope_key("project").is_err());
    assert!(!v.key_path("project").exists());
    assert!(key.seal(b"aad", b"after erase").is_err());
    assert!(v.initialize_scope_key("project").is_err());
    state.refuse_record.store(false, Ordering::SeqCst);
    assert!(!v.erase_scope_key("project").unwrap());
    assert_eq!(
        state.ids.lock().unwrap().as_slice(),
        &[crate::org::sha256_hex("project")]
    );
}

#[test]
fn published_native_input_store_retains_the_actual_scope_key_through_publication() {
    use crate::action_inputs::ActionInputCustody;
    use whipplescript_store::{
        content::ContentStore, payload_protection::PayloadProtection, StoreError,
    };
    let dir = tempfile::tempdir().unwrap();
    let v = vault(&dir.path().join("keys"));
    let key = Arc::new(v.initialize_scope_key("project").unwrap());
    let protection = PayloadProtection::new("project", key.clone()).unwrap();
    let path = dir.path().join("inputs.sqlite");
    let content = ContentStore::create_protected(&path, protection).unwrap();
    let custody = ActionInputCustody::new(content, "project", 4096).unwrap();
    let input = custody
        .prepare("draft", "private", "scope protected input")
        .unwrap();
    assert!(ContentStore::open_existing(&path).is_err());
    let error = custody
        .publish::<()>(std::slice::from_ref(&input), || {
            Err(StoreError::fault("fixture", "rollback"))
        })
        .unwrap_err();
    assert!(
        matches!(error, StoreError::Fault { subject, detail } if subject == "fixture" && detail == "rollback")
    );
    let (started_tx, started_rx) = mpsc::channel();
    let (finished_tx, finished_rx) = mpsc::channel();
    let eraser = v.clone();
    let mut worker = None;
    custody
        .with_resolved(&input, |resolved| {
            assert_eq!(resolved.content, "scope protected input");
            worker = Some(std::thread::spawn(move || {
                started_tx.send(()).unwrap();
                finished_tx.send(eraser.erase_scope_key("project")).unwrap();
            }));
            started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            assert!(matches!(
                finished_rx.recv_timeout(Duration::from_millis(50)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ));
            assert_eq!(custody.resolve(&input)?.content, "scope protected input");
            Ok(())
        })
        .unwrap();
    assert!(finished_rx
        .recv_timeout(Duration::from_secs(5))
        .unwrap()
        .unwrap());
    worker.unwrap().join().unwrap();
    assert!(custody.resolve(&input).is_err());
    let reached = AtomicBool::new(false);
    assert!(custody
        .publish(std::slice::from_ref(&input), || {
            reached.store(true, Ordering::SeqCst);
            Ok(())
        })
        .is_err());
    assert!(!reached.load(Ordering::SeqCst));
    for file in [&path, &path.with_extension("sqlite-wal")] {
        if file.exists() {
            assert!(!std::fs::read(file)
                .unwrap()
                .windows(b"scope protected input".len())
                .any(|bytes| bytes == b"scope protected input"));
        }
    }
}
