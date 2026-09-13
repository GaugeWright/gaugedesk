//! Explicit native pipeline measurements, outside the ordinary gate. This is
//! neither an HTTP/editor benchmark nor a rollout budget or parity claim.
use super::*;
use crate::file_action_factory::tests::home_storage_fixture;
use std::{
    fs,
    io::Write,
    path::Path,
    time::{Duration, Instant},
};
use whipplescript_kernel::file_lease::FileLeasePolicy;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    root: std::path::PathBuf,
    samples_per_size: usize,
    warmup: usize,
    sizes: Vec<usize>,
    timeout_seconds: u64,
}

fn bytes(root: &Path) -> u64 {
    fs::read_dir(root)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            assert!(!kind.is_symlink());
            if kind.is_dir() {
                bytes(&entry.path())
            } else {
                entry.metadata().unwrap().len()
            }
        })
        .sum()
}

fn history(product: &Path, root: &Path) -> serde_json::Value {
    let product =
        rusqlite::Connection::open_with_flags(product, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let runtime = rusqlite::Connection::open_with_flags(
        root.join("actions/native/runtime.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let count = |db: &rusqlite::Connection, sql: &str| {
        u64::try_from(db.query_row(sql, [], |row| row.get::<_, i64>(0)).unwrap()).unwrap()
    };
    serde_json::json!({
        "product_events": count(&product, "SELECT COUNT(*) FROM events"),
        "product_records": count(&product, "SELECT COUNT(*) FROM records"),
        "product_commands": count(&product, "SELECT COUNT(*) FROM commands"),
        "product_json_bytes": count(&product, "SELECT (SELECT COALESCE(SUM(length(CAST(payload AS BLOB))),0) FROM events) + (SELECT COALESCE(SUM(length(CAST(payload AS BLOB))),0) FROM records) + (SELECT COALESCE(SUM(length(CAST(snapshot_json AS BLOB))),0) FROM commands)"),
        "runtime_events": count(&runtime, "SELECT COUNT(*) FROM events"),
        "runtime_event_json_bytes": count(&runtime, "SELECT COALESCE(SUM(length(CAST(payload_json AS BLOB))),0) FROM events"),
    })
}

async fn completed(
    receiver: &mut mpsc::Receiver<NativeEditorDispatchNotice>,
    grant: &str,
    timeout_seconds: u64,
) -> (String, usize) {
    tokio::time::timeout(Duration::from_secs(timeout_seconds), async {
        let mut other = 0;
        loop {
            let notice = receiver.recv().await.expect("supervisor notice channel closed");
            let NativeEditorDispatchOutcome::Saved { cut_id, .. } = notice.outcome else {
                panic!("save qualification encountered {:?}", notice.outcome);
            };
            if notice.grant_ref == grant { return (cut_id, other); }
            other += 1;
        }
    }).await.expect("no matching notice before deadline; inspect retained Home before concluding that the save failed")
}

/// Test-side inspection deliberately checks the committed product fact and its
/// receipt as well as the independently authorized runtime/target observation.
/// A disposable supervisor notice alone is not a durable acknowledgment.
fn verify(wb: &SharedWorkbench, token: &str, command: &HostActionCommand, cut: &str, body: &str) {
    let mut wb = wb.lock_unpoisoned();
    let context = wb.authenticate_action_context(token).unwrap();
    let instance = command.instance_ref().unwrap();
    let facts = wb
        .store_ref()
        .records(&instance, "native_editor_saved_result_v1")
        .unwrap();
    assert_eq!(facts.len(), 1);
    let result: NativeEditorSavedResult = serde_json::from_str(&facts[0]).unwrap();
    assert_eq!(result.cut_id, cut);
    let runtime = whipplescript_store::SqliteStore::open_read_only(
        wb.root_path().join("actions/native/runtime.sqlite"),
    )
    .unwrap();
    let effects = runtime.list_effects(&instance).unwrap();
    assert_eq!(effects.len(), 2);
    let writes = effects
        .iter()
        .filter(|effect| effect.kind == "file.write")
        .collect::<Vec<_>>();
    assert_eq!(writes.len(), 1);
    let runs = runtime.list_runs(&instance).unwrap();
    assert_eq!(runs.len(), 2);
    let write_runs = runs
        .iter()
        .filter(|run| run.effect_id == writes[0].effect_id)
        .collect::<Vec<_>>();
    assert_eq!(write_runs.len(), 1);
    let key = serde_json::to_string(&(&writes[0].effect_id, &write_runs[0].run_id)).unwrap();
    assert_eq!(
        wb.store_ref()
            .committed_record_snapshot(&format!("host-action-native-save-result:{instance}"), &key)
            .unwrap(),
        Some(facts[0].clone())
    );
    let observation = wb
        .observe_editor_file_save(
            &context,
            command,
            &result.admission,
            EditorFileSaveAttempt {
                effect_id: &writes[0].effect_id,
                run_id: &write_runs[0].run_id,
            },
        )
        .unwrap();
    assert_eq!(observation.saved().unwrap().accepted_content, body);
    assert_eq!(
        observation.evidence().terminal.as_ref().unwrap().status,
        gaugedesk_whip_runtime::host_actions::action_result::ActionWorkflowStatus::Completed
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit native pipeline qualification; run scripts/qualify-native-save.py"]
async fn measure_native_save_pipeline() {
    let config_path = gaugedesk_env::var_os("NATIVE_SAVE_QUALIFICATION_CONFIG")
        .expect("run the qualification script with an explicit output directory");
    let config: Config = serde_json::from_slice(&fs::read(config_path).unwrap()).unwrap();
    assert!((1..=1000).contains(&config.samples_per_size));
    assert!(config.warmup <= 100);
    assert!(!config.sizes.is_empty() && config.sizes.len() <= 10);
    assert!(config
        .sizes
        .iter()
        .all(|size| (64..=1_048_576).contains(size)));
    assert!((1..=3600).contains(&config.timeout_seconds));
    // Create rather than adopt: a qualification can never open a user's Home.
    fs::create_dir(&config.root).expect("qualification Home must not already exist");
    let storage_config = NativeActionStorageConfig {
        input_byte_limit: *config.sizes.iter().max().unwrap(),
        file_lease: FileLeasePolicy::new(60).unwrap(),
    };
    let (wb, bootstrap, storage, token) = home_storage_fixture(&config.root, storage_config);
    let (_, _, chat): (String, String, String) = serde_json::from_str(&bootstrap.scope).unwrap();
    let (shutdown, signal) = watch::channel(false);
    let (sender, mut receiver) = mpsc::channel(4096);
    let task = tokio::spawn(supervise_native_editor_dispatch(
        wb.clone(),
        NativeEditorSupervisorConfig {
            storage: storage_config,
            discovery_page_size: NonZeroUsize::new(32).unwrap(),
        },
        signal,
        sender,
    ));
    let grant = {
        let mut wb = wb.lock_unpoisoned();
        let context = wb.authenticate_action_context(&token).unwrap();
        wb.authorize_editor_file_save_dispatch(&context, storage.inputs(), &bootstrap, "bootstrap")
            .unwrap()
            .grant_ref
    };
    let (mut base, _) = completed(&mut receiver, &grant, config.timeout_seconds).await;
    verify(&wb, &token, &bootstrap, &base, "private editor draft");
    let product_path = std::path::PathBuf::from(wb.lock_unpoisoned().store_ref().path());
    let baseline_bytes = bytes(&config.root);
    let baseline_history = history(&product_path, &config.root);
    let mut output =
        fs::File::create_new(config.root.parent().unwrap().join("samples.jsonl")).unwrap();
    let count = config.warmup + config.samples_per_size * config.sizes.len();
    for index in 0..count {
        let size = config.sizes[index % config.sizes.len()];
        let mut body = format!("native save qualification revision {index:08}\n");
        body.extend(std::iter::repeat_n('x', size - body.len()));
        let request_id = format!("qualification-{index:08}");
        let start = Instant::now();
        let command = {
            let mut wb = wb.lock_unpoisoned();
            let context = wb.authenticate_action_context(&token).unwrap();
            let identity = wb
                .prepare_editor_file_save_request(&context, &chat, "note.txt", &request_id)
                .unwrap();
            wb.admit_editor_file_save(
                &context,
                storage.inputs(),
                &identity,
                &EditorFileSave {
                    chat_id: &chat,
                    request_id: &request_id,
                    path: "note.txt",
                    base_cut: &base,
                    content: &body,
                },
            )
            .unwrap()
            .command
        };
        let admitted = start.elapsed();
        let grant = {
            let mut wb = wb.lock_unpoisoned();
            let context = wb.authenticate_action_context(&token).unwrap();
            wb.authorize_editor_file_save_dispatch(
                &context,
                storage.inputs(),
                &command,
                &request_id,
            )
            .unwrap()
            .grant_ref
        };
        let authorized = start.elapsed();
        let (cut, other_notices) = completed(&mut receiver, &grant, config.timeout_seconds).await;
        let notified = start.elapsed();
        verify(&wb, &token, &command, &cut, &body);
        let verified = start.elapsed();
        base = cut;
        let sample = serde_json::json!({
            "index": index, "warmup": index < config.warmup, "input_bytes": size,
            "input_admission_us": admitted.as_micros(),
            "grant_us": (authorized - admitted).as_micros(),
            "dispatch_to_notice_us": (notified - authorized).as_micros(),
            "proof_read_us": (verified - notified).as_micros(), "total_us": verified.as_micros(),
            "other_notices": other_notices, "home_bytes": bytes(&config.root), "baseline_home_bytes": baseline_bytes,
            "debug_assertions": cfg!(debug_assertions), "instance_ref": command.instance_ref().unwrap(),
            "history": history(&product_path, &config.root),
        });
        writeln!(output, "{sample}").unwrap();
        output.flush().unwrap();
        eprintln!(
            "qualification sample {index}: {size} bytes, {} us",
            verified.as_micros()
        );
    }
    shutdown.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(config.timeout_seconds), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    drop(storage);
    drop(wb);
    // SQLite files and WAL are measured again after orderly shutdown. This is
    // occupied file length, not logical history size or a retention guarantee.
    fs::write(config.root.parent().unwrap().join("finished.json"), serde_json::to_vec_pretty(&serde_json::json!({
        "samples": count, "final_home_bytes": bytes(&config.root), "baseline_home_bytes": baseline_bytes,
        "baseline_history": baseline_history, "final_history": history(&product_path, &config.root),
        "debug_assertions": cfg!(debug_assertions), "scope": "native sequential save pipeline; no HTTP, UI, hosted transport, conflicts, agent transformation or publication"
    })).unwrap()).unwrap();
}
