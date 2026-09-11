use super::*;
use std::sync::{Arc, Barrier};
use whipplescript_store::content::{ContentBlobs, ContentStore};

const ISSUER: &str = "authority:one";
const HOME: &str = "home:one";
const BODY: &str = "private correction text\n";

fn setup(root: &std::path::Path) -> (Store, NativeActionInputCustody, ActionInput, SigningKey) {
    let product = Store::open(root.join("product.sqlite").to_str().unwrap()).unwrap();
    let inputs = NativeActionInputCustody::open(root.join("inputs.sqlite"), HOME, 4096).unwrap();
    let input = inputs.prepare("corrections", "restricted", BODY).unwrap();
    let key = SigningKey::from_seed(&[43; 32]).unwrap();
    (product, inputs, input, key)
}

#[test]
fn original_mapping_survives_restart_and_erasure_without_reading_or_repairing_content() {
    let dir = tempfile::tempdir().unwrap();
    let (mut product, inputs, input, key) = setup(dir.path());
    let scope = input_binding_scope(ISSUER, &input).unwrap();
    let original = retain_input_binding(&mut product, &inputs, ISSUER, HOME, &input, &key).unwrap();
    assert_eq!(original.input(), &input);
    assert_eq!(
        original.content_hash(),
        whipplescript_store::stable_hash_hex(BODY)
    );
    assert_ne!(original.content_hash(), input.version_ref);
    let records = product.records(&scope, KIND).unwrap();
    assert_eq!(records.len(), 1);
    assert!(!records[0].contains("private correction text"));
    let snapshot = product.committed_record_snapshot(&scope, KEY).unwrap();
    assert!(!snapshot
        .as_ref()
        .unwrap()
        .contains("private correction text"));
    drop(product);
    let mut product = Store::open(dir.path().join("product.sqlite").to_str().unwrap()).unwrap();
    retain_input_binding(&mut product, &inputs, ISSUER, HOME, &input, &key).unwrap();
    assert_eq!(product.records(&scope, KIND).unwrap(), records);
    ContentStore::open(dir.path().join("inputs.sqlite"))
        .unwrap()
        .erase(&input.version_ref, "input erased after admission")
        .unwrap();
    assert!(inputs.resolve(&input).is_err());
    let loaded = load_input_binding(&product, ISSUER, HOME, &input, &key.public_key())
        .unwrap()
        .unwrap();
    assert_eq!(loaded.statement, original.statement);
    assert!(retain_input_binding(&mut product, &inputs, ISSUER, HOME, &input, &key).is_err());
    assert_eq!(product.records(&scope, KIND).unwrap(), records);
    assert_eq!(
        product.committed_record_snapshot(&scope, KEY).unwrap(),
        snapshot
    );
}

#[test]
fn mappings_refuse_corrupt_signature_receipt_and_coordinates_without_repair() {
    for case in 0..8 {
        let dir = tempfile::tempdir().unwrap();
        let (mut product, inputs, input, key) = setup(dir.path());
        retain_input_binding(&mut product, &inputs, ISSUER, HOME, &input, &key).unwrap();
        let scope = input_binding_scope(ISSUER, &input).unwrap();
        let fault = rusqlite::Connection::open(product.path()).unwrap();
        let mut signed: SignedBinding =
            serde_json::from_str(&product.records(&scope, KIND).unwrap()[0]).unwrap();
        match case {
            0 => signed.signature[0] ^= 1,
            1 => signed.statement.home.push_str("-other"),
            2 => signed.statement.input.label_ref.push_str("-other"),
            3 => signed.statement.content_hash = "0".repeat(32),
            4 => {
                fault
                    .execute("DELETE FROM command_receipts WHERE scope_id = ?1", [&scope])
                    .unwrap();
            }
            5 => {
                fault
                    .execute(
                        "UPDATE commands SET snapshot_json = '{}' WHERE scope_id = ?1",
                        [&scope],
                    )
                    .unwrap();
            }
            6 => {
                product
                    .append_record(&scope, KIND, &serde_json::to_string(&signed).unwrap())
                    .unwrap();
            }
            _ => {
                fault
                    .execute("DELETE FROM events WHERE scope_id = ?1", [&scope])
                    .unwrap();
            }
        }
        if case < 4 {
            // Also replace the unsigned command snapshot: a matching snapshot
            // must not make a forged statement into a Home attestation.
            fault
                .execute(
                    "UPDATE events SET payload = ?1 WHERE scope_id = ?2",
                    rusqlite::params![serde_json::to_string(&signed).unwrap(), scope],
                )
                .unwrap();
            fault
                .execute(
                    "UPDATE commands SET snapshot_json = ?1 WHERE scope_id = ?2",
                    rusqlite::params![signed.statement.snapshot(&key.public_key()).unwrap(), scope],
                )
                .unwrap();
        }
        let before = product.records(&scope, KIND).unwrap();
        assert!(
            load_input_binding(&product, ISSUER, HOME, &input, &key.public_key()).is_err(),
            "case {case}"
        );
        assert!(
            retain_input_binding(&mut product, &inputs, ISSUER, HOME, &input, &key).is_err(),
            "case {case}"
        );
        assert_eq!(product.records(&scope, KIND).unwrap(), before);
    }
}

#[test]
fn absent_unavailable_and_foreign_inputs_cannot_be_attested() {
    let dir = tempfile::tempdir().unwrap();
    let (mut product, inputs, input, key) = setup(dir.path());
    let scope = input_binding_scope(ISSUER, &input).unwrap();
    assert!(
        load_input_binding(&product, ISSUER, HOME, &input, &key.public_key())
            .unwrap()
            .is_none()
    );
    let foreign =
        NativeActionInputCustody::open(dir.path().join("inputs.sqlite"), "home:other", 4096)
            .unwrap();
    assert!(retain_input_binding(&mut product, &foreign, ISSUER, HOME, &input, &key).is_err());
    let narrow = NativeActionInputCustody::open(dir.path().join("inputs.sqlite"), HOME, 1).unwrap();
    assert!(retain_input_binding(&mut product, &narrow, ISSUER, HOME, &input, &key).is_err());
    let changed = ActionInput {
        label_ref: "unrestricted".into(),
        ..input.clone()
    };
    assert!(retain_input_binding(&mut product, &inputs, ISSUER, HOME, &changed, &key).is_err());
    ContentStore::open(dir.path().join("inputs.sqlite"))
        .unwrap()
        .erase(&input.version_ref, "erased before preparation")
        .unwrap();
    assert!(retain_input_binding(&mut product, &inputs, ISSUER, HOME, &input, &key).is_err());
    assert!(product.records(&scope, KIND).unwrap().is_empty());
    assert!(product
        .committed_record_snapshot(&scope, KEY)
        .unwrap()
        .is_none());
}

#[test]
fn failed_receipt_rolls_back_mapping_and_retry_retains_one_original_statement() {
    let dir = tempfile::tempdir().unwrap();
    let (mut product, inputs, input, key) = setup(dir.path());
    let scope = input_binding_scope(ISSUER, &input).unwrap();
    let fault = rusqlite::Connection::open(product.path()).unwrap();
    fault.execute_batch("CREATE TRIGGER lose_input_binding_receipt BEFORE INSERT ON command_receipts BEGIN SELECT RAISE(ABORT, 'lost mapping receipt'); END;").unwrap();
    assert!(retain_input_binding(&mut product, &inputs, ISSUER, HOME, &input, &key).is_err());
    assert!(product.records(&scope, KIND).unwrap().is_empty());
    assert!(product
        .committed_record_snapshot(&scope, KEY)
        .unwrap()
        .is_none());
    fault
        .execute_batch("DROP TRIGGER lose_input_binding_receipt")
        .unwrap();
    retain_input_binding(&mut product, &inputs, ISSUER, HOME, &input, &key).unwrap();
    let original = product.records(&scope, KIND).unwrap();
    let wrong_key = SigningKey::from_seed(&[44; 32]).unwrap();
    assert!(load_input_binding(&product, ISSUER, HOME, &input, &wrong_key.public_key()).is_err());
    assert!(retain_input_binding(&mut product, &inputs, ISSUER, HOME, &input, &wrong_key).is_err());
    retain_input_binding(&mut product, &inputs, ISSUER, HOME, &input, &key).unwrap();
    assert_eq!(original.len(), 1);
    assert_eq!(product.records(&scope, KIND).unwrap(), original);
}

#[test]
fn concurrent_preparation_reuses_one_receipted_statement_and_refuses_another_root() {
    for changed_root in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (product, inputs, input, _) = setup(dir.path());
        drop(product);
        drop(inputs);
        let start = Arc::new(Barrier::new(2));
        let writers = (0..2)
            .map(|index| {
                let product =
                    Store::open(dir.path().join("product.sqlite").to_str().unwrap()).unwrap();
                let inputs =
                    NativeActionInputCustody::open(dir.path().join("inputs.sqlite"), HOME, 4096)
                        .unwrap();
                (index, product, inputs)
            })
            .collect::<Vec<_>>();
        let jobs = writers
            .into_iter()
            .map(|(index, mut product, inputs)| {
                let start = start.clone();
                let input = input.clone();
                std::thread::spawn(move || {
                    let seed = if changed_root && index == 1 { 44 } else { 43 };
                    let key = SigningKey::from_seed(&[seed; 32]).unwrap();
                    start.wait();
                    retain_input_binding(&mut product, &inputs, ISSUER, HOME, &input, &key)
                        .map(|binding| binding.statement)
                })
            })
            .collect::<Vec<_>>();
        let results = jobs
            .into_iter()
            .map(|job| job.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            results.iter().filter(|result| result.is_ok()).count(),
            if changed_root { 1 } else { 2 }
        );
        if !changed_root {
            assert_eq!(results[0].as_ref().unwrap(), results[1].as_ref().unwrap());
        }
        let product = Store::open(dir.path().join("product.sqlite").to_str().unwrap()).unwrap();
        let scope = input_binding_scope(ISSUER, &input).unwrap();
        assert_eq!(product.records(&scope, KIND).unwrap().len(), 1);
        assert!(product
            .committed_record_snapshot(&scope, KEY)
            .unwrap()
            .is_some());
    }
}
