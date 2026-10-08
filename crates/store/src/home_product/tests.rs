use super::*;
use std::sync::Arc;

fn binding(project: &str, home: &str, marker: char) -> HomeProductBinding {
    HomeProductBinding {
        project_id: project.into(),
        home_id: home.into(),
        incarnation: marker.to_string().repeat(32),
    }
}

#[test]
fn creation_reopens_exact_state_without_granting_activation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("product.sqlite");
    let expected = binding("project.one", "home.one", 'a');
    let mut product = Store::create_home_product(&path, expected.clone()).unwrap();
    product
        .append_record("original:scope", "fact", "{\"original\":true}")
        .unwrap();
    assert_eq!(product.home_product_binding(), Some(&expected));
    assert!(product.home_product_registration("project.one").is_err());
    assert!(product.register_home_product("other", "other").is_err());
    assert!(product.records("org", "membership").unwrap().is_empty());
    let original_events = product.events("original:scope").unwrap();
    drop(product);
    let reopened = Store::open_home_product_existing(&path, &expected).unwrap();
    assert_eq!(
        reopened.records("original:scope", "fact").unwrap(),
        ["{\"original\":true}"]
    );
    assert!(Store::create_home_product(&path, expected.clone()).is_err());
    assert!(Store::open(path.to_str().unwrap()).is_err());
    assert_eq!(reopened.events("original:scope").unwrap(), original_events);
}

#[test]
fn missing_foreign_replaced_and_partial_files_are_not_adopted() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("product.sqlite");
    let expected = binding("project", "home", 'a');
    assert!(Store::open_home_product_existing(&path, &expected).is_err());
    assert!(!path.exists());
    std::fs::write(&path, []).unwrap();
    assert!(Store::open_home_product_existing(&path, &expected).is_err());
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
    std::fs::remove_file(&path).unwrap();
    let product = Store::create_home_product(&path, expected.clone()).unwrap();
    for wrong in [
        binding("other", "home", 'a'),
        binding("project", "other", 'a'),
        binding("project", "home", 'b'),
    ] {
        assert!(Store::open_home_product_existing(&path, &wrong).is_err());
    }
    product.conn.execute_batch("DROP TABLE events").unwrap();
    assert!(Store::open_home_product_existing(&path, &expected).is_err());
    assert!(product.sibling().is_err());
    assert!(product.read_only_sibling().is_err());
}

#[test]
fn missing_immutable_guard_and_incompatible_ledger_refuse_reopen() {
    for sql in [
        "DROP TRIGGER home_product_storage_no_update",
        "DELETE FROM schema_migrations WHERE version=1",
        "INSERT INTO schema_migrations(version) VALUES (999)",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("product.sqlite");
        let expected = binding("project", "home", 'a');
        let product = Store::create_home_product(&path, expected.clone()).unwrap();
        product.conn.execute_batch(sql).unwrap();
        assert!(Store::open_home_product_existing(&path, &expected).is_err());
        assert!(product.read_only_sibling().is_err());
        assert_eq!(product.home_product_binding(), Some(&expected));
    }
}

#[test]
fn identity_is_immutable_and_invalid_bindings_create_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("product.sqlite");
    for bad in [
        binding(" ", "home", 'a'),
        binding("project", "", 'a'),
        binding("project", "home", 'A'),
        binding("project", "home", 'z'),
    ] {
        assert!(Store::create_home_product(&path, bad).is_err());
        assert!(!path.exists());
    }
    let expected = binding("project", "home", 'a');
    let product = Store::create_home_product(&path, expected.clone()).unwrap();
    for sql in [
        "UPDATE home_product_storage SET home_id='other'",
        "DELETE FROM home_product_storage",
        "INSERT OR REPLACE INTO home_product_storage SELECT * FROM home_product_storage",
    ] {
        assert!(product.conn.execute_batch(sql).is_err());
    }
    assert_eq!(
        product.sibling().unwrap().home_product_binding(),
        Some(&expected)
    );
}

struct Codec;
impl crate::ContentCodec for Codec {
    fn encode(&self, _: &str, _: &str, payload: &str) -> Result<String, String> {
        Ok(format!("wrapped:{payload}"))
    }
    fn decode(&self, _: &str, _: &str, payload: &str) -> Option<String> {
        payload.strip_prefix("wrapped:").map(str::to_owned)
    }
}

#[test]
fn siblings_preserve_binding_codec_and_read_only_behavior() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("product.sqlite");
    let expected = binding("project", "home", 'a');
    let mut product = Store::create_home_product(&path, expected.clone())
        .unwrap()
        .with_codec(Arc::new(Codec));
    product
        .append_record("scope", "secret", "protected")
        .unwrap();
    let raw: String = product
        .conn
        .query_row("SELECT payload FROM events", [], |row| row.get(0))
        .unwrap();
    assert_eq!(raw, "wrapped:protected");
    let mut sibling = product.sibling().unwrap();
    sibling.append_record("scope", "secret", "more").unwrap();
    let mut reader = product.read_only_sibling().unwrap();
    assert_eq!(reader.home_product_binding(), Some(&expected));
    assert_eq!(
        reader.records("scope", "secret").unwrap(),
        ["protected", "more"]
    );
    assert!(reader
        .append_record("scope", "secret", "forbidden")
        .is_err());
    drop(sibling);
    assert!(reader.sibling().unwrap().conn.is_readonly("main").unwrap());
    // Readers retain the no-write property across their own siblings, too.
    assert!(reader
        .read_only_sibling()
        .unwrap()
        .conn
        .is_readonly("main")
        .unwrap());
}

#[test]
fn independent_homes_keep_data_and_writers_apart() {
    let dir = tempfile::tempdir().unwrap();
    let mut catalog = Store::open_in_memory().unwrap();
    let mut first = catalog
        .initialize_home_product(dir.path(), "project.one", "home.one")
        .unwrap();
    let mut second = catalog
        .initialize_home_product(dir.path(), "project-one", "home-two")
        .unwrap();
    assert_ne!(first.path(), second.path());
    first
        .append_record("same-original-scope", "fact", "first")
        .unwrap();
    second
        .append_record("same-original-scope", "fact", "second")
        .unwrap();
    first.conn.execute_batch("BEGIN IMMEDIATE").unwrap();
    second
        .conn
        .busy_timeout(Duration::from_millis(100))
        .unwrap();
    second
        .append_record("same-original-scope", "fact", "second-next")
        .unwrap();
    assert_eq!(
        first.records("same-original-scope", "fact").unwrap(),
        ["first"]
    );
    assert_eq!(
        second.records("same-original-scope", "fact").unwrap(),
        ["second", "second-next"]
    );
    first.conn.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn host_catalog_retains_exact_identity_and_readiness_durably() {
    let dir = tempfile::tempdir().unwrap();
    let mut catalog = Store::open_in_memory().unwrap();
    let before = catalog.synchronous().unwrap();
    let registered = catalog.register_home_product("project", "home").unwrap();
    assert!(!registered.ready);
    assert_eq!(catalog.synchronous().unwrap(), before);
    assert_eq!(
        registered,
        catalog.register_home_product("project", "home").unwrap()
    );
    assert!(catalog.register_home_product("project", "other").is_err());
    assert!(catalog.register_home_product("other", "home").is_err());
    assert!(catalog
        .open_registered_home_product(dir.path(), "project")
        .is_err());
    let product = catalog
        .initialize_home_product(dir.path(), "project", "home")
        .unwrap();
    assert_eq!(product.home_product_binding(), Some(&registered.binding));
    assert!(
        catalog
            .sibling()
            .unwrap()
            .home_product_registration("project")
            .unwrap()
            .unwrap()
            .ready
    );
    for sql in [
        "UPDATE home_product_bindings SET incarnation='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'",
        "DELETE FROM home_product_bindings",
        "INSERT OR REPLACE INTO home_product_bindings SELECT * FROM home_product_bindings",
        "DELETE FROM home_product_ready",
        "UPDATE home_product_ready SET home_id='other'",
        "INSERT OR REPLACE INTO home_product_ready SELECT * FROM home_product_ready",
    ] {
        assert!(catalog.conn.execute_batch(sql).is_err());
    }
    assert_eq!(catalog.synchronous().unwrap(), before);
    assert_eq!(
        catalog
            .open_registered_home_product(dir.path(), "project")
            .unwrap()
            .home_product_binding(),
        Some(&registered.binding)
    );
}

#[test]
fn ready_storage_cannot_be_recreated_and_lost_catalog_cannot_adopt_it() {
    let dir = tempfile::tempdir().unwrap();
    let mut catalog = Store::open_in_memory().unwrap();
    let product = catalog
        .initialize_home_product(dir.path(), "project", "home")
        .unwrap();
    let binding = product.home_product_binding().unwrap().clone();
    let mut lost_catalog = Store::open_in_memory().unwrap();
    assert!(lost_catalog
        .initialize_home_product(dir.path(), "project", "home")
        .is_err());
    assert!(
        !lost_catalog
            .home_product_registration("project")
            .unwrap()
            .unwrap()
            .ready
    );
    drop(product);
    std::fs::remove_file(home_product_path(dir.path(), "project")).unwrap();
    assert!(catalog
        .initialize_home_product(dir.path(), "project", "home")
        .is_err());
    assert!(!home_product_path(dir.path(), "project").exists());
    assert_eq!(
        catalog
            .home_product_registration("project")
            .unwrap()
            .unwrap()
            .binding,
        binding
    );
}

#[test]
fn stale_connections_refuse_missing_or_replaced_storage() {
    for replace in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("product.sqlite");
        let expected = binding("project", "home", 'a');
        let product = Store::create_home_product(&path, expected).unwrap();
        // Quiesce the WAL before moving the store as a deliberately invalid restore.
        product
            .conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
        std::fs::rename(&path, dir.path().join("old.sqlite")).unwrap();
        if replace {
            let replacement =
                Store::create_home_product(&path, binding("project", "home", 'b')).unwrap();
            drop(replacement);
        }
        assert!(product.sibling().is_err());
        assert!(product.read_only_sibling().is_err());
        assert_eq!(path.exists(), replace);
    }
}

#[test]
fn open_writer_refuses_catalog_registration_without_partial_commit() {
    let mut catalog = Store::open_in_memory().unwrap();
    catalog.conn.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert!(catalog.register_home_product("project", "home").is_err());
    assert!(catalog
        .home_product_registration("project")
        .unwrap()
        .is_none());
    catalog.conn.execute_batch("ROLLBACK").unwrap();
    assert!(
        !catalog
            .register_home_product("project", "home")
            .unwrap()
            .ready
    );
}

#[test]
fn interrupted_initialization_recovers_original_binding_and_history() {
    for phase in ["registered", "product", "ready"] {
        let dir = tempfile::tempdir().unwrap();
        let catalog_path = dir.path().join("host.sqlite");
        let mut catalog = Store::open(catalog_path.to_str().unwrap()).unwrap();
        let original = catalog.register_home_product("project", "home").unwrap();
        drop(catalog);
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "home_product::tests::crash_after_product_commit",
                "--nocapture",
            ])
            .env("GAUGEDESK_HOME_PRODUCT_TEST_ROOT", dir.path())
            .env("GAUGEDESK_HOME_PRODUCT_TEST_PHASE", phase)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(23));
        let mut recovered_catalog = Store::open(catalog_path.to_str().unwrap()).unwrap();
        let before = recovered_catalog
            .home_product_registration("project")
            .unwrap()
            .unwrap();
        assert_eq!(before.ready, phase == "ready");
        assert_eq!(before.binding, original.binding);
        let recovered = recovered_catalog
            .initialize_home_product(dir.path(), "project", "home")
            .unwrap();
        assert_eq!(recovered.home_product_binding(), Some(&original.binding));
        assert_eq!(
            recovered.records("original-scope", "fact").unwrap(),
            if phase == "registered" {
                vec![]
            } else {
                vec!["retained"]
            }
        );
        assert!(
            recovered_catalog
                .home_product_registration("project")
                .unwrap()
                .unwrap()
                .ready
        );
    }
}

#[test]
fn crash_after_product_commit() {
    let Some(root) = std::env::var_os("GAUGEDESK_HOME_PRODUCT_TEST_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let phase = std::env::var("GAUGEDESK_HOME_PRODUCT_TEST_PHASE").unwrap();
    let mut catalog = Store::open(root.join("host.sqlite").to_str().unwrap()).unwrap();
    if phase != "registered" {
        let mut product = if phase == "ready" {
            catalog
                .initialize_home_product(&root, "project", "home")
                .unwrap()
        } else {
            let binding = catalog
                .home_product_registration("project")
                .unwrap()
                .unwrap()
                .binding;
            let path = home_product_path(&root, "project");
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            Store::create_home_product(&path, binding).unwrap()
        };
        product
            .append_record("original-scope", "fact", "retained")
            .unwrap();
        std::process::exit(23);
    }
    std::process::exit(23);
}

#[test]
fn product_and_journal_catalogs_cannot_disagree_about_home_identity() {
    let mut catalog = Store::open_in_memory().unwrap();
    catalog.register_home_product("project", "home").unwrap();
    assert!(catalog.register_home_journal("project", "other").is_err());
    assert!(catalog.register_home_journal("other", "home").is_err());
    assert!(catalog.register_home_journal("project", "home").is_ok());
    let mut older_catalog = Store::open_in_memory().unwrap();
    older_catalog
        .register_home_journal("legacy", "legacy-home")
        .unwrap();
    assert!(older_catalog
        .register_home_product("legacy", "other")
        .is_err());
    assert!(older_catalog
        .register_home_product("other", "legacy-home")
        .is_err());
    assert!(older_catalog
        .register_home_product("legacy", "legacy-home")
        .is_ok());
}

#[test]
fn home_product_store_requires_its_own_journal_registration_and_separate_operations() {
    let dir = tempfile::tempdir().unwrap();
    let mut product = Store::create_home_product(
        &dir.path().join("product.sqlite"),
        binding("project", "home", 'a'),
    )
    .unwrap();
    assert!(product.register_home_journal("other", "home").is_err());
    assert!(product.register_home_journal("project", "other").is_err());
    let journal = product
        .initialize_home_journal(dir.path(), "project", "home")
        .unwrap();
    assert_eq!(journal.binding().home_id, "home");
    assert!(product
        .register_checked_program_request("home", "target", &"b".repeat(32), "request", "basis")
        .is_err());
    // Product writer exclusion cannot stall the separate journal's registration.
    product.conn.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut journal = journal;
    assert!(journal
        .register_checked_program_request("home", "target", &"b".repeat(32), "request", "basis")
        .is_ok());
    product.conn.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn paired_home_storage_recovers_the_exact_product_and_journal_after_interruption() {
    let dir = tempfile::tempdir().unwrap();
    let mut catalog = Store::open(dir.path().join("host.sqlite").to_str().unwrap()).unwrap();
    let mut staged = catalog
        .initialize_home_product(dir.path(), "project", "home:project")
        .unwrap();
    let product_binding = staged.home_product_binding().unwrap().clone();
    staged
        .append_record("original:scope", "fact", "retained")
        .unwrap();
    let journal_binding = staged
        .register_home_journal("project", "home:project")
        .unwrap()
        .binding;
    let mut interrupted_journal = HomeReferenceJournal::create(
        &crate::home_reference_journal::home_reference_journal_path(dir.path(), "project"),
        journal_binding.clone(),
    )
    .unwrap();
    let pending = interrupted_journal
        .register_checked_program_request(
            "home:project",
            "runtime:one",
            &"a".repeat(32),
            "request:one",
            "basis:one",
        )
        .unwrap();
    drop(interrupted_journal);
    drop(staged);

    let prepared = catalog
        .prepare_project_home_storage(dir.path(), "project", "home:project")
        .unwrap();
    assert_eq!(
        prepared.product.home_product_binding(),
        Some(&product_binding)
    );
    assert_eq!(prepared.journal.binding(), &journal_binding);
    assert_eq!(
        prepared
            .journal
            .reference_operation(&pending.operation_id)
            .unwrap(),
        Some(pending)
    );
    assert_eq!(
        prepared.product.records("original:scope", "fact").unwrap(),
        ["retained"]
    );
    assert!(
        prepared
            .product
            .home_journal_registration("project")
            .unwrap()
            .unwrap()
            .ready
    );
    assert!(catalog
        .home_journal_registration("project")
        .unwrap()
        .is_none());
    drop(prepared);

    let retried = catalog
        .prepare_project_home_storage(dir.path(), "project", "home:project")
        .unwrap();
    assert_eq!(
        retried.product.home_product_binding(),
        Some(&product_binding)
    );
    assert_eq!(retried.journal.binding(), &journal_binding);
    assert!(catalog
        .prepare_project_home_storage(dir.path(), "project", "home:other")
        .is_err());
    assert!(catalog
        .prepare_project_home_storage(dir.path(), "other", "home:project")
        .is_err());
    let other = catalog
        .prepare_project_home_storage(dir.path(), "other", "home:other")
        .unwrap();
    assert_ne!(
        other.product.home_product_binding().unwrap().home_id,
        product_binding.home_id
    );
    assert_ne!(
        home_product_path(dir.path(), "project"),
        home_product_path(dir.path(), "other")
    );
}

#[test]
fn paired_home_storage_refuses_a_lost_journal_without_replacing_either_store() {
    let dir = tempfile::tempdir().unwrap();
    let mut catalog = Store::open(dir.path().join("host.sqlite").to_str().unwrap()).unwrap();
    let mut prepared = catalog
        .prepare_project_home_storage(dir.path(), "project", "home:project")
        .unwrap();
    let product_binding = prepared.product.home_product_binding().unwrap().clone();
    let journal_binding = prepared.journal.binding().clone();
    prepared
        .product
        .append_record("original:scope", "fact", "retained")
        .unwrap();
    drop(prepared);
    let journal_path =
        crate::home_reference_journal::home_reference_journal_path(dir.path(), "project");
    std::fs::remove_file(&journal_path).unwrap();

    assert!(catalog
        .prepare_project_home_storage(dir.path(), "project", "home:project")
        .is_err());
    assert!(!journal_path.exists());
    let product = catalog
        .open_registered_home_product(dir.path(), "project")
        .unwrap();
    assert_eq!(product.home_product_binding(), Some(&product_binding));
    assert_eq!(
        product.records("original:scope", "fact").unwrap(),
        ["retained"]
    );
    assert_eq!(
        product
            .home_journal_registration("project")
            .unwrap()
            .unwrap()
            .binding,
        journal_binding
    );
}

#[test]
fn dispatch_basis_refuses_replacement_even_at_the_same_path_and_heads() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("product.sqlite");
    let mut original = Store::create_home_product(&path, binding("project", "home", 'a')).unwrap();
    original.append_record("authority", "fact", "same").unwrap();
    let (_, captured) = original
        .read_for_dispatch(&["authority"], |_| Ok(()))
        .unwrap();
    let (_, another_capture) = original
        .read_for_dispatch(&["authority"], |_| Ok(()))
        .unwrap();
    drop(original);
    std::fs::rename(&path, dir.path().join("old.sqlite")).unwrap();
    let mut replaced = Store::create_home_product(&path, binding("project", "home", 'b')).unwrap();
    replaced.append_record("authority", "fact", "same").unwrap();
    let (_, current) = replaced
        .read_for_dispatch(&["authority"], |_| Ok(()))
        .unwrap();
    assert!(another_capture.combine(current).is_err());
    let ran = std::cell::Cell::new(false);
    assert!(replaced
        .with_dispatch_basis(&captured, || ran.set(true))
        .is_err());
    assert!(!ran.get());
}
