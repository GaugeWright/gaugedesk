//! ACTION-8 boundary check: who may write product command/effect evidence.
//!
//! GaugeDesk DR-0164 §5 says a surface cannot claim complete provenance while
//! its inventory contains a bypass. This check makes that inventory exact for
//! the product store's command ledger:
//!
//! 1. Interface. Every public mutating method of `gaugedesk-store` (`&mut self`
//!    or a consumed `self`) is classified in `contracts/action-evidence-writers.json`.
//!    A new writer fails until someone says whether it writes command/effect
//!    evidence, and whether it is fenced by current product standing (`seam`) or
//!    writes the ledger directly (`ledger`).
//! 2. Call sites. Every production call of a `ledger` method in the product
//!    packages is either inside a declared seam owner — the module that owns the
//!    HTTP command envelope or the action outbox — or listed as a named bypass
//!    with the ACTION row that must remove it. A new bypass fails, and so does a
//!    listed bypass that no longer exists, so the list only ever shrinks honestly.
//!
//! This is a syntax inventory, like `action_source_inventory`: it cannot see a
//! write through an alias or a trait object, and it is never authorization.
#[path = "support/action_source.rs"]
mod action_source;
use action_source::{Api, Scanner, Site};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

const PACKAGES: &[&str] = &["gaugedesk-app", "gaugedesk-workspace", "gaugedesk-ee"];
const STORE_ROOT: &str = "crates/store/src";
const CLASSES: &[&str] = &[
    "seam",
    "ledger",
    "product-fact",
    "reference-journal",
    "configuration",
];

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClassifiedApi {
    declaration: Api,
    classification: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SeamOwner {
    file: String,
    reason: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    coverage_id: String,
    reason: String,
    required_evidence: Vec<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bypass {
    site: Site,
    profile: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    schema: String,
    coverage: String,
    packages: Vec<String>,
    store: String,
    classifications: BTreeMap<String, String>,
    api: Vec<ClassifiedApi>,
    seam_owners: Vec<SeamOwner>,
    profiles: BTreeMap<String, Profile>,
    bypasses: Vec<Bypass>,
}

/// The method names a syntax scan must treat as direct ledger writes. A name
/// shared by a ledger method and a differently classified method is refused,
/// because a call site cannot be told apart by its receiver.
fn ledger_names(inventory: &Inventory) -> Result<BTreeSet<String>, Vec<String>> {
    let mut by_name: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for api in &inventory.api {
        by_name
            .entry(&api.declaration.name)
            .or_default()
            .insert(&api.classification);
    }
    let ambiguous: Vec<_> = by_name
        .iter()
        .filter(|(_, classes)| classes.contains("ledger") && classes.len() > 1)
        .map(|(name, classes)| {
            format!("`{name}` is a ledger writer and also {classes:?}; a call site cannot be classified")
        })
        .collect();
    if !ambiguous.is_empty() {
        return Err(ambiguous);
    }
    Ok(by_name
        .into_iter()
        .filter(|(_, classes)| classes.contains("ledger"))
        .map(|(name, _)| name.to_owned())
        .collect())
}

/// Every reason the scanned source and the committed inventory disagree.
/// Empty means the boundary is exactly as declared.
fn verdict(inventory: &Inventory, writers: &BTreeSet<Api>, sites: &[Site]) -> Vec<String> {
    let mut problems = Vec::new();
    let declared: BTreeSet<_> = inventory
        .api
        .iter()
        .map(|a| a.declaration.clone())
        .collect();
    if declared.len() != inventory.api.len() {
        problems.push("duplicate store API classification".into());
    }
    for api in declared.difference(writers) {
        problems.push(format!("store writer removed or changed: {api:?}"));
    }
    for api in writers.difference(&declared) {
        problems.push(format!(
            "unclassified store writer: {api:?}; classify whether it writes command/effect evidence"
        ));
    }
    for api in &inventory.api {
        if !CLASSES.contains(&api.classification.as_str()) {
            problems.push(format!("unknown classification for {:?}", api.declaration));
        }
    }
    for class in CLASSES {
        if inventory
            .classifications
            .get(*class)
            .is_none_or(|reason| reason.len() < 30)
        {
            problems.push(format!("classification `{class}` needs a stated meaning"));
        }
    }
    if inventory.classifications.len() != CLASSES.len() {
        problems.push("classification meanings name an unknown class".into());
    }
    if let Err(ambiguous) = ledger_names(inventory) {
        problems.extend(ambiguous);
    }
    let owners: BTreeSet<_> = inventory
        .seam_owners
        .iter()
        .map(|o| o.file.as_str())
        .collect();
    if owners.len() != inventory.seam_owners.len() {
        problems.push("duplicate seam owner".into());
    }
    for owner in &inventory.seam_owners {
        if owner.reason.len() < 30 {
            problems.push(format!("seam owner {} needs its reason", owner.file));
        }
        if !sites.iter().any(|site| site.file == owner.file) {
            problems.push(format!(
                "seam owner {} writes no ledger evidence; remove it rather than keep a standing exemption",
                owner.file
            ));
        }
    }
    for (name, profile) in &inventory.profiles {
        if !["ACTION-3", "ACTION-4", "ACTION-5", "ACTION-6", "ACTION-8"]
            .contains(&profile.coverage_id.as_str())
        {
            problems.push(format!("profile {name} names no open ACTION row"));
        }
        if profile.reason.len() < 30
            || profile.required_evidence.is_empty()
            || profile.required_evidence.iter().any(|item| item.len() < 10)
        {
            problems.push(format!(
                "profile {name} needs its reason and required evidence"
            ));
        }
        if !inventory.bypasses.iter().any(|b| &b.profile == name) {
            problems.push(format!("unused bypass profile {name}"));
        }
    }
    let listed: BTreeSet<_> = inventory.bypasses.iter().map(|b| &b.site).collect();
    if listed.len() != inventory.bypasses.len() {
        problems.push("duplicate bypass".into());
    }
    for bypass in &inventory.bypasses {
        if !inventory.profiles.contains_key(&bypass.profile) {
            problems.push(format!("bypass without a profile: {:?}", bypass.site));
        }
        if owners.contains(bypass.site.file.as_str()) {
            problems.push(format!(
                "bypass listed inside a seam owner: {:?}",
                bypass.site
            ));
        }
    }
    let outside: BTreeSet<_> = sites
        .iter()
        .filter(|site| !owners.contains(site.file.as_str()))
        .collect();
    for site in outside.difference(&listed) {
        problems.push(format!(
            "unmediated command/effect evidence write outside the ACTION seam: {site:?}"
        ));
    }
    for site in listed.difference(&outside) {
        problems.push(format!(
            "listed bypass no longer exists or changed; remove or re-list it: {site:?}"
        ));
    }
    problems
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}
fn entrypoints(root: &Path) -> Vec<PathBuf> {
    let output = std::process::Command::new(env!("CARGO"))
        .args(["metadata", "--no-deps", "--locked", "--format-version", "1"])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Cargo entrypoint discovery failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let mut result = Vec::new();
    for name in PACKAGES {
        let package = metadata["packages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|package| package["name"] == *name)
            .expect("inventoried package must remain present");
        let before = result.len();
        for target in package["targets"].as_array().unwrap() {
            if target["kind"]
                .as_array()
                .unwrap()
                .iter()
                .any(|kind| kind == "lib" || kind == "bin")
            {
                result.push(PathBuf::from(target["src_path"].as_str().unwrap()));
            }
        }
        assert!(
            result.len() > before,
            "inventoried package must retain production targets"
        );
    }
    result.sort();
    result.dedup();
    result
}
fn store_writers(root: &Path) -> BTreeSet<Api> {
    let store = root.join(STORE_ROOT);
    let mut scanner = Scanner::new(root, BTreeSet::new()).with_writer_root(&store);
    scanner.scan(&store.join("lib.rs")).unwrap();
    scanner.writers
}

#[test]
fn command_evidence_writers_match_the_declared_action_seam() {
    let root = root();
    let writers = store_writers(&root);
    let path = root.join("contracts/action-evidence-writers.json");
    let inventory: Inventory = match std::fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str(&text).unwrap(),
        Err(_) => panic!(
            "EVIDENCE_WRITERS_BEGIN\n{}\nEVIDENCE_WRITERS_END",
            serde_json::to_string_pretty(&writers).unwrap()
        ),
    };
    assert_eq!(inventory.schema, "gaugedesk.action-evidence-writers.v1");
    assert_eq!(inventory.coverage, "store-ledger-call-syntax");
    assert_eq!(inventory.packages, PACKAGES);
    assert_eq!(inventory.store, STORE_ROOT);
    let ledger = ledger_names(&inventory).unwrap_or_default();
    assert!(
        !ledger.is_empty(),
        "an inventory with no ledger writer would pass every bypass"
    );
    let mut scanner = Scanner::new(&root, ledger);
    for entry in entrypoints(&root) {
        scanner.scan(&entry).unwrap();
    }
    let sites = scanner.sites();
    let problems = verdict(&inventory, &writers, &sites);
    assert!(
        problems.is_empty(),
        "command/effect evidence boundary drifted:\n{}\nSITES_BEGIN\n{}\nSITES_END",
        problems.join("\n"),
        serde_json::to_string_pretty(&sites).unwrap()
    );
}

// --- negative controls: each proves the check can fail -------------------

const FIXTURE_STORE: &str = r#"
    pub struct Store;
    pub struct Handle;
    impl Store {
        pub fn set_command_status(&mut self) {}
        pub fn admit_with_dispatch(&mut self) {}
        pub fn append_record(&mut self) {}
        pub fn command(&self) {}
        fn private_writer(&mut self) {}
        #[cfg(test)] pub fn test_writer(&mut self) {}
    }
    impl Handle { pub fn commit(self) {} }
"#;
const FIXTURE_SEAM: &str = "pub fn claim(store: &mut Store) { store.set_command_status(); }";

struct Fixture {
    _dir: tempfile::TempDir,
    writers: BTreeSet<Api>,
    sites: Vec<Site>,
}

fn fixture(store: &str, files: &[(&str, &str)]) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let write = |path: &str, body: &str| {
        let path = dir.path().join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    };
    write("store/lib.rs", store);
    let modules: String = files
        .iter()
        .map(|(path, _)| format!("mod {};\n", path.trim_end_matches(".rs")))
        .collect();
    write("app/lib.rs", &modules);
    for (path, body) in files {
        write(&format!("app/{path}"), body);
    }
    let mut writers =
        Scanner::new(dir.path(), BTreeSet::new()).with_writer_root(&dir.path().join("store"));
    writers.scan(&dir.path().join("store/lib.rs")).unwrap();
    let mut calls = Scanner::new(dir.path(), BTreeSet::from(["set_command_status".into()]));
    calls.scan(&dir.path().join("app/lib.rs")).unwrap();
    Fixture {
        _dir: dir,
        writers: writers.writers,
        sites: calls.sites(),
    }
}

fn api(owner: &str, signature: &str) -> Api {
    let name = signature
        .trim_start_matches("fn ")
        .split([' ', '('])
        .next()
        .unwrap()
        .to_owned();
    Api {
        owner: owner.into(),
        name,
        signature: signature.into(),
    }
}

fn inventory(bypasses: Vec<Bypass>) -> Inventory {
    let classified = |owner: &str, signature: &str, classification: &str| ClassifiedApi {
        declaration: api(owner, signature),
        classification: classification.into(),
    };
    Inventory {
        schema: "gaugedesk.action-evidence-writers.v1".into(),
        coverage: "store-ledger-call-syntax".into(),
        packages: PACKAGES.iter().map(|p| (*p).into()).collect(),
        store: STORE_ROOT.into(),
        classifications: CLASSES
            .iter()
            .map(|class| {
                (
                    (*class).into(),
                    format!("{class} — a fixture meaning long enough"),
                )
            })
            .collect(),
        api: vec![
            classified("Store", "fn set_command_status (& mut self)", "ledger"),
            classified("Store", "fn admit_with_dispatch (& mut self)", "seam"),
            classified("Store", "fn append_record (& mut self)", "product-fact"),
            classified("Handle", "fn commit (self)", "seam"),
        ],
        seam_owners: vec![SeamOwner {
            file: "app/seam.rs".into(),
            reason: "owns the fixture's command envelope ledger".into(),
        }],
        // A profile is declared only while some bypass uses it.
        profiles: if bypasses.is_empty() {
            BTreeMap::new()
        } else {
            BTreeMap::from([(
                "open".into(),
                Profile {
                    coverage_id: "ACTION-8".into(),
                    reason: "a fixture bypass the boundary has not yet removed".into(),
                    required_evidence: vec!["route it through the fixture seam".into()],
                },
            )])
        },
        bypasses,
    }
}

fn bypass(site: &Site) -> Bypass {
    Bypass {
        site: site.clone(),
        profile: "open".into(),
    }
}

#[test]
fn writer_interface_is_mutating_public_production_methods_only() {
    let fixture = fixture(FIXTURE_STORE, &[("seam.rs", FIXTURE_SEAM)]);
    let names: BTreeSet<_> = fixture
        .writers
        .iter()
        .map(|api| format!("{}::{}", api.owner, api.name))
        .collect();
    assert_eq!(
        names,
        BTreeSet::from([
            "Handle::commit".to_owned(),
            "Store::admit_with_dispatch".to_owned(),
            "Store::append_record".to_owned(),
            "Store::set_command_status".to_owned(),
        ])
    );
}

#[test]
fn ledger_writes_inside_the_seam_owner_pass() {
    let fixture = fixture(
        FIXTURE_STORE,
        &[
            ("seam.rs", FIXTURE_SEAM),
            // A fenced seam call and an ordinary product record are not bypasses.
            (
                "handler.rs",
                "fn save(s: &mut Store) { s.admit_with_dispatch(); s.append_record(); }",
            ),
        ],
    );
    assert_eq!(
        verdict(&inventory(vec![]), &fixture.writers, &fixture.sites),
        Vec::<String>::new()
    );
}

#[test]
fn a_direct_ledger_write_outside_the_seam_fails() {
    for body in [
        "fn save(s: &mut Store) { s.set_command_status(); }",
        "fn save(s: &mut Store) { Store::set_command_status(s); }",
        "fn save(s: &mut Store) { let write = Store::set_command_status; write(s); }",
        "fn save(s: &mut Store) { s.r#set_command_status(); }",
    ] {
        let fixture = fixture(
            FIXTURE_STORE,
            &[("seam.rs", FIXTURE_SEAM), ("handler.rs", body)],
        );
        let problems = verdict(&inventory(vec![]), &fixture.writers, &fixture.sites);
        assert!(
            problems.iter().any(
                |p| p.starts_with("unmediated command/effect evidence write")
                    && p.contains("app/handler.rs")
            ),
            "{body}: {problems:?}"
        );
    }
}

#[test]
fn a_listed_bypass_passes_only_while_it_exists() {
    let handler = "fn save(s: &mut Store) { s.set_command_status(); }";
    let with = fixture(
        FIXTURE_STORE,
        &[("seam.rs", FIXTURE_SEAM), ("handler.rs", handler)],
    );
    let site = with
        .sites
        .iter()
        .find(|site| site.file == "app/handler.rs")
        .unwrap();
    let listed = inventory(vec![bypass(site)]);
    assert_eq!(
        verdict(&listed, &with.writers, &with.sites),
        Vec::<String>::new()
    );
    let without = fixture(
        FIXTURE_STORE,
        &[
            ("seam.rs", FIXTURE_SEAM),
            (
                "handler.rs",
                "fn save(s: &mut Store) { s.admit_with_dispatch(); }",
            ),
        ],
    );
    let problems = verdict(&listed, &without.writers, &without.sites);
    assert!(
        problems
            .iter()
            .any(|p| p.starts_with("listed bypass no longer exists")),
        "{problems:?}"
    );
}

#[test]
fn a_new_store_writer_fails_until_classified() {
    let store = FIXTURE_STORE.replace(
        "pub fn command(&self) {}",
        "pub fn command(&self) {}\n pub fn overwrite_receipt(&mut self) {}",
    );
    let fixture = fixture(&store, &[("seam.rs", FIXTURE_SEAM)]);
    let problems = verdict(&inventory(vec![]), &fixture.writers, &fixture.sites);
    assert!(
        problems
            .iter()
            .any(|p| p.starts_with("unclassified store writer") && p.contains("overwrite_receipt")),
        "{problems:?}"
    );
}

#[test]
fn a_ledger_name_shared_with_another_class_is_refused() {
    let mut ambiguous = inventory(vec![]);
    ambiguous.api.push(ClassifiedApi {
        declaration: api("Handle", "fn set_command_status (self)"),
        classification: "seam".into(),
    });
    assert!(ledger_names(&ambiguous).is_err());
}

#[test]
fn an_idle_seam_owner_and_a_bypass_inside_it_fail() {
    let idle = fixture(FIXTURE_STORE, &[("seam.rs", "pub fn idle() {}")]);
    let problems = verdict(&inventory(vec![]), &idle.writers, &idle.sites);
    assert!(
        problems
            .iter()
            .any(|p| p.contains("writes no ledger evidence")),
        "{problems:?}"
    );
    let busy = fixture(FIXTURE_STORE, &[("seam.rs", FIXTURE_SEAM)]);
    let problems = verdict(
        &inventory(vec![bypass(&busy.sites[0])]),
        &busy.writers,
        &busy.sites,
    );
    assert!(
        problems
            .iter()
            .any(|p| p.starts_with("bypass listed inside a seam owner")),
        "{problems:?}"
    );
}
