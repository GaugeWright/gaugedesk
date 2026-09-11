#[path = "support/action_source.rs"]
mod action_source;
use action_source::{Api, Scanner, Site};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

const PACKAGES: &[&str] = &["gaugedesk-app", "gaugedesk-workspace", "gaugedesk-ee"];
const LOCATORS: &[&str] = &[
    "ChatWorkspace::boxed_clone",
    "ChatWorkspace::path",
    "ChatWorkspace::branch",
    "ChatWorkspace::target",
    "Workspace::mainline",
    "Workspace::workstream_ref",
    "Workspace::workstream_id_of",
    "Workspace::export_format",
    "Workspace::peer_source",
    "WorkspaceProvider::export_format",
];
fn locator(api: &Api) -> bool {
    LOCATORS.contains(&format!("{}::{}", api.owner, api.name).as_str())
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
        let targets: Vec<_> = package["targets"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|target| {
                target["kind"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|kind| kind == "lib" || kind == "bin")
            })
            .collect();
        assert!(
            !targets.is_empty(),
            "inventoried package must retain production targets"
        );
        result.extend(
            targets
                .iter()
                .map(|target| PathBuf::from(target["src_path"].as_str().unwrap())),
        );
    }
    result.sort();
    result.dedup();
    result
}
fn scan(root: &Path, roots: &[PathBuf], capabilities: BTreeSet<String>) -> Scanner {
    let mut scanner = Scanner::new(root, capabilities);
    for path in roots {
        scanner.scan(path).unwrap();
    }
    scanner
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClassifiedApi {
    declaration: Api,
    classification: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClassifiedSite {
    site: Site,
    profile: String,
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
struct Inventory {
    schema: String,
    coverage: String,
    packages: Vec<String>,
    api: Vec<ClassifiedApi>,
    profiles: BTreeMap<String, Profile>,
    sites: Vec<ClassifiedSite>,
}

fn changes<T: Ord + std::fmt::Debug>(expected: &BTreeSet<T>, actual: &BTreeSet<T>) -> Vec<String> {
    expected
        .difference(actual)
        .map(|site| format!("removed/changed: {site:?}"))
        .chain(
            actual
                .difference(expected)
                .map(|site| format!("new/changed: {site:?}")),
        )
        .collect()
}

#[test]
fn workspace_capability_source_inventory_matches_production_items() {
    let root = root();
    let roots = entrypoints(&root);
    let declarations = scan(&root, &roots, BTreeSet::new()).api;
    let capabilities = declarations
        .iter()
        .filter(|api| !locator(api))
        .map(|api| api.name.clone())
        .collect();
    let scanner = scan(&root, &roots, capabilities);
    let path = root.join("contracts/workspace-action-sites.json");
    if !path.exists() {
        panic!(
            "SOURCE_INVENTORY_BEGIN\n{}\nSOURCE_INVENTORY_END",
            serde_json::to_string_pretty(
                &serde_json::json!({"api": declarations, "sites": scanner.sites()})
            )
            .unwrap()
        );
    }
    let inventory: Inventory =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(inventory.schema, "gaugedesk.workspace-action-sites.v1");
    assert_eq!(inventory.coverage, "workspace-capability-syntax");
    assert_eq!(inventory.packages, PACKAGES);
    let declared: BTreeSet<_> = inventory
        .api
        .iter()
        .map(|api| api.declaration.clone())
        .collect();
    assert_eq!(
        declared.len(),
        inventory.api.len(),
        "duplicate API classification"
    );
    assert_eq!(
        changes(&declared, &declarations),
        Vec::<String>::new(),
        "workspace API changed; classify its authority and effects"
    );
    for api in &inventory.api {
        let expected = if locator(&api.declaration) {
            "locator"
        } else {
            "requires-provenance-review"
        };
        assert_eq!(api.classification, expected, "unsupported API exemption");
    }
    for profile in inventory.profiles.values() {
        assert!(["ACTION-3", "ACTION-4", "ACTION-5", "ACTION-6", "ACTION-8"]
            .contains(&profile.coverage_id.as_str()));
        assert!(profile.reason.len() > 30 && !profile.required_evidence.is_empty());
        assert!(profile.required_evidence.iter().all(|item| item.len() > 10));
    }
    let actual = scanner.sites();
    let expected: Vec<_> = inventory.sites.iter().map(|row| row.site.clone()).collect();
    for row in &inventory.sites {
        assert!(
            inventory.profiles.contains_key(&row.profile),
            "unclassified site: {:?}",
            row.site
        );
    }
    assert_eq!(
        expected.iter().collect::<BTreeSet<_>>().len(),
        expected.len(),
        "duplicate site"
    );
    assert_eq!(
        changes(&expected.iter().collect(), &actual.iter().collect()),
        Vec::<String>::new(),
        "new, changed or removed workspace capability sites require classification"
    );
    assert!(
        inventory
            .profiles
            .keys()
            .all(|id| inventory.sites.iter().any(|row| &row.profile == id)),
        "unused source profile"
    );
}

fn fixture(source: &str, files: &[(&str, &str)]) -> (tempfile::TempDir, Vec<Site>) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("lib.rs"), source).unwrap();
    for (path, body) in files {
        let path = dir.path().join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }
    let mut scanner = Scanner::new(
        dir.path(),
        BTreeSet::from(["write_file".into(), "current_cut".into(), "export".into()]),
    );
    scanner.scan(&dir.path().join("lib.rs")).unwrap();
    (dir, scanner.sites())
}

#[test]
fn syntax_scan_preserves_production_after_tests_and_ignores_strings_comments() {
    let (_, sites) = fixture(
        r###"
        // workspace.write_file("not", "code");
        const TEXT: &str = r#"workspace.current_cut()"#;
        #[cfg(test)] mod tests { fn helper() { workspace.write_file("test", "only"); } }
        fn after_tests() { workspace.write_file("production", "bytes"); }
        impl Holder { #[cfg(test)] fn test_helper() { self.current_cut(); } fn production() { target.current_cut(); } }
        fn outer() { #[cfg(test)] { target.write_file("test", "block"); } }
    "###,
        &[],
    );
    assert_eq!(sites.len(), 2);
    assert!(sites.iter().any(|site| site.callable == "after_tests"));
    assert!(sites
        .iter()
        .any(|site| site.callable.ends_with("::production")));
}

#[test]
fn syntax_scan_follows_named_inline_and_external_modules_without_loading_test_files() {
    let (_, sites) = fixture(
        r#"
        #[cfg(test)] #[path="missing-test.rs"] mod tests;
        #[path="owner.rs"] mod owner;
        mod nested { mod child; }
    "#,
        &[
            (
                "owner.rs",
                "fn writer() { target.write_file(\"a\", \"b\"); }",
            ),
            ("nested/child.rs", "fn reader() { target.current_cut(); }"),
        ],
    );
    assert_eq!(sites.len(), 2);
    assert_eq!(sites[0].file, "nested/child.rs");
    assert_eq!(sites[1].file, "owner.rs");
}

#[test]
fn syntax_scan_keeps_unknown_platform_branches_and_records_ufcs_and_function_references() {
    let (_, sites) = fixture(
        r#"
        #[cfg(all(test, feature="fixture"))] fn only_test() { target.current_cut(); }
        #[cfg(any(test, feature="desktop"))] fn available() {
            Workspace::write_file(target, "path", "body");
            let write = Workspace::write_file;
            target.current_cut(); target.current_cut();
        }
        #[cfg(not(test))] fn normal() { target.current_cut(); }
    "#,
        &[],
    );
    assert_eq!(sites.len(), 4);
    assert!(sites
        .iter()
        .any(|site| site.capability == "current_cut" && site.count == 2));
    assert!(sites
        .iter()
        .any(|site| site.expression == "Workspace :: write_file"));
    assert!(sites
        .iter()
        .any(|site| site.expression.starts_with("Workspace :: write_file (")));
}

#[test]
fn missing_modules_or_invalid_rust_never_pass_as_an_empty_inventory() {
    for source in ["mod missing;", "fn malformed( {"] {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lib.rs"), source).unwrap();
        let mut scanner = Scanner::new(dir.path(), BTreeSet::new());
        assert!(scanner.scan(&dir.path().join("lib.rs")).is_err());
    }
}

#[test]
fn raw_identifier_calls_are_inventory_sites_and_bare_values_are_not() {
    let (_, sites) = fixture(
        r#"
        fn observe(export: &[u8]) {
            target.r#write_file("path", "body");
            Workspace::r#write_file(target, "path", "body");
            let value = export;
        }
    "#,
        &[],
    );
    assert_eq!(sites.len(), 2);
    assert!(sites.iter().all(|site| site.capability == "write_file"));
}

#[test]
fn conditional_module_paths_require_coverage_instead_of_selecting_one_branch() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("lib.rs"),
        r#"
        #[cfg_attr(feature="another", path="other.rs")] mod platform;
    "#,
    )
    .unwrap();
    std::fs::write(dir.path().join("platform.rs"), "fn harmless() {}").unwrap();
    let mut scanner = Scanner::new(dir.path(), BTreeSet::new());
    assert!(scanner
        .scan(&dir.path().join("lib.rs"))
        .unwrap_err()
        .contains("conditional module path"));
}

#[test]
fn conditional_attributes_without_path_overrides_keep_the_module() {
    let (_, sites) = fixture(
        r#"
        #[cfg_attr(feature="pathfinder", allow(dead_code))] mod platform;
    "#,
        &[("platform.rs", "fn observes() { target.current_cut(); }")],
    );
    assert_eq!(sites.len(), 1);
}

#[test]
fn custom_crate_roots_resolve_modules_beside_the_entrypoint() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("custom.rs"), "mod child;").unwrap();
    std::fs::write(
        dir.path().join("child.rs"),
        "fn observes() { target.current_cut(); }",
    )
    .unwrap();
    let mut scanner = Scanner::new(dir.path(), BTreeSet::from(["current_cut".into()]));
    scanner.scan(&dir.path().join("custom.rs")).unwrap();
    assert_eq!(scanner.sites().len(), 1);
    assert_eq!(scanner.sites()[0].file, "child.rs");
}

#[test]
fn explicit_paths_and_ordinary_main_named_modules_keep_distinct_child_directories() {
    let (_, sites) = fixture(
        "#[path=\"owner.rs\"] mod owner; mod main;",
        &[
            ("owner.rs", "mod child;"),
            ("child.rs", "fn observes() { target.current_cut(); }"),
            ("main.rs", "mod child;"),
            ("main/child.rs", "fn observes() { target.current_cut(); }"),
        ],
    );
    assert_eq!(sites.len(), 2);
    assert_eq!(sites[0].file, "child.rs");
    assert_eq!(sites[1].file, "main/child.rs");
}
