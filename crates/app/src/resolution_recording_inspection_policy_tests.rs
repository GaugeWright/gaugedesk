use super::*;

fn labeled(readers: &[&str]) -> HostGovernancePolicy {
    let label = ResourcePolicy {
        reader: readers.iter().map(|value| (*value).into()).collect(),
        writer: BTreeSet::new(),
        principal: false,
        internal: false,
    };
    HostGovernancePolicy {
        resources: [
            "file:/action/output",
            "memory:/action/corrections",
            "memory:/action/resolutions",
            "result",
            "error",
        ]
        .into_iter()
        .map(|address| (address.into(), label.clone()))
        .collect(),
        ..HostGovernancePolicy::default()
    }
}
fn scope(
    home: &str,
    target: &str,
    paths: &[&str],
    policy: &HostGovernancePolicy,
) -> ResolutionMemoryScope {
    resolution_scope::scope(
        home,
        "target-authority",
        "project",
        target,
        &paths
            .iter()
            .map(|path| (*path).to_owned())
            .collect::<Vec<_>>(),
        &["".into()],
        policy,
    )
    .unwrap()
}
fn current(paths: &[&str], policy: HostGovernancePolicy, clearances: &[&str]) -> FileAuthority {
    FileAuthority {
        target_id: "target".into(),
        project_id: "project".into(),
        workspace_path: "notes/item".into(),
        resolution_scope: scope("home", "target", paths, &policy),
        policy,
        read_clearances: clearances.iter().map(|value| (*value).to_owned()).collect(),
        valid_until_ms: None,
    }
}

#[test]
fn complete_correction_metadata_keeps_stricter_original_input_and_current_restrictions() {
    let mut original = labeled(&["past"]);
    original
        .resources
        .get_mut("memory:/action/corrections")
        .unwrap()
        .reader
        .insert("past-private".into());
    let original_scope = scope("home", "target", &["notes"], &original);
    let mut reader = current(&[""], labeled(&["now"]), &["past", "past-private", "now"]);
    let policy = compile(&reader, &original_scope, &original).unwrap();
    for resource in policy.resources.values() {
        assert_eq!(
            resource.reader,
            BTreeSet::from(["past".into(), "past-private".into(), "now".into()])
        );
        assert!(resource.writer.is_empty());
    }
    assert!(policy.capabilities.is_empty());
    assert!(policy.provider_bindings.is_empty());
    assert!(policy.placements.is_empty());
    assert!(policy.endorsements.is_empty());
    assert!(policy.declassifications.is_empty());
    reader.read_clearances.remove("past-private");
    assert!(compile(&reader, &original_scope, &original).is_err());
}

#[test]
fn inspection_requires_complete_original_path_coverage_and_the_same_home_and_target() {
    let original = labeled(&["restricted"]);
    for (old, now, permitted) in [
        ("notes", "", true),
        ("", "notes", false),
        ("notes-private", "notes", false),
    ] {
        let original_scope = scope("home", "target", &[old], &original);
        let reader = current(&[now], original.clone(), &["restricted"]);
        assert_eq!(
            compile(&reader, &original_scope, &original).is_ok(),
            permitted,
            "{old} under {now}"
        );
    }
    let reader = current(&[""], original.clone(), &["restricted"]);
    for (home, target) in [("foreign", "target"), ("home", "other-target")] {
        assert!(compile(
            &reader,
            &scope(home, target, &["notes"], &original),
            &original
        )
        .is_err());
    }
    let other_policy = labeled(&["different-original-policy"]);
    assert!(compile(
        &reader,
        &scope("home", "target", &["notes"], &other_policy),
        &original
    )
    .is_err());
}
