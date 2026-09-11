//! Product coordinates for the runtime owner's remembered-input namespace.
//! These descriptors convey no access; callers hold the current authority fence.
use super::*;
use gaugedesk_whip_runtime::ResourcePolicy;
use whipplescript_store::vcs::resolution_scope::ResolutionMemoryScope;

pub(super) fn covers(parent: &str, child: &str) -> bool {
    parent.is_empty()
        || parent == child
        || child
            .strip_prefix(parent)
            .is_some_and(|tail| tail.starts_with('/'))
}

pub(super) fn canonical_paths(paths: &[String]) -> Result<Vec<String>, String> {
    let mut paths = paths
        .iter()
        .map(|path| {
            let path = path.trim().trim_start_matches("./").trim_end_matches('/');
            let path = if path == "." { "" } else { path };
            if !path.is_empty() && !normalized(path) {
                return Err("resolution memory path ceiling is malformed".into());
            }
            Ok(path.to_owned())
        })
        .collect::<Result<Vec<_>, String>>()?;
    paths.sort();
    paths.dedup();
    let mut roots: Vec<String> = Vec::new();
    for path in paths {
        if !roots.iter().any(|parent| covers(parent, &path)) {
            roots.push(path);
        }
    }
    Ok(roots)
}

pub(super) fn scope(
    home: &str,
    authority: &str,
    project: &str,
    target: &str,
    target_paths: &[String],
    member_paths: &[String],
    policy: &HostGovernancePolicy,
) -> Result<ResolutionMemoryScope, String> {
    if [home, authority, project, target]
        .iter()
        .any(|value| value.trim().is_empty())
    {
        return Err("resolution memory requires complete resource authority".into());
    }
    let target_paths = canonical_paths(target_paths)?;
    let member_paths = canonical_paths(member_paths)?;
    let mut intersection = Vec::new();
    for left in &target_paths {
        for right in &member_paths {
            if covers(left, right) {
                intersection.push(right.clone());
            } else if covers(right, left) {
                intersection.push(left.clone());
            }
        }
    }
    let paths = canonical_paths(&intersection)?;
    if paths.is_empty() {
        return Err("resolution memory has no effective path grant".into());
    }
    let resource: &ResourcePolicy = policy
        .resources
        .get("file:/action/output")
        .ok_or("resolution memory has no target policy")?;
    let json =
        |value: serde_json::Value| serde_json::to_string(&value).map_err(|error| error.to_string());
    ResolutionMemoryScope::new(
        json(serde_json::json!([
            "gaugedesk.resolutions.authority.v1",
            home,
            authority
        ]))?,
        json(serde_json::json!([
            "gaugedesk.resolutions.resource.v1",
            project,
            target,
            paths
        ]))?,
        json(serde_json::json!([
            "gaugedesk.resolutions.compartment.v1",
            resource
        ]))?,
    )
    .map_err(|error| format!("{error:?}"))
}

pub(super) fn resource(
    scope: &ResolutionMemoryScope,
    policy_hash: &str,
) -> Result<ActionResource, String> {
    Ok(ActionResource {
        resource: ResourceRef {
            handle: "admitted_resolutions".into(),
            kind: "resolution_memory".into(),
            selector: Some(serde_json::to_string(scope).map_err(|error| error.to_string())?),
            writable: Some(false),
        },
        basis: ActionBasis::Version {
            version_ref: scope.version_ref(),
        },
        label_ref: format!("policy:{policy_hash}:admitted_resolutions"),
    })
}

/// Read only the original admitted descriptor. Never infer a missing namespace.
pub(super) fn original(command: &HostActionCommand) -> Result<ResolutionMemoryScope, String> {
    let admitted = command
        .resources
        .get("resolutions")
        .ok_or("editor command has no admitted resolution scope")?;
    let scope: ResolutionMemoryScope = serde_json::from_str(
        admitted
            .resource
            .selector
            .as_deref()
            .ok_or("editor resolution scope is missing")?,
    )
    .map_err(|error| error.to_string())?;
    if admitted != &resource(&scope, &command.policy.envelope_hash)? {
        return Err("editor resolution resource differs from its admitted descriptor".into());
    }
    Ok(scope)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn paths(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).into()).collect()
    }
    fn policy() -> HostGovernancePolicy {
        HostGovernancePolicy {
            resources: BTreeMap::from([(
                "file:/action/output".into(),
                ResourcePolicy {
                    reader: BTreeSet::from(["owner".into()]),
                    writer: BTreeSet::new(),
                    principal: false,
                    internal: false,
                },
            )]),
            ..HostGovernancePolicy::default()
        }
    }
    #[test]
    fn effective_grant_is_canonical_and_uses_component_boundaries() {
        let policy = policy();
        let make = |target: &[&str], member: &[&str]| {
            scope(
                "home",
                "owner",
                "project",
                "target",
                &paths(target),
                &paths(member),
                &policy,
            )
        };
        let expected = make(&["docs", "src"], &["src/lib", "docs"]).unwrap();
        assert_eq!(
            expected,
            make(
                &["./src/", "docs", "src/deeper", "src"],
                &["docs/child", "docs", "src/lib/"]
            )
            .unwrap()
        );
        assert_eq!(expected, make(&["."], &["docs", "src/lib"]).unwrap());
        assert_ne!(expected, make(&["."], &["src", "docs"]).unwrap());
        assert_ne!(expected, make(&["docs"], &["docs"]).unwrap());
        assert!(make(&["src"], &["src-other"]).is_err());
        assert!(make(&[], &["src"]).is_err());
        for invalid in [
            "/src",
            "src/../secret",
            "src//secret",
            "src\\secret",
            "src\0secret",
        ] {
            assert!(make(&[invalid], &["."]).is_err(), "{invalid:?}");
        }
    }
    #[test]
    fn namespace_binds_authority_resource_and_policy_but_not_actor_clearance() {
        let policy = policy();
        let make = |home, owner, project, target, policy: &HostGovernancePolicy| {
            scope(
                home,
                owner,
                project,
                target,
                &paths(&["."]),
                &paths(&["src"]),
                policy,
            )
            .unwrap()
        };
        let expected = make("home", "owner", "project", "target", &policy);
        for coords in [
            ("other", "owner", "project", "target"),
            ("home", "other", "project", "target"),
            ("home", "owner", "other", "target"),
            ("home", "owner", "project", "other"),
        ] {
            assert_ne!(
                expected,
                make(coords.0, coords.1, coords.2, coords.3, &policy)
            );
        }
        let mut actor = policy.clone();
        actor.parties.insert("agent".into(), "agent-role".into());
        actor
            .delegations
            .push(["agent-role".into(), "owner".into()]);
        assert_eq!(expected, make("home", "owner", "project", "target", &actor));
        for writers in [false, true] {
            let mut changed = policy.clone();
            let target = changed.resources.get_mut("file:/action/output").unwrap();
            if writers {
                target.writer.insert("endorser".into());
            } else {
                target.reader.insert("private".into());
            }
            assert_ne!(
                expected,
                make("home", "owner", "project", "target", &changed)
            );
        }
    }
}
