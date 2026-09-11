//! Current access to an original recording compartment; no execution capability.
use super::*;
use crate::file_action_factory::resolution_scope::{canonical_paths, covers};
use gaugedesk_whip_runtime::ResourcePolicy;
use whipplescript_store::vcs::resolution_scope::ResolutionMemoryScope;

fn coordinates(scope: &ResolutionMemoryScope) -> Result<(String, String, String), String> {
    // The owner has already validated its wire object. These strings contain
    // GaugeDesk's versioned namespace tuples, whose meaning is product-owned.
    let value = serde_json::to_value(scope).map_err(|e| e.to_string())?;
    let field = |name: &str| -> Result<String, String> {
        value[name]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| "missing namespace coordinate".into())
    };
    Ok((
        field("authority")?,
        field("resource")?,
        field("compartment")?,
    ))
}
fn paths_canonical(paths: &[String]) -> bool {
    !paths.is_empty() && canonical_paths(paths).as_deref() == Ok(paths)
}

fn original_ceiling_is_covered(
    original: &ResolutionMemoryScope,
    current: &ResolutionMemoryScope,
    original_memory: &ResourcePolicy,
) -> Result<(), String> {
    let (old_authority, old_resource, old_compartment) = coordinates(original)?;
    let (now_authority, now_resource, _) = coordinates(current)?;
    let old_authority: (String, String, String) =
        serde_json::from_str(&old_authority).map_err(|e| e.to_string())?;
    let now_authority: (String, String, String) =
        serde_json::from_str(&now_authority).map_err(|e| e.to_string())?;
    let old_resource: (String, String, String, Vec<String>) =
        serde_json::from_str(&old_resource).map_err(|e| e.to_string())?;
    let now_resource: (String, String, String, Vec<String>) =
        serde_json::from_str(&now_resource).map_err(|e| e.to_string())?;
    let (version, memory): (String, ResourcePolicy) =
        serde_json::from_str(&old_compartment).map_err(|e| e.to_string())?;
    if old_authority.0 != "gaugedesk.resolutions.authority.v1"
        || old_authority != now_authority
        || old_resource.0 != "gaugedesk.resolutions.resource.v1"
        || (
            old_resource.0.as_str(),
            old_resource.1.as_str(),
            old_resource.2.as_str(),
        ) != (
            now_resource.0.as_str(),
            now_resource.1.as_str(),
            now_resource.2.as_str(),
        )
        || version != "gaugedesk.resolutions.compartment.v1"
        || &memory != original_memory
        || !paths_canonical(&old_resource.3)
        || !paths_canonical(&now_resource.3)
        || !old_resource
            .3
            .iter()
            .all(|old| now_resource.3.iter().any(|now| covers(now, old)))
    {
        return Err("current read grant does not cover the original recording namespace".into());
    }
    Ok(())
}

pub(super) fn compile(
    current: &FileAuthority,
    original_scope: &ResolutionMemoryScope,
    original: &HostGovernancePolicy,
) -> Result<HostGovernancePolicy, String> {
    let memory = original
        .resources
        .get("memory:/action/resolutions")
        .ok_or("original recording policy has no memory compartment")?;
    original_ceiling_is_covered(original_scope, &current.resolution_scope, memory)?;
    // The response contains complete instance metadata. Preserve every original
    // resource restriction, including a stricter input than its result label.
    let readers: BTreeSet<_> = original
        .resources
        .values()
        .chain(current.policy.resources.values())
        .flat_map(|resource| resource.reader.iter().cloned())
        .collect();
    if !readers.is_subset(&current.read_clearances) {
        return Err(
            "investigator does not clear original and current evidence restrictions".into(),
        );
    }
    let mut resources = BTreeMap::new();
    for address in [
        "memory:/action/corrections",
        "memory:/action/resolutions",
        "result",
        "error",
    ] {
        if !original.resources.contains_key(address) {
            return Err("original recording evidence policy is incomplete".into());
        }
        resources.insert(
            address.into(),
            ResourcePolicy {
                reader: readers.clone(),
                writer: BTreeSet::new(),
                principal: false,
                internal: false,
            },
        );
    }
    let policy = HostGovernancePolicy {
        resources,
        parties: current.policy.parties.clone(),
        delegations: current.policy.delegations.clone(),
        bindings: BTreeMap::from([
            (
                "admitted_corrections".into(),
                "memory:/action/corrections".into(),
            ),
            (
                "admitted_resolutions".into(),
                "memory:/action/resolutions".into(),
            ),
            ("result".into(), "result".into()),
            ("error".into(), "error".into()),
        ]),
        ..HostGovernancePolicy::default()
    };
    policy.validate()?;
    Ok(policy)
}

#[cfg(test)]
#[path = "resolution_recording_inspection_policy_tests.rs"]
mod tests;
