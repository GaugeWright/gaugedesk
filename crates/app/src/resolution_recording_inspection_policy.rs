//! Current access to an original recording compartment; no execution capability.
use super::*;
use crate::file_action_factory::resolution_scope::original_ceiling_is_covered;
use gaugedesk_whip_runtime::ResourcePolicy;
use whipplescript_store::vcs::resolution_scope::ResolutionMemoryScope;

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
