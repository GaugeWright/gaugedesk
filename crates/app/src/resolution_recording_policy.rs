//! Policy for authored corrections and corrections from saved sources (ACTION-4).
//! Current admission, retained read taint, input/store binding and execution
//! remain separate obligations. This compiler grants no file operation.

use std::collections::{BTreeMap, BTreeSet};

use crate::file_action_policy::{compile_file_save_policy, FileSavePolicyInput};
use gaugedesk_whip_runtime::{HostGovernancePolicy, ResourcePolicy};

/// The same admitted actor/input/target records used by file policy compilation.
/// Sharing this shape also shares its resource restrictions and clearance check;
/// it is not a file-save request or a claim about any prior text's provenance.
pub type ResolutionRecordingPolicyInput = FileSavePolicyInput;

pub fn compile_resolution_recording_policy(
    input: &ResolutionRecordingPolicyInput,
) -> Result<HostGovernancePolicy, String> {
    let shared = compile_file_save_policy(input)?;
    // Keep the original input label and the same unendorsed memory compartment
    // a scoped save reads. An explicit allowlist prevents a future file-policy
    // resource or binding from silently widening this recording profile.
    let resources = shared
        .resources
        .into_iter()
        .filter_map(|(address, resource)| match address.as_str() {
            "file:/action/input" => Some(("memory:/action/corrections".into(), resource)),
            "memory:/action/resolutions" | "result" | "error" => Some((address, resource)),
            _ => None,
        })
        .collect();
    let bindings = BTreeMap::from([
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
    ]);
    let policy = HostGovernancePolicy {
        resources,
        bindings,
        parties: shared.parties,
        delegations: shared.delegations,
        capabilities: BTreeSet::from(["vcs.record_resolutions".into()]),
        ..HostGovernancePolicy::default()
    };
    policy.validate()?;
    Ok(policy)
}

/// Compile restrictions for corrections derived from verified saved sources.
/// The admission boundary supplies their authenticated, retained labels. This
/// unsigned result proves neither source authenticity nor continued custody.
pub fn compile_saved_source_recording_policy(
    input: &ResolutionRecordingPolicyInput,
    sources: &[ResourcePolicy],
) -> Result<HostGovernancePolicy, String> {
    if sources.is_empty() {
        return Err("derived correction has no retained source".into());
    }
    let mut policy = compile_resolution_recording_policy(input)?;
    let clearances = crate::policy_compiler::actor_clearances(
        &input.actor_attributes,
        input.purpose.as_deref(),
        &[input.input.clone(), input.target.clone()],
        std::iter::empty(),
    );
    let mut source_readers = BTreeSet::new();
    for source in sources {
        if source.principal || source.internal || !source.writer.is_empty() {
            return Err("saved source requires unendorsed data restrictions".into());
        }
        if !source.reader.is_subset(&clearances) {
            return Err("correction actor does not clear retained source restrictions".into());
        }
        source_readers.extend(source.reader.iter().cloned());
    }
    for address in ["memory:/action/corrections", "result", "error"] {
        let resource = policy
            .resources
            .get_mut(address)
            .ok_or("correction policy is missing a required resource")?;
        resource.reader.extend(source_readers.iter().cloned());
        resource.writer.clear();
    }
    // Destination authority stays independently admitted. A stricter source
    // produces a refused flow, never an implicit declassification or a rewrite
    // of existing memory's label. The admission boundary runs the IFC check.
    policy.validate()?;
    Ok(policy)
}

/// Check the materialized recording boundary before command publication.
/// The fixed workflow carries an input reference; its static check cannot prove
/// every flow performed when the owner resolves and records that reference.
pub fn validate_resolution_recording_flows(
    envelope: &gaugedesk_whip_runtime::ifc::VerifiedEnvelope,
) -> Result<(), String> {
    for (source, destination) in [
        ("admitted_corrections", "admitted_resolutions"),
        ("admitted_corrections", "result"),
        ("admitted_corrections", "error"),
        ("admitted_resolutions", "result"),
        ("admitted_resolutions", "error"),
    ] {
        envelope
            .check_resource_flow(source, destination)
            .map_err(|error| format!("correction flow refused: {error:?}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gaugedesk_core::{
        abac::{
            Action, AuthorityAttributes, Classification, Condition, Constraint, Policy, Role, Rule,
        },
        boundary::Authority,
        ids::AuthorityId,
        resource::{ContentLocator, Resource, ResourceId, ResourceKind, ResourceRecord},
        signature::SigningKey,
    };
    use gaugedesk_whip_runtime::{ifc, sign_hosted_policy_envelope, GovernanceRootVerifier};

    fn input(actor: &str) -> ResolutionRecordingPolicyInput {
        let owner = Authority::new("resource-owner");
        let record = |name| {
            ResourceRecord::new(
                Resource::input(
                    ResourceId::new(name),
                    ResourceKind::context(),
                    owner.clone(),
                ),
                ContentLocator::Content {
                    handle: format!("retained:{name}"),
                },
                |_| owner.clone(),
            )
        };
        ResolutionRecordingPolicyInput {
            actor: AuthorityId::new(actor),
            actor_attributes: AuthorityAttributes {
                roles: BTreeSet::from([Role::owner()]),
                ..AuthorityAttributes::default()
            },
            org_policy: Policy::default(),
            purpose: None,
            ceiling_attested: false,
            input: record("corrections"),
            target: record("target"),
        }
    }

    fn verified(policy: &HostGovernancePolicy) -> ifc::VerifiedEnvelope {
        let issuer = AuthorityId::new("home:recording-policy");
        let key = SigningKey::from_seed(&[93; 32]).unwrap();
        let signed =
            sign_hosted_policy_envelope(&policy.to_json().unwrap(), &issuer, &key, 1).unwrap();
        ifc::VerifiedEnvelope::verify_signed_text_with(
            &signed,
            &GovernanceRootVerifier::new(issuer, key.public_key()),
        )
        .unwrap()
    }

    #[test]
    fn equivalent_callers_get_only_recording_with_the_save_memory_compartment() {
        let mut previous_memory = None;
        for actor in ["human:alice", "agent:editor"] {
            let input = input(actor);
            let policy = compile_resolution_recording_policy(&input).unwrap();
            let save = compile_file_save_policy(&input).unwrap();
            assert_eq!(
                policy.capabilities,
                BTreeSet::from(["vcs.record_resolutions".into()])
            );
            assert!(policy.provider_bindings.is_empty());
            assert!(policy.placements.is_empty());
            assert!(policy.declassifications.is_empty());
            assert!(policy.endorsements.is_empty());
            assert_eq!(policy.resources.len(), 4);
            assert_eq!(policy.bindings.len(), 4);
            assert!(!policy.resources.keys().any(|key| key.starts_with("file:")));
            assert!(!policy.bindings.contains_key("admitted_target"));
            assert!(!policy.bindings.contains_key("admitted_input"));
            let memory = &policy.resources["memory:/action/resolutions"];
            assert_eq!(memory, &save.resources["file:/action/output"]);
            if let Some(previous) = &previous_memory {
                assert_eq!(memory, previous);
            }
            previous_memory = Some(memory.clone());
            let envelope = verified(&policy);
            for source in ["admitted_corrections", "admitted_resolutions"] {
                for sink in ["admitted_resolutions", "result", "error"] {
                    envelope.check_resource_flow(source, sink).unwrap();
                }
            }
        }
    }

    #[test]
    fn a_private_correction_cannot_flow_into_less_restricted_memory() {
        for actor in ["human:alice", "agent:editor"] {
            let mut input = input(actor);
            input.target.attributes.classification = Classification::Public;
            let policy = compile_resolution_recording_policy(&input).unwrap();
            let envelope = verified(&policy);
            assert!(envelope
                .check_resource_flow("admitted_corrections", "admitted_resolutions")
                .is_err());
            // Failure and result references retain the combined restrictions.
            for terminal in ["result", "error"] {
                envelope
                    .check_resource_flow("admitted_corrections", terminal)
                    .unwrap();
                let mut widened = policy.clone();
                widened.resources.get_mut(terminal).unwrap().reader.clear();
                assert!(verified(&widened)
                    .check_resource_flow("admitted_corrections", terminal)
                    .is_err());
            }
        }
    }

    #[test]
    fn remembering_content_does_not_endorse_its_existing_winner() {
        for actor in ["human:alice", "agent:editor"] {
            let policy = compile_resolution_recording_policy(&input(actor)).unwrap();
            for terminal in ["result", "error", "memory:/action/resolutions"] {
                assert!(policy.resources[terminal].writer.is_empty());
                let mut endorsed = policy.clone();
                endorsed.resources.insert(
                    "memory:/original".into(),
                    policy.resources["memory:/action/resolutions"].clone(),
                );
                endorsed
                    .bindings
                    .insert("original".into(), "memory:/original".into());
                endorsed.resources.get_mut(terminal).unwrap().writer = policy.resources
                    ["memory:/action/corrections"]
                    .writer
                    .clone();
                let sink = if terminal == "memory:/action/resolutions" {
                    "admitted_resolutions"
                } else {
                    terminal
                };
                assert!(verified(&endorsed)
                    .check_resource_flow("original", sink)
                    .is_err());
            }
        }
    }

    #[test]
    fn recording_keeps_current_resource_and_actor_refusals() {
        for actor in ["human:alice", "agent:editor"] {
            for reason in ["input", "target", "clearance", "policy"] {
                let mut input = input(actor);
                match reason {
                    "input" => input.input.tombstoned = true,
                    "target" => input.target.tombstoned = true,
                    "clearance" => input.actor_attributes = AuthorityAttributes::default(),
                    "policy" => input.org_policy.rules.push(Rule {
                        when: Condition::Always,
                        require: Constraint::DenyAction(Action::Run),
                    }),
                    _ => unreachable!(),
                }
                assert!(
                    compile_resolution_recording_policy(&input).is_err(),
                    "{actor}/{reason}"
                );
            }
        }
    }

    fn saved_source(readers: &[&str]) -> ResourcePolicy {
        ResourcePolicy {
            reader: readers.iter().map(|reader| (*reader).into()).collect(),
            writer: BTreeSet::new(),
            principal: false,
            internal: false,
        }
    }

    #[test]
    fn derived_corrections_keep_source_confidentiality_without_relabeling_memory() {
        for actor in ["human:alice", "agent:editor"] {
            let mut input = input(actor);
            input.input.attributes.classification = Classification::Public;
            input.target.attributes.classification = Classification::Public;
            let authored = compile_resolution_recording_policy(&input).unwrap();
            let sources = [
                saved_source(&["classification:regulated"]),
                saved_source(&["role:owner"]),
            ];
            let derived = compile_saved_source_recording_policy(&input, &sources).unwrap();
            assert_eq!(
                derived.resources["memory:/action/resolutions"],
                authored.resources["memory:/action/resolutions"]
            );
            for address in ["memory:/action/corrections", "result", "error"] {
                let resource = &derived.resources[address];
                for source in &sources {
                    assert!(source.reader.is_subset(&resource.reader));
                }
                assert!(authored.resources[address]
                    .reader
                    .is_subset(&resource.reader));
                assert!(resource.writer.is_empty());
            }
            let envelope = verified(&derived);
            assert!(envelope
                .check_resource_flow("admitted_corrections", "admitted_resolutions")
                .is_err());
            for terminal in ["result", "error"] {
                envelope
                    .check_resource_flow("admitted_corrections", terminal)
                    .unwrap();
            }
            assert!(validate_resolution_recording_flows(&envelope).is_err());
        }
    }

    #[test]
    fn derived_corrections_preserve_unendorsed_integrity_for_equivalent_actors() {
        for actor in ["human:alice", "agent:editor"] {
            let input = input(actor);
            let source = saved_source(&["classification:regulated"]);
            let derived = compile_saved_source_recording_policy(&input, &[source]).unwrap();
            let envelope = verified(&derived);
            for terminal in ["admitted_resolutions", "result", "error"] {
                envelope
                    .check_resource_flow("admitted_corrections", terminal)
                    .unwrap();
            }
            let recording =
                whipplescript_kernel::resolution_recording::ResolutionRecordingAction::compile()
                    .unwrap();
            assert!(ifc::check_with_envelope(recording.action().program(), &envelope).is_empty());
            validate_resolution_recording_flows(&envelope).unwrap();
            let mut endorsed = derived;
            endorsed.resources.get_mut("result").unwrap().writer =
                BTreeSet::from([crate::policy_compiler::authority_role(actor)]);
            assert!(verified(&endorsed)
                .check_resource_flow("admitted_corrections", "result")
                .is_err());
            assert!(validate_resolution_recording_flows(&verified(&endorsed)).is_err());
        }
    }

    #[test]
    fn derived_correction_policy_requires_sources_and_current_clearance() {
        for actor in ["human:alice", "agent:editor"] {
            let input = input(actor);
            assert!(compile_saved_source_recording_policy(&input, &[]).is_err());
            for reason in ["clearance", "principal", "internal", "endorsement"] {
                let mut source = saved_source(&["classification:regulated"]);
                match reason {
                    "clearance" => {
                        source.reader.insert("residency:unadmitted".into());
                    }
                    "principal" => source.principal = true,
                    "internal" => source.internal = true,
                    "endorsement" => {
                        source
                            .writer
                            .insert(crate::policy_compiler::authority_role(actor));
                    }
                    _ => unreachable!(),
                }
                assert!(
                    compile_saved_source_recording_policy(&input, &[source]).is_err(),
                    "{actor}/{reason}"
                );
            }
        }
    }
}
