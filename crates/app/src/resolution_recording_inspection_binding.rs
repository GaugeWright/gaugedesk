//! Bind authorized instance metadata to the original Home input and target.
//! The owner decodes binding/receipt formats and supplies their identities.
use super::*;
use gaugedesk_whip_runtime::host_actions::execution::{
    effect_observation_fingerprint, ExecuteActionEffect,
};
use sha2::{Digest, Sha256};
use whipplescript_kernel::resolution_recording::recording_operation_id;
use whipplescript_store::{
    effect_recovery::DispatchMarker,
    event_chain::{fold_owned, OwnedChainEntry},
    file_settlement::{RESOLUTION_RECORDING_CAPABILITY, RESOLUTION_RECORDING_PROVIDER},
    host_actions::dispatch_admission_binding,
    vcs::resolution_scope::ResolutionMemoryScope,
    ClaimableEffect, EffectView,
};

pub(super) struct OriginalRecording {
    pub(super) binding: ResolutionRecordingBinding,
    pub(super) execution: ExecuteActionEffect,
}

pub(super) fn binding(
    snapshot: &ActionResultSnapshot,
    prefix: Vec<OwnedChainEntry>,
    effect: EffectView,
    run_id: &str,
    mapping: &NativeInputBinding,
    target_scope: &ResolutionMemoryScope,
) -> StoreResult<ResolutionRecordingBinding> {
    verified(snapshot, prefix, effect, run_id, mapping, target_scope)
        .map(|original| original.binding)
}

pub(super) fn verified(
    snapshot: &ActionResultSnapshot,
    mut prefix: Vec<OwnedChainEntry>,
    effect: EffectView,
    run_id: &str,
    mapping: &NativeInputBinding,
    target_scope: &ResolutionMemoryScope,
) -> StoreResult<OriginalRecording> {
    let command = &snapshot.command;
    let pin = &snapshot.observed_at;
    let through = i64::try_from(pin.sequence).map_err(refused)?;
    prefix.retain(|row| row.sequence <= through);
    let head = fold_owned(&snapshot.admission.instance_ref, &prefix);
    if pin.instance_ref != snapshot.admission.instance_ref
        || head.sequence != Some(through)
        || head.digest != pin.head_digest
    {
        return Err(refused(
            "recording history differs from its authorized result prefix",
        ));
    }
    let admitted_at = i64::try_from(snapshot.admission.admitted_at.sequence).map_err(refused)?;
    let admission_prefix: Vec<_> = prefix
        .iter()
        .filter(|row| row.sequence <= admitted_at)
        .cloned()
        .collect();
    let admission_binding =
        dispatch_admission_binding(&snapshot.admission.instance_ref, &admission_prefix)?;
    let marker = snapshot
        .effects
        .iter()
        .find(|entry| entry.effect_id == effect.effect_id)
        .and_then(|entry| {
            entry
                .attempts
                .iter()
                .find(|attempt| attempt.run_id == run_id)
        })
        .and_then(|attempt| attempt.dispatch.as_ref())
        .ok_or_else(|| refused("original recording dispatch is unavailable"))?;
    let frame = &marker.frame;
    if frame.instance_id != snapshot.admission.instance_ref
        || frame.effect_id != effect.effect_id
        || frame.run_id != run_id
        || frame.kind != "capability.call"
        || frame.target.as_deref() != Some(RESOLUTION_RECORDING_CAPABILITY)
        || frame.provider != RESOLUTION_RECORDING_PROVIDER
        || frame.action_admission != admission_binding
    {
        return Err(refused(
            "recording dispatch differs from its original action",
        ));
    }
    let mut recorded = None;
    for event in prefix.iter().filter(|event| {
        event.sequence > admitted_at
            && event.source.as_deref() == Some("kernel")
            && event.event_type == "effect.run_started"
    }) {
        let payload: serde_json::Value = serde_json::from_str(&event.payload_json)?;
        if payload["run_id"].as_str() != Some(run_id) {
            continue;
        }
        let dispatch: DispatchMarker =
            serde_json::from_value(payload["external_dispatch"].clone())?;
        if &dispatch != marker || recorded.is_some() {
            return Err(refused("recording history has no unique original dispatch"));
        }
        recorded = Some(payload);
    }
    let payload =
        recorded.ok_or_else(|| refused("original recording dispatch metadata is missing"))?;
    let execution: ExecuteActionEffect =
        serde_json::from_value(payload["metadata"]["action_execution"]["request"].clone())?;
    let fingerprint = hex::encode(Sha256::digest(execution.signing_bytes().map_err(refused)?));
    let binding: ResolutionRecordingBinding =
        serde_json::from_value(payload["metadata"]["resolution_recording"].clone())?;
    let observed = ClaimableEffect {
        effect_id: effect.effect_id,
        kind: effect.kind,
        target: effect.target,
        profile: effect.profile,
        input_json: effect.input_json,
        required_capabilities_json: effect.required_capabilities_json,
        declared_profiles_json: effect.declared_profiles_json,
    };
    let input = command
        .inputs
        .get("corrections")
        .ok_or_else(|| refused("original correction input is missing"))?;
    let effect_input: serde_json::Value = serde_json::from_str(&observed.input_json)?;
    let capabilities: Vec<String> = serde_json::from_str(&observed.required_capabilities_json)?;
    // The current compiler retains the call's `for reference` argument. The
    // earlier shape remains valid history; both must name the exact input.
    let legacy_input = serde_json::json!({"target": RESOLUTION_RECORDING_CAPABILITY,
        "bindings": {"reference": input}, "rule": "record_corrections"});
    let mut current_input = legacy_input.clone();
    current_input["argument_exprs"] = serde_json::json!(["reference"]);
    current_input["arguments"] = serde_json::json!({"arg0": input});
    if execution.admission != snapshot.admission
        || execution.issuer != command.issuer
        || execution.scope != command.scope
        || execution.policy != command.policy
        || execution.provenance != command.provenance
        || execution.effect_id != observed.effect_id
        || execution.effect_fingerprint
            != effect_observation_fingerprint(&observed).map_err(refused)?
        || payload["metadata"]["action_execution"]["fingerprint"] != fingerprint
        || observed.kind != "capability.call"
        || observed.target.as_deref() != Some(RESOLUTION_RECORDING_CAPABILITY)
        || capabilities != [RESOLUTION_RECORDING_CAPABILITY]
        || (effect_input != legacy_input && effect_input != current_input)
        || mapping.input() != input
        || mapping.content_hash() != binding.input_hash()
        || binding.input_label() != input.label_ref
        || binding.scope() != target_scope
        || delivery::original_scope(command).as_ref() != Ok(target_scope)
        || binding.batch().actor != command.provenance.executor
        || binding.batch().intent != command.fingerprint().map_err(refused)?
        || binding.batch().operation_id
            != recording_operation_id(&snapshot.admission.instance_ref, &observed.effect_id)
    {
        return Err(refused(
            "recording evidence differs from its admitted input, author or target",
        ));
    }
    Ok(OriginalRecording { binding, execution })
}
