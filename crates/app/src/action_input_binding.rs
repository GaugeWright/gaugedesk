//! Home-signed, body-free input mappings retained independently of erasure.
//! A verified mapping is evidence about bytes previously resolved from custody;
//! it grants neither payload access, command admission nor effect execution.
use crate::action_inputs::NativeActionInputCustody;
use gaugedesk_core::ids::PublicKey;
use gaugedesk_core::signature::{verify_signature, Signature, SigningKey};
use gaugedesk_store::{CommandRecordFact, Store};
use gaugedesk_whip_runtime::host_actions::action::ActionInput;
use serde::{Deserialize, Serialize};
use whipplescript_store::{effect_recovery::canonical_value, StoreError, StoreResult};

const KIND: &str = "native_action_input_binding_v1";
const KEY: &str = "retain";
const PROTOCOL: &str = "gaugedesk.action-input-binding.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Statement {
    protocol: String,
    issuer: String,
    home: String,
    input: ActionInput,
    content_hash: String,
}
impl Statement {
    fn signing_bytes(&self) -> StoreResult<Vec<u8>> {
        let mut bytes = b"gaugedesk:action-input-binding:v1\0".to_vec();
        bytes.extend(serde_json::to_vec(&canonical_value(
            &serde_json::to_value(self)?,
        ))?);
        Ok(bytes)
    }
    fn snapshot(&self, key: &PublicKey) -> StoreResult<String> {
        Ok(serde_json::to_string(&canonical_value(
            &serde_json::json!([self, key.as_str()]),
        ))?)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedBinding {
    statement: Statement,
    signature: Vec<u8>,
}

/// Constructed only after verifying the retained Home attestation and original
/// record receipt. The body can be erased while this metadata remains useful.
pub(crate) struct NativeInputBinding {
    statement: Statement,
}
impl NativeInputBinding {
    pub(crate) fn input(&self) -> &ActionInput {
        &self.statement.input
    }
    pub(crate) fn content_hash(&self) -> &str {
        &self.statement.content_hash
    }
}
fn refused(message: impl std::fmt::Debug) -> StoreError {
    StoreError::Conflict(format!("native input binding refused: {message:?}"))
}

pub(crate) fn input_binding_scope(issuer: &str, input: &ActionInput) -> StoreResult<String> {
    if [issuer, &input.handle, &input.version_ref, &input.label_ref]
        .iter()
        .any(|value| value.trim().is_empty())
    {
        return Err(refused("incomplete binding coordinates"));
    }
    Ok(format!(
        "native-input-binding:{}",
        serde_json::to_string(&canonical_value(&serde_json::json!([issuer, input])))?
    ))
}

/// A missing original mapping stays missing. Reading it never resolves a body,
/// prepares an attestation, repairs a receipt or appends product evidence.
/// The caller reads this inside its declared product read snapshot.
pub(crate) fn load_input_binding(
    product: &Store,
    issuer: &str,
    home: &str,
    input: &ActionInput,
    key: &PublicKey,
) -> StoreResult<Option<NativeInputBinding>> {
    let scope = input_binding_scope(issuer, input)?;
    let records = product.records(&scope, KIND).map_err(refused)?;
    let snapshot = product
        .committed_record_snapshot(&scope, KEY)
        .map_err(refused)?;
    let record = match (records.as_slice(), snapshot) {
        ([], None) => return Ok(None),
        ([record], Some(snapshot)) => (record, snapshot),
        _ => {
            return Err(refused(
                "mapping requires one original fact and its receipt",
            ))
        }
    };
    let signed: SignedBinding = serde_json::from_str(record.0)?;
    let statement = &signed.statement;
    if statement.protocol != PROTOCOL
        || statement.issuer != issuer
        || statement.home != home
        || &statement.input != input
        || statement.content_hash.len() != 32
        || !statement
            .content_hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || statement.snapshot(key)? != record.1
        || !verify_signature(
            &statement.signing_bytes()?,
            &Signature::new(signed.signature.as_slice()),
            key,
        )
        .unwrap_or(false)
    {
        return Err(refused(
            "mapping differs from its original Home attestation",
        ));
    }
    Ok(Some(NativeInputBinding {
        statement: signed.statement,
    }))
}

/// Prepare from actual custody under its erasure exclusion. Signature randomness
/// is not command meaning: races and replay use the original receipted statement.
/// This is internal preparation, independently checked before action admission.
pub(crate) fn retain_input_binding(
    product: &mut Store,
    inputs: &NativeActionInputCustody,
    issuer: &str,
    home: &str,
    input: &ActionInput,
    key: &SigningKey,
) -> StoreResult<NativeInputBinding> {
    if inputs.authority_scope() != home || home.trim().is_empty() {
        return Err(refused("input custody belongs to another Home"));
    }
    inputs.with_resolved(input, |resolved| {
        let statement = Statement {
            protocol: PROTOCOL.into(),
            issuer: issuer.into(),
            home: home.into(),
            input: input.clone(),
            content_hash: resolved.content_hash.clone(),
        };
        let public = key.public_key();
        if let Some(previous) = read_retained_snapshot(product, issuer, home, input, &public)? {
            if previous.statement != statement {
                return Err(refused("input mapping changed meaning"));
            }
            return Ok(previous);
        }
        let signed = SignedBinding {
            signature: key.sign(&statement.signing_bytes()?).as_bytes().to_vec(),
            statement,
        };
        let scope = input_binding_scope(issuer, input)?;
        product
            .admit_record_facts(
                &scope,
                KEY,
                &signed.statement.snapshot(&public)?,
                &[CommandRecordFact {
                    scope_id: scope.clone(),
                    kind: KIND.into(),
                    payload: serde_json::to_string(&signed)?,
                }],
            )
            .map_err(refused)?;
        let retained = read_retained_snapshot(product, issuer, home, input, &public)?
            .ok_or_else(|| refused("input mapping was not retained"))?;
        if retained.statement != signed.statement {
            return Err(refused("input mapping winner changed meaning"));
        }
        Ok(retained)
    })
}

// Preparation can race another preparer. Observe the fact and receipt from one
// transaction; a commit between two independent reads is not corrupt evidence.
fn read_retained_snapshot(
    product: &Store,
    issuer: &str,
    home: &str,
    input: &ActionInput,
    key: &PublicKey,
) -> StoreResult<Option<NativeInputBinding>> {
    let scope = input_binding_scope(issuer, input)?;
    product
        .read_for_dispatch(&[&scope], |store| {
            Ok(load_input_binding(store, issuer, home, input, key))
        })
        .map_err(refused)?
        .0
}

#[cfg(test)]
#[path = "action_input_binding_tests.rs"]
mod tests;
