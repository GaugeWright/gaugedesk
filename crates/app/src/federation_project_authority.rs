//! WS-673: exact project signing custody on authenticated handoff carriage.
use super::*;

const FORMAT: &str = "gaugedesk.project-authority-capsule.v1";

/// Only public bindings and recipient ciphertext can cross the wire or log.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Capsule {
    format: String,
    project: String,
    authority: AuthorityId,
    public_key: PublicKey,
    recipient: PublicKey,
    sealed: SealedKey,
}

fn context(capsule: &Capsule) -> std::io::Result<Vec<u8>> {
    serde_json::to_vec(&(
        &capsule.format,
        &capsule.project,
        &capsule.authority,
        &capsule.public_key,
        &capsule.recipient,
    ))
    .map_err(std::io::Error::other)
}

pub(super) fn prepare(
    wb: &Workbench,
    project: &str,
    peer: &str,
    recipient: &PublicKey,
) -> std::io::Result<Option<Capsule>> {
    workflow_keys::check_recipient(wb, peer, recipient)?;
    if wb
        .store_ref()
        .project_authority_key(project)
        .map_err(std::io::Error::other)?
        .is_none()
    {
        return Ok(None); // Historical projects retain their original issuer.
    }
    let key = wb.project_signing_key(project)?;
    let public_key = key.public_key();
    let mut capsule = Capsule {
        format: FORMAT.into(),
        project: project.into(),
        authority: crate::project_authority::authority(&public_key),
        public_key,
        recipient: recipient.clone(),
        sealed: SealedKey {
            ephemeral_pubkey: String::new(),
            ciphertext: String::new(),
        },
    };
    // The encrypted context prevents a credential/device capsule from being
    // substituted even though carriage uses the existing ECIES primitive.
    let mut plaintext = Sha256::digest(context(&capsule)?).to_vec();
    plaintext.extend(key.to_seed_bytes());
    capsule.sealed = seal_to_subkey(recipient, &plaintext)
        .ok_or_else(|| std::io::Error::other("could not seal project authority to recipient"))?;
    Ok(Some(capsule))
}

pub(super) fn validate(wire: &HandoffWire) -> Result<(), &'static str> {
    for record in wire
        .log
        .iter()
        .filter(|record| record.kind == "host_action_policy_v1")
    {
        let policy: serde_json::Value = serde_json::from_str(&record.payload)
            .map_err(|_| "incoming project policy is malformed")?;
        if policy["identity"]["issuer"]
            .as_str()
            .is_some_and(|issuer| issuer.starts_with("project:"))
            && wire.project_authority.is_none()
        {
            return Err("project-signed policy requires signing custody on handoff");
        }
    }
    match (&wire.project_authority, wire.kind) {
        (Some(capsule), HandoffMsgKind::OfferWithProjectAuthority)
            if capsule.format == FORMAT
                && capsule.project == wire.project
                && capsule.authority
                    == crate::project_authority::authority(&capsule.public_key) =>
        {
            Ok(())
        }
        (None, HandoffMsgKind::OfferWithProjectAuthority) => {
            Err("project authority offer is missing its signing custody")
        }
        (Some(_), _) => {
            Err("project authority capsule requires its complete offer kind and binding")
        }
        (None, _) => Ok(()),
    }
}

pub(super) fn signed_bytes(wire: &HandoffWire) -> std::io::Result<Vec<u8>> {
    if wire.kind != HandoffMsgKind::OfferWithProjectAuthority {
        return Ok(handoff_bytes(&wire.project, &wire.source_home));
    }
    let state = serde_json::to_vec(&(
        "gaugedesk.authority-handoff-offer.v1",
        wire.kind,
        &wire.project,
        &wire.source,
        &wire.target,
        &wire.source_home,
        &wire.log,
        &wire.project_commands,
        &wire.content,
        &wire.credential_key,
        &wire.project_authority,
    ))
    .map_err(std::io::Error::other)?;
    // Retain only the signed commitment on the wire, not a second copy of
    // every workspace's content bytes.
    Ok(format!(
        "gaugedesk.authority-handoff-offer.v1:{}",
        hex::encode(Sha256::digest(state))
    )
    .into_bytes())
}

pub(super) fn receive(
    wb: &mut Workbench,
    wire: &HandoffWire,
    recovery: bool,
) -> std::io::Result<()> {
    validate(wire).map_err(std::io::Error::other)?;
    let Some(capsule) = &wire.project_authority else {
        if wb
            .store_ref()
            .project_authority_key(&wire.project)
            .map_err(std::io::Error::other)?
            .is_some()
        {
            return Err(std::io::Error::other(
                "incoming offer omits retained project authority",
            ));
        }
        return Ok(());
    };
    let recipient = federation_root_signing_key(wb);
    if recipient.public_key() != capsule.recipient {
        return Err(std::io::Error::other(
            "project authority capsule addresses another recipient",
        ));
    }
    let plaintext = open_sealed(&recipient, &capsule.sealed)
        .ok_or_else(|| std::io::Error::other("incoming project authority did not open"))?;
    let binding = Sha256::digest(context(capsule)?);
    if plaintext.len() != 64 || plaintext[..32] != binding[..] {
        return Err(std::io::Error::other(
            "incoming project authority context differs",
        ));
    }
    let seed: [u8; 32] = plaintext[32..].try_into().map_err(std::io::Error::other)?;
    let key = SigningKey::from_seed(&seed)
        .map_err(|_| std::io::Error::other("incoming project signing key is invalid"))?;
    if key.public_key() != capsule.public_key {
        return Err(std::io::Error::other(
            "incoming signing key differs from offered public authority",
        ));
    }
    wb.stage_project_authority(&wire.project, &key, recovery)
}
