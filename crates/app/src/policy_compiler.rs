//! GaugeDesk product facts compiled into WhippleScript's governance policy.
//!
//! GaugeDesk owns the inputs and epoch lifecycle; WhippleScript owns the schema,
//! canonicalization, signature bytes, and enforcement.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use gaugedesk_core::abac::{
    permitted_with_policy, Action, AuthorityAttributes, Classification, Context, Decision, Policy,
};
use gaugedesk_core::resource::ResourceRecord;
use gaugedesk_whip_runtime::{
    sign_policy_envelope, HostGovernancePolicy, ProviderBindingPolicy, ResourcePolicy,
    WhipplePlacementPolicy,
};

use crate::library::RecordOp;
use crate::Workbench;

const POLICY_RECORD_KIND: &str = "whip_policy_epoch";
const POLICY_RECORD_ID: &str = "active";
pub(crate) const PROVIDER_BINDING_HANDLE: &str = "model";
pub(crate) const PLACEMENT_HANDLE: &str = "local";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PolicyCompilationInput {
    pub chat_id: String,
    pub project_id: Option<String>,
    pub actor: String,
    pub actor_attributes: AuthorityAttributes,
    pub org_policy: Policy,
    pub turn_purpose: Option<String>,
    pub package_capabilities: BTreeSet<String>,
    pub provider: String,
    pub model: String,
    pub base_url: String,
    pub credential_ref: String,
    pub placement_kind: String,
    pub command_network: bool,
    pub resources: Vec<ResourceRecord>,
    /// The operator's auto-keep scopes (ATTN-3), declared into the envelope as
    /// the [`crate::advancement::OPERATOR_WRITES_GUARANTEE`] dynamic guarantee
    /// (ADR 0082 §5, WhippleScript DR-0036). Empty = nothing declared.
    pub advancement_scopes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompiledPolicyEpoch {
    pub epoch: u64,
    pub signed_envelope: String,
    pub provider_binding_ref: String,
    pub credential_ref: String,
    pub placement_ceiling_ref: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct PolicyEpochRecord {
    id: String,
    #[serde(default)]
    op: RecordOp,
    epoch: u64,
    unsigned_policy: String,
    signed_envelope: String,
}

impl Workbench {
    /// Compile live product decisions and publish a new immutable epoch only
    /// when their canonical WhippleScript document changes.
    pub(crate) fn compile_whipple_policy(
        &mut self,
        input: PolicyCompilationInput,
    ) -> Result<CompiledPolicyEpoch, String> {
        let policy = compile_policy(&input)?;
        let unsigned_policy = declare_guarantees(policy.to_json()?, &input.advancement_scopes)?;
        let previous = latest_epoch(self, &input.chat_id)?;
        let record = match previous {
            Some(previous) if previous.unsigned_policy == unsigned_policy => previous,
            previous => {
                let epoch = previous.map_or(1, |record| record.epoch.saturating_add(1));
                if epoch == 0 {
                    return Err("WhippleScript policy epoch overflowed".to_owned());
                }
                let signing_key =
                    gaugedesk_core::signature::SigningKey::from_seed(&self.governance_seed())
                        .map_err(|error| error.reason)?;
                let signed_envelope =
                    sign_policy_envelope(&unsigned_policy, self.authority(), &signing_key)?;
                let record = PolicyEpochRecord {
                    id: POLICY_RECORD_ID.to_owned(),
                    op: RecordOp::Upsert,
                    epoch,
                    unsigned_policy,
                    signed_envelope,
                };
                self.store
                    .append_record(
                        &input.chat_id,
                        POLICY_RECORD_KIND,
                        &serde_json::to_string(&record).map_err(|error| error.to_string())?,
                    )
                    .map_err(|error| format!("{error:?}"))?;
                record
            }
        };
        Ok(CompiledPolicyEpoch {
            epoch: record.epoch,
            signed_envelope: record.signed_envelope,
            provider_binding_ref: PROVIDER_BINDING_HANDLE.to_owned(),
            credential_ref: input.credential_ref,
            placement_ceiling_ref: PLACEMENT_HANDLE.to_owned(),
        })
    }

    pub(crate) fn latest_whipple_policy(
        &self,
        chat_id: &str,
    ) -> Result<Option<(u64, String)>, String> {
        latest_epoch(self, chat_id)
            .map(|record| record.map(|record| (record.epoch, record.signed_envelope)))
    }
}

/// Declare the operator's auto-keep scopes as a dynamic envelope guarantee
/// (DR-0036 §2: `{"guarantees":[{"name","paths"}]}` — WhippleScript owns the
/// schema and evaluation; GaugeDesk only composes the declaration). A runtime
/// predating DR-0036 ignores the key (its parser reads known keys only), so
/// declaring is forward-compatible; the report's dynamic section appears once
/// the runtime evaluates it. No scopes → the envelope is untouched, so
/// existing epochs stay hash-stable.
fn declare_guarantees(unsigned_policy: String, scopes: &[String]) -> Result<String, String> {
    if scopes.is_empty() {
        return Ok(unsigned_policy);
    }
    let mut value: serde_json::Value =
        serde_json::from_str(&unsigned_policy).map_err(|error| error.to_string())?;
    value["guarantees"] = serde_json::json!([{
        "name": crate::advancement::OPERATOR_WRITES_GUARANTEE,
        "paths": scopes,
    }]);
    serde_json::to_string(&value).map_err(|error| error.to_string())
}

fn latest_epoch(wb: &Workbench, chat_id: &str) -> Result<Option<PolicyEpochRecord>, String> {
    let mut latest = None;
    for body in wb
        .store
        .records(chat_id, POLICY_RECORD_KIND)
        .map_err(|error| format!("{error:?}"))?
    {
        let record: PolicyEpochRecord =
            serde_json::from_str(&body).map_err(|error| error.to_string())?;
        latest = match record.op {
            RecordOp::Upsert => Some(record),
            RecordOp::Tombstone => None,
        };
    }
    Ok(latest)
}

fn compile_policy(input: &PolicyCompilationInput) -> Result<HostGovernancePolicy, String> {
    require_nonempty("chat id", &input.chat_id)?;
    require_nonempty("actor", &input.actor)?;
    require_nonempty("provider", &input.provider)?;
    require_nonempty("model", &input.model)?;
    require_nonempty("provider base URL", &input.base_url)?;
    require_nonempty("credential reference", &input.credential_ref)?;
    require_nonempty("placement kind", &input.placement_kind)?;

    let actor_role = authority_role(&input.actor);
    let active_resources = input
        .resources
        .iter()
        .filter(|record| !record.tombstoned)
        .collect::<Vec<_>>();
    for record in &active_resources {
        if !permitted_with_policy(
            true,
            &input.org_policy,
            &Decision {
                actor: input.actor_attributes.clone(),
                resource: record.attributes.clone(),
                action: Action::Run,
                context: Context {
                    // A remote host is not automatically an attested host.
                    // Cloudflare DO is hosted/unattested; only the explicit
                    // confidential-compute placement may raise this ceiling.
                    ceiling_attested: input.placement_kind == "attested",
                },
            },
        ) {
            return Err(format!(
                "organization policy denies runtime access to resource `{}`",
                record.resource.id.as_str()
            ));
        }
        if !record.attributes.purpose.is_empty()
            && input.turn_purpose.as_ref().is_none_or(|purpose| {
                !record
                    .attributes
                    .purpose
                    .iter()
                    .any(|allowed| allowed.as_str() == purpose)
            })
        {
            return Err(format!(
                "resource `{}` requires an admitted run purpose ({})",
                record.resource.id.as_str(),
                record
                    .attributes
                    .purpose
                    .iter()
                    .map(|purpose| purpose.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }

    let mut workspace_readers = BTreeSet::new();
    for record in &active_resources {
        workspace_readers.extend(resource_reader_roles(record));
    }
    if workspace_readers.is_empty() {
        workspace_readers.insert(actor_role.clone());
    }
    let labeled = |principal| ResourcePolicy {
        reader: workspace_readers.clone(),
        writer: BTreeSet::from([actor_role.clone()]),
        principal,
        internal: false,
    };
    let provider_address = format!(
        "provider:{}:{}",
        input.provider,
        short_hash(&format!("{}\0{}", input.model, input.base_url))
    );
    let placement_address = format!(
        "placement:{}:{}",
        input.placement_kind,
        input.project_id.as_deref().unwrap_or("personal")
    );
    let mut policy = HostGovernancePolicy {
        resources: BTreeMap::from([
            (format!("file:workspace:{}", input.chat_id), labeled(false)),
            (
                format!("memory:turn-images:{}", input.chat_id),
                labeled(false),
            ),
            (
                format!("command:workspace:{}", input.chat_id),
                labeled(true),
            ),
            (format!("human:{}", input.actor), labeled(true)),
            (provider_address.clone(), labeled(true)),
            ("provider:owned".to_owned(), labeled(true)),
            (placement_address.clone(), labeled(true)),
        ]),
        bindings: BTreeMap::from([
            (
                "project".to_owned(),
                format!("file:workspace:{}", input.chat_id),
            ),
            (
                "turn_images".to_owned(),
                format!("memory:turn-images:{}", input.chat_id),
            ),
            (
                "command".to_owned(),
                format!("command:workspace:{}", input.chat_id),
            ),
            ("human".to_owned(), format!("human:{}", input.actor)),
            (PROVIDER_BINDING_HANDLE.to_owned(), provider_address),
            ("owned".to_owned(), "provider:owned".to_owned()),
            (PLACEMENT_HANDLE.to_owned(), placement_address),
        ]),
        parties: BTreeMap::from([(input.actor.clone(), actor_role.clone())]),
        capabilities: input.package_capabilities.clone(),
        provider_bindings: BTreeMap::from([(
            PROVIDER_BINDING_HANDLE.to_owned(),
            ProviderBindingPolicy {
                provider: input.provider.clone(),
                model: input.model.clone(),
                base_url: input.base_url.clone(),
                credential_ref: input.credential_ref.clone(),
            },
        )]),
        placements: BTreeMap::from([(
            PLACEMENT_HANDLE.to_owned(),
            WhipplePlacementPolicy {
                kind: input.placement_kind.clone(),
                provider_bindings: BTreeSet::from([PROVIDER_BINDING_HANDLE.to_owned()]),
                command_network: input.command_network,
            },
        )]),
        ..HostGovernancePolicy::default()
    };

    for record in active_resources {
        let id = record.resource.id.as_str();
        let address = format!("gaugedesk:resource:{id}");
        let handle = format!("resource:{id}");
        let reader = resource_reader_roles(record);
        for authority in &record.stakeholders {
            policy
                .parties
                .entry(authority.as_str().to_owned())
                .or_insert_with(|| authority_role(authority.as_str()));
        }
        let writer_role = authority_role(record.resource.owner.as_str());
        policy
            .parties
            .entry(record.resource.owner.as_str().to_owned())
            .or_insert_with(|| writer_role.clone());
        policy.resources.insert(
            address.clone(),
            ResourcePolicy {
                reader,
                writer: BTreeSet::from([writer_role]),
                principal: false,
                internal: false,
            },
        );
        policy.bindings.insert(handle, address);
    }
    let mut clearances = BTreeSet::new();
    clearances.insert("classification:public".to_owned());
    // The role floor, not the raw claim: an IdP that asserts no clearance leaves
    // `Clearance::default()`, which clears only `public`, while an unlabeled
    // resource is fail-closed `Regulated` — so the default actor could not read
    // the default resource and an agent turn over an ordinary project was
    // refused for a reason nobody chose. See `Clearance::implied_by`.
    let clearance = input.actor_attributes.effective_clearance();
    for (level, name) in [
        (1, "classification:internal"),
        (2, "classification:pii"),
        (3, "classification:regulated"),
    ] {
        if clearance.0 >= level {
            clearances.insert(name.to_owned());
        }
    }
    clearances.extend(
        input
            .actor_attributes
            .roles
            .iter()
            .map(|role| format!("role:{}", role.as_str())),
    );
    if let Some(region) = &input.actor_attributes.region {
        clearances.insert(format!("residency:{}", region.as_str()));
    }
    if let Some(purpose) = &input.turn_purpose {
        clearances.insert(format!("purpose:{purpose}"));
    }
    // A granted GaugeDesk resource-access decision explicitly clears this actor
    // for the stakeholder compartments on the resources handed to the runtime.
    for record in &input.resources {
        clearances.extend(
            record
                .stakeholders
                .iter()
                .map(|authority| authority_role(authority.as_str())),
        );
    }
    policy.delegations.extend(
        clearances
            .into_iter()
            .filter(|clearance| clearance != &actor_role)
            .map(|clearance| [actor_role.clone(), clearance]),
    );
    policy.validate()?;
    Ok(policy)
}

fn resource_reader_roles(record: &ResourceRecord) -> BTreeSet<String> {
    let mut roles = record
        .stakeholders
        .iter()
        .map(|authority| authority_role(authority.as_str()))
        .collect::<BTreeSet<_>>();
    roles.insert(format!(
        "classification:{}",
        match record.attributes.classification {
            Classification::Public => "public",
            Classification::Internal => "internal",
            Classification::Pii => "pii",
            Classification::Regulated => "regulated",
        }
    ));
    if let Some(region) = &record.attributes.region {
        roles.insert(format!("residency:{}", region.as_str()));
    }
    roles.extend(
        record
            .attributes
            .purpose
            .iter()
            .map(|purpose| format!("purpose:{}", purpose.as_str())),
    );
    roles
}

fn authority_role(authority: &str) -> String {
    format!("authority:{}", short_hash(authority))
}

fn short_hash(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))[..24].to_owned()
}

fn require_nonempty(what: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{what} must not be empty"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gaugedesk_core::boundary::Authority;
    use gaugedesk_core::resource::{ContentLocator, Resource, ResourceId, ResourceKind};
    use gaugedesk_store::Store;

    fn input() -> PolicyCompilationInput {
        PolicyCompilationInput {
            chat_id: "chat-1".to_owned(),
            project_id: Some("project-1".to_owned()),
            actor: "operator-1".to_owned(),
            actor_attributes: AuthorityAttributes {
                clearance: gaugedesk_core::abac::Clearance(3),
                ..AuthorityAttributes::default()
            },
            org_policy: Policy::default(),
            turn_purpose: None,
            package_capabilities: BTreeSet::from([
                "workspace.read".to_owned(),
                "workspace.write".to_owned(),
            ]),
            provider: "openai".to_owned(),
            model: "gpt-5".to_owned(),
            base_url: "https://api.openai.com".to_owned(),
            credential_ref: "gaugedesk:credential:account:openai".to_owned(),
            placement_kind: "local".to_owned(),
            command_network: false,
            resources: Vec::new(),
            advancement_scopes: Vec::new(),
        }
    }

    /// The envelope an OIDC actor gets when the IdP asserts no clearance.
    ///
    /// This is the production case: the wiring canary's owner authenticated
    /// through OIDC, whose claims carry no clearance, so the compiled epoch
    /// cleared only `classification:public` while the project it owned was
    /// unlabeled — therefore fail-closed `Regulated` — and the agent turn was
    /// denied `denied read in rule \`converse\``. The role is the authorization
    /// fact the directory carries, so it supplies the floor.
    #[test]
    fn an_owner_clears_regulated_without_a_clearance_claim() {
        let mut owner = input();
        owner.actor_attributes = AuthorityAttributes {
            clearance: gaugedesk_core::abac::Clearance(0),
            roles: BTreeSet::from([gaugedesk_core::abac::Role::owner()]),
            ..AuthorityAttributes::default()
        };
        let epoch = compile_policy(&owner)
            .expect("policy")
            .to_json()
            .expect("json");
        for level in ["public", "internal", "pii", "regulated"] {
            assert!(
                epoch.contains(&format!("classification:{level}")),
                "an owner must clear {level}: {epoch}",
            );
        }

        // A billing-only authority is never run/access authority (INV-18), so
        // the floor lifts it no further than the fail-closed default.
        let mut billing = input();
        billing.actor_attributes = AuthorityAttributes {
            clearance: gaugedesk_core::abac::Clearance(0),
            roles: BTreeSet::from([gaugedesk_core::abac::Role::billing()]),
            ..AuthorityAttributes::default()
        };
        let epoch = compile_policy(&billing)
            .expect("policy")
            .to_json()
            .expect("json");
        assert!(epoch.contains("classification:public"), "{epoch}");
        assert!(
            !epoch.contains("classification:regulated"),
            "billing must not reach regulated: {epoch}",
        );
    }

    #[test]
    fn auto_keep_scopes_declare_the_operator_guarantee() {
        // No scopes → the envelope is untouched (existing epochs hash-stable).
        let bare = compile_policy(&input())
            .expect("policy")
            .to_json()
            .expect("json");
        assert_eq!(declare_guarantees(bare.clone(), &[]).expect("noop"), bare);

        // Scopes → one declared guarantee under the stable operator name.
        let declared =
            declare_guarantees(bare, &["docs/**".to_owned(), "*.md".to_owned()]).expect("declare");
        let value: serde_json::Value = serde_json::from_str(&declared).expect("parse");
        assert_eq!(
            value["guarantees"],
            serde_json::json!([{
                "name": crate::advancement::OPERATOR_WRITES_GUARANTEE,
                "paths": ["docs/**", "*.md"],
            }])
        );
    }

    #[test]
    fn compilation_binds_product_authority_package_provider_and_placement() {
        let policy = compile_policy(&input()).expect("policy");
        let expected_role = authority_role("operator-1");
        assert_eq!(
            policy.parties.get("operator-1").map(String::as_str),
            Some(expected_role.as_str())
        );
        assert!(policy.capabilities.contains("workspace.write"));
        assert_eq!(
            policy
                .provider_bindings
                .get(PROVIDER_BINDING_HANDLE)
                .map(|binding| binding.credential_ref.as_str()),
            Some("gaugedesk:credential:account:openai")
        );
        assert!(policy
            .placements
            .get(PLACEMENT_HANDLE)
            .is_some_and(|placement| !placement.command_network));
    }

    #[test]
    fn compilation_projects_real_resource_stakeholders_into_reader_labels() {
        let resource = Resource::input(
            ResourceId::new("customer-data"),
            ResourceKind::context(),
            Authority::from("client"),
        );
        let record = ResourceRecord::new(
            resource,
            ContentLocator::Content {
                handle: "content-1".to_owned(),
            },
            |_| Authority::from("client"),
        );
        let mut input = input();
        input.resources.push(record);
        let policy = compile_policy(&input).expect("policy");
        let label = policy
            .resources
            .get("gaugedesk:resource:customer-data")
            .expect("resource label");
        assert!(label.reader.contains(&authority_role("client")));
        assert!(label.reader.contains("classification:regulated"));
        assert!(policy
            .resources
            .get("file:workspace:chat-1")
            .is_some_and(|workspace| workspace.reader == label.reader));
        assert!(policy
            .delegations
            .contains(&[authority_role("operator-1"), authority_role("client")]));
        assert_eq!(
            policy.bindings.get("resource:customer-data"),
            Some(&"gaugedesk:resource:customer-data".to_owned())
        );
    }

    #[test]
    fn purpose_constrained_resource_fails_closed_without_an_admitted_run_purpose() {
        let resource = Resource::input(
            ResourceId::new("customer-data"),
            ResourceKind::context(),
            Authority::from("client"),
        );
        let record = ResourceRecord::new(
            resource,
            ContentLocator::Content {
                handle: "content-1".to_owned(),
            },
            |_| Authority::from("client"),
        )
        .with_attributes(gaugedesk_core::abac::ResourceAttributes {
            purpose: BTreeSet::from([gaugedesk_core::abac::Purpose::new("support")]),
            ..Default::default()
        });
        let mut input = input();
        input.resources.push(record);
        assert!(compile_policy(&input)
            .expect_err("missing purpose decision must deny")
            .contains("requires an admitted run purpose"));
        input.turn_purpose = Some("support".to_owned());
        assert!(compile_policy(&input).is_ok());
    }

    #[test]
    fn unchanged_facts_reuse_epoch_and_changed_facts_publish_the_next_epoch() {
        let mut wb = Workbench::new(Store::open_in_memory().expect("store"));
        let first = wb.compile_whipple_policy(input()).expect("first epoch");
        let same = wb.compile_whipple_policy(input()).expect("same epoch");
        assert_eq!(same.epoch, first.epoch);
        assert_eq!(same.signed_envelope, first.signed_envelope);

        let mut changed = input();
        changed.model = "gpt-5.1".to_owned();
        let next = wb.compile_whipple_policy(changed).expect("next epoch");
        assert_eq!(next.epoch, first.epoch + 1);
        assert_ne!(next.signed_envelope, first.signed_envelope);
        assert!(!next.signed_envelope.contains("sk-secret"));
        assert_eq!(
            wb.latest_whipple_policy("chat-1")
                .expect("latest")
                .map(|(epoch, _)| epoch),
            Some(next.epoch)
        );
    }
}
