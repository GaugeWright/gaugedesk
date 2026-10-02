//! A bridge grant — the durable record that lets a source authority's run reach
//! a target environment over a governed route, bound to a device key
//! (D-REMOTE / ADR 0009).
//!
//! The grant carries the source authority's root key and the key id that selects
//! the governance subkey it was issued under, plus the device key the bridge
//! call must present. Validity is a pure predicate over the grant and a caller-
//! supplied clock — the imperative shell materializes `now`; the core decides.

use crate::ids::{BridgeGrantId, KeyId, PublicKey};

/// A governed bridge grant: source authority → target environment/route, bound
/// to a device key and a governance scope, with an expiry and an active flag.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BridgeGrant {
    /// Stable identifier for this grant.
    pub id: BridgeGrantId,
    /// The root identity key of the source authority that issued the grant.
    pub source_authority_root_pubkey: PublicKey,
    /// Selects which governance subkey of the source authority signed the grant.
    pub source_authority_key_id: KeyId,
    /// The environment the grant authorizes reaching.
    pub target_environment: String,
    /// The route within the target environment the grant authorizes.
    pub target_route: String,
    /// The device key a bridge call must present to use this grant.
    pub device_key: PublicKey,
    /// The governance scope the grant was issued under.
    pub governance_scope: String,
    /// The clock value at and after which the grant is no longer valid.
    pub expiry: u64,
    /// Whether the grant is currently active (not revoked).
    pub active: bool,
}

impl BridgeGrant {
    /// Whether the grant is usable at `now`: active and not yet expired.
    pub fn is_valid(&self, now: u64) -> bool {
        self.active && now < self.expiry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_grant() -> BridgeGrant {
        BridgeGrant {
            id: BridgeGrantId::new("grant-1"),
            source_authority_root_pubkey: PublicKey::new("04a1b2c3d4e5f6"),
            source_authority_key_id: KeyId::new("gov-1"),
            target_environment: "prod".into(),
            target_route: "/v1/agent".into(),
            device_key: PublicKey::new("04ffeeddccbbaa"),
            governance_scope: "bridge:invoke".into(),
            expiry: 100,
            active: true,
        }
    }

    /// Complete 18-case guard domain from bridge-grant-admission.qnt.
    #[test]
    fn crypto_model_domain_bridge_grant() {
        for active in [false, true] {
            for expiry in 0..=2 {
                let mut grant = sample_grant();
                grant.active = active;
                grant.expiry = expiry;
                for now in 0..=2 {
                    let expected = active && matches!((now, expiry), (0, 1) | (0, 2) | (1, 2));
                    assert_eq!(grant.is_valid(now), expected);
                }
            }
        }
    }

    #[test]
    fn is_valid_respects_expiry() {
        let grant = sample_grant();
        assert!(grant.is_valid(50));
        assert!(!grant.is_valid(200));
    }

    #[test]
    fn bridge_grant_serde_round_trip() {
        let grant = sample_grant();

        let mut bytes = Vec::new();
        ciborium::into_writer(&grant, &mut bytes).unwrap();
        let restored: BridgeGrant = ciborium::from_reader(bytes.as_slice()).unwrap();

        assert_eq!(restored.id, grant.id);
        assert_eq!(
            restored.source_authority_root_pubkey,
            grant.source_authority_root_pubkey
        );
        assert_eq!(
            restored.source_authority_key_id,
            grant.source_authority_key_id
        );
        assert_eq!(restored.target_environment, grant.target_environment);
        assert_eq!(restored.target_route, grant.target_route);
        assert_eq!(restored.device_key, grant.device_key);
        assert_eq!(restored.governance_scope, grant.governance_scope);
        assert_eq!(restored.expiry, grant.expiry);
        assert_eq!(restored.active, grant.active);
    }
}
