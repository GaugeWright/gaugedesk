//! Descriptive domain identities — newtypes, never bare strings
//! (`principles.md` "Contracts at the boundary"). Parsing untyped input into
//! these happens at the imperative shell; the core then trusts the types, and
//! one identity cannot be passed where another is wanted.

/// An identity could not be parsed from untrusted input — it was empty. The
/// boundary rejects it (`INV-1`: every durable fact names a *non-null* authority
/// and scope) rather than minting a blank identity that later reads as "nobody".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmptyId;

impl std::fmt::Display for EmptyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("identity may not be empty")
    }
}
impl std::error::Error for EmptyId {}

macro_rules! id_newtype {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(
            Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord,
            serde::Serialize, serde::Deserialize,
        )]
        pub struct $name(String);

        impl $name {
            /// Construct from an already-validated string. Used by the pure core to
            /// replay values that were validated when they first entered (e.g. from
            /// the log); the **boundary** uses [`Self::parse`] on untrusted input.
            pub fn new(s: impl Into<String>) -> Self {
                Self(s.into())
            }
            /// Parse untrusted input at the imperative shell: a non-empty (after
            /// trimming) identity, else [`EmptyId`]. This is the validating gate the
            /// `new`/`From` brands deliberately lack, so a blank id cannot slip in
            /// and later satisfy a required-authority set as "nobody" (`INV-1`).
            pub fn parse(s: impl Into<String>) -> Result<Self, $crate::ids::EmptyId> {
                let s = s.into();
                if s.trim().is_empty() {
                    Err($crate::ids::EmptyId)
                } else {
                    Ok(Self(s))
                }
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl std::str::FromStr for $name {
            type Err = std::convert::Infallible;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(Self::new(s))
            }
        }

        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                Self::new(s)
            }
        }

        impl From<String> for $name {
            fn from(s: String) -> Self {
                Self(s)
            }
        }
    };
}

id_newtype!(
    /// The authority responsible for a durable fact (`INV-1`).
    AuthorityId
);
id_newtype!(
    /// The one authoritative Home that owns and admits a project's GaugeDesk
    /// log/content (`ADR 0084`). A Home is a durable service identity, never a
    /// browser session, process, VM, or runtime object id.
    HomeId
);
id_newtype!(
    /// A single-writer ordered event stream owned by one authority (ADR 0005).
    ScopeId
);
id_newtype!(
    /// One agent run — an episode of work (ADR 0026).
    RunId
);
id_newtype!(
    /// A durable conversation within an instance (ADR 0027).
    EngagementId
);
id_newtype!(
    /// A P-256 public key (hex-encoded SEC1 bytes) — the root identity key of an
    /// authority, or one of its governance subkeys (both use this same type;
    /// D-REMOTE / ADR 0009).
    PublicKey
);
id_newtype!(
    /// Names one key within an authority's keyset — selects which [`PublicKey`]
    /// (root or governance subkey) a signature or grant is bound to (D-REMOTE).
    KeyId
);
id_newtype!(
    /// A paired device — the mobile/desktop client a bridge grant binds its
    /// reachability to. One device is a single physical endpoint that presents a
    /// [`PublicKey`] device key; the id is the stable handle the boundary's
    /// `DeviceBinding` phase records so a revoked device cannot keep delivering
    /// (D-MOBILE / ADR 0009).
    DeviceId
);
id_newtype!(
    /// Stable identifier for a [`BridgeGrant`](crate::bridge_grant::BridgeGrant) —
    /// the typed handle a federated envelope/delivery carries so the target can
    /// bind the crossing to exactly the grant it was issued under, never a bare
    /// string (D-MOBILE / D-REMOTE / ADR 0009).
    BridgeGrantId
);
id_newtype!(
    /// A client's tag for one optimistic command — the handle the mobile
    /// projection client mints before it knows the authoritative outcome, so it
    /// can render the command immediately and then reconcile (drop the pending
    /// entry) once the run's authoritative effect is admitted (D-MOBILE / MOB-003).
    ClientRequestId
);
id_newtype!(
    /// A single-use anti-replay nonce a source stamps on a federated envelope —
    /// the typed handle the target tracks in its `seen_nonces` so a replayed
    /// envelope is rejected (`NONCE_NOT_REUSED`), never a bare string (CORE-7).
    Nonce
);

#[cfg(test)]
mod tests {
    use super::*;

    fn cbor_round_trip<T>(value: &T) -> T
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        let mut bytes = Vec::new();
        ciborium::into_writer(value, &mut bytes).unwrap();
        ciborium::from_reader(bytes.as_slice()).unwrap()
    }

    /// The federation identity newtypes round-trip through serde unchanged — the
    /// invariant the imperative shell relies on to ferry them through the log and
    /// over the wire (D-REMOTE / `INV-8`).
    #[test]
    fn authority_pubkey_keyid_serde_round_trip() {
        let authority = AuthorityId::new("did:gaugewright:acme");
        let home = HomeId::new("home:acme");
        let pubkey = PublicKey::new("04a1b2c3d4e5f6");
        let key_id = KeyId::new("root");

        assert_eq!(cbor_round_trip(&authority), authority);
        assert_eq!(cbor_round_trip(&home), home);
        assert_eq!(cbor_round_trip(&pubkey), pubkey);
        assert_eq!(cbor_round_trip(&key_id), key_id);
    }

    /// The D-MOBILE identity newtypes round-trip through serde unchanged — the
    /// device handle the boundary's `DeviceBinding` phase records and the typed
    /// grant id a delivery carries both ferry through the log and over the wire.
    #[test]
    fn device_and_bridge_grant_id_serde_round_trip() {
        let device = DeviceId::new("device:pixel-9");
        let grant = BridgeGrantId::new("grant-7");

        assert_eq!(cbor_round_trip(&device), device);
        assert_eq!(cbor_round_trip(&grant), grant);
        assert_eq!("device:pixel-9".parse::<DeviceId>().unwrap(), device);
        assert_eq!("grant-7".parse::<BridgeGrantId>().unwrap(), grant);
    }

    /// The optimistic-command tag round-trips unchanged — the client mints it,
    /// ferries it through the run log as `pending_commands`, and reconciles
    /// against it once the authoritative effect lands (D-MOBILE / MOB-003).
    #[test]
    fn client_request_id_serde_round_trip() {
        let rid = ClientRequestId::new("req:42");
        assert_eq!(cbor_round_trip(&rid), rid);
        assert_eq!("req:42".parse::<ClientRequestId>().unwrap(), rid);
        assert_eq!(rid.to_string(), "req:42");
    }

    /// `parse` is the boundary's validating gate: it rejects empty/whitespace
    /// input (so a blank authority/scope can never enter, `INV-1`) but accepts any
    /// non-empty value, round-tripping like `new`.
    #[test]
    fn parse_rejects_empty_accepts_nonempty() {
        assert!(AuthorityId::parse("").is_err());
        assert!(AuthorityId::parse("   ").is_err());
        assert_eq!(
            AuthorityId::parse("did:gaugewright:acme").unwrap(),
            AuthorityId::new("did:gaugewright:acme")
        );
        assert!(ScopeId::parse("scope-1").is_ok());
    }

    /// Display and FromStr are inverses for these identities.
    #[test]
    fn display_fromstr_inverse() {
        let authority = AuthorityId::new("did:gaugewright:acme");
        assert_eq!(authority.to_string(), "did:gaugewright:acme");
        assert_eq!(
            "did:gaugewright:acme".parse::<AuthorityId>().unwrap(),
            authority
        );
        assert_eq!("root".parse::<KeyId>().unwrap(), KeyId::new("root"));
    }
}
