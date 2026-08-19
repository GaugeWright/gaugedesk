//! The enterprise **login fold** (ADR 0122 §3): what this composition does with
//! a verified login *beyond* the session itself.
//!
//! The auth shell verifies identity and mints the session; folding the
//! authenticated subject into **org membership** is an enterprise concern and
//! stays in this band, registered into the shell's
//! [`AuthShellState`](crate::auth_oidc::AuthShellState) as its
//! [`LoginFold`](crate::auth_oidc::LoginFold) hook by the route builder. A
//! composition without a fold (the solo desktop, a private Home) gets a login
//! with no membership consequences — exactly the consumer contract.

use gaugedesk_app::org::{MembershipRecord, MembershipStatus, Org, RecordOp, ORG_ID};
use gaugedesk_app::Workbench;

use crate::auth_oidc::LoginFold;

/// The hosted/enterprise fold: verified-domain JIT membership (`ONB-2`).
pub fn hub_login_fold() -> LoginFold {
    std::sync::Arc::new(|wb, scope, authority, id_token| {
        jit_provision(wb, scope, authority, id_token);
    })
}

/// Extract the `email` claim from an **already-verified** id-token (the caller verified
/// signature + claims via the shell's callback) — used only for JIT domain matching, so
/// decoding the payload without re-checking the signature is safe here. `None` if the
/// token has no readable `email`, **or** if the IdP did not assert `email_verified:true`:
/// JIT auto-join into a verified org domain must never trust an unverified address (a
/// federated IdP could otherwise assert any in-domain email). Such users are instead
/// invited or SCIM-provisioned (fail-closed, `INV-20`).
fn email_claim(id_token: &str) -> Option<String> {
    use base64::Engine as _;
    let payload = id_token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    if claims.get("email_verified").and_then(|v| v.as_bool()) != Some(true) {
        return None; // unverified (or absent) ⇒ no JIT domain trust (fail-closed)
    }
    claims
        .get("email")
        .and_then(|e| e.as_str())
        .filter(|s| !s.trim().is_empty())
        .map(str::to_string)
}

/// JIT provisioning (`ONB-2`): a successful SSO login whose verified subject is **not
/// yet a member** auto-creates an active `member` — *iff* the subject's email domain is
/// a **verified** org domain (the same basis as domain-capture, `ID-6`). Fail-closed
/// (`INV-20`): an unverified domain (or no email claim) provisions nothing — the user
/// must be invited or SCIM-provisioned. No-op if already an active member. Returns
/// whether a member was newly provisioned. JIT seeds `member`; SCIM/group-mapping or an
/// admin elevates (the directory stays the role authority).
pub fn jit_provision(wb: &mut Workbench, scope: &str, authority: &str, id_token: &str) -> bool {
    let Ok(org) = Org::rebuild_in(wb.store_ref(), scope) else {
        return false;
    };
    if org.role_of(authority).is_some() {
        return false; // already an active member
    }
    let Some(email) = email_claim(id_token) else {
        return false; // no email ⇒ cannot match a verified domain (fail-closed)
    };
    if !org.domain_is_verified(&email) {
        return false; // unverified domain ⇒ no auto-join (fail-closed)
    }
    let record = MembershipRecord {
        id: authority.to_string(),
        op: RecordOp::Upsert,
        org_id: ORG_ID.to_string(),
        authority: authority.to_string(),
        email,
        role: "member".to_string(),
        status: MembershipStatus::Active,
        managed_by_scim: false,
        team: None,
    };
    crate::org_routes::write_membership(wb, scope, &record);
    gaugedesk_app::audit::record_in(wb, scope, authority, "member.jit-provision", authority);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn token_with_claims(claims: &serde_json::Value) -> String {
        use base64::Engine as _;
        let b64 = |v: &serde_json::Value| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap())
        };
        format!("{}.{}.sig", b64(&json!({ "alg": "none" })), b64(claims))
    }

    #[test]
    fn jit_provisions_a_verified_domain_subject_and_skips_others() {
        use gaugedesk_app::org::{Org, OrgRecord, ORG_ID, ORG_SCOPE};
        let store = gaugedesk_store::Store::open_in_memory().unwrap();
        let mut wb = Workbench::new(store);
        // Seed an org with a verified domain (the JIT basis).
        let org_rec = OrgRecord {
            id: ORG_ID.to_string(),
            op: RecordOp::Upsert,
            display_name: "Acme".into(),
            verified_domains: vec!["acme.com".into()],
            default_region: None,
            kind: Default::default(),
        };
        wb.store_mut()
            .append_record(ORG_SCOPE, "org", &serde_json::to_string(&org_rec).unwrap())
            .unwrap();

        // Verified-domain subject with a verified email → provisioned as an active member.
        let tok = token_with_claims(
            &json!({ "sub": "sub-alice", "email": "alice@acme.com", "email_verified": true }),
        );
        assert!(
            jit_provision(&mut wb, ORG_SCOPE, "sub-alice", &tok),
            "verified domain provisions"
        );
        assert!(Org::rebuild(wb.store_ref())
            .unwrap()
            .role_of("sub-alice")
            .is_some());
        // Idempotent: already a member → no-op.
        assert!(!jit_provision(&mut wb, ORG_SCOPE, "sub-alice", &tok));

        // Unverified domain → fail-closed, no provision.
        let evil = token_with_claims(&json!({ "sub": "sub-eve", "email": "eve@evil.com" }));
        assert!(!jit_provision(&mut wb, ORG_SCOPE, "sub-eve", &evil));
        assert!(Org::rebuild(wb.store_ref())
            .unwrap()
            .role_of("sub-eve")
            .is_none());

        // No email claim → cannot match a verified domain → no provision.
        let anon = token_with_claims(&json!({ "sub": "sub-anon" }));
        assert!(!jit_provision(&mut wb, ORG_SCOPE, "sub-anon", &anon));
    }

    #[test]
    fn jit_skips_unverified_email_claim() {
        // A federated IdP that asserts an *unverified* email inside a verified org domain
        // must not get the subject auto-joined — even though acme.com is a verified domain.
        use gaugedesk_app::org::{OrgRecord, ORG_ID, ORG_SCOPE};
        let store = gaugedesk_store::Store::open_in_memory().unwrap();
        let mut wb = Workbench::new(store);
        let org_rec = OrgRecord {
            id: ORG_ID.to_string(),
            op: RecordOp::Upsert,
            display_name: "Acme".into(),
            verified_domains: vec!["acme.com".into()],
            default_region: None,
            kind: Default::default(),
        };
        wb.store_mut()
            .append_record(ORG_SCOPE, "org", &serde_json::to_string(&org_rec).unwrap())
            .unwrap();

        // email_verified:false ⇒ fail-closed, no provision, no role.
        let unverified = token_with_claims(
            &json!({ "sub": "sub-alice", "email": "alice@acme.com", "email_verified": false }),
        );
        assert!(!jit_provision(&mut wb, ORG_SCOPE, "sub-alice", &unverified));
        assert!(Org::rebuild(wb.store_ref())
            .unwrap()
            .role_of("sub-alice")
            .is_none());

        // The claim absent entirely is treated the same (an IdP that omits it).
        let absent = token_with_claims(&json!({ "sub": "sub-bob", "email": "bob@acme.com" }));
        assert!(!jit_provision(&mut wb, ORG_SCOPE, "sub-bob", &absent));
        assert!(Org::rebuild(wb.store_ref())
            .unwrap()
            .role_of("sub-bob")
            .is_none());
    }
}
