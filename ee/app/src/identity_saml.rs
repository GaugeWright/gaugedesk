//! SAML SSO adapter (M3 `ID-2`) — a real [`IdentityProvider`](gaugedesk_app::identity::IdentityProvider)
//! that authenticates a **SAML Response** by delegating the signature/XML-dsig
//! verification to a co-resident **sidecar** process, then maps the verified subject
//! + attributes onto an [`AuthorityId`] + [`AuthorityAttributes`].
//!
//! ## Why a sidecar
//!
//! SAML SP verification requires XML canonicalization (C14N) + XML-dsig — the most
//! attack-prone code in SSO (signature-wrapping / XSW) and the one piece with no
//! vetted, OpenSSL-free, pure-Rust library. Rather than hand-roll dangerous crypto or
//! pull libxml2/OpenSSL into the Rust binary, the verification runs in a small
//! **bun/node sidecar** built on a maintained SAML library, behind a narrow
//! subprocess seam.
//! The Rust core stays memory-safe and OpenSSL-free; correctness of the XSW-prone path
//! lives in a maintained library.
//!
//! ## Trust boundary (fail-closed, `INV-20`)
//!
//! The sidecar is co-resident (loopback IPC, same host trust) and is given
//! the IdP's **public** signing certificate + the expected audience; it returns a
//! `{subject, attributes}` verdict or a rejection. **Anything** that is not an
//! explicit success — a non-zero exit, malformed output, `ok:false`, an empty subject,
//! a spawn failure — yields **no** authority. The Rust side never parses XML.
//!
//! The wire contract is one JSON request on the child's stdin and one JSON response on
//! its stdout (spawn-per-verify; SAML auth is login-frequency, not per-request).

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use gaugedesk_core::abac::{AuthorityAttributes, Region, Role, Tenant};
use gaugedesk_core::ids::AuthorityId;

use gaugedesk_app::identity::IdentityProvider;

/// Resolve the verify-sidecar command (an explicit env-override seam,
/// SELFHOST). A packaged bundle vendors the sidecar (e.g. a bun-compiled binary) and
/// points here via `GAUGEDESK_SAML_SIDECAR`; the dev build falls back to running the
/// script on `node` under the repo's `ee/sidecar/saml-verify/verify.mjs`. `None` when
/// neither is resolvable (the SAML provider is then simply not configured).
pub fn saml_command_from(env: Option<String>, cwd: Option<&Path>) -> Option<Vec<String>> {
    if let Some(bin) = env.filter(|s| !s.trim().is_empty()) {
        return Some(vec![bin]);
    }
    cwd.map(|c| {
        vec![
            "node".to_string(),
            c.join("ee/sidecar/saml-verify/verify.mjs")
                .display()
                .to_string(),
        ]
    })
}

/// Which SAML **attribute names** carry the claims the ABAC evaluator reads. Unset
/// (`None`) ⇒ that attribute is not mapped (fail-closed — no role is safer than a
/// wrongly-mapped one). IdP-specific (Entra emits `http://schemas.../groups`, etc.).
#[derive(Clone, Debug, Default)]
pub struct SamlClaimMapping {
    pub roles_attribute: Option<String>,
    pub region_attribute: Option<String>,
    pub tenant_attribute: Option<String>,
}

/// The request handed to the verify sidecar on stdin.
#[derive(Serialize)]
struct VerifyRequest<'a> {
    /// The base64-encoded (or raw XML) SAML Response from the IdP POST binding.
    saml_response: &'a str,
    /// The IdP's signing certificate (PEM) — the trust anchor the sidecar checks the
    /// assertion's XML signature against.
    idp_cert: &'a str,
    /// The SP entity id the assertion's `AudienceRestriction` must contain.
    audience: &'a str,
}

/// The sidecar's verdict on stdout. `ok:false` (or any non-success) is a rejection.
#[derive(Deserialize, Default)]
struct VerifyResponse {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    subject: String,
    /// Verified attribute statements: name → values.
    #[serde(default)]
    attributes: BTreeMap<String, Vec<String>>,
    /// The assertion's unique `@ID` — the replay key. A verified SAML assertion must
    /// carry one; an empty id is treated fail-closed (we cannot enforce single-use).
    #[serde(default)]
    assertion_id: String,
    /// The assertion's `NotOnOrAfter` as epoch milliseconds (the tighter of
    /// SubjectConfirmationData / Conditions). Bounds how long the replay entry is kept.
    #[serde(default)]
    not_on_or_after: Option<i64>,
}

/// How long a consumed assertion id is remembered when the sidecar reports no expiry
/// (defensive; a valid assertion normally carries a `NotOnOrAfter`). Comfortably covers
/// a typical assertion validity window.
const DEFAULT_REPLAY_RETENTION_MS: i64 = 10 * 60 * 1000;

fn now_epoch_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// A SAML `IdentityProvider` backed by the verify sidecar.
pub struct SamlSidecarIdentityProvider {
    /// The verifier command: program + args (request on stdin, verdict on stdout).
    /// Production: the vendored bun sidecar (resolved via `GAUGEDESK_SAML_SIDECAR`);
    /// dev: `["node", "ee/sidecar/saml-verify/verify.mjs"]`.
    command: Vec<String>,
    idp_cert_pem: String,
    audience: String,
    mapping: SamlClaimMapping,
    /// Attributes materialized at the last successful [`authenticate`], per authority
    /// (the seam splits authenticate from claims; the SAML attributes live in the
    /// just-verified assertion). Interior-mutable behind the `&self` trait methods.
    ///
    /// [`authenticate`]: IdentityProvider::authenticate
    cache: Mutex<BTreeMap<AuthorityId, AuthorityAttributes>>,
    /// One-time-use cache of consumed assertion ids → their expiry (epoch ms). A
    /// signed assertion is otherwise replayable within its validity window; this makes
    /// each one single-use (the Web-Browser-SSO requirement node-saml does not itself
    /// enforce). Interior-mutable behind the `&self` trait methods.
    replay: Mutex<BTreeMap<String, i64>>,
}

impl SamlSidecarIdentityProvider {
    pub fn new(
        command: Vec<String>,
        idp_cert_pem: impl Into<String>,
        audience: impl Into<String>,
    ) -> Self {
        Self {
            command,
            idp_cert_pem: idp_cert_pem.into(),
            audience: audience.into(),
            mapping: SamlClaimMapping::default(),
            cache: Mutex::new(BTreeMap::new()),
            replay: Mutex::new(BTreeMap::new()),
        }
    }

    /// Record a one-time assertion id, pruning entries that have expired by `now_ms`.
    /// Returns `false` if the id was already consumed and is still within its validity
    /// window — a replay, rejected fail-closed. `now_ms`/`expiry_ms` are parameters so
    /// the policy is deterministically testable without the wall clock.
    fn record_assertion(&self, id: &str, expiry_ms: i64, now_ms: i64) -> bool {
        let mut replay = self.replay.lock().expect("saml replay cache poisoned");
        replay.retain(|_, exp| *exp > now_ms);
        if replay.contains_key(id) {
            return false;
        }
        // Keep the entry at least until the assertion's expiry; never insert an
        // already-expired entry that an immediate replay could slip past.
        let keep_until = expiry_ms.max(now_ms + 1);
        replay.insert(id.to_string(), keep_until);
        true
    }

    pub fn with_mapping(mut self, mapping: SamlClaimMapping) -> Self {
        self.mapping = mapping;
        self
    }

    /// Run the verify sidecar once: write the request to stdin, read the JSON verdict
    /// from stdout. `None` on any spawn/IO/parse failure or non-zero exit (fail-closed).
    fn verify(&self, saml_response: &str) -> Option<VerifyResponse> {
        let (program, args) = self.command.split_first()?;
        let request = serde_json::to_string(&VerifyRequest {
            saml_response,
            idp_cert: &self.idp_cert_pem,
            audience: &self.audience,
        })
        .ok()?;

        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        if let Some(mut stdin) = child.stdin.take() {
            // Best-effort: a child that ignores stdin still gets the request in the
            // pipe buffer; dropping the handle at end of block closes it.
            let _ = stdin.write_all(request.as_bytes());
        }
        let output = child.wait_with_output().ok()?;
        if !output.status.success() {
            return None;
        }
        serde_json::from_slice(&output.stdout).ok()
    }

    /// Map a verified attribute set onto authority attributes per [`SamlClaimMapping`].
    /// Only ever *adds* attributes the assertion carries.
    fn map_attributes(&self, attrs: &BTreeMap<String, Vec<String>>) -> AuthorityAttributes {
        let mut out = AuthorityAttributes::default();
        if let Some(name) = &self.mapping.roles_attribute {
            if let Some(values) = attrs.get(name) {
                out.roles = values.iter().map(|v| Role::new(v.as_str())).collect();
            }
        }
        if let Some(name) = &self.mapping.region_attribute {
            out.region = attrs.get(name).and_then(|v| v.first()).map(Region::new);
        }
        if let Some(name) = &self.mapping.tenant_attribute {
            out.affiliation = attrs.get(name).and_then(|v| v.first()).map(Tenant::new);
        }
        out
    }
}

impl IdentityProvider for SamlSidecarIdentityProvider {
    fn authenticate(&self, credential: &str) -> Option<AuthorityId> {
        let verdict = self.verify(credential)?;
        if !verdict.ok || verdict.subject.is_empty() {
            return None; // rejection or empty subject ⇒ no authority (fail-closed)
        }
        // A verified SAML assertion must carry an id; without one we cannot enforce
        // single-use, so reject (fail-closed, INV-20).
        if verdict.assertion_id.is_empty() {
            return None;
        }
        // Single-use: a signed assertion is replayable within its validity window
        // until consumed. Reject the second presentation of the same assertion id.
        let now_ms = now_epoch_ms();
        let expiry_ms = verdict
            .not_on_or_after
            .unwrap_or(now_ms + DEFAULT_REPLAY_RETENTION_MS);
        if !self.record_assertion(&verdict.assertion_id, expiry_ms, now_ms) {
            return None; // replay of an already-consumed assertion
        }
        let authority = AuthorityId::new(verdict.subject.as_str());
        let attrs = self.map_attributes(&verdict.attributes);
        self.cache
            .lock()
            .expect("saml cache mutex poisoned")
            .insert(authority.clone(), attrs);
        Some(authority)
    }

    fn claims(&self, authority: &AuthorityId) -> AuthorityAttributes {
        self.cache
            .lock()
            .expect("saml cache mutex poisoned")
            .get(authority)
            .cloned()
            .unwrap_or_default()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    const CERT: &str = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----";

    /// A mock sidecar: a shell command that ignores stdin and prints `stdout_json`.
    fn provider_with_stdout(stdout_json: &str) -> SamlSidecarIdentityProvider {
        SamlSidecarIdentityProvider::new(
            vec![
                "sh".into(),
                "-c".into(),
                format!("cat >/dev/null; printf '%s' '{stdout_json}'"),
            ],
            CERT,
            "sp-entity-id",
        )
        .with_mapping(SamlClaimMapping {
            roles_attribute: Some("roles".into()),
            region_attribute: Some("region".into()),
            tenant_attribute: Some("org".into()),
        })
    }

    #[test]
    fn verified_assertion_authenticates_and_maps_attributes() {
        let idp = provider_with_stdout(
            r#"{"ok":true,"subject":"alice@acme.com","assertion_id":"_a1","not_on_or_after":4102444799000,"attributes":{"roles":["admin","member"],"region":["eu"],"org":["acme"]}}"#,
        );
        let authority = idp
            .authenticate("<base64 saml response>")
            .expect("authenticates");
        assert_eq!(authority, AuthorityId::new("alice@acme.com"));
        let attrs = idp.claims(&authority);
        assert!(attrs.roles.contains(&Role::admin()));
        assert!(attrs.roles.contains(&Role::member()));
        assert_eq!(attrs.region, Some(Region::new("eu")));
        assert_eq!(attrs.affiliation, Some(Tenant::new("acme")));
    }

    #[test]
    fn a_replayed_assertion_is_rejected() {
        // The same signed assertion (same id) presented twice: first consumes, second
        // is a replay and must be refused (fail-closed).
        let idp = provider_with_stdout(
            r#"{"ok":true,"subject":"alice@acme.com","assertion_id":"_a1","not_on_or_after":4102444799000,"attributes":{}}"#,
        );
        assert_eq!(
            idp.authenticate("<resp>"),
            Some(AuthorityId::new("alice@acme.com"))
        );
        assert_eq!(idp.authenticate("<resp>"), None, "replay must be rejected");
    }

    #[test]
    fn a_verified_assertion_without_an_id_is_rejected() {
        // No assertion id ⇒ single-use cannot be enforced ⇒ fail-closed.
        let idp = provider_with_stdout(r#"{"ok":true,"subject":"alice@acme.com","attributes":{}}"#);
        assert_eq!(idp.authenticate("<resp>"), None);
    }

    #[test]
    fn replay_cache_is_single_use_per_id_and_prunes_expired() {
        let idp = SamlSidecarIdentityProvider::new(vec!["true".into()], CERT, "sp");
        let now = 1_000_000;
        let far = now + 60_000;
        // First sight of an id within its window: accepted + recorded.
        assert!(idp.record_assertion("_a", far, now));
        // Second sight within the window: a replay.
        assert!(!idp.record_assertion("_a", far, now));
        // A different id is independent.
        assert!(idp.record_assertion("_b", far, now));
        // Once past its expiry the entry is pruned, so memory does not grow without
        // bound (a genuinely expired assertion is already rejected upstream by node-saml).
        assert!(idp.record_assertion("_a", now + 120_000, now + 90_000));
    }

    #[test]
    fn rejection_yields_no_authority() {
        let idp = provider_with_stdout(r#"{"ok":false,"error":"signature did not verify"}"#);
        assert_eq!(idp.authenticate("<resp>"), None);
    }

    #[test]
    fn empty_subject_is_rejected() {
        let idp = provider_with_stdout(r#"{"ok":true,"subject":"","attributes":{}}"#);
        assert_eq!(idp.authenticate("<resp>"), None);
    }

    #[test]
    fn sidecar_crash_is_fail_closed() {
        let idp = SamlSidecarIdentityProvider::new(
            vec!["sh".into(), "-c".into(), "exit 1".into()],
            CERT,
            "sp",
        );
        assert_eq!(idp.authenticate("<resp>"), None);
    }

    #[test]
    fn garbage_output_is_fail_closed() {
        let idp = provider_with_stdout("not json at all");
        assert_eq!(idp.authenticate("<resp>"), None);
    }

    #[test]
    fn missing_sidecar_binary_is_fail_closed() {
        let idp = SamlSidecarIdentityProvider::new(
            vec!["gaugewright-no-such-sidecar-binary-xyz".into()],
            CERT,
            "sp",
        );
        assert_eq!(idp.authenticate("<resp>"), None);
    }

    #[test]
    fn unknown_authority_gets_default_claims() {
        let idp = provider_with_stdout(r#"{"ok":true,"subject":"x","attributes":{}}"#);
        assert_eq!(
            idp.claims(&AuthorityId::new("ghost")),
            AuthorityAttributes::default()
        );
    }

    #[test]
    fn command_resolves_from_env_then_cwd() {
        // A vendored binary wins.
        assert_eq!(
            saml_command_from(Some("/opt/gw/saml-verify".into()), None),
            Some(vec!["/opt/gw/saml-verify".to_string()])
        );
        // Else the dev fallback runs the script on node, under cwd.
        assert_eq!(
            saml_command_from(None, Some(Path::new("/repo"))),
            Some(vec![
                "node".to_string(),
                "/repo/ee/sidecar/saml-verify/verify.mjs".to_string()
            ])
        );
        // Blank env is ignored; nothing resolvable ⇒ None.
        assert_eq!(saml_command_from(Some("  ".into()), None), None);
        assert_eq!(saml_command_from(None, None), None);
    }
}
