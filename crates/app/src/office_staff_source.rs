//! Current Hub source proof for office staff leases (DR-0262/DR-0263).
//!
//! This sends only the explicit workforce bearer to the configured sign-in
//! service. It has no account cache, owner substitution or Home/project input.
//! A proof is current authentication evidence, never permission to work or an
//! offline capability. The office lease boundary consumes it separately.

use std::io::Read;
use std::time::Duration;

use crate::account_identity::AccountIdentity;
use crate::account_session::AccountSessionEvidence;

/// A current authenticated response. Private fields prevent constructing proof
/// from a client-supplied account string or deserialized identity response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSourceSession {
    issuer: String,
    account: String,
    session: AccountSessionEvidence,
    checked_at_ms: u64,
}

impl VerifiedSourceSession {
    #[cfg(test)]
    pub(crate) fn for_test(
        issuer: &str,
        account: &str,
        session: AccountSessionEvidence,
        checked_at_ms: u64,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            account: account.into(),
            session,
            checked_at_ms,
        }
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn account(&self) -> &str {
        &self.account
    }

    pub fn session(&self) -> &AccountSessionEvidence {
        &self.session
    }

    pub fn checked_at_ms(&self) -> u64 {
        self.checked_at_ms
    }
}

/// Only a connection/service outage is eligible for an existing lease to run
/// down. Invalid successful responses and authentication refusals admit nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceCheck {
    Verified(VerifiedSourceSession),
    Refused,
    Unavailable,
}

/// Native office sign-in verification. HTTPS authenticates the configured Hub;
/// cleartext is limited to explicit loopback development/test services.
pub struct HubStaffSource {
    endpoint: url::Url,
    agent: ureq::Agent,
}

impl HubStaffSource {
    pub fn issuer(&self) -> &str {
        self.endpoint.as_str()
    }

    pub fn configured() -> Result<Self, &'static str> {
        let hub = crate::account_signin::hub_base().ok_or("office sign-in service is disabled")?;
        Self::at(&hub)
    }

    pub fn at(hub: &str) -> Result<Self, &'static str> {
        let mut endpoint = url::Url::parse(hub).map_err(|_| "invalid office sign-in URL")?;
        let loopback = match endpoint.host() {
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            // A name can resolve somewhere else; only a literal loopback address
            // qualifies for the development exception.
            _ => false,
        };
        if (endpoint.scheme() != "https" && !(endpoint.scheme() == "http" && loopback))
            || endpoint.host().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err("office sign-in requires an authenticated HTTPS destination");
        }
        endpoint
            .path_segments_mut()
            .map_err(|_| "invalid office sign-in URL")?
            .pop_if_empty()
            .extend(["account", "identity"]);
        let agent = ureq::AgentBuilder::new()
            .redirects(0)
            .timeout(Duration::from_secs(30))
            .timeout_connect(Duration::from_secs(10))
            .timeout_read(Duration::from_secs(15))
            .timeout_write(Duration::from_secs(10))
            .build();
        Ok(Self { endpoint, agent })
    }

    /// Call from a blocking worker, outside the Home's store/mutex. No response
    /// body, network error or credential is emitted into logs or diagnostics.
    pub fn check(&self, bearer: &str) -> SourceCheck {
        self.check_with_clock(bearer, crate::account::session_now_ms)
    }

    fn check_with_clock(&self, bearer: &str, now: impl FnOnce() -> u64) -> SourceCheck {
        // Native opaque tokens are nonempty ASCII; reject header injection before
        // constructing the HTTP request. Identity evidence must match this token.
        if bearer.is_empty()
            || bearer.len() > 4096
            || !bearer.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        {
            return SourceCheck::Refused;
        }
        let response = match self
            .agent
            .get(self.endpoint.as_str())
            .set("authorization", &format!("Bearer {bearer}"))
            .set("cache-control", "no-store")
            .call()
        {
            Ok(response) if response.status() == 200 => response,
            Ok(_) => return SourceCheck::Refused,
            Err(ureq::Error::Transport(_)) => return SourceCheck::Unavailable,
            Err(ureq::Error::Status(502..=504, _)) => return SourceCheck::Unavailable,
            Err(ureq::Error::Status(_, _)) => return SourceCheck::Refused,
        };
        if !response.header("cache-control").is_some_and(|value| {
            value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("no-store"))
        }) {
            return SourceCheck::Refused;
        }
        // Bound the response before parsing. Only the account and session facts
        // are consumed, with no remote body retained in a refusal or diagnostic.
        const MAX_RESPONSE_BYTES: u64 = 16 * 1024;
        let mut bytes = Vec::new();
        if response
            .into_reader()
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .is_err()
        {
            return SourceCheck::Unavailable;
        }
        if bytes.len() as u64 > MAX_RESPONSE_BYTES {
            return SourceCheck::Refused;
        }
        let Ok(identity) = serde_json::from_slice::<AccountIdentity>(&bytes) else {
            return SourceCheck::Refused;
        };
        let Some(session) = identity.session else {
            return SourceCheck::Refused;
        };
        let checked_at_ms = now();
        if identity.account.trim().is_empty()
            || identity.account.len() > 512
            || session.method.trim().is_empty()
            || session.method.len() > 512
            || session.session_ref != crate::account_session::session_id(bearer)
            || checked_at_ms == 0
            || session.issued_at_ms == 0
            || session.issued_at_ms > checked_at_ms
            || session.expires_at_ms <= checked_at_ms
            || session.expires_at_ms
                > session
                    .issued_at_ms
                    .saturating_add(crate::account::SESSION_ABSOLUTE_LIFETIME_MS)
        {
            return SourceCheck::Refused;
        }
        SourceCheck::Verified(VerifiedSourceSession {
            issuer: self.endpoint.as_str().to_owned(),
            account: identity.account,
            session,
            checked_at_ms,
        })
    }
}

#[cfg(test)]
#[path = "office_staff_source_tests.rs"]
pub(super) mod tests;
