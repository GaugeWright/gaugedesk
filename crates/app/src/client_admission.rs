//! Enterprise client software admission (`ITGOV-4`, ADR 0095).
//!
//! The browser/desktop client reports compatibility metadata on each request. The
//! Home evaluates that declaration against the org's admitted software policy before
//! serving organization data. This is deliberately **not** device or binary
//! attestation: a report can be forged by a modified endpoint, so no product authority
//! depends on it. Identity, scope, policy epochs, export, and runtime enforcement stay
//! server-side.

use axum::http::HeaderMap;
use semver::Version;
use serde::{Deserialize, Serialize};

pub const VERSION_HEADER: &str = "x-gaugedesk-client-version";
pub const PROTOCOL_HEADER: &str = "x-gaugedesk-client-protocol";
pub const CHANNEL_HEADER: &str = "x-gaugedesk-client-channel";
pub const PLATFORM_HEADER: &str = "x-gaugedesk-client-platform";

/// Compatibility metadata reported by a GaugeDesk client. It is operational
/// evidence, not an authenticated device claim.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientBuild {
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub protocol: Option<u32>,
    #[serde(default)]
    pub channel: Option<String>,
    #[serde(default)]
    pub platform: Option<String>,
}

impl ClientBuild {
    pub fn from_headers(headers: &HeaderMap) -> Self {
        fn text(headers: &HeaderMap, name: &'static str) -> Option<String> {
            headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| value.chars().take(128).collect())
        }
        Self {
            version: text(headers, VERSION_HEADER),
            protocol: text(headers, PROTOCOL_HEADER).and_then(|value| value.parse().ok()),
            channel: text(headers, CHANNEL_HEADER),
            platform: text(headers, PLATFORM_HEADER),
        }
    }
}

/// The canonical organization policy for client/session compatibility. Empty/zero
/// fields impose no constraint; a fully empty record is equivalent to no policy.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftwarePolicy {
    #[serde(default)]
    pub minimum_version: String,
    #[serde(default)]
    pub minimum_protocol: u32,
    #[serde(default)]
    pub allowed_channels: Vec<String>,
    /// Unix milliseconds. A nonconforming client warns strictly before this instant
    /// and is blocked at/after it. `None`/`0` means enforce immediately.
    #[serde(default)]
    pub grace_until_unix_ms: Option<u64>,
}

impl SoftwarePolicy {
    pub fn is_active(&self) -> bool {
        !self.minimum_version.trim().is_empty()
            || self.minimum_protocol > 0
            || !self.allowed_channels.is_empty()
    }

    pub fn validate(&self) -> Result<(), String> {
        if !self.minimum_version.trim().is_empty() {
            Version::parse(self.minimum_version.trim()).map_err(|_| {
                "minimum_version must be a semantic version such as 0.4.3".to_string()
            })?;
        }
        for channel in &self.allowed_channels {
            if !matches!(channel.as_str(), "stable" | "beta" | "dev") {
                return Err("allowed_channels may contain only stable, beta, or dev".to_string());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientAdmissionStatus {
    Unmanaged,
    Current,
    Warning,
    Blocked,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientAdmission {
    pub status: ClientAdmissionStatus,
    pub reason: String,
}

/// Pure evaluation of one reported build at an injected wall-clock instant.
pub fn evaluate_client(
    policy: Option<&SoftwarePolicy>,
    build: &ClientBuild,
    now_unix_ms: u64,
) -> ClientAdmission {
    let Some(policy) = policy.filter(|policy| policy.is_active()) else {
        return ClientAdmission {
            status: ClientAdmissionStatus::Unmanaged,
            reason: "no organization software policy".to_string(),
        };
    };

    let mut failures = Vec::new();
    if !policy.minimum_version.trim().is_empty() {
        let current = build
            .version
            .as_deref()
            .and_then(|value| Version::parse(value).ok());
        let required = Version::parse(policy.minimum_version.trim()).ok();
        if !matches!((current, required), (Some(current), Some(required)) if current >= required) {
            failures.push(format!(
                "requires GaugeDesk {} or newer",
                policy.minimum_version
            ));
        }
    }
    if policy.minimum_protocol > 0
        && build
            .protocol
            .is_none_or(|protocol| protocol < policy.minimum_protocol)
    {
        failures.push(format!(
            "requires client protocol {} or newer",
            policy.minimum_protocol
        ));
    }
    if !policy.allowed_channels.is_empty()
        && build
            .channel
            .as_ref()
            .is_none_or(|channel| !policy.allowed_channels.contains(channel))
    {
        failures.push(format!(
            "release channel must be one of {}",
            policy.allowed_channels.join(", ")
        ));
    }

    if failures.is_empty() {
        return ClientAdmission {
            status: ClientAdmissionStatus::Current,
            reason: "reported build conforms".to_string(),
        };
    }

    let grace = policy
        .grace_until_unix_ms
        .filter(|deadline| *deadline > now_unix_ms);
    ClientAdmission {
        status: if grace.is_some() {
            ClientAdmissionStatus::Warning
        } else {
            ClientAdmissionStatus::Blocked
        },
        reason: failures.join("; "),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> SoftwarePolicy {
        SoftwarePolicy {
            minimum_version: "1.2.0".into(),
            minimum_protocol: 3,
            allowed_channels: vec!["stable".into()],
            grace_until_unix_ms: None,
        }
    }

    fn build(version: &str, protocol: u32, channel: &str) -> ClientBuild {
        ClientBuild {
            version: Some(version.into()),
            protocol: Some(protocol),
            channel: Some(channel.into()),
            platform: Some("desktop".into()),
        }
    }

    #[test]
    fn absent_policy_is_unmanaged_and_non_blocking() {
        assert_eq!(
            evaluate_client(None, &ClientBuild::default(), 100).status,
            ClientAdmissionStatus::Unmanaged
        );
    }

    #[test]
    fn conforming_build_is_current() {
        assert_eq!(
            evaluate_client(Some(&policy()), &build("1.2.1", 3, "stable"), 100).status,
            ClientAdmissionStatus::Current
        );
    }

    #[test]
    fn missing_or_below_floor_build_is_blocked_without_grace() {
        assert_eq!(
            evaluate_client(Some(&policy()), &ClientBuild::default(), 100).status,
            ClientAdmissionStatus::Blocked
        );
        assert_eq!(
            evaluate_client(Some(&policy()), &build("1.1.9", 2, "dev"), 100).status,
            ClientAdmissionStatus::Blocked
        );
    }

    #[test]
    fn nonconforming_build_warns_only_before_the_deadline() {
        let mut policy = policy();
        policy.grace_until_unix_ms = Some(1_000);
        assert_eq!(
            evaluate_client(Some(&policy), &build("1.0.0", 1, "dev"), 999).status,
            ClientAdmissionStatus::Warning
        );
        assert_eq!(
            evaluate_client(Some(&policy), &build("1.0.0", 1, "dev"), 1_000).status,
            ClientAdmissionStatus::Blocked
        );
    }

    #[test]
    fn malformed_policy_is_rejected() {
        let mut invalid = policy();
        invalid.minimum_version = "latest".into();
        assert!(invalid.validate().is_err());
        invalid.minimum_version = "1.2.3".into();
        invalid.allowed_channels = vec!["nightly".into()];
        assert!(invalid.validate().is_err());
    }
}
