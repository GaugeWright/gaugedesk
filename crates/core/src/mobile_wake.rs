//! Carrier-neutral mobile wake admission (ADR 0116).
//!
//! APNs/FCM are best-effort transport. This reducer admits only a generic,
//! reference-only wake for a proof-bound, current installation epoch. Carrier
//! acceptance never grants work; resolution still requires fresh Home
//! admission. Provider SDKs and credentials remain imperative adapters.

use crate::Rejection;

/// Canonical, domain-separated statement a registered Device signs when
/// installing or rotating a carrier token. The token itself is represented by
/// its handle so proofs and durable events never contain provider material.
pub fn installation_proof_bytes(
    account: &str,
    device: &str,
    platform: CarrierPlatform,
    token_handle: &str,
    epoch: u64,
) -> Vec<u8> {
    format!(
        "gaugewright-mobile-wake-installation/v1\naccount={account}\ndevice={device}\nplatform={}\ntoken_handle={token_handle}\nepoch={epoch}\n",
        match platform {
            CarrierPlatform::Apns => "apns",
            CarrierPlatform::Fcm => "fcm",
        }
    )
    .into_bytes()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CarrierPlatform {
    Apns,
    Fcm,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InstallationState {
    pub account: String,
    pub device: String,
    pub platform: Option<CarrierPlatform>,
    /// Opaque provider-token handle. The raw token belongs to the provider
    /// adapter's secret/routing store, not the event body.
    pub token_handle: String,
    pub epoch: u64,
    pub active: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InstallationCommand {
    Register {
        account: String,
        device: String,
        platform: CarrierPlatform,
        token_handle: String,
        epoch: u64,
        device_proof_verified: bool,
    },
    Disable {
        account: String,
        device: String,
        epoch: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum InstallationEvent {
    Registered {
        account: String,
        device: String,
        platform: CarrierPlatform,
        token_handle: String,
        epoch: u64,
    },
    Disabled {
        epoch: u64,
    },
}

pub fn decide_installation(
    state: &InstallationState,
    command: InstallationCommand,
) -> Result<Vec<InstallationEvent>, Rejection> {
    match command {
        InstallationCommand::Register {
            account,
            device,
            platform,
            token_handle,
            epoch,
            device_proof_verified,
        } => {
            if !device_proof_verified {
                return reject("wake registration requires device proof");
            }
            if account.is_empty() || device.is_empty() || token_handle.is_empty() || epoch == 0 {
                return reject("wake registration is incomplete");
            }
            if !state.account.is_empty() && (state.account != account || state.device != device) {
                return reject("wake registration cannot change account or Device");
            }
            if epoch <= state.epoch {
                return reject("wake registration epoch must advance");
            }
            Ok(vec![InstallationEvent::Registered {
                account,
                device,
                platform,
                token_handle,
                epoch,
            }])
        }
        InstallationCommand::Disable {
            account,
            device,
            epoch,
        } => {
            if !state.active || state.account != account || state.device != device {
                return reject("wake installation is not active for this Device");
            }
            if epoch != state.epoch {
                return reject("wake disable uses a stale installation epoch");
            }
            Ok(vec![InstallationEvent::Disabled { epoch }])
        }
    }
}

pub fn evolve_installation(
    state: &InstallationState,
    event: InstallationEvent,
) -> InstallationState {
    match event {
        InstallationEvent::Registered {
            account,
            device,
            platform,
            token_handle,
            epoch,
        } => InstallationState {
            account,
            device,
            platform: Some(platform),
            token_handle,
            epoch,
            active: true,
        },
        InstallationEvent::Disabled { epoch } => InstallationState {
            epoch,
            active: false,
            token_handle: String::new(),
            ..state.clone()
        },
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WakePhase {
    #[default]
    Draft,
    Queued,
    CarrierAccepted,
    Resolved,
    Expired,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WakeState {
    pub phase: WakePhase,
    pub notification_id: String,
    pub installation_epoch: u64,
    pub target_reference: String,
    pub expires_at: u64,
    pub carrier_accept_count: u32,
    pub resolution_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WakeCommand {
    Submit {
        notification_id: String,
        installation_epoch: u64,
        target_reference: String,
        expires_at: u64,
        now: u64,
        home_authenticated: bool,
        protected_payload_present: bool,
        installation: InstallationState,
    },
    RecordCarrierAccepted,
    Resolve {
        now: u64,
        home_admitted: bool,
        installation: InstallationState,
    },
    Expire {
        now: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum WakeEvent {
    Queued {
        notification_id: String,
        installation_epoch: u64,
        target_reference: String,
        expires_at: u64,
    },
    CarrierAccepted,
    Resolved,
    Expired,
}

pub fn decide_wake(state: &WakeState, command: WakeCommand) -> Result<Vec<WakeEvent>, Rejection> {
    match command {
        WakeCommand::Submit {
            notification_id,
            installation_epoch,
            target_reference,
            expires_at,
            now,
            home_authenticated,
            protected_payload_present,
            installation,
        } => {
            if state.phase != WakePhase::Draft {
                return reject("wake notification id is already admitted");
            }
            if !home_authenticated {
                return reject("wake intent requires an authenticated Home");
            }
            if protected_payload_present {
                return reject("wake intent must be reference-only");
            }
            if notification_id.is_empty() || target_reference.is_empty() || expires_at <= now {
                return reject("wake intent is incomplete or expired");
            }
            if !installation.active || installation.epoch != installation_epoch {
                return reject("wake intent uses a stale or disabled installation");
            }
            Ok(vec![WakeEvent::Queued {
                notification_id,
                installation_epoch,
                target_reference,
                expires_at,
            }])
        }
        WakeCommand::RecordCarrierAccepted => match state.phase {
            WakePhase::Queued | WakePhase::CarrierAccepted => {
                // Provider retries may repeat acceptance. Folding this event
                // never resolves the target or admits work.
                Ok(vec![WakeEvent::CarrierAccepted])
            }
            _ => reject("carrier acceptance has no queued wake"),
        },
        WakeCommand::Resolve {
            now,
            home_admitted,
            installation,
        } => {
            if state.phase == WakePhase::Resolved {
                return Ok(Vec::new());
            }
            if !matches!(state.phase, WakePhase::Queued | WakePhase::CarrierAccepted) {
                return reject("wake is not available to resolve");
            }
            if now >= state.expires_at {
                return reject("wake reference expired");
            }
            if !installation.active || installation.epoch != state.installation_epoch {
                return reject("wake installation is stale or disabled");
            }
            if !home_admitted {
                return reject("wake resolution requires fresh Home admission");
            }
            Ok(vec![WakeEvent::Resolved])
        }
        WakeCommand::Expire { now } => {
            if matches!(state.phase, WakePhase::Queued | WakePhase::CarrierAccepted)
                && now >= state.expires_at
            {
                Ok(vec![WakeEvent::Expired])
            } else {
                reject("wake is not yet expirable")
            }
        }
    }
}

pub fn evolve_wake(state: &WakeState, event: WakeEvent) -> WakeState {
    match event {
        WakeEvent::Queued {
            notification_id,
            installation_epoch,
            target_reference,
            expires_at,
        } => WakeState {
            phase: WakePhase::Queued,
            notification_id,
            installation_epoch,
            target_reference,
            expires_at,
            carrier_accept_count: 0,
            resolution_count: 0,
        },
        WakeEvent::CarrierAccepted => WakeState {
            phase: WakePhase::CarrierAccepted,
            carrier_accept_count: state.carrier_accept_count.saturating_add(1),
            ..state.clone()
        },
        WakeEvent::Resolved => WakeState {
            phase: WakePhase::Resolved,
            resolution_count: state.resolution_count.saturating_add(1),
            ..state.clone()
        },
        WakeEvent::Expired => WakeState {
            phase: WakePhase::Expired,
            ..state.clone()
        },
    }
}

fn reject<T>(reason: &'static str) -> Result<Vec<T>, Rejection> {
    Err(Rejection { reason })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn active_installation() -> InstallationState {
        let events = decide_installation(
            &InstallationState::default(),
            InstallationCommand::Register {
                account: "account:a".into(),
                device: "device:a".into(),
                platform: CarrierPlatform::Apns,
                token_handle: "provider-token-handle".into(),
                epoch: 1,
                device_proof_verified: true,
            },
        )
        .unwrap();
        evolve_installation(&InstallationState::default(), events[0].clone())
    }

    fn queued(installation: &InstallationState) -> WakeState {
        let events = decide_wake(
            &WakeState::default(),
            WakeCommand::Submit {
                notification_id: "wake:1".into(),
                installation_epoch: installation.epoch,
                target_reference: "opaque:target:1".into(),
                expires_at: 20,
                now: 10,
                home_authenticated: true,
                protected_payload_present: false,
                installation: installation.clone(),
            },
        )
        .unwrap();
        evolve_wake(&WakeState::default(), events[0].clone())
    }

    #[test]
    fn registration_requires_proof_and_monotonic_rotation() {
        let mut installation = active_installation();
        assert!(decide_installation(
            &installation,
            InstallationCommand::Register {
                account: "account:a".into(),
                device: "device:a".into(),
                platform: CarrierPlatform::Fcm,
                token_handle: "rotated".into(),
                epoch: 1,
                device_proof_verified: true,
            }
        )
        .is_err());
        let event = decide_installation(
            &installation,
            InstallationCommand::Register {
                account: "account:a".into(),
                device: "device:a".into(),
                platform: CarrierPlatform::Fcm,
                token_handle: "rotated".into(),
                epoch: 2,
                device_proof_verified: true,
            },
        )
        .unwrap()
        .remove(0);
        installation = evolve_installation(&installation, event);
        assert_eq!(installation.epoch, 2);
        assert_eq!(installation.platform, Some(CarrierPlatform::Fcm));
    }

    #[test]
    fn protected_or_unauthenticated_wakes_fail_closed() {
        let installation = active_installation();
        for (home_authenticated, protected_payload_present) in [(false, false), (true, true)] {
            assert!(decide_wake(
                &WakeState::default(),
                WakeCommand::Submit {
                    notification_id: "wake:bad".into(),
                    installation_epoch: 1,
                    target_reference: "opaque:target".into(),
                    expires_at: 20,
                    now: 10,
                    home_authenticated,
                    protected_payload_present,
                    installation: installation.clone(),
                }
            )
            .is_err());
        }
    }

    #[test]
    fn carrier_duplicates_grant_nothing_and_resolution_is_idempotent() {
        let installation = active_installation();
        let mut wake = queued(&installation);
        for _ in 0..2 {
            let event = decide_wake(&wake, WakeCommand::RecordCarrierAccepted).unwrap()[0].clone();
            wake = evolve_wake(&wake, event);
        }
        assert_eq!(wake.carrier_accept_count, 2);
        assert_eq!(wake.resolution_count, 0);
        assert!(decide_wake(
            &wake,
            WakeCommand::Resolve {
                now: 11,
                home_admitted: false,
                installation: installation.clone(),
            }
        )
        .is_err());
        let event = decide_wake(
            &wake,
            WakeCommand::Resolve {
                now: 11,
                home_admitted: true,
                installation: installation.clone(),
            },
        )
        .unwrap()[0]
            .clone();
        wake = evolve_wake(&wake, event);
        assert!(decide_wake(
            &wake,
            WakeCommand::Resolve {
                now: 12,
                home_admitted: true,
                installation,
            }
        )
        .unwrap()
        .is_empty());
        assert_eq!(wake.resolution_count, 1);
    }

    #[test]
    fn disable_or_rotation_blocks_an_old_wake() {
        let installation = active_installation();
        let wake = queued(&installation);
        let disabled = evolve_installation(
            &installation,
            decide_installation(
                &installation,
                InstallationCommand::Disable {
                    account: "account:a".into(),
                    device: "device:a".into(),
                    epoch: 1,
                },
            )
            .unwrap()[0]
                .clone(),
        );
        assert!(decide_wake(
            &wake,
            WakeCommand::Resolve {
                now: 11,
                home_admitted: true,
                installation: disabled,
            }
        )
        .is_err());
    }
}
