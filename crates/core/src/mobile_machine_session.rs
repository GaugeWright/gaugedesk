//! Pure admission contract for a device-bound controller session to one exact
//! Machine (ADR 0109).
//!
//! The imperative shell supplies clocks, random nonces, credential hashes,
//! durable storage, and P-256 verification. This module owns the canonical bytes
//! and state guards shared by every client adapter.

use crate::ids::{DeviceId, HomeId, PublicKey};

pub fn enrollment_challenge_bytes(
    machine: &HomeId,
    endpoint: &str,
    request_id: &str,
    device: &DeviceId,
    public_key: &PublicKey,
    nonce_hex: &str,
) -> Vec<u8> {
    format!(
        "gaugewright-mobile-machine-enrollment::v1::machine={}::endpoint={}::request={}::device={}::key={}::nonce={}",
        machine.as_str(),
        endpoint,
        request_id,
        device.as_str(),
        public_key.as_str(),
        nonce_hex,
    )
    .into_bytes()
}

pub fn session_challenge_bytes(
    machine: &HomeId,
    grant_id: &str,
    device: &DeviceId,
    public_key: &PublicKey,
    nonce_hex: &str,
) -> Vec<u8> {
    format!(
        "gaugewright-mobile-machine-session::v1::machine={}::grant={}::device={}::key={}::nonce={}",
        machine.as_str(),
        grant_id,
        device.as_str(),
        public_key.as_str(),
        nonce_hex,
    )
    .into_bytes()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControllerPhase {
    Challenged,
    Proved,
    Granted,
    Active,
    Rejected,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ControllerState {
    pub machine: HomeId,
    pub device: DeviceId,
    pub public_key: PublicKey,
    pub phase: ControllerPhase,
    pub credential_issued: bool,
    pub grant_active: bool,
    pub session_active: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControllerCommand {
    Prove {
        signature_valid: bool,
    },
    Approve,
    Reject,
    OpenSession {
        machine: HomeId,
        device: DeviceId,
        public_key: PublicKey,
        credential_valid: bool,
        signature_valid: bool,
    },
    Revoke,
    AdmitWork {
        machine: HomeId,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControllerRejection {
    WrongPhase,
    BadKeyProof,
    OwnerApprovalRequired,
    CredentialRequired,
    DeviceMismatch,
    MachineMismatch,
    Revoked,
    SessionRequired,
}

impl ControllerState {
    pub fn challenged(machine: HomeId, device: DeviceId, public_key: PublicKey) -> Self {
        Self {
            machine,
            device,
            public_key,
            phase: ControllerPhase::Challenged,
            credential_issued: false,
            grant_active: false,
            session_active: false,
        }
    }

    /// Decide and evolve one controller command. Rejection never mutates state.
    pub fn apply(&self, command: ControllerCommand) -> Result<Self, ControllerRejection> {
        let mut next = self.clone();
        match command {
            ControllerCommand::Prove { signature_valid } => {
                if self.phase != ControllerPhase::Challenged {
                    return Err(ControllerRejection::WrongPhase);
                }
                if !signature_valid {
                    return Err(ControllerRejection::BadKeyProof);
                }
                next.phase = ControllerPhase::Proved;
            }
            ControllerCommand::Approve => {
                if self.phase != ControllerPhase::Proved {
                    return Err(ControllerRejection::OwnerApprovalRequired);
                }
                next.phase = ControllerPhase::Granted;
                next.credential_issued = true;
                next.grant_active = true;
            }
            ControllerCommand::Reject => {
                if !matches!(
                    self.phase,
                    ControllerPhase::Challenged | ControllerPhase::Proved
                ) {
                    return Err(ControllerRejection::WrongPhase);
                }
                next.phase = ControllerPhase::Rejected;
            }
            ControllerCommand::OpenSession {
                machine,
                device,
                public_key,
                credential_valid,
                signature_valid,
            } => {
                if self.phase == ControllerPhase::Revoked || !self.grant_active {
                    return Err(ControllerRejection::Revoked);
                }
                if !matches!(
                    self.phase,
                    ControllerPhase::Granted | ControllerPhase::Active
                ) {
                    return Err(ControllerRejection::WrongPhase);
                }
                if machine != self.machine {
                    return Err(ControllerRejection::MachineMismatch);
                }
                if device != self.device || public_key != self.public_key {
                    return Err(ControllerRejection::DeviceMismatch);
                }
                if !self.credential_issued || !credential_valid {
                    return Err(ControllerRejection::CredentialRequired);
                }
                if !signature_valid {
                    return Err(ControllerRejection::BadKeyProof);
                }
                next.phase = ControllerPhase::Active;
                next.session_active = true;
            }
            ControllerCommand::Revoke => {
                if matches!(
                    self.phase,
                    ControllerPhase::Rejected | ControllerPhase::Revoked
                ) {
                    return Err(ControllerRejection::WrongPhase);
                }
                next.phase = ControllerPhase::Revoked;
                next.grant_active = false;
                next.session_active = false;
            }
            ControllerCommand::AdmitWork { machine } => {
                if machine != self.machine {
                    return Err(ControllerRejection::MachineMismatch);
                }
                if self.phase == ControllerPhase::Revoked || !self.grant_active {
                    return Err(ControllerRejection::Revoked);
                }
                if self.phase != ControllerPhase::Active || !self.session_active {
                    return Err(ControllerRejection::SessionRequired);
                }
            }
        }
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn challenged() -> ControllerState {
        ControllerState::challenged(
            HomeId::new("machine-a"),
            DeviceId::new("device:phone"),
            PublicKey::new("device-key"),
        )
    }

    fn active() -> ControllerState {
        challenged()
            .apply(ControllerCommand::Prove {
                signature_valid: true,
            })
            .unwrap()
            .apply(ControllerCommand::Approve)
            .unwrap()
            .apply(ControllerCommand::OpenSession {
                machine: HomeId::new("machine-a"),
                device: DeviceId::new("device:phone"),
                public_key: PublicKey::new("device-key"),
                credential_valid: true,
                signature_valid: true,
            })
            .unwrap()
    }

    #[test]
    fn happy_path_requires_every_gate() {
        assert!(active()
            .apply(ControllerCommand::AdmitWork {
                machine: HomeId::new("machine-a")
            })
            .is_ok());
    }

    #[test]
    fn approval_before_proof_and_foreign_key_resume_fail_closed() {
        assert_eq!(
            challenged().apply(ControllerCommand::Approve),
            Err(ControllerRejection::OwnerApprovalRequired)
        );
        let granted = challenged()
            .apply(ControllerCommand::Prove {
                signature_valid: true,
            })
            .unwrap()
            .apply(ControllerCommand::Approve)
            .unwrap();
        assert_eq!(
            granted.apply(ControllerCommand::OpenSession {
                machine: HomeId::new("machine-a"),
                device: DeviceId::new("device:phone"),
                public_key: PublicKey::new("attacker-key"),
                credential_valid: true,
                signature_valid: true,
            }),
            Err(ControllerRejection::DeviceMismatch)
        );
    }

    #[test]
    fn revocation_immediately_denies_an_existing_session() {
        let revoked = active().apply(ControllerCommand::Revoke).unwrap();
        assert_eq!(
            revoked.apply(ControllerCommand::AdmitWork {
                machine: HomeId::new("machine-a")
            }),
            Err(ControllerRejection::Revoked)
        );
    }

    proptest! {
        #[test]
        fn controller_rejection_is_terminal(proved in any::<bool>()) {
            let pending = if proved {
                challenged()
                    .apply(ControllerCommand::Prove {
                        signature_valid: true,
                    })
                    .unwrap()
            } else {
                challenged()
            };
            let rejected = pending.apply(ControllerCommand::Reject).unwrap();
            prop_assert_eq!(rejected.phase, ControllerPhase::Rejected);
            prop_assert!(!rejected.credential_issued);
            prop_assert!(!rejected.grant_active);
            prop_assert!(!rejected.session_active);
            prop_assert!(rejected.apply(ControllerCommand::Approve).is_err());
            let reproved = rejected.apply(ControllerCommand::Prove {
                signature_valid: true,
            });
            prop_assert!(reproved.is_err());
            let admitted = rejected.apply(ControllerCommand::AdmitWork {
                machine: HomeId::new("machine-a"),
            });
            prop_assert!(admitted.is_err());
        }
    }

    #[test]
    fn challenge_bytes_bind_machine_and_key() {
        let base = enrollment_challenge_bytes(
            &HomeId::new("machine-a"),
            "https://machine.example.test",
            "request-1",
            &DeviceId::new("device:phone"),
            &PublicKey::new("key-a"),
            "nonce-a",
        );
        assert_ne!(
            base,
            enrollment_challenge_bytes(
                &HomeId::new("machine-b"),
                "https://machine.example.test",
                "request-1",
                &DeviceId::new("device:phone"),
                &PublicKey::new("key-a"),
                "nonce-a",
            )
        );
        assert_ne!(
            base,
            enrollment_challenge_bytes(
                &HomeId::new("machine-a"),
                "https://machine.example.test",
                "request-1",
                &DeviceId::new("device:phone"),
                &PublicKey::new("key-b"),
                "nonce-a",
            )
        );
    }
}
