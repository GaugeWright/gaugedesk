//! Immutable product admission for a non-chat host action (ADR 0164).
//!
//! The runtime owns `Command`'s wire type and validation. The product shell
//! authenticates and materializes it before admission. This fold retains that
//! exact value; it neither grants execution nor tracks runtime attempts.

use crate::{Lifecycle, Rejection};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostActionAdmission<Command> {
    pub command: Option<Command>,
}

impl<Command> Default for HostActionAdmission<Command> {
    fn default() -> Self {
        Self { command: None }
    }
}

impl<Command> Lifecycle for HostActionAdmission<Command>
where
    Command: Clone + serde::Serialize + serde::de::DeserializeOwned,
{
    type State = Self;
    type Command = Command;
    // Carry the owner's command directly, without another wire schema.
    type Event = Command;
    const KIND: &'static str = "host_action_admission_v1";

    fn decide(state: &Self, command: Command) -> Result<Vec<Command>, Rejection> {
        if state.command.is_some() {
            return Err(Rejection {
                reason: "host action is already admitted",
            });
        }
        Ok(vec![command])
    }

    fn evolve(state: &Self, event: Command) -> Self {
        // A later delivery cannot replace the original command, even when a
        // history reader encounters another admission-shaped event.
        Self {
            command: state.command.clone().or(Some(event)),
        }
    }
}
