//! One immutable, secret-free GaugeVault namespace per owner account.
//!
//! The admitting shell derives the owner scope from the authenticated account.
//! A prefix organizes shared-vault names; it never grants Azure or product use.

use crate::ids::{ScopeId, VaultTenantPrefixId};
use crate::{Lifecycle, Rejection};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct State {
    pub owner_scope: Option<ScopeId>,
    pub prefix: Option<VaultTenantPrefixId>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Command {
    pub owner_scope: ScopeId,
    pub prefix: VaultTenantPrefixId,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Event {
    pub owner_scope: ScopeId,
    pub prefix: VaultTenantPrefixId,
}

fn canonical_prefix(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl Lifecycle for State {
    type State = State;
    type Command = Command;
    type Event = Event;
    const KIND: &'static str = "gaugevault_namespace";

    fn decide(state: &State, command: Command) -> Result<Vec<Event>, Rejection> {
        if state.owner_scope.is_some()
            || state.prefix.is_some()
            || command.owner_scope.as_str().trim().is_empty()
            || !canonical_prefix(command.prefix.as_str())
        {
            return Err(Rejection {
                reason: "GaugeVault: namespace cannot be provisioned",
            });
        }
        Ok(vec![Event {
            owner_scope: command.owner_scope,
            prefix: command.prefix,
        }])
    }

    fn evolve(state: &State, event: Event) -> State {
        if state.owner_scope.is_some() || state.prefix.is_some() {
            return state.clone();
        }
        State {
            owner_scope: Some(event.owner_scope),
            prefix: Some(event.prefix),
        }
    }
}
