//! Who exists, what standing they hold, and who may be given work (`GATE-3f`).
//!
//! Removing `askHuman` (WhippleScript DR-0050) moved the choice of *who* from the
//! runtime to the agent, and nothing in GaugeDesk let an agent make that choice:
//! the org directory knew the answer and no agent-facing surface exposed it. This
//! is the join. One roster, read by both paths that need a person — asking a
//! question (ADR 0113) and directing an issue at someone.
//!
//! **Derived, never authored.** A roster row is a projection of an `Active`
//! membership (`INV-5`). An invited or deprovisioned member carries no standing
//! (`INV-20`), so they are not on it: asking them is a question nobody receives,
//! and assigning them is work nobody owns.
//!
//! **Assignment is advisory, and that is a decision rather than a shortcut**
//! (§"only the assignee may claim", below). WhippleScript made `assigned_to`
//! advisory because that crate lacks an authority model. GaugeDesk *has* one, so
//! it could enforce "only the assignee may claim" — and deliberately does not.
//! Enforcing it converts an away assignee into stuck work, which is the opposite
//! of what a shared queue is for; the queue's whole premise is that anyone with
//! access can pick an item up. Exclusivity is what `claim` already provides, with
//! a holder and an expiry, and it is earned by taking the work rather than
//! granted by being named. So assignment records who *should* act, `claim`
//! records who *is* acting, and nothing conflates them.
//!
//! **The whip surface deliberately gains no assignee.** WhippleScript DR-0051 §5
//! extends NMIF to *who is asked*: a `file issue` whose assignee derives from a
//! low-integrity source must be refused when the resulting issue is later claimed
//! endorsed, because choosing the endorser is part of the crossing. That check is
//! recorded as vacuous *because* the language has no assignee field to steer.
//! Assignment here is a host act by an authenticated actor or an agent tool call
//! the host resolves — it never becomes whip syntax — so §5 stays vacuous by
//! design rather than by oversight. Putting an assignee into `file issue` is the
//! change that makes the check load-bearing, and it must not happen without it.

use crate::agent_question::Addressee;
use crate::Workbench;

impl Workbench {
    /// Resolve a name — an authority or a display name — to an authority.
    ///
    /// Shared by the ask path and the assign path so the two can never disagree
    /// about who exists. Accepting the display name matters: an agent writes what
    /// it saw, and refusing `alex@example.com` because the row is keyed by an
    /// opaque authority would be a distinction only the implementation cares
    /// about.
    pub fn resolve_on_roster(&self, requested: &str) -> Option<String> {
        self.roster()
            .into_iter()
            .find(|person| person.authority == requested || person.display == requested)
            .map(|person| person.authority)
    }
}

/// The roster as the agent's tool schema shows it: the authorities it may name.
///
/// Rendered into the `ask` tool's `to` field so the model *chooses from* a list
/// rather than guessing and being refused. The refusal path stays — a roster can
/// change between the schema being built and the call arriving — but guessing
/// should not be the primary way an agent finds a person.
pub fn tool_choices(roster: &[Addressee]) -> Vec<String> {
    roster
        .iter()
        .map(|person| person.authority.clone())
        .collect()
}

/// One line per person, for the tool description. Authority plus who it is, so a
/// model picking from `tool_choices` knows which opaque string is which human.
pub fn tool_description(roster: &[Addressee]) -> String {
    roster
        .iter()
        .map(|person| {
            if person.display == person.authority {
                format!("{} ({})", person.authority, person.role)
            } else {
                format!(
                    "{} — {} ({})",
                    person.authority, person.display, person.role
                )
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_question::Addressee;

    fn person(authority: &str, display: &str, role: &str) -> Addressee {
        Addressee {
            authority: authority.to_owned(),
            display: display.to_owned(),
            role: role.to_owned(),
        }
    }

    #[test]
    fn the_tool_offers_authorities_and_says_who_each_one_is() {
        let roster = vec![
            person("auth:alex", "alex@example.com", "admin"),
            person("auth:owner", "auth:owner", "owner"),
        ];
        // The model picks an authority, because that is what the host resolves.
        assert_eq!(tool_choices(&roster), vec!["auth:alex", "auth:owner"]);
        // ...and is told which opaque string is which human, or it would be
        // choosing between indistinguishable identifiers.
        let described = tool_description(&roster);
        assert!(described.contains("auth:alex — alex@example.com (admin)"));
        // A row whose display *is* its authority does not repeat itself.
        assert!(described.contains("auth:owner (owner)"));
        assert!(!described.contains("auth:owner — auth:owner"));
    }

    #[test]
    fn an_empty_roster_offers_nothing_rather_than_an_empty_choice() {
        // An `enum: []` would make the field unsatisfiable, so a caller with no
        // directory must leave `to` a free string the host still resolves.
        assert!(tool_choices(&[]).is_empty());
        assert!(tool_description(&[]).is_empty());
    }
}
