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

/// Why work could not be directed at someone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AssignError {
    /// The named person is not on this roster. Carries the roster, so a refusal
    /// is also the discovery path — an agent that guessed wrong learns who it
    /// could have asked instead of only that it failed.
    NotOnRoster {
        requested: String,
        roster: Vec<String>,
    },
    /// No such work item, or the tracker refused.
    Tracker(String),
}

impl std::fmt::Display for AssignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotOnRoster { requested, roster } => write!(
                f,
                "`{requested}` is not someone you can assign work to; available: {}",
                roster.join(", ")
            ),
            Self::Tracker(detail) => write!(f, "{detail}"),
        }
    }
}

impl std::error::Error for AssignError {}

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

    /// Direct an open issue at someone, or clear it with `None`.
    ///
    /// The assignee is bound to a roster authority before it is stored, which is
    /// what makes `assigned_to` a typed reference rather than the opaque string
    /// WhippleScript keeps. Advisory by construction: nothing here consults the
    /// assignee when someone claims.
    pub fn assign_work_item(
        &mut self,
        boundary_id: &str,
        item_id: &str,
        to: Option<&str>,
    ) -> Result<Option<String>, AssignError> {
        let assignee = match to {
            None => None,
            Some(requested) => match self.resolve_on_roster(requested) {
                Some(authority) => Some(authority),
                None => {
                    return Err(AssignError::NotOnRoster {
                        requested: requested.to_owned(),
                        roster: self
                            .roster()
                            .into_iter()
                            .map(|person| person.display)
                            .collect(),
                    })
                }
            },
        };
        let tracker = self
            .tracker_for_boundary(boundary_id)
            .map_err(|error| AssignError::Tracker(format!("{error:?}")))?;
        tracker
            .assign_item(item_id, assignee.as_deref())
            .map_err(|error| AssignError::Tracker(format!("{error:?}")))?;
        Ok(assignee)
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

    #[test]
    fn a_refusal_names_who_could_have_been_asked() {
        // The refusal is also the discovery path: an agent that guessed wrong
        // learns the roster rather than only that it failed.
        let error = AssignError::NotOnRoster {
            requested: "someone-else".to_owned(),
            roster: vec!["alex@example.com".to_owned(), "sam@example.com".to_owned()],
        };
        let message = error.to_string();
        assert!(message.contains("someone-else"));
        assert!(message.contains("alex@example.com"));
        assert!(message.contains("sam@example.com"));
    }
}
