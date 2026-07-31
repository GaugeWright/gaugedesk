//! An agent's question, addressed to a person (ADR 0113).
//!
//! WhippleScript removed `ask_human` (DR-0050) because it fused communication
//! with control flow and named neither the party nor the channel. This is the
//! replacement, and it differs on all three counts:
//!
//! - **It does not block.** The tool returns the question's id, the turn settles
//!   (ADR 0111), and the answer arrives as context in a later turn. `blocking`
//!   is the agent *declaring* it cannot usefully proceed — a stronger signal and
//!   no automatic continuation — never a lock on the person's own chat.
//! - **It names the party.** A recipient, defaulting to the chat owner, resolved
//!   against the account roster. Deliberately the opposite of the collection
//!   inbox, where unassigned means whoever has access because a drained artifact
//!   is directed at nobody.
//! - **It is a governed ability.** `question.ask` is a capability the
//!   `gaugewright` package declares, so an archetype whose ceiling omits it
//!   cannot ask at all.
//!
//! The record here is GaugeDesk's own. An earlier draft leaned the outstanding
//! question on an unsettled WhippleScript effect, which is durable for free —
//! but a tool call returns, so there is no pending effect in this path. One
//! writer, one reader, no correlation between two stores.

use std::collections::BTreeMap;

use gaugewright_store::{AdmitError, Store};
use serde::{Deserialize, Serialize};

use crate::workbench_state::Workbench;

/// The capability that admits asking, and the turn resource it admits.
///
/// Single-sourced from the crate that owns the *gate* (app depends on
/// whip-runtime, not the reverse), so the manifest, the ceiling check, and this
/// record cannot drift onto three different strings — the drift `ASK-1` flagged
/// as ungated. `tests/gaugewright_package.rs` ties the manifest's JSON to these.
pub use gaugewright_whip_runtime::{QUESTION_ASK_CAPABILITY, QUESTION_RESOURCE};

/// The GaugeWright package manifest, registered beside the std set.
pub const GAUGEWRIGHT_PACKAGE_MANIFEST: &str = include_str!("../packages/gaugewright.json");

const QUESTION_KIND: &str = "agent-question";

/// One person an agent may address.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Addressee {
    pub authority: String,
    pub display: String,
    pub role: String,
}

/// Where a question stands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum QuestionState {
    /// Asked, unanswered. This is what raises the `question` signal.
    Open,
    Answered {
        answer: String,
        answered_by: String,
    },
    /// Withdrawn without an answer. Kept rather than deleted so the record stays
    /// honest about what was asked.
    Withdrawn,
}

/// One question an agent asked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentQuestion {
    pub id: String,
    pub chat_id: String,
    pub question: String,
    /// Admitted answers. Empty means any text is acceptable.
    #[serde(default)]
    pub choices: Vec<String>,
    /// Who should answer. Advisory: anyone with access to the chat may.
    pub recipient: String,
    /// The agent declaring it cannot usefully proceed without an answer.
    #[serde(default)]
    pub blocking: bool,
    pub asked_at_unix_ms: u64,
    pub state: QuestionState,
    /// Whether the answer has been handed to the asking agent as turn context.
    ///
    /// A question settles its turn (ADR 0111 §1), so the answer cannot be returned
    /// to the call that asked — it rides the *next* turn's prompt instead, which is
    /// exactly what the `ask` tool promises the agent when it returns. This flag is
    /// what keeps that delivery **once**: without it every later turn would replay
    /// every answer the chat has ever received.
    #[serde(default)]
    pub answer_delivered: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AskError {
    /// Carries the roster so the caller can correct itself rather than guess.
    UnknownRecipient {
        requested: String,
        roster: Vec<String>,
    },
    Refused(String),
    Store(String),
}

impl std::fmt::Display for AskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownRecipient { requested, roster } => write!(
                f,
                "`{requested}` is not someone you can ask; available: {}",
                roster.join(", ")
            ),
            Self::Refused(detail) | Self::Store(detail) => write!(f, "{detail}"),
        }
    }
}

impl std::error::Error for AskError {}

fn question_scope(chat_id: &str) -> String {
    format!("questions::{chat_id}")
}

impl Workbench {
    /// Everyone the asking agent may address, in a stable order.
    ///
    /// Only `Active` members: an invited or deprovisioned one carries no
    /// standing, so asking them would be a question nobody receives.
    ///
    /// This is *the* roster (`GATE-3f`), not the ask path's private one — the
    /// assign path resolves against the same list, so the two can never disagree
    /// about who exists. See [`crate::roster`].
    pub fn roster(&self) -> Vec<Addressee> {
        let mut people: BTreeMap<String, Addressee> = BTreeMap::new();
        let acting = self.authority().as_str().to_owned();
        people.insert(
            acting.clone(),
            Addressee {
                authority: acting.clone(),
                display: acting,
                role: "owner".to_owned(),
            },
        );
        if let Ok(org) = crate::org::Org::rebuild_in(
            self.store_ref(),
            crate::workbench_state::ACCOUNT_GLOBAL_BOUNDARY,
        ) {
            for member in org.members.values() {
                if member.status != crate::org::MembershipStatus::Active {
                    continue;
                }
                people.insert(
                    member.authority.clone(),
                    Addressee {
                        authority: member.authority.clone(),
                        display: if member.email.is_empty() {
                            member.authority.clone()
                        } else {
                            member.email.clone()
                        },
                        role: member.role.clone(),
                    },
                );
            }
        }
        people.into_values().collect()
    }

    /// The default recipient for `chat_id`: its owner. The single-authority
    /// collapse makes that the acting authority; when chats carry a distinct
    /// owner this reads it instead and no call site changes.
    pub fn default_addressee(&self, _chat_id: &str) -> String {
        self.authority().as_str().to_owned()
    }

    /// Ask a person a question. Returns the question's id.
    pub fn ask_question(
        &mut self,
        chat_id: &str,
        question: &str,
        choices: &[String],
        to: Option<&str>,
        blocking: bool,
    ) -> Result<String, AskError> {
        let question = question.trim();
        if question.is_empty() {
            return Err(AskError::Refused("a question needs text".to_owned()));
        }
        let recipient = match to {
            None => self.default_addressee(chat_id),
            Some(requested) => {
                let roster = self.roster();
                match roster
                    .iter()
                    .find(|person| person.authority == requested || person.display == requested)
                {
                    Some(person) => person.authority.clone(),
                    None => {
                        return Err(AskError::UnknownRecipient {
                            requested: requested.to_owned(),
                            roster: roster.into_iter().map(|person| person.display).collect(),
                        })
                    }
                }
            }
        };
        let asked_at_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| AskError::Store(error.to_string()))?
            .as_millis() as u64;
        let asked_so_far = list(self.store_ref(), chat_id)
            .map_err(|error| AskError::Store(format!("{error:?}")))?
            .len();
        let id = format!("q-{chat_id}-{}", asked_so_far + 1);
        let record = AgentQuestion {
            id: id.clone(),
            chat_id: chat_id.to_owned(),
            question: question.to_owned(),
            choices: choices.to_vec(),
            recipient,
            blocking,
            asked_at_unix_ms,
            state: QuestionState::Open,
            answer_delivered: false,
        };
        put(self.store_mut(), &record).map_err(|error| AskError::Store(format!("{error:?}")))?;
        self.notify_library_changed("question", chat_id, "upsert");
        Ok(id)
    }

    /// Answer a question, attributing it to `answered_by`.
    ///
    /// Anyone with access to the chat may answer, whoever the recipient names —
    /// the recipient says who *should*, not who *may*, which keeps a question
    /// from dying with one unavailable person.
    pub fn answer_question(
        &mut self,
        chat_id: &str,
        id: &str,
        answer: &str,
        answered_by: &str,
    ) -> Result<bool, AskError> {
        let answer = answer.trim();
        if answer.is_empty() {
            return Err(AskError::Refused("an answer needs text".to_owned()));
        }
        let Some(existing) = get(self.store_ref(), chat_id, id)
            .map_err(|error| AskError::Store(format!("{error:?}")))?
        else {
            return Ok(false);
        };
        if existing.state != QuestionState::Open {
            return Ok(false);
        }
        if !existing.choices.is_empty() && !existing.choices.iter().any(|choice| choice == answer) {
            return Err(AskError::Refused(format!(
                "`{answer}` is not one of the offered choices: {}",
                existing.choices.join(", ")
            )));
        }
        let answered = AgentQuestion {
            state: QuestionState::Answered {
                answer: answer.to_owned(),
                answered_by: answered_by.to_owned(),
            },
            ..existing
        };
        put(self.store_mut(), &answered).map_err(|error| AskError::Store(format!("{error:?}")))?;
        self.notify_library_changed("question", chat_id, "upsert");
        Ok(true)
    }

    /// Withdraw an unanswered question.
    pub fn withdraw_question(&mut self, chat_id: &str, id: &str) -> Result<bool, AskError> {
        let Some(existing) = get(self.store_ref(), chat_id, id)
            .map_err(|error| AskError::Store(format!("{error:?}")))?
        else {
            return Ok(false);
        };
        if existing.state != QuestionState::Open {
            return Ok(false);
        }
        let withdrawn = AgentQuestion {
            state: QuestionState::Withdrawn,
            ..existing
        };
        put(self.store_mut(), &withdrawn).map_err(|error| AskError::Store(format!("{error:?}")))?;
        self.notify_library_changed("question", chat_id, "upsert");
        Ok(true)
    }

    /// Take the answers this chat has received but not yet handed to its agent,
    /// marking them delivered.
    ///
    /// Called once at the start of a turn. Taking and marking together is what
    /// makes delivery exactly-once: an answer the agent has already been told is
    /// not repeated on every subsequent turn, and one that arrived mid-turn is not
    /// lost — it is simply picked up by the next one.
    pub fn take_undelivered_answers(&mut self, chat_id: &str) -> Vec<AgentQuestion> {
        let undelivered: Vec<AgentQuestion> = list(self.store_ref(), chat_id)
            .unwrap_or_default()
            .into_iter()
            .filter(|question| {
                !question.answer_delivered
                    && matches!(question.state, QuestionState::Answered { .. })
            })
            .collect();
        for question in &undelivered {
            let delivered = AgentQuestion {
                answer_delivered: true,
                ..question.clone()
            };
            if let Err(error) = put(self.store_mut(), &delivered) {
                tracing::warn!(?error, chat = %chat_id, "could not mark an answer delivered");
            }
        }
        undelivered
    }

    /// Answers this chat has received — the context a later turn carries.
    pub fn answered_questions(&self, chat_id: &str) -> Vec<AgentQuestion> {
        list(self.store_ref(), chat_id)
            .unwrap_or_default()
            .into_iter()
            .filter(|question| matches!(question.state, QuestionState::Answered { .. }))
            .collect()
    }
}

fn put(store: &mut Store, question: &AgentQuestion) -> Result<(), AdmitError> {
    let payload = serde_json::to_string(question)?;
    store.append_record(&question_scope(&question.chat_id), QUESTION_KIND, &payload)?;
    Ok(())
}

/// Every question in a chat at its current state, oldest first.
pub fn list(store: &Store, chat_id: &str) -> Result<Vec<AgentQuestion>, AdmitError> {
    let mut latest: BTreeMap<String, AgentQuestion> = BTreeMap::new();
    for row in store.records(&question_scope(chat_id), QUESTION_KIND)? {
        let question: AgentQuestion = serde_json::from_str(&row)?;
        // records() is position-ordered, so a later write wins.
        latest.insert(question.id.clone(), question);
    }
    let mut questions: Vec<AgentQuestion> = latest.into_values().collect();
    questions.sort_by_key(|question| question.asked_at_unix_ms);
    Ok(questions)
}

pub fn get(store: &Store, chat_id: &str, id: &str) -> Result<Option<AgentQuestion>, AdmitError> {
    Ok(list(store, chat_id)?
        .into_iter()
        .find(|question| question.id == id))
}

/// Unanswered questions — what raises the `question` signal (ADR 0082 §3).
pub fn open_questions(store: &Store, chat_id: &str) -> Result<Vec<AgentQuestion>, AdmitError> {
    Ok(list(store, chat_id)?
        .into_iter()
        .filter(|question| question.state == QuestionState::Open)
        .collect())
}

/// Render answers as the context block a turn's prompt carries. Empty when there
/// is nothing to deliver, so an ordinary turn's prompt is untouched.
pub fn answers_context(answers: &[AgentQuestion]) -> String {
    if answers.is_empty() {
        return String::new();
    }
    let mut out = String::from(
        "You asked for input and it has arrived. Answers to your earlier questions:\n",
    );
    for question in answers {
        if let QuestionState::Answered {
            answer,
            answered_by,
        } = &question.state
        {
            out.push_str(&format!(
                "- You asked: {}\n  {answered_by} answered: {answer}\n",
                question.question
            ));
        }
    }
    out.push('\n');
    out
}

/// Whether an open question declares the agent cannot proceed. Drives the
/// stronger presentation and suppresses automatic continuation — never a
/// human's own turn (ADR 0113 §3).
pub fn is_blocked(store: &Store, chat_id: &str) -> bool {
    open_questions(store, chat_id)
        .unwrap_or_default()
        .iter()
        .any(|question| question.blocking)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LockUnpoisoned;

    fn workbench() -> (tempfile::TempDir, crate::SharedWorkbench) {
        let dir = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(dir.path()).unwrap();
        (dir, wb)
    }

    #[test]
    fn a_question_defaults_to_the_chat_owner() {
        let (_dir, wb) = workbench();
        let mut guard = wb.lock_unpoisoned();
        let owner = guard.default_addressee("chat-1");
        let id = guard
            .ask_question("chat-1", "Which environment?", &[], None, false)
            .expect("asks");
        let question = get(guard.store_ref(), "chat-1", &id).unwrap().unwrap();
        assert_eq!(question.recipient, owner);
        assert_eq!(question.state, QuestionState::Open);
        assert!(!question.blocking);
    }

    #[test]
    fn an_unknown_recipient_is_refused_with_the_roster() {
        let (_dir, wb) = workbench();
        let mut guard = wb.lock_unpoisoned();
        match guard.ask_question("chat-1", "Which?", &[], Some("nobody"), false) {
            Err(AskError::UnknownRecipient { requested, roster }) => {
                assert_eq!(requested, "nobody");
                assert!(
                    !roster.is_empty(),
                    "the refusal carries the roster so the agent corrects itself \
                     rather than guessing again",
                );
            }
            other => panic!("expected a roster-carrying refusal, got {other:?}"),
        }
    }

    #[test]
    fn the_owner_can_be_addressed_by_name() {
        let (_dir, wb) = workbench();
        let mut guard = wb.lock_unpoisoned();
        let owner = guard.default_addressee("chat-1");
        let id = guard
            .ask_question("chat-1", "Which?", &[], Some(&owner), false)
            .expect("asks");
        assert_eq!(
            get(guard.store_ref(), "chat-1", &id)
                .unwrap()
                .unwrap()
                .recipient,
            owner
        );
    }

    #[test]
    fn an_open_question_raises_the_signal_and_an_answer_clears_it() {
        let (_dir, wb) = workbench();
        let mut guard = wb.lock_unpoisoned();
        let id = guard
            .ask_question("chat-1", "Which?", &[], None, false)
            .expect("asks");
        assert_eq!(
            open_questions(guard.store_ref(), "chat-1").unwrap().len(),
            1
        );
        assert!(guard
            .answer_question("chat-1", &id, "staging", "someone-else")
            .expect("answers"));
        assert!(open_questions(guard.store_ref(), "chat-1")
            .unwrap()
            .is_empty());
        assert_eq!(
            guard.answered_questions("chat-1")[0].state,
            QuestionState::Answered {
                answer: "staging".into(),
                answered_by: "someone-else".into()
            },
        );
    }

    #[test]
    fn anyone_may_answer_whoever_the_recipient_names() {
        // The recipient says who *should*, not who *may* — otherwise a question
        // dies with one unavailable person.
        let (_dir, wb) = workbench();
        let mut guard = wb.lock_unpoisoned();
        let id = guard
            .ask_question("chat-1", "Which?", &[], None, false)
            .expect("asks");
        assert!(guard
            .answer_question("chat-1", &id, "prod", "a-different-authority")
            .expect("answers"));
    }

    #[test]
    fn an_answer_outside_the_offered_choices_is_refused() {
        let (_dir, wb) = workbench();
        let mut guard = wb.lock_unpoisoned();
        let choices = vec!["staging".to_owned(), "production".to_owned()];
        let id = guard
            .ask_question("chat-1", "Which?", &choices, None, false)
            .expect("asks");
        assert!(guard
            .answer_question("chat-1", &id, "somewhere else", "owner")
            .is_err());
        assert!(guard
            .answer_question("chat-1", &id, "staging", "owner")
            .expect("a listed choice is accepted"));
    }

    #[test]
    fn a_question_is_answered_once() {
        let (_dir, wb) = workbench();
        let mut guard = wb.lock_unpoisoned();
        let id = guard
            .ask_question("chat-1", "Which?", &[], None, false)
            .expect("asks");
        assert!(guard.answer_question("chat-1", &id, "a", "owner").unwrap());
        assert!(
            !guard.answer_question("chat-1", &id, "b", "owner").unwrap(),
            "a second answer must not overwrite the first",
        );
    }

    #[test]
    fn blocking_is_scoped_to_its_own_chat() {
        let (_dir, wb) = workbench();
        let mut guard = wb.lock_unpoisoned();
        guard
            .ask_question("chat-1", "Need this", &[], None, true)
            .expect("asks");
        assert!(is_blocked(guard.store_ref(), "chat-1"));
        assert!(
            !is_blocked(guard.store_ref(), "chat-2"),
            "one chat's blocking question must not block another",
        );
    }

    #[test]
    fn answering_clears_the_block() {
        let (_dir, wb) = workbench();
        let mut guard = wb.lock_unpoisoned();
        let id = guard
            .ask_question("chat-1", "Need this", &[], None, true)
            .expect("asks");
        guard.answer_question("chat-1", &id, "ok", "owner").unwrap();
        assert!(!is_blocked(guard.store_ref(), "chat-1"));
    }

    #[test]
    fn a_withdrawn_question_stops_asking_but_stays_on_the_record() {
        let (_dir, wb) = workbench();
        let mut guard = wb.lock_unpoisoned();
        let id = guard
            .ask_question("chat-1", "Never mind", &[], None, true)
            .expect("asks");
        assert!(guard.withdraw_question("chat-1", &id).expect("withdraws"));
        assert!(open_questions(guard.store_ref(), "chat-1")
            .unwrap()
            .is_empty());
        assert!(!is_blocked(guard.store_ref(), "chat-1"));
        assert_eq!(
            list(guard.store_ref(), "chat-1").unwrap().len(),
            1,
            "the question stays on the record so it is honest about what was asked",
        );
    }

    #[test]
    fn an_empty_question_or_answer_is_refused() {
        let (_dir, wb) = workbench();
        let mut guard = wb.lock_unpoisoned();
        assert!(guard
            .ask_question("chat-1", "   ", &[], None, false)
            .is_err());
        let id = guard
            .ask_question("chat-1", "Which?", &[], None, false)
            .expect("asks");
        assert!(guard.answer_question("chat-1", &id, "  ", "owner").is_err());
    }

    #[test]
    fn the_shipped_package_manifest_declares_the_capability() {
        // The manifest is what makes asking a governed ability rather than a
        // tool the host hands out unconditionally (ADR 0113 §1).
        let manifest: serde_json::Value =
            serde_json::from_str(GAUGEWRIGHT_PACKAGE_MANIFEST).expect("the manifest parses");
        assert_eq!(manifest["package_id"], "gaugewright");
        let declares = manifest["capabilities"]
            .as_array()
            .expect("capabilities")
            .iter()
            .any(|capability| capability["id"] == QUESTION_ASK_CAPABILITY);
        assert!(
            declares,
            "the package must declare {QUESTION_ASK_CAPABILITY}"
        );
    }

    #[test]
    fn an_answer_reaches_the_agent_once_and_only_once() {
        // A question settles its turn, so the answer cannot be returned to the call
        // that asked — it rides the next turn's prompt. The delivery must happen,
        // and must not repeat on every later turn (ADR 0113 §1).
        let (_dir, wb) = workbench();
        let mut guard = wb.lock_unpoisoned();
        let id = guard
            .ask_question("chat-1", "which region?", &[], None, false)
            .expect("asked");

        assert!(
            guard.take_undelivered_answers("chat-1").is_empty(),
            "an unanswered question carries no context"
        );

        guard
            .answer_question("chat-1", &id, "eu-west-1", "alice")
            .expect("answered");

        let first = guard.take_undelivered_answers("chat-1");
        assert_eq!(first.len(), 1, "the answer is delivered");
        let context = answers_context(&first);
        assert!(
            context.contains("which region?"),
            "the question is restated"
        );
        assert!(context.contains("eu-west-1"), "the answer is carried");
        assert!(context.contains("alice"), "the answer is attributed");

        assert!(
            guard.take_undelivered_answers("chat-1").is_empty(),
            "a delivered answer is never replayed on a later turn"
        );
        assert!(
            answers_context(&[]).is_empty(),
            "an ordinary turn's prompt is untouched"
        );
    }

    #[test]
    fn one_chats_answer_is_not_delivered_to_another() {
        let (_dir, wb) = workbench();
        let mut guard = wb.lock_unpoisoned();
        let id = guard
            .ask_question("chat-1", "which region?", &[], None, false)
            .expect("asked");
        guard
            .answer_question("chat-1", &id, "eu-west-1", "alice")
            .expect("answered");

        assert!(
            guard.take_undelivered_answers("chat-2").is_empty(),
            "answers are scoped to the chat that asked"
        );
        assert_eq!(guard.take_undelivered_answers("chat-1").len(), 1);
    }

    #[test]
    fn the_capability_and_resource_are_the_ones_the_gate_reads() {
        // ASK-1 flagged this as ungated drift: the manifest, the ceiling check, and
        // this record each named the strings independently, so a rename in one would
        // leave a capability that silently never admits anything.
        assert_eq!(
            QUESTION_ASK_CAPABILITY,
            gaugewright_whip_runtime::QUESTION_ASK_CAPABILITY
        );
        assert_eq!(
            QUESTION_RESOURCE,
            gaugewright_whip_runtime::QUESTION_RESOURCE
        );
        let manifest: serde_json::Value =
            serde_json::from_str(GAUGEWRIGHT_PACKAGE_MANIFEST).expect("the manifest parses");
        let provider_backs_it = manifest["providers"]
            .as_array()
            .expect("providers")
            .iter()
            .any(|provider| provider["capability"] == QUESTION_ASK_CAPABILITY);
        assert!(
            provider_backs_it,
            "a capability with no provider admits an effect nothing can execute"
        );
    }
}
