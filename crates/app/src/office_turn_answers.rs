//! Answer context is released only after the original pending task's phase commits.
use super::office_authority::OfficeTaskAuthority;
use super::RunState;
use crate::agent_question::{AgentQuestion, QuestionState, QUESTION_KIND};
use crate::command_idempotency::ClaimedHttpCommand;
use crate::workbench_state::Workbench;
use gaugedesk_store::{command_dispatch::LifecycleBatch, AdmitError, CommandRecordFact, Store};
use serde::{Deserialize, Serialize};

pub(crate) const KIND: &str = "office_legacy_answers";
const PHASE: &str = "legacy-answer-delivery";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    revision: String,
    command: String,
    chat: String,
    answers: Vec<AgentQuestion>,
}
fn refused() -> AdmitError {
    AdmitError::Rejected(gaugedesk_core::Rejection {
        reason: "office answer phase has no exact retained original selection",
    })
}

pub(crate) fn take(
    wb: &mut Workbench,
    authority: &OfficeTaskAuthority,
    original: &ClaimedHttpCommand,
) -> Result<Vec<AgentQuestion>, AdmitError> {
    let chat = authority.chat();
    let questions = crate::agent_question::question_scope(chat);
    let phase_scope = Store::claimed_lifecycle_prefix_scope(original.command_id(), PHASE);
    let authorization = authority.prepare_basis(wb)?;
    let (snapshot, observed) =
        wb.store_ref()
            .read_for_dispatch(&[chat, &questions, &phase_scope], |reader| {
                reader.retained_events(chat)?;
                reader.retained_events(&questions)?;
                reader.retained_events(&phase_scope)?;
                let recorded =
                    reader.claimed_lifecycle_prefix_recorded(original.command_id(), PHASE)?;
                let snapshots = reader
                    .records(chat, KIND)?
                    .into_iter()
                    .map(|row| serde_json::from_str::<Snapshot>(&row).map_err(AdmitError::Json))
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .filter(|snapshot| snapshot.command == original.command_id())
                    .collect::<Vec<_>>();
                let snapshot = match (recorded, snapshots.len()) {
                    (true, 1) => snapshots.into_iter().next().ok_or_else(refused)?,
                    (false, 0) => Snapshot {
                        revision: "office-legacy-answers/v1".into(),
                        command: original.command_id().into(),
                        chat: chat.into(),
                        answers: crate::agent_question::list(reader, chat)?
                            .into_iter()
                            .filter(|question| {
                                !question.answer_delivered
                                    && matches!(question.state, QuestionState::Answered { .. })
                            })
                            .collect(),
                    },
                    _ => return Err(refused()),
                };
                if snapshot.revision != "office-legacy-answers/v1"
                    || snapshot.chat != chat
                    || snapshot.answers.iter().any(|question| {
                        question.chat_id != chat
                            || question.id.is_empty()
                            || question.answer_delivered
                            || !matches!(question.state, QuestionState::Answered { .. })
                    })
                {
                    return Err(refused());
                }
                Ok(snapshot)
            })?;
    let basis = authorization.combine(observed)?;
    let mut facts = vec![CommandRecordFact {
        scope_id: chat.into(),
        kind: KIND.into(),
        payload: serde_json::to_string(&snapshot)?,
    }];
    for answer in &snapshot.answers {
        let mut delivered = answer.clone();
        delivered.answer_delivered = true;
        facts.push(CommandRecordFact {
            scope_id: questions.clone(),
            kind: QUESTION_KIND.into(),
            payload: serde_json::to_string(&delivered)?,
        });
    }
    wb.store_mut()
        .with_dispatch_record_admission(&basis, |writer| {
            writer.require_pending_claim(
                original.command_id(),
                original.scope(),
                original.key(),
                original.snapshot(),
            )?;
            writer.commit_claimed_lifecycle_prefix(
                original.command_id(),
                original.scope(),
                original.key(),
                original.snapshot(),
                PHASE,
                LifecycleBatch::<RunState> {
                    scope: chat.into(),
                    commands: vec![],
                },
                &facts,
            )
        })??;
    Ok(snapshot.answers)
}
