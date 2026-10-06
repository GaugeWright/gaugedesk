//! Staff questions publish as a phase of the exact original submitted task.
use super::{office_turn_startup::OfficeTurnContext, RunState};
use crate::choice_prompt::{ChoiceCard, ChoiceRequest, CARD_KIND};
use crate::LockUnpoisoned;
use gaugedesk_store::{command_dispatch::LifecycleBatch, AdmitError, CommandRecordFact};

fn refused(reason: &'static str) -> AdmitError {
    AdmitError::Rejected(gaugedesk_core::Rejection { reason })
}

pub(crate) fn ask(
    office: &OfficeTurnContext<'_>,
    chat: &str,
    call_key: &str,
    request: &ChoiceRequest,
) -> Result<ChoiceCard, String> {
    admit(office, chat, call_key, request).map_err(|error| format!("{error:?}"))
}

fn admit(
    office: &OfficeTurnContext<'_>,
    chat: &str,
    call_key: &str,
    request: &ChoiceRequest,
) -> Result<ChoiceCard, AdmitError> {
    if chat != office.authority.chat() || call_key.is_empty() {
        return Err(refused("office question differs from original task"));
    }
    let mut wb = office.wb.lock_unpoisoned();
    let authority = office.authority.prepare_basis(&wb)?;
    let original = office.original;
    // Structured encoding prevents command/call separator collisions.
    let identity = serde_json::to_vec(&(original.command_id(), call_key))?;
    let bound_call = format!(
        "office-question:{}",
        crate::command_idempotency::digest(&identity)
    );
    let home_recipient = wb
        .home_owner_account()
        .unwrap_or_else(|| wb.authority().as_str().to_owned());
    let (card, observed) = wb.store_ref().read_for_dispatch(
        &[chat, crate::org::ORG_SCOPE, crate::library::LIBRARY_SCOPE],
        |reader| {
            reader.retained_events(chat)?;
            reader.retained_events(crate::org::ORG_SCOPE)?;
            let org = crate::org::Org::rebuild(reader)?;
            reader.retained_events(crate::library::LIBRARY_SCOPE)?;
            let library = crate::library::Library::rebuild(reader)?;
            let default_recipient = library
                .chats
                .get(chat)
                .and_then(|chat| chat.owner.as_deref())
                .unwrap_or(&home_recipient);
            let requested = request.to.as_deref().unwrap_or(default_recipient);
            let matches: Vec<_> = org
                .members
                .values()
                .filter(|member| {
                    member.status == crate::org::MembershipStatus::Active
                        && (member.authority == requested
                            || (!member.email.is_empty() && member.email == requested))
                })
                .collect();
            if matches.len() != 1
                || !org.can_access_project(&matches[0].authority, office.authority.project())
            {
                return Err(refused(
                    "office question recipient lacks current project access",
                ));
            }
            let existing = reader
                .records(chat, CARD_KIND)?
                .into_iter()
                .map(|row| serde_json::from_str::<ChoiceCard>(&row).map_err(AdmitError::Json))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .find(|card| card.origin_call_key == bound_call);
            let timestamp = existing
                .as_ref()
                .map(|card| card.asked_at_unix_ms)
                .unwrap_or_else(|| {
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64
                });
            let mut card = crate::choice_prompt::prepare_card(
                chat,
                &bound_call,
                &matches[0].authority,
                request,
                timestamp,
            )
            .map_err(|_| refused("office question input is invalid"))?;
            card.asked_by = Some(office.authority.actor().into());
            card.origin_command_id = Some(original.command_id().into());
            card.origin_request_digest = Some(crate::command_idempotency::digest(
                &serde_json::to_vec(request)?,
            ));
            if existing.as_ref().is_some_and(|existing| existing != &card) {
                return Err(refused("office question retry changed original input"));
            }
            Ok(card)
        },
    )?;
    let basis = authority.combine(observed)?;
    let facts = [CommandRecordFact {
        scope_id: chat.into(),
        kind: CARD_KIND.into(),
        payload: serde_json::to_string(&card)?,
    }];
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
                &bound_call,
                LifecycleBatch::<RunState> {
                    scope: chat.into(),
                    commands: vec![],
                },
                &facts,
            )
        })??;
    wb.notify_library_changed("question", chat, "upsert");
    Ok(card)
}
