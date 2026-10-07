//! Current office authority at every SSE publication boundary.
use std::{
    convert::Infallible,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use axum::{
    http::StatusCode,
    response::{
        sse::{Event, Sse},
        IntoResponse, Response,
    },
};
use futures::Stream;
use gaugedesk_store::AdmitError;
use tokio_stream::wrappers::BroadcastStream;

use crate::{
    identity::{ActorAuthentication, AuthenticatedActionContext},
    LockUnpoisoned, ServerEvent, SharedWorkbench,
};

pub(crate) struct OfficeChatStream {
    wb: SharedWorkbench,
    source: super::lease::OfficeStaffActionAuthority,
    chat: String,
    project: String,
    client: crate::client_admission::ClientBuild,
    events: BroadcastStream<ServerEvent>,
    checks: tokio::time::Interval,
    ended: bool,
}

fn refused() -> AdmitError {
    AdmitError::Rejected(gaugedesk_core::Rejection {
        reason: "office stream authority ended",
    })
}

impl OfficeChatStream {
    pub(crate) fn open(
        wb: SharedWorkbench,
        context: &AuthenticatedActionContext,
        chat: String,
        client: crate::client_admission::ClientBuild,
    ) -> Result<Self, AdmitError> {
        let ActorAuthentication::OfficeStaff { authority } = context.authentication() else {
            return Err(refused());
        };
        let (project, events) = {
            let mut guard = wb.lock_unpoisoned();
            guard
                .store_ref()
                .retained_events(crate::library::LIBRARY_SCOPE)?;
            let lib = crate::library::Library::rebuild(guard.store_ref())?;
            let project = lib.project_of_chat(&chat).ok_or_else(refused)?.to_owned();
            (
                project,
                BroadcastStream::new(guard.sender(&chat).subscribe()),
            )
        };
        let stream = Self {
            wb,
            source: authority.clone(),
            chat,
            project,
            client,
            events,
            checks: tokio::time::interval(Duration::from_secs(1)),
            ended: false,
        };
        let _ = stream.frame(None)?;
        Ok(stream)
    }

    /// No await or pre-serialized work between the final writer fence and the
    /// ready frame. A quiet stream also rechecks authority, without user activity.
    fn frame(&self, event: Option<ServerEvent>) -> Result<Event, AdmitError> {
        let mut wb = self.wb.lock_unpoisoned();
        let (_, basis) = prepare_frame(&wb, &self.source, &self.client, |lib, org, context| {
            if lib.project_of_chat(&self.chat) != Some(self.project.as_str())
                || lib.project_home_id(&self.project) != Some(wb.home_id())
                || !org.can_access_project(context.actor().as_str(), &self.project)
            {
                return Err(refused());
            }
            Ok(())
        })?;
        wb.store_mut().with_dispatch_basis(&basis, || match event {
            Some(event) => Event::default().data(event.to_json()),
            None => Event::default().comment("keepalive"),
        })
    }
}

/// Shared source, policy and scope fence for office stream publication. Resource
/// selection must use these current projections, never the Workbench cache.
pub(super) fn prepare_frame<T>(
    wb: &crate::Workbench,
    source: &super::lease::OfficeStaffActionAuthority,
    client: &crate::client_admission::ClientBuild,
    select: impl FnOnce(
        &crate::library::Library,
        &crate::org::Org,
        &AuthenticatedActionContext,
    ) -> Result<T, AdmitError>,
) -> Result<(T, gaugedesk_store::command_dispatch::DispatchReadBasis), AdmitError> {
    let context = wb
        .office_staff_dispatch_context(
            source.actor().as_str(),
            source.source_reference(),
            source.process_epoch(),
            source.admission_reference(),
        )
        .ok_or_else(refused)?;
    let ActorAuthentication::OfficeStaff { authority } = context.authentication() else {
        return Err(refused());
    };
    let (selected, basis) = wb.store_ref().read_for_dispatch(
        &[crate::library::LIBRARY_SCOPE, crate::org::ORG_SCOPE],
        |reader| {
            reader.retained_events(crate::library::LIBRARY_SCOPE)?;
            reader.retained_events(crate::org::ORG_SCOPE)?;
            let lib = crate::library::Library::rebuild(reader)?;
            let org = crate::org::Org::rebuild(reader)?;
            crate::identity::revalidate_action_context(reader, wb.home_id(), &context)?;
            if crate::client_admission::evaluate_client(
                org.software_policy.as_ref(),
                client,
                authority.now_ms(),
            )
            .status
                == crate::client_admission::ClientAdmissionStatus::Blocked
            {
                return Err(refused());
            }
            select(&lib, &org, &context)
        },
    )?;
    Ok((selected, authority.bind_basis(wb.store_ref(), basis, None)?))
}

impl Stream for OfficeChatStream {
    type Item = Result<Event, Infallible>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.ended {
            return Poll::Ready(None);
        }
        let check = self.checks.poll_tick(cx).is_ready();
        let event = match Pin::new(&mut self.events).poll_next(cx) {
            Poll::Ready(Some(Ok(event))) => Some(event),
            Poll::Ready(None) => {
                self.ended = true;
                return Poll::Ready(None);
            }
            // A lagged subscriber has missed events it can never be sent: end
            // the stream so the client reconnects and reloads the durable
            // transcript, rather than continuing with a gap (SCALE-4).
            Poll::Ready(Some(Err(_))) => {
                self.ended = true;
                return Poll::Ready(None);
            }
            Poll::Pending if !check => return Poll::Pending,
            _ => None,
        };
        match self.frame(event) {
            Ok(frame) => Poll::Ready(Some(Ok(frame))),
            Err(_) => {
                self.ended = true;
                Poll::Ready(None)
            }
        }
    }
}

pub(crate) fn response(
    wb: SharedWorkbench,
    context: &AuthenticatedActionContext,
    chat: String,
    client: crate::client_admission::ClientBuild,
) -> Response {
    match OfficeChatStream::open(wb, context, chat, client) {
        Ok(stream) => Sse::new(stream).into_response(),
        Err(_) => (StatusCode::FORBIDDEN, "office stream is unavailable").into_response(),
    }
}
