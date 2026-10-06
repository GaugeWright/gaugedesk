//! Workspace references selected under current office project authority.
use crate::{
    identity::{ActorAuthentication, AuthenticatedActionContext},
    LockUnpoisoned, ServerEvent, SharedWorkbench,
};
use axum::{
    http::StatusCode,
    response::{
        sse::{Event, Sse},
        IntoResponse, Response,
    },
};
use futures::Stream;
use gaugedesk_core::ids::HomeId;
use gaugedesk_store::AdmitError;
use std::{
    collections::BTreeSet,
    convert::Infallible,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio_stream::wrappers::BroadcastStream;

type References = BTreeSet<(String, String)>;

/// Closed notification vocabulary. Unknown/account/session records never enter
/// this projection, even if their id happens to equal an accessible project.
fn references(
    lib: &crate::library::Library,
    org: &crate::org::Org,
    actor: &str,
    home: &HomeId,
) -> References {
    let allowed = |project: &str| {
        lib.project_home_id(project) == Some(home) && org.can_access_project(actor, project)
    };
    let mut visible = References::new();
    let mut add = |record: &str, id: &str| {
        visible.insert((record.into(), id.into()));
    };
    for project in lib.projects.keys().filter(|id| allowed(id)) {
        for kind in [
            "project",
            "project_tracker",
            "quarantine",
            "project-model-access",
        ] {
            add(kind, project);
        }
    }
    for instance in lib.instances.values() {
        if instance.project_id.as_deref().is_some_and(&allowed) {
            add("placement", &instance.id);
            add("archetype", &instance.agent_id);
        }
    }
    for chat in lib.chats.keys() {
        if lib.project_of_chat(chat).is_some_and(&allowed) {
            add("chat", chat);
            add("question", chat);
        }
    }
    for workstream in lib.workstreams.values() {
        if lib
            .project_of_instance(&workstream.instance_id)
            .is_some_and(&allowed)
        {
            add("workstream", &workstream.id);
        }
    }
    for target in lib.work_targets.values() {
        if let crate::library::WorkTargetOwner::Project { project_id } = &target.owner {
            if allowed(project_id) {
                add("work_target", &target.id);
            }
        }
    }
    for deployment in lib.public_deployments.values() {
        if allowed(&deployment.project_id) {
            add("public_deployment", &deployment.id);
        }
    }
    visible
}

struct OfficeWorkspaceStream {
    wb: SharedWorkbench,
    source: super::lease::OfficeStaffActionAuthority,
    client: crate::client_admission::ClientBuild,
    visible: References,
    events: BroadcastStream<ServerEvent>,
    checks: tokio::time::Interval,
    ended: bool,
}

impl OfficeWorkspaceStream {
    fn open(
        wb: SharedWorkbench,
        context: &AuthenticatedActionContext,
        client: crate::client_admission::ClientBuild,
    ) -> Result<Self, AdmitError> {
        let ActorAuthentication::OfficeStaff { authority } = context.authentication() else {
            return Err(AdmitError::Rejected(gaugedesk_core::Rejection {
                reason: "office stream requires staff standing",
            }));
        };
        let events = BroadcastStream::new(wb.lock_unpoisoned().workspace_sender().subscribe());
        let mut stream = Self {
            wb,
            source: authority.clone(),
            client,
            visible: References::new(),
            events,
            checks: tokio::time::interval(Duration::from_secs(1)),
            ended: false,
        };
        let _ = stream.frame(None, false, false)?;
        Ok(stream)
    }

    fn frame(
        &mut self,
        event: Option<ServerEvent>,
        heartbeat: bool,
        lagged: bool,
    ) -> Result<Option<Event>, AdmitError> {
        let mut wb = self.wb.lock_unpoisoned();
        let (visible, basis) = super::chat_stream::prepare_frame(
            &wb,
            &self.source,
            &self.client,
            |lib, org, context| Ok(references(lib, org, context.actor().as_str(), wb.home_id())),
        )?;
        let data = match event {
            Some(ServerEvent::WorkspaceChanged { record, id, op })
                if visible.contains(&(record.clone(), id.clone()))
                    && matches!(op.as_str(), "upsert" | "tombstone") =>
            {
                Some(ServerEvent::WorkspaceChanged { record, id, op })
            }
            _ => None,
        };
        let changed = visible != self.visible;
        let frame = wb.store_mut().with_dispatch_basis(&basis, || {
            if changed || lagged {
                // The client refreshes its authorized workspace, including removals.
                // No retired or newly inaccessible id crosses this boundary.
                Some(
                    Event::default().data(
                        ServerEvent::WorkspaceChanged {
                            record: "project".into(),
                            id: String::new(),
                            op: "upsert".into(),
                        }
                        .to_json(),
                    ),
                )
            } else if let Some(data) = data {
                Some(Event::default().data(data.to_json()))
            } else if heartbeat {
                Some(Event::default().comment("keepalive"))
            } else {
                None
            }
        })?;
        self.visible = visible;
        Ok(frame)
    }
}

impl Stream for OfficeWorkspaceStream {
    type Item = Result<Event, Infallible>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.ended {
            return Poll::Ready(None);
        }
        let heartbeat = self.checks.poll_tick(cx).is_ready();
        let (event, lagged) = match Pin::new(&mut self.events).poll_next(cx) {
            Poll::Ready(Some(Ok(event))) => (Some(event), false),
            Poll::Ready(Some(Err(_))) => (None, true),
            Poll::Ready(None) => {
                self.ended = true;
                return Poll::Ready(None);
            }
            Poll::Pending if !heartbeat => return Poll::Pending,
            _ => (None, false),
        };
        match self.frame(event, heartbeat, lagged) {
            Ok(Some(frame)) => Poll::Ready(Some(Ok(frame))),
            Ok(None) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
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
    client: crate::client_admission::ClientBuild,
) -> Response {
    match OfficeWorkspaceStream::open(wb, context, client) {
        Ok(stream) => Sse::new(stream).into_response(),
        Err(_) => (StatusCode::FORBIDDEN, "office stream is unavailable").into_response(),
    }
}
