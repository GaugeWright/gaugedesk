use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use gaugedesk_core::boundary_lifecycle::BoundaryState;
use gaugedesk_core::freshness::{Freshness, FreshnessMarker};
use gaugedesk_core::instance::{InstanceCommand, InstanceState};
use gaugedesk_core::merge::MergeState;
use gaugedesk_core::resource_export::{ExportCommand, ExportState};
use gaugedesk_core::review::{ReviewCommand, ReviewState};
use gaugedesk_core::run::{RunCommand, RunState};
use gaugedesk_store::{AdmitError, MaterializedAdmission};
use serde::Deserialize;

use crate::stream::ServerEvent;
use crate::{
    command_idempotency::caller_idempotency_key, err_response, library, library_routes,
    LockUnpoisoned, SharedWorkbench, Workbench,
};

impl Workbench {
    pub(crate) fn boundary_projection_value(
        &self,
        id: &str,
    ) -> Result<serde_json::Value, AdmitError> {
        self.store_ref().fold::<BoundaryState>(id).map(|state| {
            serde_json::json!({
                "state": state,
                "ceiling": library::BoundaryProjection::from_state(&state),
            })
        })
    }

    pub(crate) fn has_instance_record(&self, id: &str) -> bool {
        self.library_has_instance_record(id)
    }

    pub(crate) fn instance_lifecycle_state(&self, id: &str) -> Result<InstanceState, AdmitError> {
        self.store_ref().fold::<InstanceState>(id)
    }

    pub(crate) fn admit_instance_lifecycle(
        &mut self,
        id: &str,
        idempotency_key: &str,
        command: InstanceCommand,
    ) -> Result<MaterializedAdmission<InstanceState>, AdmitError> {
        self.store_mut()
            .admit_materialized::<InstanceState>(id, idempotency_key, command)
    }

    pub(crate) fn run_state(&self, scope: &str) -> Result<RunState, AdmitError> {
        self.store_ref().fold::<RunState>(scope)
    }

    pub(crate) fn admit_run_command(
        &mut self,
        scope: &str,
        idempotency_key: &str,
        command: RunCommand,
    ) -> Result<MaterializedAdmission<RunState>, AdmitError> {
        let admission =
            self.store_mut()
                .admit_materialized::<RunState>(scope, idempotency_key, command)?;
        if !admission.replayed {
            self.publish(
                scope,
                ServerEvent::Admitted {
                    kind: "run".into(),
                    text: format!("run → {:?}", admission.state.phase),
                },
            );
        }
        Ok(admission)
    }

    pub(crate) fn review_state(&self, scope: &str) -> Result<ReviewState, AdmitError> {
        self.store_ref().fold::<ReviewState>(scope)
    }

    pub(crate) fn admit_review_command(
        &mut self,
        scope: &str,
        idempotency_key: &str,
        command: ReviewCommand,
    ) -> Result<MaterializedAdmission<ReviewState>, AdmitError> {
        let admission =
            self.store_mut()
                .admit_materialized::<ReviewState>(scope, idempotency_key, command)?;
        if !admission.replayed {
            self.publish(
                scope,
                ServerEvent::Admitted {
                    kind: "review".into(),
                    text: format!("review → {:?}", admission.state.phase),
                },
            );
        }
        Ok(admission)
    }

    pub(crate) fn export_state(&self, scope: &str) -> Result<ExportState, AdmitError> {
        self.store_ref().fold::<ExportState>(scope)
    }

    pub(crate) fn admit_export_command(
        &mut self,
        scope: &str,
        idempotency_key: &str,
        command: ExportCommand,
    ) -> Result<MaterializedAdmission<ExportState>, AdmitError> {
        let admission =
            self.store_mut()
                .admit_materialized::<ExportState>(scope, idempotency_key, command)?;
        if !admission.replayed {
            self.publish(
                scope,
                ServerEvent::Admitted {
                    kind: "export".into(),
                    text: format!("export → {:?}", admission.state.phase),
                },
            );
        }
        Ok(admission)
    }

    pub(crate) fn fork_forest_value(&self) -> serde_json::Value {
        serde_json::json!({ "forest": self.library_fork_forest() })
    }

    pub(crate) fn lifecycle_projection_value(
        &self,
        scope: &str,
        kind: &str,
    ) -> Result<Option<serde_json::Value>, AdmitError> {
        let value = match kind {
            "run" => serde_json::json!(self.run_state(scope)?),
            "review" => serde_json::json!(self.review_state(scope)?),
            "export" => serde_json::json!(self.export_state(scope)?),
            "boundary" => self.boundary_projection_value(scope)?,
            "merge" => serde_json::json!(self.store_ref().fold::<MergeState>(scope)?),
            "audit" => self.audit_events_value(scope)?,
            _ => return Ok(None),
        };
        Ok(Some(value))
    }

    pub(crate) fn lifecycle_projection_generated_at(&self, scope: &str) -> u64 {
        self.store_ref()
            .events(scope)
            .ok()
            .and_then(|events| {
                events
                    .last()
                    .map(|(position, _, _)| (*position).max(0) as u64)
            })
            .unwrap_or(0)
    }
}

/// The audit timeline (`INV-6`): the ordered event history for a scope.
pub(crate) async fn get_audit(
    State(wb): State<SharedWorkbench>,
    Path(scope): Path<String>,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    match wb.audit_events_value(&scope) {
        Ok(events) => (StatusCode::OK, Json(events)).into_response(),
        Err(e) => err_response(e),
    }
}

/// The instance/deployment lifecycle state (M1, DL-1): fold the instance scope.
pub(crate) async fn get_instance(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    if !wb.has_instance_record(&id) {
        return (StatusCode::NOT_FOUND, "no such instance").into_response();
    }
    match wb.instance_lifecycle_state(&id) {
        Ok(state) => (StatusCode::OK, Json(state)).into_response(),
        Err(e) => err_response(e),
    }
}

/// Drive the instance lifecycle: `Suspend` / `Resume` / `TearDown` (M1). Pinning
/// happens automatically at creation.
pub(crate) async fn post_instance_command(
    State(wb): State<SharedWorkbench>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(command): Json<InstanceCommand>,
) -> impl IntoResponse {
    if let InstanceCommand::SetLocalConfig { config, .. } = &command {
        if !config.trim().is_empty() {
            if let Err(error) = gaugedesk_boundary::AgentConfig::runtime_settings_from_json(config)
            {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("invalid placement config: {error}"),
                )
                    .into_response();
            }
        }
    }
    let key = match caller_idempotency_key(&headers) {
        Ok(key) => key,
        Err(response) => return response,
    };
    let mut wb = wb.lock_unpoisoned();
    if !wb.has_instance_record(&id) {
        return (StatusCode::NOT_FOUND, "no such instance").into_response();
    }
    match wb.admit_instance_lifecycle(&id, &key, command) {
        Ok(admission) => (StatusCode::OK, Json(admission.state)).into_response(),
        Err(AdmitError::Rejected(r)) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "rejected": r.reason })),
        )
            .into_response(),
        Err(e) => err_response(e),
    }
}

/// Query: fold the run scope to current state (a projection; `INV-5`).
pub(crate) async fn get_run(
    State(wb): State<SharedWorkbench>,
    Path(scope): Path<String>,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    match wb.run_state(&scope) {
        Ok(state) => (StatusCode::OK, Json(state)).into_response(),
        Err(e) => err_response(e),
    }
}

/// Command: admit a run command. Rejection is a receipt (409), not a fact (`INV-2`).
pub(crate) async fn post_run_command(
    State(wb): State<SharedWorkbench>,
    Path(scope): Path<String>,
    headers: HeaderMap,
    Json(command): Json<RunCommand>,
) -> impl IntoResponse {
    let key = match caller_idempotency_key(&headers) {
        Ok(key) => key,
        Err(response) => return response,
    };
    let mut wb = wb.lock_unpoisoned();
    match wb.admit_run_command(&scope, &key, command) {
        Ok(admission) => (StatusCode::OK, Json(admission.state)).into_response(),
        Err(AdmitError::Rejected(r)) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "rejected": r.reason })),
        )
            .into_response(),
        Err(e) => err_response(e),
    }
}

/// The `?freshness=` declaration on a projection read (MOB-012). The caller
/// states how current the basis it is reading against is: a fresh online client
/// asks for `live`; an offline cache replays a `stale`/`indeterminate` read so
/// the carriage it stores keeps the honest caveat. Absent means `live`.
#[derive(Deserialize, Default)]
pub(crate) struct FreshnessQuery {
    freshness: Option<String>,
}

impl FreshnessQuery {
    fn marker(&self) -> Result<FreshnessMarker, String> {
        match self.freshness.as_deref() {
            None | Some("live") => Ok(FreshnessMarker::Live),
            Some("stale") => Ok(FreshnessMarker::Stale),
            Some("partial") => Ok(FreshnessMarker::Partial),
            Some("redacted") => Ok(FreshnessMarker::Redacted),
            Some("indeterminate") => Ok(FreshnessMarker::Indeterminate),
            Some(other) => Err(format!("unknown freshness marker: {other}")),
        }
    }
}

/// `GET /projections/library/workspace/:record/:id`: resolve the reference-only
/// workspace event into a freshness-carried delta projection. This preserves the
/// ADR 0037 protection boundary while avoiding a full workspace transfer on every
/// mobile update.
pub(crate) async fn get_workspace_delta(
    State(wb): State<SharedWorkbench>,
    Path((record, id)): Path<(String, String)>,
    Query(q): Query<FreshnessQuery>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let marker = match q.marker() {
        Ok(marker) => marker,
        Err(reason) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": reason })),
            )
                .into_response()
        }
    };
    let wb = wb.lock_unpoisoned();
    let vis = wb.project_visibility_in(
        crate::net_http::bearer(&headers),
        &crate::workbench_auth::req_scope(&headers),
    );
    let workspace =
        library_routes::scope_workspace_value(&wb, library_routes::workspace_value(&wb), &vis);
    let Some(value) = library_routes::workspace_delta_value(&workspace, &record, &id) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("unknown workspace record: {record}") })),
        )
            .into_response();
    };
    let generated_at = wb.lifecycle_projection_generated_at(library::LIBRARY_SCOPE);
    let freshness = if marker.is_current() {
        Freshness::live(generated_at)
    } else {
        Freshness::stale(
            marker,
            generated_at,
            Some(format!("refresh {record} {id} for workspace")),
        )
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "value": value,
            "freshness": freshness,
            "client_request_id": serde_json::Value::Null,
        })),
    )
        .into_response()
}

/// The chat fork forest (`UX-8`): live chats nested by `forked_from`, a derived
/// read-only projection (`INV-5`) over the library.
pub(crate) async fn get_fork_tree(State(wb): State<SharedWorkbench>) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    (StatusCode::OK, Json(wb.fork_forest_value())).into_response()
}

/// `GET /projections/:scope/:kind?freshness=`: the freshness-carrying projection
/// shim (MOB-012). Every projection the client renders arrives with a freshness
/// stamp, so stale/offline reads cannot silently present as current truth.
pub(crate) async fn get_projection(
    State(wb): State<SharedWorkbench>,
    Path((scope, kind)): Path<(String, String)>,
    Query(q): Query<FreshnessQuery>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let marker = match q.marker() {
        Ok(m) => m,
        Err(reason) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": reason })),
            )
                .into_response()
        }
    };
    let wb = wb.lock_unpoisoned();
    let value =
        if scope == library::LIBRARY_SCOPE && kind == "workspace" {
            // ENTSEC-2: the carriage serves the same nav projection as GET /workspace, so it is
            // scoped to the caller's visible projects too (a no-op for solo/owner).
            let vis = wb.project_visibility_in(
                crate::net_http::bearer(&headers),
                &crate::workbench_auth::req_scope(&headers),
            );
            library_routes::scope_workspace_value(&wb, library_routes::workspace_value(&wb), &vis)
        } else {
            match wb.lifecycle_projection_value(&scope, &kind) {
                Ok(Some(value)) => value,
                Ok(None) => return (
                    StatusCode::NOT_FOUND,
                    Json(
                        serde_json::json!({ "error": format!("unknown projection kind: {kind}") }),
                    ),
                )
                    .into_response(),
                Err(e) => return err_response(e),
            }
        };
    let generated_at = wb.lifecycle_projection_generated_at(&scope);
    let freshness = if marker.is_current() {
        Freshness::live(generated_at)
    } else {
        Freshness::stale(
            marker,
            generated_at,
            Some(format!("refresh {kind} for {scope}")),
        )
    };
    let carriage = serde_json::json!({
        "value": value,
        "freshness": freshness,
        "client_request_id": serde_json::Value::Null,
    });
    (StatusCode::OK, Json(carriage)).into_response()
}
