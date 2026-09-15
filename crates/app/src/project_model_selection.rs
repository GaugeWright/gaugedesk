//! Project-owned selection of an organization model connection (GAUGEAPP-6,
//! ADR 0162).
//!
//! The project Home stores only a non-secret connection/model reference. A
//! browser may choose one of the rows it was shown, but it cannot make that row
//! authoritative: immediately before every write the Home asks the signed-in
//! account Hub for the current, separately admitted option set and checks the
//! exact actor, project authority, Home and organization-authority binding.
//! Actual model use must re-admit all of those facts again; this setting is not
//! dispatch authority and never contains a provider endpoint, grant or cap.

use std::collections::BTreeSet;
use std::time::Duration;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use gaugedesk_core::{
    ids::{AuthorityId, HomeId, ModelConnectionId, ProjectId, ScopeId},
    model_connection::AuthorityBinding,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    account::project_scope, identity::AuthenticatedActor, library::RecordOp, net_http,
    LockUnpoisoned, SharedWorkbench, Workbench,
};

const RECORD_KIND: &str = "organization-model-selection";
const RECORD_ID: &str = "selection";
const BASIS_PREFIX: &str = "organization-model-eligibility:v2:";

/// Optional composition-time Hub origin. Desktop uses the configured account
/// Hub; hosted compositions and hermetic authority journeys can inject the
/// exact sibling Hub without mutating process-global environment state.
#[derive(Clone, Debug)]
pub struct OrganizationModelEligibilityOrigin(String);

impl OrganizationModelEligibilityOrigin {
    pub fn new(origin: impl Into<String>) -> Self {
        Self(origin.into())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectionRecord {
    id: String,
    op: RecordOp,
    project: ProjectReference,
    home: HomeId,
    binding: AuthorityBinding,
    connection: ModelConnectionId,
    model: String,
    /// Provider identity observed in the same authority option that admitted
    /// the connection/model pair. Older records deliberately remain
    /// non-executable: without this value WhippleScript cannot construct the
    /// provider request whose final fetch will be re-admitted.
    #[serde(default)]
    provider: Option<String>,
    /// Added in v2. A legacy selection without this value never becomes
    /// executable merely because the connection is still available.
    #[serde(default)]
    private_broker: Option<PrivateBrokerSelection>,
    resource_basis: String,
    selected_by: AuthorityId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateBrokerSelection {
    pub authority: AuthorityId,
    pub name: String,
    pub operator: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectReference {
    pub authority: AuthorityId,
    pub id: ProjectId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SelectionProjection {
    pub binding: AuthorityBinding,
    pub project: ProjectReference,
    pub home: HomeId,
    pub connection: ModelConnectionId,
    pub model: String,
    pub provider: String,
    pub private_broker: PrivateBrokerSelection,
    pub resource_basis: String,
    pub selected_by: AuthorityId,
}

impl SelectionProjection {
    fn from_record(record: SelectionRecord) -> Option<Self> {
        let private_broker = record.private_broker?;
        let provider = record.provider?;
        record
            .resource_basis
            .starts_with(BASIS_PREFIX)
            .then_some(Self {
                binding: record.binding,
                project: record.project,
                home: record.home,
                connection: record.connection,
                model: record.model,
                provider,
                private_broker,
                resource_basis: record.resource_basis,
                selected_by: record.selected_by,
            })
    }
}

/// Read the Home's current persisted organization-model selection for trusted
/// server composition. This performs no authorization: callers must first
/// authenticate the actor and exact project/Home relationship. Keeping the
/// record fold here prevents a Hub or broker from copying the private storage
/// schema or treating a browser-echoed selection as current truth.
pub fn current_selection(
    wb: &Workbench,
    project_id: &str,
) -> Result<Option<SelectionProjection>, &'static str> {
    current_selection_in(wb.store_ref(), project_id)
}

/// Store-level sibling for a server authority that deliberately holds no
/// mutable Workbench. It reads the same private record fold and carries the
/// same fail-closed corruption behavior as [`current_selection`].
pub fn current_selection_in(
    store: &gaugedesk_store::Store,
    project_id: &str,
) -> Result<Option<SelectionProjection>, &'static str> {
    let rows = store
        .records(&project_scope(project_id), RECORD_KIND)
        .map_err(|_| "organization model selection is unavailable")?;
    let Some(last) = rows.last() else {
        return Ok(None);
    };
    let record: SelectionRecord =
        serde_json::from_str(last).map_err(|_| "organization model selection is unavailable")?;
    if record.id != RECORD_ID || record.project.id.as_str() != project_id {
        return Err("organization model selection is unavailable");
    }
    Ok((record.op == RecordOp::Upsert)
        .then_some(record)
        .and_then(SelectionProjection::from_record))
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectOrganizationModel {
    binding: BindingWire,
    connection: String,
    model: String,
    private_broker: String,
    admit_private_plaintext: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingWire {
    authority: String,
    organization: String,
    environment: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectWire {
    authority: String,
    id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct OptionWire {
    connection: String,
    name: String,
    provider: String,
    models: Vec<String>,
    organization_default: Option<String>,
    private_broker: PrivateBrokerWire,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateBrokerWire {
    authority: String,
    name: String,
    operator: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct EligibilityWire {
    v: u8,
    binding: BindingWire,
    actor: String,
    project: ProjectWire,
    home: String,
    resource_basis: String,
    options: Vec<OptionWire>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SelectionError {
    Unauthorized,
    Forbidden,
    Invalid,
    Unavailable,
}

impl SelectionError {
    fn response(self) -> Response {
        let (status, message) = match self {
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "sign in to choose organization model access",
            ),
            Self::Forbidden => (
                StatusCode::FORBIDDEN,
                "current project and organization access required",
            ),
            Self::Invalid => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "choose a current organization connection and model",
            ),
            Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "organization model authority unavailable",
            ),
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}

fn checked_text(value: &str) -> Result<&str, SelectionError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        return Err(SelectionError::Invalid);
    }
    Ok(value)
}

fn binding(wire: &BindingWire) -> Result<AuthorityBinding, SelectionError> {
    Ok(AuthorityBinding {
        authority: AuthorityId::parse(checked_text(&wire.authority)?.to_owned())
            .map_err(|_| SelectionError::Invalid)?,
        organization: ScopeId::parse(checked_text(&wire.organization)?.to_owned())
            .map_err(|_| SelectionError::Invalid)?,
        environment: checked_text(&wire.environment)?.to_owned(),
    })
}

fn current_record(
    wb: &Workbench,
    project_id: &str,
) -> Result<Option<SelectionRecord>, SelectionError> {
    let rows = wb
        .store_ref()
        .records(&project_scope(project_id), RECORD_KIND)
        .map_err(|_| SelectionError::Unavailable)?;
    let Some(last) = rows.last() else {
        return Ok(None);
    };
    let record: SelectionRecord =
        serde_json::from_str(last).map_err(|_| SelectionError::Unavailable)?;
    if record.id != RECORD_ID || record.project.id.as_str() != project_id {
        return Err(SelectionError::Unavailable);
    }
    Ok((record.op == RecordOp::Upsert).then_some(record))
}

fn write_record(wb: &mut Workbench, record: &SelectionRecord) -> Result<(), SelectionError> {
    wb.store_mut()
        .append_record(
            &project_scope(record.project.id.as_str()),
            RECORD_KIND,
            &serde_json::to_string(record).map_err(|_| SelectionError::Unavailable)?,
        )
        .map_err(|_| SelectionError::Unavailable)?;
    wb.notify_library_changed(
        "project-model-access",
        record.project.id.as_str(),
        match record.op {
            RecordOp::Upsert => "upsert",
            RecordOp::Tombstone => "tombstone",
        },
    );
    Ok(())
}

fn admit_and_store(
    wb: &mut Workbench,
    project_id: &str,
    expected_actor: &str,
    request: &SelectOrganizationModel,
    reply: EligibilityWire,
) -> Result<SelectionProjection, SelectionError> {
    if reply.v != 2
        || reply.actor != expected_actor
        || reply.project.id != project_id
        || reply.project.authority != wb.authority().as_str()
        || reply.home != wb.home_id().as_str()
        || !wb.owns_project(project_id)
        || !reply.resource_basis.starts_with(BASIS_PREFIX)
    {
        return Err(SelectionError::Forbidden);
    }
    checked_text(&reply.resource_basis)?;
    let admitted_binding = binding(&reply.binding)?;
    if admitted_binding != binding(&request.binding)? {
        return Err(SelectionError::Forbidden);
    }
    let requested_connection =
        ModelConnectionId::parse(checked_text(&request.connection)?.to_owned())
            .map_err(|_| SelectionError::Invalid)?;
    let requested_model = checked_text(&request.model)?.to_owned();
    let requested_broker = AuthorityId::parse(checked_text(&request.private_broker)?.to_owned())
        .map_err(|_| SelectionError::Invalid)?;
    if !request.admit_private_plaintext {
        return Err(SelectionError::Forbidden);
    }
    let mut connection_ids = BTreeSet::new();
    let mut selected_option = None;
    for option in reply.options {
        let option_connection =
            ModelConnectionId::parse(checked_text(&option.connection)?.to_owned())
                .map_err(|_| SelectionError::Invalid)?;
        checked_text(&option.name)?;
        let provider = checked_text(&option.provider)?.to_owned();
        if !connection_ids.insert(option_connection.clone()) || option.models.is_empty() {
            return Err(SelectionError::Unavailable);
        }
        let mut models = BTreeSet::new();
        for model in option.models {
            if !models.insert(checked_text(&model)?.to_owned()) {
                return Err(SelectionError::Unavailable);
            }
        }
        if option
            .organization_default
            .as_ref()
            .is_some_and(|default| !models.contains(default))
        {
            return Err(SelectionError::Unavailable);
        }
        let broker = PrivateBrokerSelection {
            authority: AuthorityId::parse(
                checked_text(&option.private_broker.authority)?.to_owned(),
            )
            .map_err(|_| SelectionError::Unavailable)?,
            name: checked_text(&option.private_broker.name)?.to_owned(),
            operator: checked_text(&option.private_broker.operator)?.to_owned(),
        };
        if option_connection == requested_connection
            && models.contains(&requested_model)
            && broker.authority == requested_broker
        {
            selected_option = Some((broker, provider));
        }
    }
    let (private_broker, provider) = selected_option.ok_or(SelectionError::Forbidden)?;
    let record = SelectionRecord {
        id: RECORD_ID.to_owned(),
        op: RecordOp::Upsert,
        project: ProjectReference {
            authority: wb.authority().clone(),
            id: ProjectId::parse(project_id.to_owned()).map_err(|_| SelectionError::Invalid)?,
        },
        home: wb.home_id().clone(),
        binding: admitted_binding,
        connection: requested_connection,
        model: requested_model,
        provider: Some(provider),
        private_broker: Some(private_broker),
        resource_basis: reply.resource_basis,
        selected_by: AuthorityId::parse(expected_actor.to_owned())
            .map_err(|_| SelectionError::Forbidden)?,
    };
    write_record(wb, &record)?;
    SelectionProjection::from_record(record).ok_or(SelectionError::Unavailable)
}

fn hub_options_url(base: &str, project: &str) -> Result<String, SelectionError> {
    let mut url = url::Url::parse(base).map_err(|_| SelectionError::Unavailable)?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(SelectionError::Unavailable);
    }
    let loopback = url.host_str().is_some_and(|host| {
        host == "localhost"
            || host.ends_with(".localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(SelectionError::Unavailable);
    }
    let mut segments = url
        .path_segments_mut()
        .map_err(|_| SelectionError::Unavailable)?;
    segments.pop_if_empty();
    segments.extend(["projects", project, "organization-model-options"]);
    drop(segments);
    Ok(url.to_string())
}

async fn fetch_eligibility(
    base: String,
    bearer: String,
    project: String,
    organization: String,
) -> Result<EligibilityWire, SelectionError> {
    let url = hub_options_url(&base, &project)?;
    let fetched = tokio::task::spawn_blocking(move || {
        net_http::HttpClient::with_timeout_no_redirects(Duration::from_secs(5)).get_string_headers(
            &url,
            &[
                ("authorization".to_owned(), format!("Bearer {bearer}")),
                ("x-gaugewright-tenant".to_owned(), organization),
            ],
        )
    })
    .await
    .map_err(|_| SelectionError::Unavailable)?
    .map_err(|_| SelectionError::Unavailable)?;
    match fetched.0 {
        200 => serde_json::from_str(&fetched.1).map_err(|_| SelectionError::Unavailable),
        401 => Err(SelectionError::Unauthorized),
        403 | 404 => Err(SelectionError::Forbidden),
        400..=499 => Err(SelectionError::Invalid),
        _ => Err(SelectionError::Unavailable),
    }
}

fn account_identity(
    wb: &SharedWorkbench,
    headers: &HeaderMap,
    actor: Option<AuthenticatedActor>,
) -> Result<(String, String), SelectionError> {
    if let (Some(bearer), Some(person)) = (
        crate::account_signin::hub_session_token(wb),
        crate::account_signin::hub_session_actor(wb),
    ) {
        return Ok((bearer, person));
    }
    let bearer = net_http::bearer(headers)
        .filter(|value| !value.is_empty())
        .ok_or(SelectionError::Unauthorized)?;
    let actor = actor.ok_or(SelectionError::Unauthorized)?;
    Ok((bearer.to_owned(), actor.0.as_str().to_owned()))
}

/// `GET /projects/:id/organization-model-selection` — the Home's durable,
/// secret-free selection. Availability is deliberately not cached here; the
/// option read and every future dispatch recheck current organization authority.
pub async fn get_selection(
    State(wb): State<SharedWorkbench>,
    Path(project): Path<String>,
) -> Response {
    let result = {
        let guard = wb.lock_unpoisoned();
        if !guard.owns_project(&project) {
            Err(SelectionError::Forbidden)
        } else {
            current_selection(&guard, &project).map_err(|_| SelectionError::Unavailable)
        }
    };
    match result {
        Ok(selection) => (StatusCode::OK, Json(json!({ "selection": selection }))).into_response(),
        Err(error) => error.response(),
    }
}

/// `PUT /projects/:id/organization-model-selection` — re-read current Hub /
/// model-authority eligibility, then persist the exact admitted reference in
/// the project coordination scope. The request carries no secret or cap.
pub async fn put_selection(
    State(wb): State<SharedWorkbench>,
    Path(project): Path<String>,
    headers: HeaderMap,
    actor: Option<Extension<AuthenticatedActor>>,
    origin: Option<Extension<OrganizationModelEligibilityOrigin>>,
    Json(body): Json<SelectOrganizationModel>,
) -> Response {
    let result = async {
        let (bearer, expected_actor) = account_identity(&wb, &headers, actor.map(|value| value.0))?;
        {
            let guard = wb.lock_unpoisoned();
            if !guard.owns_project(&project) {
                return Err(SelectionError::Forbidden);
            }
        }
        let base = origin
            .map(|value| value.0 .0)
            .or_else(crate::account_signin::hub_base)
            .ok_or(SelectionError::Unavailable)?;
        let requested_binding = binding(&body.binding)?;
        let reply = fetch_eligibility(
            base,
            bearer,
            project.clone(),
            requested_binding.organization.as_str().to_owned(),
        )
        .await?;
        let mut guard = wb.lock_unpoisoned();
        admit_and_store(&mut guard, &project, &expected_actor, &body, reply)
    }
    .await;
    match result {
        Ok(selection) => (StatusCode::OK, Json(json!({ "selection": selection }))).into_response(),
        Err(error) => error.response(),
    }
}

/// `DELETE /projects/:id/organization-model-selection` — remove the project
/// reference. Clearing needs only current Home/project authority and remains
/// available when the organization authority is offline or already revoked.
pub async fn delete_selection(
    State(wb): State<SharedWorkbench>,
    Path(project): Path<String>,
) -> Response {
    let result = {
        let mut guard = wb.lock_unpoisoned();
        if !guard.owns_project(&project) {
            Err(SelectionError::Forbidden)
        } else if let Some(mut record) = match current_record(&guard, &project) {
            Ok(record) => record,
            Err(error) => return error.response(),
        } {
            record.op = RecordOp::Tombstone;
            write_record(&mut guard, &record)
        } else {
            Ok(())
        }
    };
    match result {
        Ok(()) => (StatusCode::OK, Json(json!({ "selection": null }))).into_response(),
        Err(error) => error.response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{library::Library, open_workbench};

    fn fixture(
        wb: &Workbench,
        project: &str,
        actor: &str,
    ) -> (SelectOrganizationModel, EligibilityWire) {
        let binding = BindingWire {
            authority: "model-authority:test".to_owned(),
            organization: "tenant:test".to_owned(),
            environment: "test".to_owned(),
        };
        let request = SelectOrganizationModel {
            binding: binding.clone(),
            connection: "connection:primary".to_owned(),
            model: "model-a".to_owned(),
            private_broker: "broker:model-fetch".to_owned(),
            admit_private_plaintext: true,
        };
        let reply = EligibilityWire {
            v: 2,
            binding,
            actor: actor.to_owned(),
            project: ProjectWire {
                authority: wb.authority().as_str().to_owned(),
                id: project.to_owned(),
            },
            home: wb.home_id().as_str().to_owned(),
            resource_basis: format!("{BASIS_PREFIX}abc"),
            options: vec![OptionWire {
                connection: "connection:primary".to_owned(),
                name: "Primary".to_owned(),
                provider: "openai".to_owned(),
                models: vec!["model-a".to_owned(), "model-b".to_owned()],
                organization_default: Some("model-a".to_owned()),
                private_broker: PrivateBrokerWire {
                    authority: "broker:model-fetch".to_owned(),
                    name: "GaugeWright model broker".to_owned(),
                    operator: "GaugeWright".to_owned(),
                },
            }],
        };
        (request, reply)
    }

    #[test]
    fn current_authority_option_is_stored_in_the_project_scope_and_clears() {
        let dir = tempfile::tempdir().unwrap();
        let wb = open_workbench(dir.path()).unwrap();
        let project = {
            let guard = wb.lock_unpoisoned();
            Library::rebuild(guard.store_ref())
                .unwrap()
                .projects
                .values()
                .next()
                .unwrap()
                .id
                .clone()
        };
        let actor = "person:test";
        let mut guard = wb.lock_unpoisoned();
        let (request, reply) = fixture(&guard, &project, actor);
        let stored = admit_and_store(&mut guard, &project, actor, &request, reply).unwrap();
        assert_eq!(stored.connection.as_str(), "connection:primary");
        assert_eq!(stored.model, "model-a");
        assert_eq!(
            stored.private_broker.authority.as_str(),
            "broker:model-fetch"
        );
        assert_eq!(
            current_record(&guard, &project)
                .unwrap()
                .unwrap()
                .selected_by
                .as_str(),
            actor
        );
        assert_eq!(
            current_selection(&guard, &project).unwrap().unwrap(),
            stored
        );
        let mut record = current_record(&guard, &project).unwrap().unwrap();
        record.op = RecordOp::Tombstone;
        write_record(&mut guard, &record).unwrap();
        assert!(current_record(&guard, &project).unwrap().is_none());
        assert!(current_selection(&guard, &project).unwrap().is_none());
    }

    #[test]
    fn copied_or_stale_option_cannot_select() {
        let dir = tempfile::tempdir().unwrap();
        let wb = open_workbench(dir.path()).unwrap();
        let project = {
            let guard = wb.lock_unpoisoned();
            Library::rebuild(guard.store_ref())
                .unwrap()
                .projects
                .values()
                .next()
                .unwrap()
                .id
                .clone()
        };
        let mut guard = wb.lock_unpoisoned();
        let (mut request, reply) = fixture(&guard, &project, "person:test");
        request.connection = "connection:copied".to_owned();
        assert_eq!(
            admit_and_store(&mut guard, &project, "person:test", &request, reply),
            Err(SelectionError::Forbidden)
        );
        assert!(current_record(&guard, &project).unwrap().is_none());
    }

    #[test]
    fn broker_recipient_requires_an_exact_explicit_admission() {
        let dir = tempfile::tempdir().unwrap();
        let wb = open_workbench(dir.path()).unwrap();
        let project = {
            let guard = wb.lock_unpoisoned();
            Library::rebuild(guard.store_ref())
                .unwrap()
                .projects
                .values()
                .next()
                .unwrap()
                .id
                .clone()
        };
        let mut guard = wb.lock_unpoisoned();
        let (mut request, reply) = fixture(&guard, &project, "person:test");
        request.admit_private_plaintext = false;
        assert_eq!(
            admit_and_store(&mut guard, &project, "person:test", &request, reply.clone()),
            Err(SelectionError::Forbidden)
        );
        request.admit_private_plaintext = true;
        request.private_broker = "broker:copied".to_owned();
        assert_eq!(
            admit_and_store(&mut guard, &project, "person:test", &request, reply),
            Err(SelectionError::Forbidden)
        );
        assert!(current_record(&guard, &project).unwrap().is_none());
    }

    #[test]
    fn response_scope_and_shape_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let wb = open_workbench(dir.path()).unwrap();
        let project = {
            let guard = wb.lock_unpoisoned();
            Library::rebuild(guard.store_ref())
                .unwrap()
                .projects
                .values()
                .next()
                .unwrap()
                .id
                .clone()
        };
        let mut guard = wb.lock_unpoisoned();
        let (request, mut reply) = fixture(&guard, &project, "person:test");
        reply.home = "home:other".to_owned();
        assert_eq!(
            admit_and_store(&mut guard, &project, "person:test", &request, reply),
            Err(SelectionError::Forbidden)
        );
        assert!(serde_json::from_str::<EligibilityWire>(
            r#"{"v":2,"binding":{"authority":"a","organization":"o","environment":"e"},"actor":"p","project":{"authority":"a","id":"p"},"home":"h","resource_basis":"organization-model-eligibility:v2:x","options":[],"secret":"no"}"#
        )
        .is_err());
    }

    #[test]
    fn authority_url_is_exact_and_allows_only_tls_or_loopback() {
        assert_eq!(
            hub_options_url("https://desk.gaugewright.com", "project/one").unwrap(),
            "https://desk.gaugewright.com/projects/project%2Fone/organization-model-options"
        );
        assert!(hub_options_url("http://desk.gaugewright.com", "project").is_err());
        assert!(hub_options_url("http://desk.gw.localhost:7523", "project").is_ok());
        assert!(hub_options_url("https://user:pass@desk.gaugewright.com", "project").is_err());
    }
}
