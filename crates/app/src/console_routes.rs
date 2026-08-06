//! Count-only Console projections. These routes deliberately expose no work,
//! resource, engagement, or review identifiers across the account shell.

use axum::{
    extract::{Extension, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use gaugedesk_core::ids::AuthorityId;
use serde_json::json;

use crate::{identity::AuthenticatedActor, net_http, LockUnpoisoned, SharedWorkbench};

/// The notification projection is only the number of output reviews that still
/// require the authenticated person's consent. Hosted Homes inject the actor
/// after account/Home-admission verification; open local Homes retain their
/// established bearer-auth path for the same route surface.
pub(crate) async fn get_review_count(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    actor: Option<Extension<AuthenticatedActor>>,
) -> axum::response::Response {
    let wb = wb.lock_unpoisoned();
    let actor = match actor {
        Some(Extension(actor)) => actor.0,
        None => match wb.admit_data_request(net_http::bearer(&headers), None) {
            Ok(actor) => AuthorityId::new(actor),
            Err((code, message)) => {
                return (code, Json(json!({ "error": message }))).into_response()
            }
        },
    };
    match wb.review_notification_count(&actor) {
        Ok(review_count) => (
            StatusCode::OK,
            Json(json!({ "review_count": review_count })),
        )
            .into_response(),
        Err(error) => crate::err_response(error),
    }
}
