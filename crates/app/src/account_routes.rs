//! The account surface (ACCT-1): the operator's own device registry, settings, and
//! linked-credential management, over the reserved `account` scope. These act on the
//! operator's *own* account (not org admin), so they are ungated on the loopback
//! desktop — the operator is the account owner. CRUD writes durable records (latest-
//! wins / tombstone) and pushes a workspace-change reference so clients refresh live.
//!
//! The linked credential's **plaintext** is never returned over HTTP — only the
//! provider list and link/unlink. Decryption is the internal
//! [`crate::account::resolve_token`] API the local runtime uses.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;

use crate::account::{seal_token, HomeRouteRecord, RecordOp, RegisteredHomeRecord, SettingRecord};
#[cfg(debug_assertions)]
use crate::account::{DeviceRecord, DeviceStatus};
use crate::codex_oauth;
use crate::{err_response, net_http, LockUnpoisoned, SharedWorkbench};
use gaugedesk_core::ids::HomeId;

/// Split account route surface. Local device/settings/credential ownership stays
/// open; hosted token brokerage and account-ledger operation are split later.
pub fn hub_routes() -> Router<SharedWorkbench> {
    Router::new()
        // Account (ACCT-1): the operator's own device registry, settings, and
        // sealed linked-credentials. The raw Device writer is a guarded BDD
        // fixture compiled only into debug builds (DR-0054 Phase A); product
        // enrollment uses only the proof-bound routes below.
        .route("/account/devices", {
            #[cfg(debug_assertions)]
            {
                get(get_devices).post(post_test_device_fixture)
            }
            #[cfg(not(debug_assertions))]
            {
                get(get_devices)
            }
        })
        .route("/account/devices/{id}/revoke", post(post_device_revoke))
        // Device-enrollment handshake drive (ACCT-1, ADR 0055): the holder hosts +
        // authorizes; the new device joins. Both dial the rendezvous broker; status
        // GETs surface the phase + SAS for the out-of-band human compare. The account
        // key crosses only as ECIES ciphertext over the broker, never over HTTP.
        .route("/account/devices/enroll/host", post(post_enroll_host))
        .route(
            "/account/devices/enroll/host/{session}",
            get(get_enroll_host),
        )
        .route(
            "/account/devices/enroll/authorize",
            post(post_enroll_authorize),
        )
        .route("/account/devices/enroll/join", post(post_enroll_join))
        .route(
            "/account/devices/enroll/join/{session}",
            get(get_enroll_join),
        )
        .route("/account/settings", get(get_settings))
        .route("/account/settings/{key}", put(put_setting))
        .route("/account/homes", get(get_homes).post(post_home))
        .route("/account/homes/selected", put(put_selected_home))
        .route("/account/homes/{id}", delete(delete_home))
        .route(
            "/account/home-routes",
            get(get_home_routes).post(post_home_route),
        )
        .route("/account/home-routes/{project}", delete(delete_home_route))
        .merge(managed_inference_routes())
}

/// Library sync is a sovereign-desktop operation: it signs and opens account
/// state with the root key held by this exact Workbench process. A shared Hub
/// must not mount these routes under a person session and accidentally use its
/// process-default key for an unrelated person.
fn library_sync_routes() -> Router<SharedWorkbench> {
    Router::new()
        .route("/account/library-sync", post(post_library_sync_publish))
        .route("/account/library-sync/pull", post(post_library_sync_pull))
}

/// Complete co-resident/local account surface. Hosted compositions choose the
/// blind Hub and runtime-credential subsets independently.
pub fn routes() -> Router<SharedWorkbench> {
    hub_routes()
        .merge(runtime_credential_routes())
        .merge(library_sync_routes())
}

/// Runtime credential subset. A hosted Home mounts this so provider material
/// is linked directly into the Home's sealed account scope; the blind Hub does
/// not need to receive plaintext model credentials.
pub fn runtime_credential_routes() -> Router<SharedWorkbench> {
    shared_runtime_credential_routes()
        .merge(crate::local_model_broker::routes())
        // Desktop Codex OAuth helper: its callback listener is co-resident with
        // the browser. Hosted Homes mount the separate device-code handlers.
        .route(
            "/account/oauth/openai-codex",
            get(codex_oauth::get_codex_status),
        )
        .route(
            "/account/oauth/openai-codex/start",
            post(codex_oauth::post_codex_login_start),
        )
        // Desktop → Hub account sign-in: the native device handoff's local half
        // (ADR 0123, LOGIN-2). Account identity, not a model credential — the
        // sealed session stays in this control plane; routes carry no token.
        .route(
            "/account/hub-session",
            get(crate::account_signin::get_signin_status),
        )
        .route(
            "/account/hub-session/start",
            post(crate::account_signin::post_signin_start),
        )
        .route(
            "/account/hub-session/callback",
            post(crate::account_signin::post_signin_callback),
        )
        .route(
            "/account/hub-session/reach",
            get(crate::account_signin::get_signin_reach),
        )
        .route(
            "/account/hub-session/logout",
            post(crate::account_signin::post_signin_logout),
        )
}

pub fn home_runtime_credential_routes() -> Router<SharedWorkbench> {
    shared_runtime_credential_routes()
        .route(
            "/account/oauth/openai-codex",
            get(codex_oauth::get_home_codex_status),
        )
        .route(
            "/account/oauth/openai-codex/start",
            post(codex_oauth::post_home_codex_login_start),
        )
        .route(
            "/account/oauth/openai-codex/cancel",
            post(codex_oauth::post_home_codex_login_cancel),
        )
}

fn shared_runtime_credential_routes() -> Router<SharedWorkbench> {
    Router::new()
        .route(
            "/account/credentials",
            get(get_credentials).post(post_credential),
        )
        .route("/account/credentials/{provider}", delete(delete_credential))
        // First-run gate signal (ADR 0075 Phase 0): whether the default runtime
        // actually needs an LLM credential. False under the scripted fake agent
        // (dev/e2e), so the first-run overlay never blocks a no-credential test.
        .route("/account/onboarding-status", get(get_onboarding_status))
        // The resolved no-pin default (provider + model), so the composer picker
        // can name its "Default" row instead of leaving it blind.
        .route("/account/default-model", get(get_default_model))
}

/// Non-secret managed-model plan projection. The Hub owns billing truth; a
/// Cloud Home receives the same admitted plan as an operational entitlement so
/// its unattended resolver can fail closed without asking the browser.
pub fn managed_inference_routes() -> Router<SharedWorkbench> {
    Router::new().route(
        "/account/managed-inference",
        get(get_managed_inference).post(post_managed_inference),
    )
}

pub(crate) fn secure_home_endpoint(endpoint: &str) -> bool {
    let Ok(uri) = endpoint.parse::<axum::http::Uri>() else {
        return false;
    };
    let Some(scheme) = uri.scheme_str() else {
        return false;
    };
    let Some(host) = uri.host() else {
        return false;
    };
    scheme == "https"
        || (scheme == "http" && matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]"))
}

pub async fn get_homes(State(wb): State<SharedWorkbench>, headers: HeaderMap) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    let scope = wb.account_scope_for(net_http::bearer(&headers));
    match crate::account::Account::rebuild_in(wb.store_ref(), &scope) {
        Ok(account) => {
            let selected_home = account
                .settings
                .get("selected_home")
                .map(|s| s.value.clone());
            (
                StatusCode::OK,
                Json(json!({
                    "homes": account.homes.into_values().collect::<Vec<_>>(),
                    "selected_home": selected_home,
                })),
            )
                .into_response()
        }
        Err(error) => err_response(error),
    }
}

#[derive(Deserialize)]
pub struct HomeBody {
    id: String,
    #[serde(default)]
    kind: crate::home::HomeKind,
    #[serde(default)]
    endpoint: String,
    #[serde(default)]
    relay: Option<crate::home::OpaqueRelayLocator>,
    #[serde(default)]
    selected: bool,
}

pub async fn post_home(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Json(body): Json<HomeBody>,
) -> impl IntoResponse {
    if body.id.trim().is_empty() || !valid_reachability(&body.endpoint, body.relay.as_ref()) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            "valid Home id and secure endpoint or relay required",
        )
            .into_response();
    }
    let mut wb = wb.lock_unpoisoned();
    let scope = wb.account_scope_for(net_http::bearer(&headers));
    let record = RegisteredHomeRecord {
        id: HomeId::new(body.id),
        op: RecordOp::Upsert,
        kind: body.kind,
        endpoint: body.endpoint.trim_end_matches('/').to_owned(),
        relay: body.relay,
    };
    if let Err(error) = wb.write_account_record_in(&scope, "home", record.id.as_str(), &record) {
        return err_response(error);
    }
    if body.selected {
        let selected = SettingRecord {
            id: "selected_home".into(),
            op: RecordOp::Upsert,
            value: record.id.as_str().to_owned(),
        };
        if let Err(error) = wb.write_account_record_in(&scope, "setting", &selected.id, &selected) {
            return err_response(error);
        }
    }
    (StatusCode::CREATED, Json(json!({ "home": record }))).into_response()
}

#[derive(Deserialize)]
pub struct SelectHomeBody {
    home_id: String,
}

pub async fn put_selected_home(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Json(body): Json<SelectHomeBody>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    let scope = wb.account_scope_for(net_http::bearer(&headers));
    let account = match crate::account::Account::rebuild_in(wb.store_ref(), &scope) {
        Ok(account) => account,
        Err(error) => return err_response(error),
    };
    if !account.homes.contains_key(&body.home_id) {
        return (StatusCode::NOT_FOUND, "Home is not registered").into_response();
    }
    let record = SettingRecord {
        id: "selected_home".into(),
        op: RecordOp::Upsert,
        value: body.home_id,
    };
    match wb.write_account_record_in(&scope, "setting", &record.id, &record) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => err_response(error),
    }
}

pub async fn delete_home(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    let scope = wb.account_scope_for(net_http::bearer(&headers));
    let record = RegisteredHomeRecord {
        id: HomeId::new(id),
        op: RecordOp::Tombstone,
        kind: crate::home::HomeKind::Local,
        endpoint: String::new(),
        relay: None,
    };
    match wb.write_account_record_in(&scope, "home", record.id.as_str(), &record) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => err_response(error),
    }
}

pub async fn get_home_routes(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    let scope = wb.account_scope_for(net_http::bearer(&headers));
    match crate::account::Account::rebuild_in(wb.store_ref(), &scope) {
        Ok(account) => {
            let routes: Vec<crate::home::OpaqueHomeRoute> =
                account.home_routes.into_values().map(Into::into).collect();
            (StatusCode::OK, Json(json!({ "routes": routes }))).into_response()
        }
        Err(error) => err_response(error),
    }
}

#[derive(Deserialize)]
pub struct HomeRouteBody {
    project: String,
    home_id: String,
    #[serde(default)]
    endpoint: String,
    #[serde(default)]
    relay: Option<crate::home::OpaqueRelayLocator>,
}

pub async fn post_home_route(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Json(body): Json<HomeRouteBody>,
) -> impl IntoResponse {
    if body.project.trim().is_empty()
        || body.home_id.trim().is_empty()
        || !valid_reachability(&body.endpoint, body.relay.as_ref())
    {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            "valid opaque route required",
        )
            .into_response();
    }
    let mut wb = wb.lock_unpoisoned();
    let scope = wb.account_scope_for(net_http::bearer(&headers));
    let record = HomeRouteRecord {
        id: body.project,
        op: RecordOp::Upsert,
        home_id: HomeId::new(body.home_id),
        endpoint: body.endpoint.trim_end_matches('/').to_owned(),
        relay: body.relay,
    };
    match wb.write_account_record_in(&scope, "home_route", &record.id, &record) {
        Ok(()) => (
            StatusCode::CREATED,
            Json(json!({ "route": crate::home::OpaqueHomeRoute::from(record) })),
        )
            .into_response(),
        Err(error) => err_response(error),
    }
}

fn valid_reachability(endpoint: &str, relay: Option<&crate::home::OpaqueRelayLocator>) -> bool {
    let endpoint_valid = endpoint.is_empty() || secure_home_endpoint(endpoint);
    let relay_valid = relay.is_none_or(|relay| {
        use base64::Engine;
        relay
            .endpoint
            .strip_prefix("wss://")
            .is_some_and(|authority| {
                !authority.is_empty()
                    && !authority.contains('/')
                    && !authority.contains('@')
                    && !authority.chars().any(char::is_whitespace)
            })
            && relay.route_epoch > 0
            && base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&relay.handle)
                .is_ok_and(|handle| handle.len() == 32)
            && base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&relay.proof)
                .is_ok_and(|proof| proof.len() == 32)
            && relay.home_fingerprint.len() == 64
            && hex::decode(&relay.home_fingerprint).is_ok_and(|pin| pin.len() == 32)
    });
    endpoint_valid && relay_valid && (!endpoint.is_empty() || relay.is_some())
}

pub async fn delete_home_route(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Path(project): Path<String>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    let scope = wb.account_scope_for(net_http::bearer(&headers));
    let record = HomeRouteRecord {
        id: project,
        op: RecordOp::Tombstone,
        home_id: HomeId::new("deleted"),
        endpoint: String::new(),
        relay: None,
    };
    match wb.write_account_record_in(&scope, "home_route", &record.id, &record) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => err_response(error),
    }
}

/// The person's managed-inference subscription + idempotently folded token
/// usage. Provider credentials remain in the managed host and never cross this
/// account surface.
pub async fn get_managed_inference(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    let scope = wb.account_scope_for(net_http::bearer(&headers));
    let plan = match crate::managed_inference::fold_plan(wb.store_ref(), &scope) {
        Ok(plan) => plan,
        Err(error) => return err_response(error),
    };
    let included = plan.as_ref().map_or(0, |plan| plan.included_tokens);
    let funding_ref = plan
        .as_ref()
        .map(|plan| crate::managed_inference::funding_ref(&scope, plan));
    match crate::managed_inference::fold_usage(wb.store_ref(), &scope, included) {
        Ok(usage) => (
            StatusCode::OK,
            Json(json!({ "plan": plan, "funding_ref": funding_ref, "usage": usage })),
        )
            .into_response(),
        Err(error) => err_response(error),
    }
}

pub async fn post_managed_inference(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Json(subscription): Json<crate::managed_inference::ManagedInferencePlan>,
) -> impl IntoResponse {
    if crate::workbench_auth::web_account_mode() {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            "hosted managed plans are controlled by the signed billing webhook",
        )
            .into_response();
    }
    if subscription.plan.trim().is_empty() {
        return (StatusCode::UNPROCESSABLE_ENTITY, "plan is required").into_response();
    }
    let mut wb = wb.lock_unpoisoned();
    let scope = wb.account_scope_for(net_http::bearer(&headers));
    let record = crate::managed_inference::ManagedPlanRecord {
        id: "managed-inference".into(),
        op: RecordOp::Upsert,
        subscription,
    };
    let payload = match serde_json::to_string(&record) {
        Ok(payload) => payload,
        Err(error) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response()
        }
    };
    if let Err(error) = wb.store_mut().append_record(
        &scope,
        crate::managed_inference::MANAGED_PLAN_KIND,
        &payload,
    ) {
        return err_response(error);
    }
    wb.notify_library_changed("managed_inference_plan", &record.id, "upsert");
    (StatusCode::OK, Json(json!({ "plan": record.subscription }))).into_response()
}

/// Publish the current account state to the blind directory (the `library_sync` facility). Builds
/// the signed record under the lock, then PUTs it off the lock. `409` if sync is off / unconfigured.
pub async fn post_library_sync_publish(State(wb): State<SharedWorkbench>) -> impl IntoResponse {
    let base = crate::directory_sync::directory_url_from_env();
    let (active, root) = {
        let wb = wb.lock_unpoisoned();
        (wb.library_sync_active(), wb.library_sync_root())
    };
    if !active {
        return (StatusCode::CONFLICT, "library sync is not active").into_response();
    }
    let head_base = base.clone();
    let head = tokio::task::spawn_blocking(move || {
        crate::directory_sync::fetch(&crate::net_http::HttpClient::new(), &head_base, &root)
    })
    .await;
    let generation = match head {
        Ok(Ok(Some(entry))) => match entry.generation.checked_add(1) {
            Some(generation) => generation,
            None => {
                return (StatusCode::CONFLICT, "directory generation is exhausted").into_response()
            }
        },
        Ok(Ok(None)) => 1,
        Ok(Err(error)) => return (StatusCode::BAD_GATEWAY, error).into_response(),
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "directory head task panicked",
            )
                .into_response()
        }
    };
    let put = wb.lock_unpoisoned().library_sync_signed_put(generation);
    let Some(put) = put else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "directory publish could not be signed",
        )
            .into_response();
    };
    let published = tokio::task::spawn_blocking(move || {
        crate::directory_sync::publish(&crate::net_http::HttpClient::new(), &base, &put)
    })
    .await;
    match published {
        Ok(Ok(())) => (StatusCode::OK, Json(json!({ "published": true }))).into_response(),
        Ok(Err(e)) => (StatusCode::BAD_GATEWAY, e).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "publish task panicked").into_response(),
    }
}

/// Pull the account state from the blind directory and merge it locally (the `library_sync`
/// facility). Fetches off the lock, then merges under it. `409` if sync is off / unconfigured.
pub async fn post_library_sync_pull(State(wb): State<SharedWorkbench>) -> impl IntoResponse {
    let base = crate::directory_sync::directory_url_from_env();
    let (active, root) = {
        let wb = wb.lock_unpoisoned();
        (wb.library_sync_active(), wb.library_sync_root())
    };
    if !active {
        return (StatusCode::CONFLICT, "library sync is not active").into_response();
    }
    let fetched = tokio::task::spawn_blocking(move || {
        crate::directory_sync::fetch(&crate::net_http::HttpClient::new(), &base, &root)
    })
    .await;
    let entry = match fetched {
        Ok(Ok(Some(e))) => e,
        Ok(Ok(None)) => {
            return (StatusCode::OK, Json(json!({ "found": false, "merged": 0 }))).into_response()
        }
        Ok(Err(e)) => return (StatusCode::BAD_GATEWAY, e).into_response(),
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "fetch task panicked").into_response()
        }
    };
    match wb.lock_unpoisoned().library_sync_apply(&entry) {
        Ok(merged) => (
            StatusCode::OK,
            Json(json!({ "found": true, "merged": merged })),
        )
            .into_response(),
        Err(e) => (StatusCode::UNPROCESSABLE_ENTITY, e).into_response(),
    }
}

/// Whether a first-run user must connect an LLM credential before the runtime
/// can run a turn (ADR 0075 Phase 0). Mirrors the runtime selection in
/// `harness_select::factory_for_turn`: the scripted fake agent (selected by
/// `GAUGEDESK_FAKE_AGENT`, used in dev/e2e) needs no credential, so the gate is
/// off there; the real WhippleScript runtime needs one, so it's on.
pub async fn get_onboarding_status() -> impl IntoResponse {
    let credential_required = gaugedesk_env::var("FAKE_AGENT").is_none();
    (
        StatusCode::OK,
        Json(json!({ "credential_required": credential_required })),
    )
        .into_response()
}

/// The model a turn runs when the chat pins nothing — the picker's "Default"
/// row, named. Resolves exactly as a turn would: the host override / codex-OAuth
/// provider precedence with an empty chat config, then that provider's own
/// default model. `model` is null when the resolved provider has no default
/// (it requires an explicit pin). Exposed so the picker can *name* the default
/// instead of showing a blind "Default" (LLM-1, ADR 0062).
pub async fn get_default_model() -> impl IntoResponse {
    let provider = crate::engine::resolve_turn_provider(gaugedesk_env::var("MODEL_PROVIDER"), None);
    let model =
        crate::engine::resolve_turn_model(gaugedesk_env::var("MODEL"), None).or_else(|| {
            gaugedesk_whip_runtime::native_provider_descriptor(&provider, None, None)
                .ok()
                .map(|d| d.model)
        });
    (
        StatusCode::OK,
        Json(json!({ "provider": provider, "model": model })),
    )
        .into_response()
}

#[cfg(test)]
mod home_directory_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn call(
        app: &Router,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> (StatusCode, String) {
        let mut request = Request::builder().method(method).uri(path);
        if method != "GET" {
            request = request.header("idempotency-key", format!("{method}:{path}"));
        }
        let body = match body {
            Some(body) => {
                request = request.header("content-type", "application/json");
                Body::from(body.to_owned())
            }
            None => Body::empty(),
        };
        let response = app
            .clone()
            .oneshot(request.body(body).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn account_home_registry_and_directory_are_durable_routing_only() {
        let dir = tempfile::tempdir().unwrap();
        let wb = crate::open_workbench(dir.path()).unwrap();
        let app = routes().with_state(wb);

        let (status, _) = call(
            &app,
            "POST",
            "/account/homes",
            Some(
                r#"{"id":"home:desk","kind":"registered","endpoint":"http://127.0.0.1:7878/","selected":true}"#,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);

        let (status, homes) = call(&app, "GET", "/account/homes", None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(homes.contains(r#""selected_home":"home:desk""#));
        assert!(homes.contains(r#""endpoint":"http://127.0.0.1:7878""#));

        let (status, create_route) = call(
            &app,
            "POST",
            "/account/home-routes",
            Some(
                concat!(
                    r#"{"project":"opaque-project-7","home_id":"home:desk","endpoint":"http://127.0.0.1:7878/","#,
                    r#""relay":{"endpoint":"wss://relay.gaugewright.com","handle":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","#,
                    r#""proof":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI","#,
                    r#""route_epoch":2,"home_fingerprint":"abababababababababababababababababababababababababababababababab"}}"#
                ),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{create_route}");

        let (status, routes) = call(&app, "GET", "/account/home-routes", None).await;
        assert_eq!(status, StatusCode::OK);
        let payload: serde_json::Value = serde_json::from_str(&routes).unwrap();
        assert_eq!(payload["routes"][0]["project"], "opaque-project-7");
        assert_eq!(payload["routes"][0]["home_id"], "home:desk");
        assert_eq!(payload["routes"][0]["endpoint"], "http://127.0.0.1:7878");
        assert_eq!(
            payload["routes"][0]["relay"]["endpoint"],
            "wss://relay.gaugewright.com"
        );
        assert_eq!(payload["routes"][0]["relay"]["route_epoch"], 2);
        let object = payload["routes"][0].as_object().unwrap();
        assert_eq!(
            object.len(),
            4,
            "Hub directory gained a field beyond route transport metadata"
        );

        let (status, _) = call(
            &app,
            "POST",
            "/account/home-routes",
            Some(r#"{"project":"p","home_id":"h","endpoint":"http://remote.example"}"#),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        let (status, relay_only) = call(
            &app,
            "POST",
            "/account/home-routes",
            Some(
                concat!(
                    r#"{"project":"relay-only","home_id":"home:desk","relay":{"endpoint":"wss://relay.gaugewright.com","#,
                    r#""handle":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","#,
                    r#""proof":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI","route_epoch":3,"#,
                    r#""home_fingerprint":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"}}"#
                ),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert!(
            !serde_json::from_str::<serde_json::Value>(&relay_only).unwrap()["route"]
                .as_object()
                .unwrap()
                .contains_key("endpoint")
        );

        let (status, _) = call(
            &app,
            "POST",
            "/account/home-routes",
            Some(
                r#"{"project":"p","home_id":"h","endpoint":"https://home.example","relay":{"endpoint":"https://bad.example","handle":"short","proof":"short","route_epoch":0,"home_fingerprint":"bad"}}"#,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        let (status, _) = call(
            &app,
            "DELETE",
            "/account/home-routes/opaque-project-7",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, _) = call(&app, "DELETE", "/account/home-routes/relay-only", None).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (_, routes) = call(&app, "GET", "/account/home-routes", None).await;
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&routes).unwrap()["routes"],
            serde_json::json!([])
        );
    }
}

// ---- devices (the trusted-devices registry) ------------------------------

pub async fn get_devices(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    let scope = wb.account_scope_for(net_http::bearer(&headers));
    match wb.account_devices_in(&scope) {
        Ok(devices) => (StatusCode::OK, Json(json!({ "devices": devices }))).into_response(),
        Err(e) => err_response(e),
    }
}

#[cfg(debug_assertions)]
#[derive(Deserialize)]
pub struct TestDeviceFixtureBody {
    id: String,
    #[serde(default)]
    label: String,
    #[serde(default)]
    subkey_pubkey: String,
}

/// Test-only registry fixture for authenticated browser composition.
///
/// Product enrollment is exclusively the ADR 0055 SAS-bound handshake below.
/// Keeping this raw record writer available without the browser-BDD activation
/// guard would let a caller invent a trusted Device without channel binding,
/// delegation, or sealed account-key transfer. Debug builds only (DR-0054
/// Phase A); the env-var activation guard stays as defense in depth.
#[cfg(debug_assertions)]
pub async fn post_test_device_fixture(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Json(body): Json<TestDeviceFixtureBody>,
) -> impl IntoResponse {
    if gaugedesk_env::var_os("TEST_RESET").is_none() {
        return (StatusCode::FORBIDDEN, "device fixture is disabled").into_response();
    }
    if body.id.trim().is_empty() {
        return (StatusCode::UNPROCESSABLE_ENTITY, "device id is required").into_response();
    }
    let record = DeviceRecord {
        id: body.id,
        op: RecordOp::Upsert,
        label: body.label,
        subkey_pubkey: body.subkey_pubkey,
        status: DeviceStatus::Active,
        enrolled_at: crate::account::device_enrolled_at_now(),
    };
    let mut wb = wb.lock_unpoisoned();
    let scope = wb.account_scope_for(net_http::bearer(&headers));
    if let Err(e) = wb.upsert_account_device_in(&scope, &record) {
        return err_response(e);
    }
    (StatusCode::OK, Json(json!({ "device": record }))).into_response()
}

pub async fn post_device_revoke(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    let scope = wb.account_scope_for(net_http::bearer(&headers));
    let record = match wb.revoke_account_device_in(&scope, &id) {
        Ok(Some(record)) => record,
        Ok(None) => return (StatusCode::NOT_FOUND, "no such device").into_response(),
        Err(e) => return err_response(e),
    };
    (StatusCode::OK, Json(json!({ "device": record }))).into_response()
}

// ---- device enrollment handshake (ACCT-1, ADR 0055) ----------------------
//
// An existing (holder) device authorizes a new one over the rendezvous broker and
// hands over the account key, sealed to the new device's subkey. Two roles, each a
// background leg the status GETs poll:
//
//   holder:      POST /enroll/host        -> mint + show the ticket
//                GET  /enroll/host/:sess   -> phase + SAS (compare with the new device)
//                POST /enroll/authorize    -> the human confirmed the SAS matches
//   new device:  POST /enroll/join {ticket} -> consume the ticket, start the leg
//                GET  /enroll/join/:sess    -> phase + SAS (compare with the holder)
//
// Fail-closed: no authorize without the explicit confirm; a substituted subkey shows
// up as a mismatched SAS the human catches; a lapsed pairing times the leg out.

/// A leg's phase + SAS for a status poll (never the account key — `INV-10`).
fn enroll_status_json(
    snapshot: Option<(
        crate::device_enroll_drive::EnrollPhase,
        Option<String>,
        Option<String>,
    )>,
) -> axum::response::Response {
    match snapshot {
        Some((phase, sas, error)) => (
            StatusCode::OK,
            Json(json!({ "phase": phase, "sas": sas, "error": error })),
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "no such enrollment session").into_response(),
    }
}

/// Holder: start the enrollment host leg and return the out-of-band ticket to show
/// (QR + code). The leg waits at the broker for the new device, then for the human's
/// SAS confirm.
pub async fn post_enroll_host(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let scope = wb
        .lock_unpoisoned()
        .account_scope_for(net_http::bearer(&headers));
    match crate::device_enroll_drive::start_host(&wb, scope) {
        Some(ticket) => (StatusCode::OK, Json(json!({ "ticket": ticket }))).into_response(),
        None => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not start enrollment",
        )
            .into_response(),
    }
}

/// Holder: the current phase + SAS of a host leg (poll after showing the ticket).
pub async fn get_enroll_host(
    State(wb): State<SharedWorkbench>,
    Path(session): Path<String>,
) -> impl IntoResponse {
    let drive = wb.lock_unpoisoned().enroll_drive();
    enroll_status_json(drive.host_snapshot(&session))
}

#[derive(Deserialize)]
pub struct EnrollAuthorizeBody {
    session: String,
}

/// Holder: the human confirmed the SAS matches the new device's — release the host
/// leg to authorize. `409` if the leg is not awaiting confirmation (fail-closed).
pub async fn post_enroll_authorize(
    State(wb): State<SharedWorkbench>,
    Json(body): Json<EnrollAuthorizeBody>,
) -> impl IntoResponse {
    let drive = wb.lock_unpoisoned().enroll_drive();
    match drive.confirm_host(&body.session) {
        Ok(()) => (StatusCode::OK, Json(json!({ "authorized": true }))).into_response(),
        Err(e) => (StatusCode::CONFLICT, e).into_response(),
    }
}

#[derive(Deserialize)]
pub struct EnrollJoinBody {
    ticket: crate::device_enroll_drive::EnrollmentTicket,
}

/// New device: consume a ticket and start the join leg. Returns the session id to
/// poll for the SAS + outcome.
pub async fn post_enroll_join(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Json(body): Json<EnrollJoinBody>,
) -> impl IntoResponse {
    let scope = wb
        .lock_unpoisoned()
        .account_scope_for(net_http::bearer(&headers));
    match crate::device_enroll_drive::start_join(&wb, scope, body.ticket) {
        Ok(session) => (StatusCode::OK, Json(json!({ "session": session }))).into_response(),
        Err(e) => (StatusCode::UNPROCESSABLE_ENTITY, e).into_response(),
    }
}

/// New device: the current phase + SAS of a join leg (poll for the outcome).
pub async fn get_enroll_join(
    State(wb): State<SharedWorkbench>,
    Path(session): Path<String>,
) -> impl IntoResponse {
    let drive = wb.lock_unpoisoned().enroll_drive();
    enroll_status_json(drive.join_snapshot(&session))
}

// ---- settings ------------------------------------------------------------

pub async fn get_settings(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    let scope = wb.account_scope_for(net_http::bearer(&headers));
    match wb.account_settings_in(&scope) {
        Ok(settings) => (StatusCode::OK, Json(json!({ "settings": settings }))).into_response(),
        Err(e) => err_response(e),
    }
}

#[derive(Deserialize)]
pub struct SettingBody {
    value: String,
}

pub async fn put_setting(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Path(key): Path<String>,
    Json(body): Json<SettingBody>,
) -> impl IntoResponse {
    let record = SettingRecord {
        id: key,
        op: RecordOp::Upsert,
        value: body.value,
    };
    let mut wb = wb.lock_unpoisoned();
    let scope = wb.account_scope_for(net_http::bearer(&headers));
    if let Err(e) = wb.upsert_account_setting_in(&scope, &record) {
        return err_response(e);
    }
    (StatusCode::OK, Json(json!({ "setting": record }))).into_response()
}

// ---- linked credentials (sealed; plaintext never returned) ---------------

pub async fn get_credentials(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let wb = wb.lock_unpoisoned();
    let scope = wb.account_scope_for(net_http::bearer(&headers));
    match wb.account_credential_providers_in(&scope) {
        Ok(provider_ids) => {
            // Providers + linked-flag only — never the token (sealed or otherwise).
            let providers: Vec<serde_json::Value> = provider_ids
                .iter()
                .map(|p| json!({ "provider": p, "linked": true }))
                .collect();
            (StatusCode::OK, Json(json!({ "credentials": providers }))).into_response()
        }
        Err(e) => err_response(e),
    }
}

#[derive(Deserialize)]
pub struct LinkBody {
    provider: String,
    token: String,
    /// OpenAI-compatible endpoint base URL — required for `openai-generic`,
    /// ignored otherwise (ADR 0083). Non-secret.
    #[serde(default)]
    base_url: Option<String>,
    /// Explicit future-use classes. Omission adopts this composition's narrow
    /// default (local-interactive on desktop, private-home on a Home); an empty
    /// set deliberately admits no execution. Public use is never a default.
    #[serde(default)]
    execution_classes: Option<std::collections::BTreeSet<crate::account::ModelExecutionClass>>,
}

/// Link a provider account: seal the OAuth token (`SEC-4`) and store the ciphertext.
pub async fn post_credential(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Json(body): Json<LinkBody>,
) -> impl IntoResponse {
    if body.provider.trim().is_empty() || body.token.is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            "provider and token are required",
        )
            .into_response();
    }
    let mut wb = wb.lock_unpoisoned();
    let scope = wb.account_scope_for(net_http::bearer(&headers));
    // The seal is at-rest encryption under this account's seed-derived key (ADR 0053 §4);
    // the per-person access boundary is the scope (INV-1), so a person only ever reads their
    // own credentials.
    let provider = body.provider;
    let base_url = match crate::account::link_base_url_for(&provider, body.base_url.as_deref()) {
        Ok(base_url) => base_url,
        Err(reason) => return (StatusCode::UNPROCESSABLE_ENTITY, reason).into_response(),
    };
    let Some(sealed) = seal_token(wb.account_key(), &body.token) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "seal failed").into_response();
    };
    let execution_classes = body
        .execution_classes
        .unwrap_or_else(|| wb.default_model_execution_classes());
    if let Err(e) = wb.upsert_account_credential_in_with_policy(
        &scope,
        provider.clone(),
        sealed,
        base_url,
        execution_classes.clone(),
    ) {
        return err_response(e);
    }
    // Advance the onboarding checklist (ADR 0075 Phase 2). Best-effort — the
    // credential is already saved; the provider name is not a secret.
    wb.advance_onboarding("credential", &json!({ "provider": provider }).to_string());
    (
        StatusCode::OK,
        Json(json!({
            "provider": provider,
            "linked": true,
            "execution_classes": execution_classes,
        })),
    )
        .into_response()
}

pub async fn delete_credential(
    State(wb): State<SharedWorkbench>,
    headers: HeaderMap,
    Path(provider): Path<String>,
) -> impl IntoResponse {
    let mut wb = wb.lock_unpoisoned();
    let scope = wb.account_scope_for(net_http::bearer(&headers));
    if let Err(e) = wb.tombstone_account_credential_in(&scope, provider.clone()) {
        return err_response(e);
    }
    (
        StatusCode::OK,
        Json(json!({ "provider": provider, "linked": false })),
    )
        .into_response()
}
