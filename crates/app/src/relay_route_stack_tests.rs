//! DR-0206: the relay router admits the Home's owner, as the Hub names them,
//! and nobody else. The whole path over a real relay is in `open_runtime`'s
//! reachability tests; these hold the pieces it is made of.
use super::*;
use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use tower::ServiceExt;

/// A Hub on loopback answering `GET /account/identity` with `status` and
/// `body`, counting how often it was asked.
fn hub(status: u16, body: &'static str) -> (String, Arc<AtomicUsize>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let asked = Arc::new(AtomicUsize::new(0));
    let counter = asked.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut request = [0u8; 4096];
            let read = stream.read(&mut request).unwrap_or(0);
            let text = String::from_utf8_lossy(&request[..read]);
            assert!(text.starts_with("GET /account/identity "), "{text}");
            assert!(
                text.to_ascii_lowercase().contains("authorization: bearer "),
                "{text}"
            );
            counter.fetch_add(1, Ordering::SeqCst);
            let _ = write!(
                stream,
                "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\n\
                 content-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    (format!("http://{address}"), asked)
}

#[test]
fn the_hub_names_the_account_and_is_asked_once_per_bearer() {
    let (url, asked) = hub(200, r#"{"account":"account-root"}"#);
    let accounts = HubBearerAccounts::at(Some(url));
    assert_eq!(accounts.account_for("b"), Ok(Some("account-root".into())));
    assert_eq!(accounts.account_for("b"), Ok(Some("account-root".into())));
    assert_eq!(asked.load(Ordering::SeqCst), 1, "remembered for the burst");
    assert_eq!(
        accounts.account_for("another"),
        Ok(Some("account-root".into()))
    );
    assert_eq!(
        asked.load(Ordering::SeqCst),
        2,
        "a different bearer asks again"
    );
}

/// Each lookup the cache cannot answer goes to the Hub over a connection the
/// last one left open, not a new TCP connection and TLS handshake (WS-919).
#[test]
fn identity_lookups_reuse_one_connection_to_the_hub() {
    let hub = crate::test_support::keep_alive_server(r#"{"account":"account-root"}"#);
    let accounts = HubBearerAccounts::at(Some(hub.url.clone()));
    assert_eq!(accounts.account_for("b"), Ok(Some("account-root".into())));
    assert_eq!(
        accounts.account_for("another"),
        Ok(Some("account-root".into()))
    );
    let fresh = HubBearerAccounts::at(Some(hub.url.clone()));
    assert_eq!(
        fresh.account_for("a third"),
        Ok(Some("account-root".into()))
    );
    assert_eq!(hub.requests(), 3, "each bearer asked the Hub");
    assert_eq!(hub.connections(), 1, "over one connection");
}

#[test]
fn a_bearer_the_hub_refuses_is_nobody_and_is_not_remembered() {
    let (url, asked) = hub(401, r#"{"error":"this bearer is not recognised"}"#);
    let accounts = HubBearerAccounts::at(Some(url));
    assert_eq!(accounts.account_for("b"), Ok(None));
    assert_eq!(accounts.account_for("b"), Ok(None));
    assert_eq!(asked.load(Ordering::SeqCst), 2);
}

/// Not reaching the Hub is not "nobody": it is an answer the router reports
/// as unavailable, never as a refusal of the person.
#[test]
fn an_unreachable_or_unconfigured_hub_is_an_error_not_a_verdict() {
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", closed.local_addr().unwrap());
    drop(closed);
    assert!(HubBearerAccounts::at(Some(url)).account_for("b").is_err());
    assert!(HubBearerAccounts::at(None).account_for("b").is_err());
    let (url, _) = hub(200, r#"{"account":""}"#);
    assert!(HubBearerAccounts::at(Some(url)).account_for("b").is_err());
}

#[test]
fn this_computers_own_sign_in_and_login_shell_stay_local() {
    for (method, path) in [
        (Method::POST, "/account/hub-session/start"),
        (Method::POST, "/account/hub-session/logout"),
        (Method::POST, "/account/hub-session/reach"),
        (Method::GET, "/auth/login"),
        (Method::POST, "/test/reset"),
        // The computer's own account records never cross (DR-0328 §6).
        (Method::GET, "/account/hub-session"),
        (Method::GET, "/account/hub-sessions"),
        (Method::GET, "/account/homes"),
        (Method::GET, "/account/devices"),
        (Method::POST, "/account/library-sync"),
        (Method::GET, "/gaugeapps/account-settings/page"),
    ] {
        assert!(local_only(&method, path), "{method} {path}");
    }
    for (method, path) in [
        (Method::GET, "/workspace"),
        (Method::POST, "/home/invitations"),
        // The caller's own credentials are keyed by its account.
        (Method::GET, "/account/credentials"),
        (Method::GET, "/account/oauth/openai-codex"),
    ] {
        assert!(!local_only(&method, path), "{method} {path}");
    }
}

struct Owner;

impl BearerAccounts for Owner {
    fn account_for(&self, _bearer: &str) -> Result<Option<String>, String> {
        Ok(Some("account-root".to_owned()))
    }
}

async fn send(
    app: &Router,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, String) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("idempotency-key", format!("{method}{uri}{}", headers.len()));
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// The Hub names the owner, but this computer has since been signed out: the
/// Home acts for a remote caller only as the person signed in at it.
#[tokio::test]
async fn a_signed_out_computer_admits_its_owner_to_nothing() {
    let root = tempfile::tempdir().unwrap();
    let wb = crate::open_workbench(root.path()).unwrap();
    crate::account_signin::store_session_for_test(&wb);
    crate::home_owner::claim_if_never_claimed(&wb).unwrap();
    let app = relay_control_plane(wb.clone(), Arc::new(Owner));
    let bearer = [("authorization", "Bearer owner-bearer")];
    let (status, body) = send(&app, "POST", "/home/admissions", &bearer).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let admission = serde_json::from_str::<serde_json::Value>(&body).unwrap()["admission"]
        .as_str()
        .unwrap()
        .to_owned();
    let admitted = [
        ("authorization", "Bearer owner-bearer"),
        ("x-gaugewright-home-admission", admission.as_str()),
    ];
    assert_eq!(
        send(&app, "GET", "/workspace", &admitted).await.0,
        StatusCode::OK
    );

    let _ = crate::account_signin::post_signin_logout(axum::extract::State(wb.clone())).await;
    let (status, body) = send(&app, "GET", "/workspace", &admitted).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("not signed in on this computer"), "{body}");
}

/// Served under the owner's own Home session, so a handler that attributes
/// its caller names the owner — never the local operator a desktop answers
/// an unknown bearer as.
#[tokio::test]
async fn an_admitted_call_is_served_as_the_owner() {
    let root = tempfile::tempdir().unwrap();
    let wb = crate::open_workbench(root.path()).unwrap();
    crate::account_signin::store_session_for_test(&wb);
    crate::home_owner::claim_if_never_claimed(&wb).unwrap();
    let seen = Arc::new(Mutex::new(None::<String>));
    let witness = seen.clone();
    let probe_wb = wb.clone();
    let app = crate::open_control_plane(wb.clone())
        .route(
            "/probe",
            axum::routing::get(move |headers: HeaderMap| {
                let witness = witness.clone();
                let wb = probe_wb.clone();
                async move {
                    // The judgement admitted handlers make of their caller.
                    let actor = wb
                        .lock_unpoisoned()
                        .admit_data_request(net_http::bearer(&headers), None)
                        .ok();
                    *witness.lock_unpoisoned() = actor;
                    StatusCode::NO_CONTENT
                }
            }),
        )
        .layer(axum::middleware::from_fn_with_state(
            Relay {
                wb: wb.clone(),
                accounts: Arc::new(Owner),
            },
            admit_relay_caller,
        ));
    let (_, body) = send(
        &app,
        "POST",
        "/home/admissions",
        &[("authorization", "Bearer owner-bearer")],
    )
    .await;
    let admission = serde_json::from_str::<serde_json::Value>(&body).unwrap()["admission"]
        .as_str()
        .unwrap()
        .to_owned();
    let (status, _) = send(
        &app,
        "GET",
        "/probe",
        &[
            ("authorization", "Bearer owner-bearer"),
            ("x-gaugewright-home-admission", admission.as_str()),
            ("x-gaugewright-machine-session", "smuggled"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(seen.lock_unpoisoned().as_deref(), Some("account-root"));
}

#[tokio::test]
async fn same_account_sessions_coexist_and_revoke_independently() {
    let root = tempfile::tempdir().unwrap();
    let wb = crate::open_workbench(root.path()).unwrap();
    crate::account_signin::store_session_for_test(&wb);
    crate::home_owner::claim_if_never_claimed(&wb).unwrap();
    let app = relay_control_plane(wb, Arc::new(Owner));
    let bearer = [("authorization", "Bearer owner-bearer")];
    let mut tokens = Vec::new();
    for _ in 0..2 {
        let (status, body) = send(&app, "POST", "/home/admissions", &bearer).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        tokens.push(
            serde_json::from_str::<serde_json::Value>(&body).unwrap()["admission"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    for token in &tokens {
        let headers = [
            ("authorization", "Bearer owner-bearer"),
            (HOME_ADMISSION_HEADER, token.as_str()),
        ];
        assert_eq!(
            send(&app, "GET", "/workspace", &headers).await.0,
            StatusCode::OK
        );
    }
    let first = [
        ("authorization", "Bearer owner-bearer"),
        (HOME_ADMISSION_HEADER, tokens[0].as_str()),
    ];
    assert_eq!(
        send(&app, "DELETE", "/home/admissions", &first).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        send(&app, "GET", "/workspace", &first).await.0,
        StatusCode::UNAUTHORIZED
    );
    let second = [
        ("authorization", "Bearer owner-bearer"),
        (HOME_ADMISSION_HEADER, tokens[1].as_str()),
    ];
    assert_eq!(
        send(&app, "GET", "/workspace", &second).await.0,
        StatusCode::OK
    );
}

struct Stranger;

impl BearerAccounts for Stranger {
    fn account_for(&self, _bearer: &str) -> Result<Option<String>, String> {
        Ok(Some("someone-else".to_owned()))
    }
}

async fn connection_header(
    app: &Router,
    uri: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, Option<String>) {
    let mut builder = Request::builder().method("GET").uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let close = response
        .headers()
        .get(axum::http::header::CONNECTION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    (response.status(), close)
}

/// DR-0302: a caller the Home has not verified is answered and hung up, so
/// holding the public locator holds a crossing for seconds, not for as long as
/// the caller likes.
#[tokio::test]
async fn a_caller_the_home_has_not_verified_is_hung_up_on() {
    let root = tempfile::tempdir().unwrap();
    let wb = crate::open_workbench(root.path()).unwrap();
    crate::account_signin::store_session_for_test(&wb);
    crate::home_owner::claim_if_never_claimed(&wb).unwrap();
    let strangers = relay_control_plane(wb.clone(), Arc::new(Stranger));
    for (uri, headers) in [
        ("/workspace", &[][..]),
        (
            "/workspace",
            &[("authorization", "Bearer not-the-owner")][..],
        ),
        ("/auth/login", &[][..]),
        ("/health", &[][..]),
    ] {
        let (status, close) = connection_header(&strangers, uri, headers).await;
        assert_eq!(
            close.as_deref(),
            Some("close"),
            "{uri} answered {status} and kept the connection"
        );
    }
}

/// The owner keeps their connection even when refused, because a refusal they
/// meet — an expired admission — is answered by admitting again over it.
#[tokio::test]
async fn the_owner_keeps_the_connection_through_a_refusal() {
    let root = tempfile::tempdir().unwrap();
    let wb = crate::open_workbench(root.path()).unwrap();
    crate::account_signin::store_session_for_test(&wb);
    crate::home_owner::claim_if_never_claimed(&wb).unwrap();
    let app = relay_control_plane(wb.clone(), Arc::new(Owner));
    let (status, close) = connection_header(
        &app,
        "/workspace",
        &[("authorization", "Bearer owner-bearer")],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(close, None);
}

/// A route that never crosses is refused to the owner too, but over the
/// connection their other calls share, which a hang-up would have failed.
#[tokio::test]
async fn the_owner_keeps_the_connection_through_a_local_only_refusal() {
    let root = tempfile::tempdir().unwrap();
    let wb = crate::open_workbench(root.path()).unwrap();
    crate::account_signin::store_session_for_test(&wb);
    crate::home_owner::claim_if_never_claimed(&wb).unwrap();
    let app = relay_control_plane(wb.clone(), Arc::new(Owner));
    let (status, close) = connection_header(
        &app,
        "/account/onboarding-status",
        &[("authorization", "Bearer owner-bearer")],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(close, None);

    let strangers = relay_control_plane(wb.clone(), Arc::new(Stranger));
    let (status, close) = connection_header(
        &strangers,
        "/account/onboarding-status",
        &[("authorization", "Bearer not-the-owner")],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(close.as_deref(), Some("close"));
}

/// DR-0328 §6: any account signed in on this computer crosses the relay as
/// itself, beside the claimant, and reaches only its own projects.
#[tokio::test]
async fn another_account_signed_in_here_crosses_as_itself() {
    let root = tempfile::tempdir().unwrap();
    let wb = crate::open_workbench(root.path()).unwrap();
    crate::account_signin::store_session_for_test(&wb);
    crate::home_owner::claim_if_never_claimed(&wb).unwrap();
    crate::account_signin::store_session_as_for_test(&wb, "someone-else");
    let app = relay_control_plane(wb.clone(), Arc::new(Stranger));
    let bearer = [("authorization", "Bearer someone-elses-bearer")];
    let (status, body) = send(&app, "POST", "/home/admissions", &bearer).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let admission = serde_json::from_str::<serde_json::Value>(&body).unwrap()["admission"]
        .as_str()
        .unwrap()
        .to_owned();
    let admitted = [
        ("authorization", "Bearer someone-elses-bearer"),
        ("x-gaugewright-home-admission", admission.as_str()),
    ];
    let (status, body) = send(&app, "GET", "/workspace", &admitted).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let workspace: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(
        workspace["projects"]
            .as_array()
            .unwrap()
            .iter()
            .all(|project| project["id"] != crate::DEFAULT_PROJECT),
        "the claimant's Personal is not this account's: {body}"
    );
    let (status, _) = send(&app, "GET", "/account/hub-sessions", &admitted).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the computer's accounts stay local"
    );
}

/// A project member who is not signed in on this computer reaches its
/// projects' work and nothing host-wide (DR-0328 §6, WS-861).
#[test]
fn a_member_reaches_its_projects_work_and_nothing_host_wide() {
    for (method, path) in [
        (Method::GET, "/account/credentials"),
        (Method::PUT, "/account/settings"),
        (Method::GET, "/account/default-model"),
        (Method::GET, "/admin/members"),
        (Method::POST, "/archetypes"),
        (Method::POST, "/federation/invite"),
        (Method::POST, "/home/invitations"),
        (Method::GET, "/home/projects/proj-1/invitations"),
        (Method::POST, "/tutorials/basics/start"),
        (Method::GET, "/roster"),
        (Method::POST, "/projects"),
        (Method::POST, "/chats"),
        (Method::POST, "/projects/proj-1/fork"),
        (Method::DELETE, "/projects/proj-1"),
        (Method::POST, "/local-projects/transfer"),
    ] {
        assert!(member_refused(&method, path), "{method} {path}");
    }
    for (method, path) in [
        (Method::GET, "/workspace"),
        (Method::GET, "/workspace/events"),
        (Method::GET, "/projects/proj-1/models"),
        // What its composer offers: the project's own credentials (WS-1026).
        (Method::GET, "/projects/proj-1/models"),
        (Method::POST, "/projects/proj-1/settings/sessions"),
        (Method::POST, "/projects/proj-1/placements/inst-1/chats"),
        (Method::POST, "/placements/inst-1/settings/sessions"),
        (Method::GET, "/chats/chat-1/transcript"),
        (Method::POST, "/chats/chat-1/task"),
        (Method::POST, "/chats/chat-1/fork"),
        (Method::GET, "/tasks"),
    ] {
        assert!(!member_refused(&method, path), "{method} {path}");
    }
}

/// A member authors, tries, publishes and deploys the Agents placed in its
/// projects; the handler behind decides which those are (DR-0453). What stays
/// the owner's about an Agent or a deployment never crosses.
#[test]
fn a_member_reaches_its_projects_agents_and_not_what_stays_the_owners() {
    for (method, path) in [
        (Method::GET, "/archetypes/agent-1"),
        (Method::PUT, "/archetypes/agent-1"),
        (Method::GET, "/archetypes/agent-1/abilities"),
        (Method::PUT, "/archetypes/agent-1/abilities"),
        (Method::GET, "/archetypes/agent-1/panel-profile"),
        (Method::PUT, "/archetypes/agent-1/panel-profile"),
        (Method::POST, "/archetypes/agent-1/chats"),
        (Method::POST, "/archetypes/agent-1/preview"),
        (Method::POST, "/archetypes/agent-1/publish"),
        (Method::POST, "/archetypes/agent-1/settings/sessions"),
        (Method::POST, "/archetypes/agent-1/settings/agent/messages"),
        (Method::POST, "/archetypes/agent-1/settings/commands"),
        (Method::POST, "/placements/inst-1/upgrade"),
        (Method::POST, "/public-deployments"),
        (Method::GET, "/public-deployments/publisher-authority"),
        (Method::POST, "/public-deployments/inspect"),
        (Method::POST, "/public-deployments/credentials/list"),
    ] {
        assert!(!member_refused(&method, path), "{method} {path}");
    }
    for (method, path) in [
        (Method::POST, "/archetypes"),
        (Method::DELETE, "/archetypes/agent-1"),
        (Method::POST, "/archetypes/agent-1/fork"),
        (Method::POST, "/archetypes/agent-1/copy-as-panel"),
        (Method::POST, "/archetypes/agent-1/pull-from-source"),
        (Method::POST, "/archetypes/agent-1/use"),
        (Method::DELETE, "/archetypes/agent-1/chats"),
        (Method::GET, "/archetypes//settings/sessions"),
        (Method::POST, "/public-deployments/control"),
        (Method::POST, "/public-deployments/import"),
        (Method::POST, "/public-deployments/erase-session"),
        (Method::POST, "/public-deployments/collect"),
        (Method::POST, "/public-deployments/credentials/provision"),
        (Method::POST, "/public-deployments/credentials/revoke"),
        (Method::GET, "/public-deployments"),
    ] {
        assert!(member_refused(&method, path), "{method} {path}");
    }
}
