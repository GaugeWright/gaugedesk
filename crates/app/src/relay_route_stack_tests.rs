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
    ] {
        assert!(local_only(&method, path), "{method} {path}");
    }
    for (method, path) in [
        (Method::GET, "/account/hub-session"),
        (Method::GET, "/workspace"),
        (Method::POST, "/home/invitations"),
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
    assert!(body.contains(RELAY_REFUSAL), "{body}");
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
