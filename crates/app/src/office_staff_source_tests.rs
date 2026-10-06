use super::*;
use std::io::Write;

const NOW: u64 = 1_800_000_000_000;
const BEARER: &str = "synthetic-workforce-bearer";

fn identity(account: &str, bearer: &str) -> AccountIdentity {
    AccountIdentity {
        holds_email: None,
        account: account.into(),
        session: Some(AccountSessionEvidence {
            session_ref: crate::account_session::session_id(bearer),
            method: "passkey".into(),
            issued_at_ms: NOW - 1000,
            expires_at_ms: NOW + 100_000,
        }),
    }
}

pub(in crate::office_home_admission) fn hub(
    status: u16,
    headers: &str,
    body: String,
) -> (HubStaffSource, std::thread::JoinHandle<String>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let headers = headers.to_owned();
    let thread = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut request = Vec::new();
        loop {
            let mut bytes = [0; 1024];
            let count = stream.read(&mut bytes).unwrap();
            assert!(count > 0);
            request.extend_from_slice(&bytes[..count]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
            assert!(request.len() < 8192);
        }
        write!(
            stream,
            "HTTP/1.1 {status} X\r\n{headers}content-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        String::from_utf8(request).unwrap()
    });
    (
        HubStaffSource::at(&format!("http://{address}")).unwrap(),
        thread,
    )
}

fn ask(status: u16, headers: &str, body: String) -> SourceCheck {
    let (source, server) = hub(status, headers, body);
    let result = source.check_with_clock(BEARER, || NOW);
    server.join().unwrap();
    result
}

#[test]
fn exact_authenticated_source_evidence_is_required_and_no_home_metadata_is_sent() {
    let body = serde_json::to_string(&identity("alice", BEARER)).unwrap();
    let (source, server) = hub(200, "cache-control: no-store\r\n", body);
    let SourceCheck::Verified(proof) = source.check_with_clock(BEARER, || NOW) else {
        panic!("current native source refused");
    };
    assert_eq!(proof.issuer(), source.endpoint.as_str());
    assert_eq!(proof.account(), "alice");
    assert_eq!(
        proof.session().session_ref,
        crate::account_session::session_id(BEARER)
    );
    assert_eq!(proof.checked_at_ms(), NOW);
    let request = server.join().unwrap();
    assert!(request.starts_with("GET /account/identity HTTP/1.1\r\n"));
    assert!(request.contains(&format!("authorization: Bearer {BEARER}\r\n")));
    assert!(!request.contains("x-gaugewright-home-admission"));
    assert!(!request.contains("x-gaugewright-tenant"));
    assert!(!request.contains("cookie:"));
    assert!(!format!("{proof:?}").contains(BEARER));
}

#[test]
fn old_account_only_external_token_and_incomplete_or_wrong_session_evidence_refuse() {
    for fault in 0..12 {
        let mut response = identity("alice", BEARER);
        match fault {
            0 => response.session = None,
            1 => response.account.clear(),
            2 => {
                response.session.as_mut().unwrap().session_ref =
                    crate::account_session::session_id("other-source")
            }
            3 => response.session.as_mut().unwrap().method.clear(),
            4 => response.session.as_mut().unwrap().issued_at_ms = 0,
            5 => response.session.as_mut().unwrap().issued_at_ms = NOW + 1,
            6 => response.session.as_mut().unwrap().expires_at_ms = NOW,
            7 => {
                response.session.as_mut().unwrap().expires_at_ms =
                    NOW + crate::account::SESSION_ABSOLUTE_LIFETIME_MS
            }
            8 => response.account = " ".into(),
            9 => response.account = "x".repeat(513),
            10 => response.session.as_mut().unwrap().method = "x".repeat(513),
            11 => response.session.as_mut().unwrap().method = " ".into(),
            _ => unreachable!(),
        }
        assert_eq!(
            ask(
                200,
                "cache-control: no-store\r\n",
                serde_json::to_string(&response).unwrap()
            ),
            SourceCheck::Refused,
            "fault {fault}"
        );
    }
}

#[test]
fn explicit_refusal_and_invalid_success_are_distinct_from_connection_outage() {
    for status in [401, 403, 404, 500] {
        assert_eq!(ask(status, "", "{}".into()), SourceCheck::Refused);
    }
    for status in [502, 503, 504] {
        assert_eq!(ask(status, "", "{}".into()), SourceCheck::Unavailable);
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    assert_eq!(
        HubStaffSource::at(&url).unwrap().check(BEARER),
        SourceCheck::Unavailable
    );
    assert_eq!(
        ask(200, "cache-control: no-store\r\n", "not-json".into()),
        SourceCheck::Refused
    );
    assert_eq!(
        ask(
            200,
            "cache-control: no-store\r\n",
            "x".repeat(16 * 1024 + 1)
        ),
        SourceCheck::Refused
    );
    assert_eq!(
        ask(
            200,
            "cache-control: no-store\r\n",
            "{\"account\":\"alice\",\"session\":{}}".into()
        ),
        SourceCheck::Refused
    );
}

#[test]
fn a_response_cannot_replay_a_cached_identity_or_redirect_the_bearer() {
    let body = serde_json::to_string(&identity("alice", BEARER)).unwrap();
    assert_eq!(ask(200, "", body.clone()), SourceCheck::Refused);
    assert_eq!(
        ask(200, "cache-control: max-age=300\r\n", body),
        SourceCheck::Refused
    );
    let trap = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    trap.set_nonblocking(true).unwrap();
    let headers = format!(
        "location: http://{}/account/identity\r\n",
        trap.local_addr().unwrap()
    );
    assert_eq!(ask(302, &headers, "{}".into()), SourceCheck::Refused);
    assert_eq!(
        trap.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn sign_in_destination_requires_tls_except_literal_loopback_and_rejects_url_credentials() {
    for url in [
        "http://auth.example",
        "http://localhost:1234",
        "https://user:password@auth.example",
        "https://auth.example?token=x",
        "https://auth.example#fragment",
        "file:///tmp/identity",
    ] {
        assert!(HubStaffSource::at(url).is_err(), "{url}");
    }
    for url in [
        "https://auth.example",
        "https://auth.example/base",
        "http://127.0.0.1:1234",
        "http://[::1]:1234",
    ] {
        assert!(HubStaffSource::at(url).is_ok(), "{url}");
    }
    let source = HubStaffSource::at("https://auth.example/base/").unwrap();
    assert_eq!(
        source.endpoint.as_str(),
        "https://auth.example/base/account/identity"
    );
    for bearer in ["", "a\r\ninjected: header", "a b", "é"] {
        assert_eq!(source.check(bearer), SourceCheck::Refused);
    }
}

#[test]
fn each_check_observes_current_authority_and_never_caches_a_success() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        for status in [200, 401] {
            let (mut stream, _) = listener.accept().unwrap();
            let mut bytes = [0; 4096];
            let count = stream.read(&mut bytes).unwrap();
            assert!(count > 0);
            let body = serde_json::to_string(&identity("alice", BEARER)).unwrap();
            write!(stream, "HTTP/1.1 {status} X\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).unwrap();
        }
    });
    let source = HubStaffSource::at(&url).unwrap();
    assert!(matches!(
        source.check_with_clock(BEARER, || NOW),
        SourceCheck::Verified(_)
    ));
    assert_eq!(
        source.check_with_clock(BEARER, || NOW),
        SourceCheck::Refused
    );
    server.join().unwrap();
}
