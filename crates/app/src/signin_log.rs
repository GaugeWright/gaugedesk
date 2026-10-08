//! One line for every sign-in step that is refused, and one for every step
//! that completes (WS-869).
//!
//! A desktop sign-in crosses five steps in two processes: the desktop's
//! `/account/hub-session/start`, the Hub's `/auth/login`, the provider, the
//! Hub's `/auth/callback`, then the desktop's `/account/hub-session/callback`,
//! which redeems the one-time code at the Hub's `/auth/mobile/exchange`. A
//! passkey sign-in replaces the provider and the callback with the Hub's
//! `/auth/account/passkey/login/start` and `/finish`, which issues the code
//! (DR-0457). On
//! 2026-10-07 a person's exchange answered 401 and a desktop callback answered
//! 400, and neither process had written down why: the Hub's handoff store
//! answered "no" alike for a code it never issued, one that had expired, one
//! already spent, and one presented with another attempt's verifier.
//!
//! Each refusal now names a machine-readable `reason`, and every line carries
//! whichever of these correlation ids the step holds:
//!
//! - `attempt` — the PKCE handoff challenge, which the desktop mints when the
//!   person presses Sign in and the Hub receives at `/auth/login`. Two attempts
//!   seconds apart are a double click. An exchange refused as `pkce_mismatch`
//!   names the attempt the code was issued to (`attempt`) and the attempt whose
//!   verifier was presented (`presented_attempt`).
//! - `code` — the one-time handoff code the Hub issued at the callback.
//! - `state` — the OIDC `state` joining `/auth/login` to `/auth/callback`.
//!
//! Each is the first eight hex digits of the SHA-256 of the value, never the
//! value: the code and the verifier are credentials, and the challenge and
//! state are hashed so that one rule covers every id. No line carries a token,
//! a cookie, a verifier or an email address.
//!
//! `outstanding_ms` is how long the thing being redeemed — the state, the code,
//! the desktop's pending attempt — had been outstanding when it was presented.
//!
//! Refusals are `warn`, and `error` when the step failed on the server's side
//! (a 5xx), so the Hub's default `warn` filter admits them. Completions are
//! `info`: the desktop's log admits them by default, and the Hub's admits them
//! for this target with `RUST_LOG=warn,gaugedesk_app::signin_log=info`. Every
//! event is emitted here, so its target is `gaugedesk_app::signin_log` and one
//! search for `signin_log` reads a sign-in end to end.

use std::time::Duration;

use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};

pub(crate) const LOGIN: &str = "/auth/login";
pub(crate) const WORK_EMAIL: &str = "/auth/work-email";
pub(crate) const CALLBACK: &str = "/auth/callback";
pub(crate) const SAML_ACS: &str = "/auth/saml/acs";
pub(crate) const EXCHANGE: &str = "/auth/mobile/exchange";
pub(crate) const CONSUMER_LINK_START: &str = "/auth/account/consumer-oidc/link/start";
pub(crate) const CONSUMER_AVATAR_START: &str = "/auth/account/consumer-oidc/avatar/start";
pub(crate) const PASSKEY_REGISTER_START: &str = "/auth/account/passkey/register/start";
pub(crate) const PASSKEY_REGISTER_FINISH: &str = "/auth/account/passkey/register/finish";
pub(crate) const PASSKEY_LOGIN_START: &str = "/auth/account/passkey/login/start";
pub(crate) const PASSKEY_LOGIN_FINISH: &str = "/auth/account/passkey/login/finish";
pub(crate) const DESKTOP_START: &str = "/account/hub-session/start";
pub(crate) const DESKTOP_CALLBACK: &str = "/account/hub-session/callback";

/// The Hub's sign-in steps. A refusal on one of these that no handler named is
/// still logged, as `unclassified`, by [`log_unclassified_refusals`].
const HUB_STEPS: [&str; 6] = [
    LOGIN,
    WORK_EMAIL,
    CALLBACK,
    EXCHANGE,
    PASSKEY_LOGIN_START,
    PASSKEY_LOGIN_FINISH,
];

/// The first eight hex digits of `value`'s SHA-256: enough to join lines across
/// steps and processes, and useless to anyone who reads it.
pub(crate) fn digest(value: &str) -> String {
    hex::encode(&Sha256::digest(value.as_bytes())[..4])
}

/// The correlation ids and measurements one line carries. Every field is
/// optional, and an absent one is left off the line rather than written empty.
#[derive(Clone, Debug, Default)]
pub(crate) struct Trace {
    code: Option<String>,
    attempt: Option<String>,
    presented_attempt: Option<String>,
    previous_attempt: Option<String>,
    state: Option<String>,
    outstanding_ms: Option<u64>,
    detail: Option<&'static str>,
    upstream_status: Option<u16>,
}

impl Trace {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// The one-time handoff code, by digest.
    pub(crate) fn code(mut self, code: &str) -> Self {
        self.code = Some(digest(code));
        self
    }

    /// The attempt, named by the PKCE handoff challenge it was started with.
    pub(crate) fn attempt(mut self, challenge: &str) -> Self {
        self.attempt = Some(digest(challenge));
        self
    }

    /// [`attempt`](Self::attempt), when the step may not have one.
    pub(crate) fn maybe_attempt(self, challenge: Option<&str>) -> Self {
        match challenge {
            Some(challenge) => self.attempt(challenge),
            None => self,
        }
    }

    /// The attempt whose verifier an exchange presented, named by the challenge
    /// that verifier hashes to.
    pub(crate) fn presented_attempt(mut self, challenge: &str) -> Self {
        self.presented_attempt = Some(digest(challenge));
        self
    }

    /// The attempt a new one replaced before it was completed.
    pub(crate) fn previous_attempt(mut self, challenge: &str) -> Self {
        self.previous_attempt = Some(digest(challenge));
        self
    }

    /// The OIDC `state`, by digest.
    pub(crate) fn state(mut self, state: &str) -> Self {
        self.state = Some(digest(state));
        self
    }

    pub(crate) fn outstanding(mut self, outstanding: Duration) -> Self {
        self.outstanding_ms = Some(u64::try_from(outstanding.as_millis()).unwrap_or(u64::MAX));
        self
    }

    pub(crate) fn outstanding_ms(mut self, outstanding_ms: u64) -> Self {
        self.outstanding_ms = Some(outstanding_ms);
        self
    }

    /// A bounded qualifier: which provider, which earlier outcome, which
    /// standard OAuth error. Never free text from a request or a provider.
    pub(crate) fn detail(mut self, detail: &'static str) -> Self {
        self.detail = Some(detail);
        self
    }

    /// The status another service answered this step with.
    pub(crate) fn upstream_status(mut self, status: u16) -> Self {
        self.upstream_status = Some(status);
        self
    }
}

/// Why a sign-in step was refused, carried on the response. A test reads the
/// reason from it, and [`log_unclassified_refusals`] reads from it that the
/// line has already been written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigninRefusal {
    pub route: &'static str,
    pub reason: &'static str,
}

macro_rules! refusal_event {
    ($level:ident, $route:expr, $reason:expr, $status:expr, $trace:expr) => {
        tracing::$level!(
            route = $route,
            reason = $reason,
            status = $status,
            attempt = $trace.attempt.as_deref(),
            presented_attempt = $trace.presented_attempt.as_deref(),
            code = $trace.code.as_deref(),
            state = $trace.state.as_deref(),
            outstanding_ms = $trace.outstanding_ms,
            detail = $trace.detail,
            upstream_status = $trace.upstream_status,
            "sign-in step refused"
        )
    };
}

fn emit_refusal(route: &'static str, reason: &'static str, status: StatusCode, trace: &Trace) {
    let status = status.as_u16();
    if status >= 500 {
        refusal_event!(error, route, reason, status, trace);
    } else {
        refusal_event!(warn, route, reason, status, trace);
    }
}

/// Log `response` as the refusal of `route` for `reason`, and mark it so.
pub(crate) fn refused(
    route: &'static str,
    reason: &'static str,
    trace: &Trace,
    mut response: Response,
) -> Response {
    emit_refusal(route, reason, response.status(), trace);
    response
        .extensions_mut()
        .insert(SigninRefusal { route, reason });
    response
}

/// Refuse `route` with `status` and `message`, logging `reason`.
pub(crate) fn refuse(
    route: &'static str,
    reason: &'static str,
    trace: &Trace,
    status: StatusCode,
    message: impl IntoResponse,
) -> Response {
    refused(route, reason, trace, (status, message).into_response())
}

/// Log that `route` completed with `outcome`.
pub(crate) fn completed(route: &'static str, outcome: &'static str, trace: &Trace) {
    tracing::info!(
        route,
        outcome,
        attempt = trace.attempt.as_deref(),
        previous_attempt = trace.previous_attempt.as_deref(),
        code = trace.code.as_deref(),
        state = trace.state.as_deref(),
        outstanding_ms = trace.outstanding_ms,
        detail = trace.detail,
        "sign-in step completed"
    );
}

/// Log that a sign-in recorded the address its provider attested on the
/// account it signed in to, which had not held it (WS-937). Like every line
/// here it names neither the address nor the account.
pub(crate) fn email_recorded(route: &'static str, trace: &Trace) {
    tracing::info!(
        route,
        outcome = "verified_email_recorded",
        attempt = trace.attempt.as_deref(),
        state = trace.state.as_deref(),
        detail = trace.detail,
        "sign-in recorded the provider's verified email"
    );
}

/// Log why a sign-in did not record the address its provider attested
/// (WS-937). The sign-in itself succeeded; this is the line that explains why
/// the account still cannot accept an invitation sent to that address. It says
/// that another account holds the address without saying which, or whose.
pub(crate) fn email_not_recorded(route: &'static str, reason: &'static str, trace: &Trace) {
    tracing::warn!(
        route,
        reason,
        attempt = trace.attempt.as_deref(),
        state = trace.state.as_deref(),
        detail = trace.detail,
        "sign-in did not record the provider's verified email"
    );
}

/// Log any refusal on a Hub sign-in step that its handler did not name. The
/// handlers name every refusal they write; this catches the ones axum writes
/// before a handler runs — a body or query that does not parse — and any
/// branch added later without a reason, so a refused step is never silent.
///
/// Only the path is read. The query is where the provider's code and state
/// ride, and nothing of the request's headers or body is looked at.
pub(crate) async fn log_unclassified_refusals(request: Request, next: Next) -> Response {
    let step = HUB_STEPS
        .iter()
        .copied()
        .find(|route| *route == request.uri().path());
    let response = next.run(request).await;
    if let Some(route) = step {
        let status = response.status();
        if (status.is_client_error() || status.is_server_error())
            && response.extensions().get::<SigninRefusal>().is_none()
        {
            emit_refusal(route, "unclassified", status, &Trace::new());
        }
    }
    response
}

/// The standard OAuth 2.0 and OpenID Connect error codes (RFC 6749 §4.1.2.1,
/// §5.2; OIDC Core §3.1.2.6). A provider's error is logged only as one of
/// these, so nothing it chose to write reaches the log.
const OAUTH_ERRORS: [&str; 15] = [
    "access_denied",
    "invalid_request",
    "invalid_client",
    "invalid_grant",
    "unauthorized_client",
    "unsupported_grant_type",
    "unsupported_response_type",
    "invalid_scope",
    "server_error",
    "temporarily_unavailable",
    "interaction_required",
    "login_required",
    "account_selection_required",
    "consent_required",
    "invalid_request_uri",
];

/// `error` as one of [`OAUTH_ERRORS`], or `other`.
pub(crate) fn oauth_error(error: &str) -> &'static str {
    OAUTH_ERRORS
        .iter()
        .copied()
        .find(|known| *known == error.trim())
        .unwrap_or("other")
}

/// The first standard OAuth error code named anywhere in a token endpoint's
/// failure text, or `unrecognized`.
pub(crate) fn oauth_error_in(text: &str) -> &'static str {
    OAUTH_ERRORS
        .iter()
        .copied()
        .find(|known| text.contains(known))
        .unwrap_or("unrecognized")
}

#[cfg(test)]
pub(crate) mod capture {
    //! Record what this module logs, for tests that assert the line itself.

    use std::io;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    pub(crate) struct Captured(Arc<Mutex<Vec<u8>>>);

    impl Captured {
        pub(crate) fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }
    }

    impl io::Write for Captured {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
        type Writer = Captured;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Run `f` with this thread's events recorded as the Hub writes them, and
    /// return what was written.
    pub(crate) fn lines(f: impl FnOnce()) -> String {
        let captured = Captured::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(captured.clone())
            .with_ansi(false)
            .with_env_filter(tracing_subscriber::EnvFilter::new(
                "warn,gaugedesk_app::signin_log=info",
            ))
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        captured.text()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_digest_is_eight_hex_digits_and_stable() {
        let one = digest("a-one-time-code");
        assert_eq!(one.len(), 8);
        assert!(one.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(one, digest("a-one-time-code"));
        assert_ne!(one, digest("another-code"));
    }

    #[test]
    fn a_refusal_is_one_line_with_its_reason_and_no_secret() {
        let code = "Zm9vYmFyYmF6cXV4LW9uZS10aW1lLWNvZGUtdmFsdWU";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        let response = std::cell::RefCell::new(None);
        let text = capture::lines(|| {
            *response.borrow_mut() = Some(refuse(
                EXCHANGE,
                "pkce_mismatch",
                &Trace::new()
                    .code(code)
                    .attempt(challenge)
                    .presented_attempt("another-challenge")
                    .outstanding(Duration::from_millis(8_250)),
                StatusCode::UNAUTHORIZED,
                "unknown, expired, or incorrectly bound native handoff",
            ));
        });
        let response = response.into_inner().unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.extensions().get::<SigninRefusal>(),
            Some(&SigninRefusal {
                route: EXCHANGE,
                reason: "pkce_mismatch"
            })
        );
        assert_eq!(text.lines().count(), 1, "{text}");
        for expected in [
            " WARN ",
            "gaugedesk_app::signin_log",
            "sign-in step refused",
            "route=\"/auth/mobile/exchange\"",
            "reason=\"pkce_mismatch\"",
            "status=401",
            &format!("code=\"{}\"", digest(code)),
            &format!("attempt=\"{}\"", digest(challenge)),
            &format!("presented_attempt=\"{}\"", digest("another-challenge")),
            "outstanding_ms=8250",
        ] {
            assert!(text.contains(expected), "missing {expected}: {text}");
        }
        assert!(!text.contains(code), "the code itself is never logged");
        assert!(!text.contains(challenge), "nor is the challenge");
        assert!(!text.contains("state="), "an absent id is left off: {text}");
    }

    #[test]
    fn a_server_side_failure_is_an_error_and_a_completion_is_info() {
        let text = capture::lines(|| {
            refuse(
                EXCHANGE,
                "session_mint_failed",
                &Trace::new(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not create the account session",
            );
            completed(
                EXCHANGE,
                "handoff_redeemed",
                &Trace::new().code("c").outstanding_ms(4_100),
            );
        });
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        assert!(lines[0].contains(" ERROR ") && lines[0].contains("session_mint_failed"));
        assert!(lines[1].contains(" INFO ") && lines[1].contains("sign-in step completed"));
        assert!(lines[1].contains("outcome=\"handoff_redeemed\""));
        assert!(lines[1].contains("outstanding_ms=4100"));
    }

    #[tokio::test]
    async fn a_refusal_no_handler_named_is_still_logged() {
        use axum::routing::post;
        use tower::ServiceExt;

        let app = axum::Router::new()
            .route(
                EXCHANGE,
                post(|axum::Json(_): axum::Json<serde_json::Value>| async { "ok" }),
            )
            .route(
                CALLBACK,
                post(|| async {
                    refuse(
                        CALLBACK,
                        "unknown_state",
                        &Trace::new(),
                        StatusCode::BAD_REQUEST,
                        "unknown or expired state",
                    )
                }),
            )
            .layer(axum::middleware::from_fn(log_unclassified_refusals));
        let send = |uri: &'static str| {
            let app = app.clone();
            async move {
                app.oneshot(
                    axum::http::Request::post(uri)
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from("{not json"))
                        .unwrap(),
                )
                .await
                .unwrap()
            }
        };
        let captured = capture::Captured::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(captured.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let malformed = send(EXCHANGE).await;
        assert!(malformed.status().is_client_error());
        let named = send(CALLBACK).await;
        assert_eq!(named.status(), StatusCode::BAD_REQUEST);
        let text = captured.text();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "one line per refusal, never two: {text}");
        assert!(lines[0].contains("reason=\"unclassified\""), "{text}");
        assert!(
            lines[0].contains("route=\"/auth/mobile/exchange\""),
            "{text}"
        );
        assert!(lines[1].contains("reason=\"unknown_state\""), "{text}");
    }

    #[test]
    fn a_provider_error_is_logged_only_as_a_standard_code() {
        assert_eq!(oauth_error("access_denied"), "access_denied");
        assert_eq!(oauth_error("alice@example.test said no"), "other");
        assert_eq!(
            oauth_error_in("HTTP 400: {\"error\":\"invalid_grant\",\"error_description\":\"Bad\"}"),
            "invalid_grant"
        );
        assert_eq!(oauth_error_in("connection reset"), "unrecognized");
    }
}
