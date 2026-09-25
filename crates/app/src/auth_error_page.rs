//! The page a person lands on when a browser sign-in step refuses them.
//!
//! Every `/auth/*` handler answers a refusal as `(StatusCode, message)`, which
//! axum sends as `text/plain`. For an API caller that is the right shape and
//! stays exactly as it is. But `/auth/login`, `/auth/callback`, the work-email
//! form and the SAML return are top-level navigations: a person pressed Cancel
//! at Google, or reopened a stale tab, and was left on a bare line of text with
//! no way back to GaugeDesk and no way to sign out.
//!
//! This layer changes only that case. A response is re-rendered when the
//! request was a browser navigation (`Accept` names `text/html`) and the answer
//! is a `text/plain` error. The status is kept, the handler's words are kept,
//! and the page adds the way onward: back to GaugeDesk, and Sign out when the
//! browser still carries a session.

use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// Largest refusal body re-rendered. Handler messages are one sentence; a body
/// past this is not one of them and is passed through untouched.
const MAX_MESSAGE_BYTES: usize = 16 * 1024;

/// Set by a callback refusal that is about the account the provider answered
/// for — "already linked to another account", "an account already uses this
/// email" — naming the provider's slug. The page then offers that provider's
/// account chooser, because signing in again would otherwise silently pick the
/// same account. It is a note from handler to page and never leaves the server.
pub const CHOOSE_ACCOUNT_HEADER: &str = "x-gaugedesk-choose-account";

/// Whether the request is a person's browser navigating, rather than a client
/// calling an API. `fetch()` sends `*/*`; a navigation names `text/html`.
pub fn wants_html(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|accept| accept.contains("text/html"))
}

/// Where "Back to GaugeDesk" goes: the same destination a completed sign-in
/// is sent to.
pub fn desk_url() -> String {
    gaugedesk_env::var("OIDC_POST_LOGIN_URL")
        .filter(|u| !u.trim().is_empty())
        .unwrap_or_else(|| "/".to_string())
}

/// Middleware for the browser-facing auth routes. See the module docs.
pub async fn render_browser_errors(request: Request, next: Next) -> Response {
    let html = wants_html(request.headers());
    let signed_in = crate::net_http::session_cookie(request.headers()).is_some();
    let mut response = next.run(request).await;
    let choose = response
        .headers_mut()
        .remove(CHOOSE_ACCOUNT_HEADER)
        .and_then(|v| v.to_str().ok().map(str::to_string))
        .and_then(|slug| crate::auth_oidc::consumer_provider_by_slug(&slug));
    if !html {
        return response;
    }
    let status = response.status();
    let plain = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("text/plain"));
    if !(status.is_client_error() || status.is_server_error()) || !plain {
        return response;
    }
    let (parts, body) = response.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, MAX_MESSAGE_BYTES).await else {
        // Too large or unreadable: not a handler's one-line refusal. The body
        // is consumed, so answer with the status alone rather than a lie.
        return Response::from_parts(parts, Body::empty());
    };
    let message = String::from_utf8_lossy(&bytes);
    let mut page = refusal_page(status, &message, signed_in, choose).into_response();
    // Keep whatever the handler set beside its body — a cookie it cleared, a
    // retry hint — and replace only the representation.
    for (name, value) in parts.headers.iter() {
        if name != header::CONTENT_TYPE && name != header::CONTENT_LENGTH {
            page.headers_mut().append(name.clone(), value.clone());
        }
    }
    page
}

/// Render a refusal as a page with a way onward.
pub fn refusal_page(
    status: StatusCode,
    message: &str,
    signed_in: bool,
    choose: Option<crate::auth_oidc::ConsumerProvider>,
) -> Response {
    let (title, lede, detail) = explain(status, message.trim());
    let desk = escape(&desk_url());
    let detail = detail
        .map(|d| format!("<p class=\"detail\">{}</p>", escape(&d)))
        .unwrap_or_default();
    // Only while signed out: `/auth/login` sends a browser that still holds a
    // session straight back to GaugeDesk, so there the way to another account
    // is Sign out first.
    let other_account = match choose {
        Some(provider) if !signed_in => format!(
            "<a href=\"/auth/login?provider={slug}&amp;select_account=1\">Use a different {label} account</a>",
            slug = escape(provider.slug),
            label = escape(provider.label),
        ),
        _ => String::new(),
    };
    let sign_out = if signed_in {
        "<form method=\"post\" action=\"/auth/logout\"><button type=\"submit\">Sign out</button></form>"
    } else {
        ""
    };
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>{title} · GaugeDesk</title><style>{STYLE}</style></head><body><main>\
<p class=\"kicker\">GaugeDesk sign-in</p><h1>{title}</h1><p>{lede}</p>{detail}\
<div class=\"actions\"><a class=\"primary\" href=\"{desk}\">Back to GaugeDesk</a>{other_account}{sign_out}</div>\
<p class=\"note\">Started in the GaugeDesk app? Switch back to it and choose Sign in again.</p>\
</main></body></html>",
        title = escape(title),
        lede = escape(&lede),
    );
    (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        )],
        body,
    )
        .into_response()
}

/// A heading, a sentence a person can act on, and — when the handler's own
/// words add something — those words beneath it. Only refusals common enough
/// to deserve plain language are named; every other message is shown as the
/// handler wrote it, because it is already addressed to the person.
fn explain(status: StatusCode, message: &str) -> (&'static str, String, Option<String>) {
    let lower = message.to_ascii_lowercase();
    if lower.contains("denied the login: access_denied") {
        return (
            "Sign-in was cancelled",
            "You cancelled at the sign-in provider, so nothing changed. You can sign in again from GaugeDesk.".into(),
            None,
        );
    }
    if lower.contains("unknown or expired state")
        || lower.contains("missing code or state")
        || lower.contains("unknown or expired sign-in")
    {
        return (
            "This sign-in has expired",
            "This page belongs to a sign-in that is no longer open — often an old tab, or the back button. Start again from GaugeDesk.".into(),
            None,
        );
    }
    if status == StatusCode::TOO_MANY_REQUESTS {
        return (
            "Too many sign-in attempts",
            "Sign-in is paused for this connection for a few minutes. Try again shortly.".into(),
            None,
        );
    }
    if status.is_server_error() {
        return (
            "Sign-in could not finish",
            "Something went wrong on our side, not with your account. Try again in a moment."
                .into(),
            Some(message.to_string()).filter(|m| !m.is_empty()),
        );
    }
    let lede = if message.is_empty() {
        "Sign-in could not finish.".to_string()
    } else {
        sentence(message)
    };
    ("Sign-in could not finish", lede, None)
}

/// Capitalise the handler's message and end it as a sentence.
fn sentence(message: &str) -> String {
    let mut chars = message.chars();
    let mut out = match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect::<String>(),
        None => String::new(),
    };
    if !out.ends_with(['.', '!', '?']) {
        out.push('.');
    }
    out
}

fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

const STYLE: &str = "\
:root{color-scheme:light dark;--bg:#f6f4ee;--panel:#fff;--ink:#16213a;--muted:#5b6478;--gold:#b8923a;--edge:#d9d4c7}\
@media (prefers-color-scheme:dark){:root{--bg:#141c2e;--panel:#1c2640;--ink:#e7e9ef;--muted:#a3abbd;--edge:#2c3856}}\
*{box-sizing:border-box}\
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:16px;background:var(--bg);color:var(--ink);\
font:15px/1.55 Georgia,'Iowan Old Style',serif}\
main{width:min(520px,100%);padding:32px;background:var(--panel);border:1px solid var(--edge);outline:2px solid color-mix(in srgb,var(--gold) 62%,transparent);outline-offset:5px}\
.kicker{margin:0;color:var(--gold);font-size:12px;text-transform:uppercase;letter-spacing:.09em}\
h1{margin:6px 0 12px;font-size:24px;font-weight:400}\
p{margin:0 0 12px;color:var(--muted)}\
.detail{font:12px/1.4 ui-monospace,monospace;overflow-wrap:anywhere}\
.actions{display:flex;flex-wrap:wrap;gap:12px;align-items:center;margin:20px 0 16px}\
.actions a,.actions button{padding:10px 20px;border:1px solid var(--gold);font:inherit;font-size:13px;letter-spacing:.12em;text-transform:uppercase;text-decoration:none;cursor:pointer}\
.primary{background:var(--gold);color:#16213a}\
.actions button,.actions a:not(.primary){background:none;color:var(--ink)}\
.note{font-size:13px;margin:0}";

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use tower::ServiceExt;

    fn app() -> axum::Router {
        axum::Router::new()
            .route(
                "/auth/callback",
                get(|| async {
                    (
                        StatusCode::UNAUTHORIZED,
                        "the IdP denied the login: access_denied",
                    )
                }),
            )
            .route(
                "/auth/refused",
                get(|| async {
                    (
                        StatusCode::FORBIDDEN,
                        [(header::SET_COOKIE, "gw_session=; Max-Age=0")],
                        "a GaugeDesk account already uses this email address",
                    )
                }),
            )
            .route("/auth/ok", get(|| async { "fine" }))
            .route(
                "/auth/wrong-account",
                get(|| async {
                    (
                        StatusCode::FORBIDDEN,
                        [(CHOOSE_ACCOUNT_HEADER, "google")],
                        "this Google account is already linked to another GaugeDesk account",
                    )
                }),
            )
            .layer(axum::middleware::from_fn(render_browser_errors))
    }

    async fn call(
        path: &str,
        accept: Option<&str>,
        cookie: Option<&str>,
    ) -> (StatusCode, HeaderMap, String) {
        let mut req = Request::builder().uri(path);
        if let Some(a) = accept {
            req = req.header(header::ACCEPT, a);
        }
        if let Some(c) = cookie {
            req = req.header(header::COOKIE, c);
        }
        let resp = app()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, headers, String::from_utf8(body.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn an_api_caller_gets_the_handlers_exact_text() {
        let (status, headers, body) = call("/auth/callback", Some("*/*"), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(headers[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/plain"));
        assert_eq!(body, "the IdP denied the login: access_denied");
        let (_, _, body) = call("/auth/callback", None, None).await;
        assert_eq!(body, "the IdP denied the login: access_denied");
    }

    #[tokio::test]
    async fn a_cancelled_sign_in_in_a_browser_gets_a_way_back() {
        let (status, headers, body) = call("/auth/callback", Some("text/html,*/*"), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(headers[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/html"));
        assert!(body.contains("Sign-in was cancelled"));
        assert!(body.contains("Back to GaugeDesk"));
        // No session cookie, so nothing to sign out of.
        assert!(!body.contains("/auth/logout"));
    }

    #[tokio::test]
    async fn a_browser_still_holding_a_session_is_offered_sign_out() {
        let (status, headers, body) =
            call("/auth/refused", Some("text/html"), Some("gw_session=abc")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(body.contains("A GaugeDesk account already uses this email address."));
        assert!(body.contains("action=\"/auth/logout\""));
        // The handler's own headers survive the re-render.
        assert_eq!(headers[header::SET_COOKIE], "gw_session=; Max-Age=0");
    }

    #[tokio::test]
    async fn a_refusal_about_the_account_offers_the_providers_chooser() {
        let (_, headers, body) = call("/auth/wrong-account", Some("text/html"), None).await;
        assert!(body.contains("/auth/login?provider=google&amp;select_account=1"));
        assert!(body.contains("Use a different Google account"));
        assert!(!headers.contains_key(CHOOSE_ACCOUNT_HEADER));
        // Signed in, /auth/login would bounce straight back; Sign out comes first.
        let (_, _, body) = call(
            "/auth/wrong-account",
            Some("text/html"),
            Some("gw_session=abc"),
        )
        .await;
        assert!(!body.contains("select_account"));
        assert!(body.contains("action=\"/auth/logout\""));
        // The note never reaches an API caller either.
        let (_, headers, _) = call("/auth/wrong-account", Some("*/*"), None).await;
        assert!(!headers.contains_key(CHOOSE_ACCOUNT_HEADER));
    }

    #[tokio::test]
    async fn success_is_untouched() {
        let (status, _, body) = call("/auth/ok", Some("text/html"), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "fine");
    }

    #[test]
    fn handler_words_are_escaped() {
        let resp = refusal_page(StatusCode::BAD_REQUEST, "<script>x</script>", false, None);
        let (_, body) = resp.into_parts();
        let bytes = futures::executor::block_on(axum::body::to_bytes(body, usize::MAX)).unwrap();
        let html = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(!html.contains("<script>x"));
        assert!(html.contains("&lt;script&gt;"));
    }
}
