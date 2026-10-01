//! The desktop's local channel answers only its own window (DR-0269).
//!
//! The desktop serves its control plane on loopback, and a request there with
//! no bearer acts as the local operator. Loopback is not a boundary: every
//! process on the computer, whichever OS user runs it, and every web page the
//! browser loads, can reach `127.0.0.1`. Until this guard, any of them could
//! read every project or switch the window into local mode (WS-579).
//!
//! So the desktop shell mints a secret at launch, hands it to its own window
//! over Tauri IPC — which no other process can call — and serves the channel
//! behind [`guard`]. A request without that secret is refused before any
//! route runs. The headless `gaugedesk-app`, which the e2e harness, the wiring
//! canary and local development drive, requires one only when
//! `GAUGEDESK_OPERATOR_SECRET` names it.
//!
//! This decides who may use the channel, not what the channel may do: a
//! request carrying the secret still acts as the window's selected account or
//! local mode (DR-0268).

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use sha2::{Digest, Sha256};

/// The request header carrying the secret.
pub const HEADER: &str = "x-gaugedesk-operator";

/// The environment suffix a headless server reads its secret from
/// (`GAUGEDESK_OPERATOR_SECRET`).
const ENV: &str = "OPERATOR_SECRET";

/// Below this a configured secret is refused rather than served: a short one
/// is guessable, and a server that fell back to no secret would look guarded.
const MIN_LEN: usize = 32;

/// The per-launch secret the local channel requires.
#[derive(Clone)]
pub struct LocalOperatorSecret {
    value: String,
    digest: Vec<u8>,
}

impl LocalOperatorSecret {
    /// A fresh 256-bit secret from the operating system's randomness.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).expect("the operating system provides randomness");
        Self::new(hex::encode(bytes))
    }

    /// The secret `GAUGEDESK_OPERATOR_SECRET` names, if any. A value shorter
    /// than 32 characters is an error, never a silent fallback to no secret.
    pub fn from_env() -> Result<Option<Self>, String> {
        match gaugedesk_env::var(ENV) {
            None => Ok(None),
            Some(value) => Self::parse(&value).map(Some),
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        let value = value.trim();
        if value.len() < MIN_LEN {
            return Err(format!(
                "GAUGEDESK_OPERATOR_SECRET must be at least {MIN_LEN} characters"
            ));
        }
        Ok(Self::new(value.to_owned()))
    }

    fn new(value: String) -> Self {
        let digest = Sha256::digest(value.as_bytes()).to_vec();
        Self { value, digest }
    }

    /// The secret itself, for the shell to hand its own window.
    pub fn expose(&self) -> &str {
        &self.value
    }

    /// Compared as digests, so the comparison's timing says nothing about how
    /// much of a guess was right.
    fn admits(&self, presented: &str) -> bool {
        Sha256::digest(presented.as_bytes()).as_slice() == self.digest.as_slice()
    }
}

impl std::fmt::Debug for LocalOperatorSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LocalOperatorSecret(..)")
    }
}

/// Serve `router` so that every request must carry `secret`, or unchanged
/// when there is none.
pub(crate) fn guard(router: Router, secret: Option<LocalOperatorSecret>) -> Router {
    match secret {
        None => router,
        Some(secret) => router.layer(axum::middleware::from_fn_with_state(
            Arc::new(secret),
            require,
        )),
    }
}

async fn require(
    State(secret): State<Arc<LocalOperatorSecret>>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    // A CORS preflight cannot carry the header it is asking about. `/health`
    // says only that something is listening. The model-egress route is
    // reached through an operator's tunnel with a token of its own.
    if request.method() == Method::OPTIONS
        || path == "/health"
        || path == crate::local_model_broker::PATH
    {
        return next.run(request).await;
    }
    let presented = request
        .headers()
        .get(HEADER)
        .and_then(|value| value.to_str().ok());
    if presented.is_some_and(|value| secret.admits(value)) {
        return next.run(request).await;
    }
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({
            "error": "only the GaugeDesk window may use this computer's local control plane"
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::routing::{get, post};
    use tower::ServiceExt;

    fn secret() -> LocalOperatorSecret {
        LocalOperatorSecret::parse("0123456789abcdef0123456789abcdef").unwrap()
    }

    fn router(secret: Option<LocalOperatorSecret>) -> Router {
        guard(
            Router::new()
                .route("/workspace", get(|| async { "every project" }))
                .route("/health", get(|| async { "ok" }))
                .route(crate::local_model_broker::PATH, post(|| async { "broker" })),
            secret,
        )
    }

    async fn status(router: Router, request: axum::http::Request<Body>) -> StatusCode {
        router.oneshot(request).await.unwrap().status()
    }

    fn get_workspace(header: Option<&str>) -> axum::http::Request<Body> {
        let mut request = axum::http::Request::get("/workspace");
        if let Some(value) = header {
            request = request.header(HEADER, value);
        }
        request.body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn a_request_without_the_secret_is_refused_before_any_route() {
        assert_eq!(
            status(router(Some(secret())), get_workspace(None)).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status(
                router(Some(secret())),
                get_workspace(Some("0123456789abcdef0123456789abcdeX"))
            )
            .await,
            StatusCode::UNAUTHORIZED,
            "a near guess is still refused"
        );
    }

    #[tokio::test]
    async fn the_window_with_the_secret_reaches_its_routes() {
        assert_eq!(
            status(
                router(Some(secret())),
                get_workspace(Some("0123456789abcdef0123456789abcdef"))
            )
            .await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn preflight_health_and_the_model_broker_need_no_secret() {
        let preflight = axum::http::Request::builder()
            .method(Method::OPTIONS)
            .uri("/workspace")
            .body(Body::empty())
            .unwrap();
        // The router has no OPTIONS handler, so reaching it answers 405; the
        // point is that the guard let it through rather than answering 401.
        assert_ne!(
            status(router(Some(secret())), preflight).await,
            StatusCode::UNAUTHORIZED
        );
        let health = axum::http::Request::get("/health")
            .body(Body::empty())
            .unwrap();
        assert_eq!(status(router(Some(secret())), health).await, StatusCode::OK);
        let broker = axum::http::Request::post(crate::local_model_broker::PATH)
            .body(Body::empty())
            .unwrap();
        assert_eq!(status(router(Some(secret())), broker).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn a_server_given_no_secret_is_unchanged() {
        assert_eq!(
            status(router(None), get_workspace(None)).await,
            StatusCode::OK
        );
    }

    #[test]
    fn a_short_configured_secret_is_an_error_not_an_open_channel() {
        assert!(LocalOperatorSecret::parse("too-short").is_err());
        assert!(LocalOperatorSecret::parse("   ").is_err());
        assert_eq!(format!("{:?}", secret()), "LocalOperatorSecret(..)");
    }

    #[test]
    fn generated_secrets_are_long_and_distinct() {
        let (a, b) = (
            LocalOperatorSecret::generate(),
            LocalOperatorSecret::generate(),
        );
        assert_eq!(a.expose().len(), 64);
        assert_ne!(a.expose(), b.expose());
        assert!(LocalOperatorSecret::parse(a.expose())
            .unwrap()
            .admits(a.expose()));
    }
}
