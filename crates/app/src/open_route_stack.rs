//! Open-source control-plane route composition.

use axum::Router;

use crate::{
    account_routes, command_idempotency, facility_routes, local_routes, mobile_machine_session,
    net_http, LockUnpoisoned, SharedWorkbench,
};

pub fn open_control_plane(wb: SharedWorkbench) -> Router {
    let federation_on = {
        let g = wb.lock_unpoisoned();
        g.is_federation_enabled()
    };
    Router::new()
        .merge(local_routes::routes(federation_on))
        .merge(account_routes::routes())
        // Facilities, tenants and invitations. `facility_routes` already
        // describes itself as "ungated on loopback; the hub adds auth on top",
        // and its `/account/tenants` note describes what the *solo desktop
        // path* returns — but it was merged only by the enterprise
        // composition, so none of it existed here and every call answered 404.
        //
        // The desktop needs it concretely: library sync is a facility
        // (`kind: "library_sync"`), so `desktop.library-sync.publish` and
        // `desktop.library-sync.pull` cannot be reached without a facility to
        // attach first.
        //
        // Merged here rather than inside `local_routes::routes()` because the
        // enterprise composition merges both, and registering the same path
        // twice panics the router at construction.
        .merge(facility_routes::routes())
        // The consumer login shell (ADR 0122): served by every composition of
        // the core control plane, with no composition fold on the open shell.
        // Inert until a deployment configures an IdP connection.
        .merge(crate::auth_oidc::auth_routes(
            crate::auth_oidc::AuthShellState::new(),
        ))
        .merge(mobile_machine_session::routes())
        .layer(net_http::cors_layer())
        .with_state(wb.clone())
        .layer(axum::middleware::from_fn_with_state(
            wb,
            command_idempotency::guard,
        ))
        .layer(axum::middleware::from_fn(net_http::security_headers))
}

#[cfg(test)]
mod tests {
    use super::open_control_plane;
    use crate::Workbench;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;

    fn desktop() -> axum::Router {
        let store = gaugedesk_store::Store::open_in_memory().unwrap();
        open_control_plane(Arc::new(Mutex::new(Workbench::new(store))))
    }

    /// One request against one composition, carrying a unique `Idempotency-Key`.
    ///
    /// `command_idempotency::guard` wraps the whole desktop composition and
    /// answers `400` to a keyless `POST`/`DELETE` *before* the router sees the
    /// path, so without a key an unmounted route is indistinguishable from a
    /// mounted one and a "not 404" assertion proves nothing. The key is derived
    /// from the probe itself, so no two requests claim the same command.
    ///
    /// The router is taken by reference so a sequence of requests shares one
    /// store: attaching a facility and then detaching it is the only way to
    /// tell the DELETE route being mounted from its handler's own "no such
    /// facility" 404.
    ///
    /// The body comes back too, because two of these handlers answer their own
    /// `404` — axum's unmatched-route `404` is empty, theirs is not.
    async fn send(
        app: &axum::Router,
        method: &str,
        uri: &str,
        body: Option<&str>,
    ) -> (StatusCode, String) {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("idempotency-key", format!("probe-{method}-{uri}"));
        if body.is_some() {
            builder = builder.header("content-type", "application/json");
        }
        let request = builder
            .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    /// The desktop composition serves the facility surface.
    ///
    /// Library sync is a facility (`kind: "library_sync"`), so a desktop that
    /// cannot attach one cannot reach `desktop.library-sync.publish` or
    /// `.pull` at all. These answered `404` because `facility_routes` was
    /// merged only by the enterprise composition — the module documents
    /// loopback behaviour it did not have.
    ///
    /// Asserting "not 404" rather than a success: the point is that the route
    /// is mounted and reached its handler. What the handler then decides is
    /// `facility_routes`' own tests' business. None of these five can answer
    /// `404` themselves, so a `404` here can only come from the router.
    #[tokio::test]
    async fn the_desktop_serves_facilities_tenants_and_invitations() {
        let app = desktop();
        for (method, uri) in [
            ("GET", "/account/facilities"),
            ("POST", "/account/facilities"),
            ("GET", "/account/tenants"),
            ("POST", "/account/tenants"),
            ("GET", "/account/invitations"),
        ] {
            let body = if method == "POST" { Some("{}") } else { None };
            let (status, _) = send(&app, method, uri, body).await;
            assert_ne!(
                status,
                StatusCode::NOT_FOUND,
                "{method} {uri} is not mounted in the desktop composition",
            );
        }
    }

    /// Detaching a facility is asserted as a success, not as "not 404".
    ///
    /// `delete_facility` answers its own `404` for an unknown id, so a probe
    /// against an id that was never attached cannot distinguish a mounted
    /// route from an absent one. Attaching `library_sync` first — the very
    /// facility `desktop.library-sync.publish`/`.pull` need — makes the detach
    /// return `200` only if the route is really in the desktop composition.
    #[tokio::test]
    async fn the_desktop_can_attach_and_detach_a_library_sync_facility() {
        let app = desktop();
        let (status, body) = send(
            &app,
            "POST",
            "/account/facilities",
            Some(r#"{"id":"library-sync","kind":"library_sync"}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "attach: {body}");

        let (status, body) = send(&app, "DELETE", "/account/facilities/library-sync", None).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "DELETE /account/facilities/{{id}} is not mounted in the desktop composition: {body}",
        );
    }

    /// Accepting an invitation is asserted through the response body.
    ///
    /// `post_accept_invitation` answers its own `404` when the person has no
    /// such invitation, and seeding a real one is `facility_routes`' own test.
    /// The two `404`s are still distinguishable: an unmatched axum route
    /// returns an empty body, the handler returns its message.
    #[tokio::test]
    async fn the_desktop_serves_invitation_acceptance() {
        let (status, body) = send(
            &desktop(),
            "POST",
            "/account/invitations/tenant%3Aexample/accept",
            None,
        )
        .await;
        assert_eq!(
            (status, body.as_str()),
            (StatusCode::NOT_FOUND, "invitation not found"),
            "the accept route is not mounted in the desktop composition",
        );
    }

    /// Constructing the composition at all is the other half: the enterprise
    /// composition merges `local_routes` *and* `facility_routes`, so putting
    /// the facility surface inside `local_routes` would register the same
    /// paths twice and panic axum at construction rather than at a request.
    #[tokio::test]
    async fn the_composition_constructs_without_a_duplicate_route() {
        let _ = desktop();
    }
}
