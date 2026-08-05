//! Open-source control-plane route composition.

use axum::Router;

use crate::{
    account_routes, command_idempotency, local_routes, mobile_machine_session, net_http,
    LockUnpoisoned, SharedWorkbench,
};

pub fn open_control_plane(wb: SharedWorkbench) -> Router {
    let federation_on = {
        let g = wb.lock_unpoisoned();
        g.is_federation_enabled()
    };
    Router::new()
        .merge(local_routes::routes(federation_on))
        .merge(account_routes::routes())
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
