use std::collections::HashMap;
use std::sync::Mutex;

use gaugedesk_relay_transport::{bind_client_loopback, RelayRoute, RouteProof};
use serde::{Deserialize, Serialize};
use tauri::State;

#[derive(Default)]
pub struct RelayManager {
    routes: Mutex<HashMap<String, ActiveRoute>>,
}

struct ActiveRoute {
    locator_key: String,
    endpoint: String,
    task: tokio::task::JoinHandle<()>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnsureRelayRouteRequest {
    home_id: String,
    endpoint: String,
    handle: String,
    proof: String,
    route_epoch: u64,
    home_fingerprint: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayRouteResponse {
    endpoint: String,
}

#[tauri::command]
pub async fn ensure_relay_route(
    request: EnsureRelayRouteRequest,
    manager: State<'_, RelayManager>,
) -> Result<RelayRouteResponse, String> {
    if request.home_id.trim().is_empty() || request.route_epoch == 0 {
        return Err("relay locator has no stable Home/epoch".to_owned());
    }
    let proof = RouteProof::from_base64url(&request.proof)
        .map_err(|error| format!("invalid relay route proof: {error}"))?;
    let fingerprint =
        hex::decode(&request.home_fingerprint).map_err(|_| "invalid Home TLS pin".to_owned())?;
    let fingerprint: [u8; 32] = fingerprint
        .try_into()
        .map_err(|_| "Home TLS pin must contain 32 bytes".to_owned())?;
    if !request
        .endpoint
        .strip_prefix("wss://")
        .is_some_and(|authority| {
            !authority.is_empty()
                && !authority.contains('/')
                && !authority.contains('@')
                && !authority.chars().any(char::is_whitespace)
        })
    {
        return Err("relay endpoint must be a canonical wss:// origin".to_owned());
    }
    let locator_key = format!(
        "{}\n{}\n{}\n{}\n{}",
        request.endpoint,
        request.handle,
        request.proof,
        request.route_epoch,
        request.home_fingerprint
    );
    if let Some(active) = manager
        .routes
        .lock()
        .map_err(|_| "relay manager unavailable".to_owned())?
        .get(&request.home_id)
    {
        if active.locator_key == locator_key && !active.task.is_finished() {
            return Ok(RelayRouteResponse {
                endpoint: active.endpoint.clone(),
            });
        }
    }

    let route = RelayRoute {
        endpoint: request.endpoint,
        handle: request.handle,
        epoch: request.route_epoch,
        proof,
        previous_proof: None,
        home_fingerprint: fingerprint,
    };
    let (address, task) = bind_client_loopback(route)
        .await
        .map_err(|error| format!("bind relay loopback: {error}"))?;
    let endpoint = format!("http://{address}");
    let mut routes = manager
        .routes
        .lock()
        .map_err(|_| "relay manager unavailable".to_owned())?;
    if let Some(old) = routes.insert(
        request.home_id,
        ActiveRoute {
            locator_key,
            endpoint: endpoint.clone(),
            task,
        },
    ) {
        old.task.abort();
    }
    Ok(RelayRouteResponse { endpoint })
}

#[tauri::command]
pub fn close_relay_route(home_id: String, manager: State<'_, RelayManager>) -> Result<(), String> {
    let mut routes = manager
        .routes
        .lock()
        .map_err(|_| "relay manager unavailable".to_owned())?;
    if let Some(route) = routes.remove(&home_id) {
        route.task.abort();
    }
    Ok(())
}

#[tauri::command]
pub fn close_all_relay_routes(manager: State<'_, RelayManager>) -> Result<(), String> {
    let mut routes = manager
        .routes
        .lock()
        .map_err(|_| "relay manager unavailable".to_owned())?;
    for (_, route) in routes.drain() {
        route.task.abort();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_request_wire_names_are_stable() {
        let request: EnsureRelayRouteRequest = serde_json::from_value(serde_json::json!({
            "homeId": "home:a",
            "endpoint": "wss://relay.gaugewright.com",
            "handle": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "proof": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI",
            "routeEpoch": 1,
            "homeFingerprint": "00".repeat(32),
        }))
        .unwrap();
        assert_eq!(request.home_id, "home:a");
        assert_eq!(request.route_epoch, 1);
    }
}
