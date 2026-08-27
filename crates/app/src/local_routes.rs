use axum::{
    routing::{delete, get, post, put},
    Router,
};

use crate::{
    engagement_routes as er, federation, library_routes as lr, lifecycle_routes as life, net_http,
    project_credential_routes, resource_store as rs, workstream_routes as wr, SharedWorkbench,
};

/// Open-source local workbench route surface: health, workspace/library,
/// project/chat/resource lifecycles, package primitives, projections, test reset
/// hooks (debug builds only), and the self-operated federation route surface
/// whenever the workbench carries its normally initialized federation identity.
pub fn routes(federation_on: bool) -> Router<SharedWorkbench> {
    let routes = Router::new()
        .route("/health", get(net_http::health))
        .route(
            "/console/review-count",
            get(crate::console_routes::get_review_count),
        )
        .route("/workspace", get(lr::get_workspace))
        .route("/workspace/events", get(er::workspace_events))
        .route("/tasks", get(lr::get_tasks))
        .route("/roster", get(lr::get_roster))
        .route("/work-items/{item_id}/assign", post(lr::assign_work_item))
        .route("/search", get(lr::search))
        .route("/archetypes", post(lr::create_agent))
        .route(
            "/archetypes/{id}",
            get(lr::get_agent)
                .put(lr::update_agent)
                .delete(lr::delete_agent),
        )
        .route(
            "/archetypes/{id}/abilities",
            get(lr::get_archetype_abilities).put(lr::put_archetype_abilities),
        )
        .route("/archetypes/{id}/chats", post(lr::create_chat_under_agent))
        .route("/archetypes/{id}/use", post(lr::use_archetype))
        .route("/archetypes/{id}/fork", post(lr::fork_archetype))
        .route(
            "/archetypes/{id}/copy-as-panel",
            post(lr::copy_agent_as_panel),
        )
        .route(
            "/archetypes/{id}/panel-profile",
            get(lr::get_panel_profile).put(lr::put_panel_profile),
        )
        .route(
            "/archetypes/{id}/pull-from-source",
            post(lr::post_pull_from_source),
        )
        .route("/archetypes/{id}/publish", post(lr::post_publish_archetype))
        .route(
            "/placements/{id}/abilities",
            get(lr::get_placement_abilities),
        )
        .route("/placements/{id}/upgrade", post(lr::post_upgrade_placement))
        .route("/placements/{id}/accept", post(lr::post_accept_placement))
        .route(
            "/placements/{id}/distribution",
            get(crate::protected_profiles::get_distribution)
                .put(crate::protected_profiles::put_distribution),
        )
        .route(
            "/placements/{id}/distribution/revoke",
            post(crate::protected_profiles::revoke_distribution),
        )
        .route(
            "/placements/{id}/distribution/renew",
            post(crate::protected_profiles::renew_distribution),
        )
        .route(
            "/placements/{id}/distribution/audit",
            get(crate::protected_profiles::get_distribution_audit),
        )
        .route(
            "/public-deployments",
            post(crate::publisher_routes::publish_deployment),
        )
        .route(
            "/public-deployments/publisher-authority",
            get(crate::publisher_routes::publisher_authority),
        )
        .route(
            "/panel-previews",
            post(crate::publisher_routes::start_panel_preview),
        )
        .route(
            "/panel-previews/{id}",
            delete(crate::publisher_routes::stop_panel_preview),
        )
        .route(
            "/public-deployments/import",
            post(crate::publisher_routes::import_legacy_deployment),
        )
        .route(
            "/public-deployments/inspect",
            post(crate::publisher_routes::inspect_deployment),
        )
        .route(
            "/public-deployments/control",
            post(crate::publisher_routes::control_deployment),
        )
        .route(
            "/public-deployments/erase-session",
            post(crate::publisher_routes::erase_session),
        )
        .route(
            "/public-deployments/credentials/list",
            post(crate::publisher_routes::list_credentials),
        )
        .route(
            "/public-deployments/credentials/provision",
            post(crate::publisher_routes::provision_credential),
        )
        .route(
            "/public-deployments/credentials/revoke",
            post(crate::publisher_routes::revoke_credential),
        )
        .route(
            "/public-deployments/collect",
            post(crate::publisher_routes::collect_into_project),
        )
        .route(
            "/collection-recipients",
            get(crate::publisher_routes::list_collection_recipients)
                .post(crate::publisher_routes::ensure_collection_recipient),
        )
        .route("/projects", post(lr::create_project))
        .route(
            "/projects/{id}/quarantine",
            get(crate::publisher_routes::list_project_quarantine),
        )
        .route(
            "/projects/{id}/quarantine/{item}",
            get(crate::publisher_routes::get_quarantined_item),
        )
        .route(
            "/projects/{id}/quarantine/{item}/screen",
            post(crate::publisher_routes::screen_quarantined_item),
        )
        .route(
            "/projects/{id}/quarantine/{item}/review",
            post(crate::publisher_routes::review_quarantined_item),
        )
        .route(
            "/projects/{id}/targets",
            post(crate::target_adapter::attach_target),
        )
        .route(
            "/targets/{id}/acts",
            get(crate::target_adapter::list_target_acts),
        )
        .route(
            "/chats/{id}/target-acts/{act}",
            post(crate::target_adapter::request_terminal_target_act),
        )
        .route(
            "/projects/{id}",
            put(lr::update_project).delete(lr::delete_project),
        )
        .route("/projects/{id}/home", get(lr::project_home))
        .route(
            "/projects/{id}/credentials",
            get(project_credential_routes::get_project_credentials)
                .post(project_credential_routes::post_project_credential),
        )
        .route(
            "/projects/{id}/credentials/{provider}",
            delete(project_credential_routes::delete_project_credential),
        )
        .route("/projects/{pid}/placements", post(lr::bind_agent))
        .route("/projects/{pid}/placements/{iid}", delete(lr::unbind_agent))
        .route(
            "/placements/{iid}/workstreams",
            post(wr::create_workstream).get(wr::list_workstreams),
        )
        .route("/workstreams/{id}/join", post(wr::join_workstream))
        .route("/workstreams/{id}/leave", post(wr::leave_workstream))
        .route("/workstreams/{id}/archive", post(wr::archive_workstream))
        .route("/workstreams/{id}/promote", post(wr::promote_workstream))
        .route(
            "/projects/{pid}/placements/{iid}/chats",
            post(lr::create_chat_under_instance),
        )
        .route("/placements/{id}", get(life::get_instance))
        .route(
            "/placements/{id}/command",
            post(life::post_instance_command),
        )
        .route("/boundaries/{bid}/accept", post(lr::accept_boundary))
        .route("/pairing-requests", post(lr::create_pairing_request))
        .route("/pairing-status/{id}", get(lr::get_pairing_status))
        .merge(federation::featured_routes(federation_on))
        .route("/chats/{id}/fork", post(lr::fork_chat))
        .route("/chats/{id}/fork/{entry_id}", post(lr::fork_chat_at))
        .route("/chats/{id}/sync", post(er::post_sync))
        .route("/chats/{id}/stop", post(er::post_stop))
        .route("/chats/{id}", delete(lr::delete_chat))
        .route("/chats/{id}/title", put(lr::rename_chat))
        .route(
            "/chats",
            post(er::create_engagement).get(er::list_engagements),
        )
        .route("/fork-tree", get(life::get_fork_tree))
        .route("/chats/{id}/diff", get(er::engagement_diff))
        .route("/chats/{id}/tree", get(er::get_tree))
        .route("/chats/{id}/file", get(er::get_file).put(er::put_file))
        .route("/chats/{id}/merge-preview", post(er::post_merge_preview))
        .route("/chats/{id}/transcript", get(er::get_transcript))
        .route("/chats/{id}/context-usage", get(er::get_context_usage))
        .route("/chats/{id}/audit", get(er::get_audit))
        .route("/chats/{id}/events", get(er::engagement_events))
        .route("/chats/{id}/task", post(er::post_task))
        .route("/chats/{id}/merge", get(er::get_merge))
        .route("/chats/{id}/merge/command", post(er::post_merge_command))
        .route("/chats/{id}/revert", post(er::post_revert))
        .route(
            "/chats/{id}/config",
            get(er::get_config).put(er::put_config),
        )
        .route("/chats/{id}/context", post(rs::post_context))
        .route("/chats/{id}/context/upload", post(rs::post_context_upload))
        .route("/chats/{id}/resources", get(rs::get_resources))
        .route(
            "/chats/{id}/resources/{rid}/content",
            get(rs::get_resource_content),
        )
        .route(
            "/chats/{id}/resources/{rid}/tombstone",
            post(rs::post_resource_tombstone),
        )
        .route(
            "/chats/{id}/resources/{rid}/export",
            get(rs::get_resource_export).post(rs::post_resource_export),
        )
        .route(
            "/chats/{id}/resources/{rid}/export/command",
            post(rs::post_resource_export_command),
        )
        .route(
            "/chats/{id}/resources/{rid}/export-to-disk",
            post(rs::post_resource_export_to_disk),
        )
        .route(
            "/chats/{id}/resources/{rid}/review",
            get(rs::get_resource_review).post(rs::post_resource_review),
        )
        .route(
            "/chats/{id}/resources/{rid}/review/command",
            post(rs::post_resource_review_command),
        )
        .route(
            "/chats/{id}/resources/{rid}/access",
            get(rs::get_resource_access),
        )
        .route(
            "/chats/{id}/resources/{rid}/access/request",
            post(rs::post_resource_access_request),
        )
        .route(
            "/chats/{id}/resources/{rid}/access/approve",
            post(rs::post_resource_access_approve),
        )
        .route(
            "/chats/{id}/resources/{rid}/access/revoke",
            post(rs::post_resource_access_revoke),
        )
        .route("/scopes/{scope}/run", get(life::get_run))
        .route("/scopes/{scope}/run/command", post(life::post_run_command))
        .route("/scopes/{scope}/audit", get(life::get_audit))
        .route(
            "/projections/library/workspace/{record}/{id}",
            get(life::get_workspace_delta),
        )
        .route("/projections/{scope}/{kind}", get(life::get_projection));
    // The destructive BDD-only surface (state-root reset, conflict injection)
    // compiles only into debug builds, so no released artifact carries a route
    // that can delete persisted user data (DR-0054 Phase A). The debug/test
    // harness binaries that need it are always debug builds (`web/e2e/*.sh`,
    // `scripts/dev.sh`), and the `GAUGEDESK_TEST_RESET` process guard stays
    // in force as defense in depth where the routes do exist.
    #[cfg(debug_assertions)]
    let routes = routes
        .route("/test/reset", post(er::post_test_reset))
        .route("/test/force-conflict", post(er::post_test_force_conflict));
    routes
}
