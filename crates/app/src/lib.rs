//! gaugewright local control plane — the axum HTTP surface over the admission shell.
//!
//! Clients submit commands and query projections; the server never owns truth
//! beyond the event log (`INV-5`). One co-resident server backs desktop, web,
//! and (later) remote (`app-stack.md`). The per-process mutex on the
//! [`Workbench`] serializes admission (single-writer per scope, `INV-7`).
//!
//! The control plane exposes the run lifecycle plus the engagement surface:
//! create a worktree off the instance `main`, query its run state, and read the
//! reviewer's diff. This is the thin API the Solid frontend develops against.

pub mod account;
pub mod account_auth;
pub mod account_auth_ceremony;
pub mod account_routes;
pub mod account_session;
pub mod account_signin;
pub mod advancement;
pub mod agent_question;
pub mod agent_release;
pub mod app_support;
pub mod at_rest;
pub mod attention;
pub mod attestation_verifier;
pub mod audit;
pub mod auth_oidc;
pub mod backup_keyring;
pub mod boundary_keeper;
pub mod challenge;
pub mod client_admission;
pub mod codex_oauth;
pub mod collection_recipient;
pub mod command_idempotency;
pub mod console_routes;
pub mod content_vault;
pub mod crypto_erasure;
pub mod deployment_pricing;
pub mod device_enroll;
pub mod device_enroll_drive;
pub mod directory_sync;
pub mod discipline;
pub mod engagement_routes;
pub mod engine;
pub mod envelope_composition;
pub mod envelope_supply;
pub mod environment_agent;
pub mod environment_contract;
pub mod facility;
pub mod facility_routes;
pub mod federation;
pub mod federation_relay;
pub mod gate;
pub mod gate_service;
pub mod harness_select;
pub mod home;
pub mod home_admission;
pub mod home_backup;
pub mod home_invitation;
pub mod home_reachability;
pub mod home_routes;
pub mod identity;
pub mod identity_oidc;
pub mod key_store;
pub mod library;
pub mod library_routes;
pub mod library_state;
pub mod lifecycle_routes;
pub mod local_model_broker;
pub mod local_routes;
pub mod managed_entitlement;
pub mod managed_inference;
pub mod measurement_store;
pub mod mobile_bridge;
pub mod mobile_machine_session;
pub mod net_http;
pub mod net_relay;
pub mod net_server;
pub mod net_tls;
pub mod official_skills;
pub mod onboarding;
pub mod open_api;
pub mod open_route_stack;
pub mod open_runtime;
pub mod org;
pub mod package_flow;
pub mod package_store;
pub mod policy_compiler;
pub mod project_credential_routes;
pub mod protected_profiles;
pub mod publisher_routes;
pub mod quarantine;
pub mod remote_runtime;
pub mod resource_store;
pub mod roster;
pub mod secret;
pub mod session;
pub mod session_activity;
pub mod stream;
pub mod target_adapter;
pub(crate) mod target_change_set;
pub(crate) mod target_settlement;
pub mod tenancy;
pub mod throttle;
pub mod turn_summary;
pub mod workbench_auth;
pub mod workbench_state;
pub mod workstream_host_contract;
pub(crate) mod workstream_promotion;
pub mod workstream_routes;
pub mod xai_oauth;
pub(crate) use app_support::io;
pub use app_support::LockUnpoisoned;
pub use app_support::{
    AttestationMode, RuntimePackageDescriptor, DEFAULT_AGENT, DEFAULT_INSTANCE, DEFAULT_PLACEMENT,
    DEFAULT_PROJECT, LOCAL_AUTHORITY,
};
// The desktop shell reads its prefixed environment through this. The
// architecture boundary allows `gaugedesk-desktop -> gaugedesk-app` and nothing
// else local, so the shell reaches the env accessor the same way it reaches
// every other crate behind this one: re-exported here, not depended on directly.
pub use gaugedesk_env::var;
pub use gaugedesk_whip_runtime::{
    AdmittedPolicyEpoch, DoHostConfig, DoHostRequest, DoHostResponse, DoHostTransport,
    PolicyAdmissionError, PolicyEpoch, WhipHarnessFactory,
};
pub use open_route_stack::open_control_plane;
pub use open_runtime::{open_control_plane_root, open_serve};
// The test-only reset route is this alias's only consumer (DR-0054 Phase A).
#[cfg(debug_assertions)]
pub(crate) use workbench_state::build_workbench;
pub use workbench_state::{
    open_workbench, open_workbench_for_home_with_content_keywrap,
    open_workbench_with_content_keywrap, SharedWorkbench, Workbench,
};

#[cfg(test)]
pub(crate) mod test_support;

pub(crate) use net_http::err_response;
pub(crate) use stream::ServerEvent;

#[cfg(test)]
mod tests;
