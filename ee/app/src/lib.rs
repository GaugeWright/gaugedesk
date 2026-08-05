//! GaugeDesk Administration capability crate (`gaugewright-ee`, ADR 0121).
//!
//! The enterprise admin/SSO/SCIM control-plane surface over the shared app
//! substrate (`gaugewright-app`): org administration + the ENTSEC-1 data-route
//! auth middleware, the OIDC auth-code + PKCE login shell and startup SSO
//! activation, the OIDC id-token verifier core, the SAML sidecar adapter, and
//! SCIM provisioning. The `ee/` subtree is a capability boundary inside the
//! AGPL-licensed GaugeDesk platform, not a separate license band.
//!
//! The shared substrate stays in `crates/app`: the org/membership records and
//! projection (`gaugewright_app::org`), the audit trail (`gaugewright_app::audit`),
//! the `IdentityProvider` seam (`gaugewright_app::identity`), and the
//! `Workbench` authorization/actor helpers (`gaugewright_app::workbench_auth`)
//! that open code also consumes. This crate only *composes* those seams.

pub mod auth_oidc;
pub mod environment_routes;
pub mod identity_oidc;
pub mod identity_saml;
pub mod org_routes;
pub mod scim_routes;

pub use auth_oidc::activate_configured_idp;
pub use org_routes::enterprise_control_plane;
