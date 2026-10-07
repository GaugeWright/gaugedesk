//! Native staff source resolution for an explicitly composed office Home.
//! Configuration is trusted composition, not a client header or profile claim.
use std::sync::Arc;

use axum::http::StatusCode;
use gaugedesk_core::ids::AuthorityId;

use super::{
    lease::{OfficeStaffLease, OfficeStaffLeases},
    source::{HubStaffSource, SourceCheck},
};
use crate::Workbench;

pub(crate) struct OfficeStaffAuthentication {
    pub(super) source: Arc<HubStaffSource>,
    pub(super) leases: OfficeStaffLeases,
}

impl Workbench {
    /// Prepare authentication for the separately qualified office listener.
    /// This mounts no routes and does not enable the healthcare profile.
    pub fn configure_office_staff_source(
        &mut self,
        source: HubStaffSource,
    ) -> Result<(), &'static str> {
        if self.hosted_home_mode() || self.office_staff_auth.is_some() {
            return Err("office source requires a fresh office-operated Home composition");
        }
        self.office_staff_auth = Some(OfficeStaffAuthentication {
            source: Arc::new(source),
            leases: OfficeStaffLeases::new(self.home_id().clone()),
        });
        Ok(())
    }

    pub(crate) fn has_office_staff_source(&self, bearer: &str) -> bool {
        self.office_staff_auth.as_ref().is_some_and(|auth| {
            let reference = auth.leases.source_reference(
                auth.source.issuer(),
                &crate::account_session::session_id(bearer),
            );
            auth.leases.recognizes_source(self.store_ref(), &reference)
        })
    }

    pub(crate) fn office_staff_lease(&self, bearer: &str) -> Option<OfficeStaffLease> {
        let auth = self.office_staff_auth.as_ref()?;
        let reference = auth.leases.source_reference(
            auth.source.issuer(),
            &crate::account_session::session_id(bearer),
        );
        let lease = auth.leases.current(self.store_ref(), &reference).ok()?;
        (lease.home() == self.home_id()).then_some(lease)
    }

    pub(crate) fn office_staff_verifier(&self) -> Option<Arc<HubStaffSource>> {
        self.office_staff_auth
            .as_ref()
            .map(|auth| Arc::clone(&auth.source))
    }

    pub(crate) fn observe_office_staff_check(
        &mut self,
        source: &Arc<HubStaffSource>,
        reference: &str,
        check: SourceCheck,
    ) -> Result<OfficeStaffLease, (StatusCode, &'static str)> {
        if self.hosted_home_mode() {
            return Err((
                StatusCode::FORBIDDEN,
                "staff source requires office-operated custody",
            ));
        }
        let home = self.home_id().clone();
        let auth = self
            .office_staff_auth
            .as_mut()
            .ok_or((StatusCode::UNAUTHORIZED, "office source is unavailable"))?;
        if auth.leases.home() != &home || !Arc::ptr_eq(&auth.source, source) {
            return Err((
                StatusCode::UNAUTHORIZED,
                "office source changed during verification",
            ));
        }
        auth.leases
            .observe(&mut self.store, source.issuer(), reference, check)
            .map_err(|error| match error {
                super::lease::LeaseError::Refused => (
                    StatusCode::UNAUTHORIZED,
                    "office source lease is expired or revoked",
                ),
                super::lease::LeaseError::Storage(_) => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "office source custody is unavailable",
                ),
            })
    }

    /// Identity/project/software admission only. Exact Home admission is still
    /// required before constructing any action or disclosing work.
    pub(crate) fn admit_office_staff_identity(
        &self,
        bearer: &str,
        project: Option<&str>,
        org_scope: &str,
        client: crate::client_admission::ClientBuild,
        enforce_software: bool,
    ) -> Result<String, (StatusCode, &'static str)> {
        if org_scope != crate::org::ORG_SCOPE {
            return Err((
                StatusCode::FORBIDDEN,
                "office identity cannot select another directory",
            ));
        }
        if let Some(refusal) = self.office_profile_channel_refusal() {
            return Err(refusal);
        }
        let lease = self.office_staff_lease(bearer).ok_or((
            StatusCode::UNAUTHORIZED,
            "office source lease is expired or revoked",
        ))?;
        self.store_ref().retained_events(org_scope).map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "office directory is unavailable",
            )
        })?;
        let org = crate::org::Org::rebuild(self.store_ref()).map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "office directory is unavailable",
            )
        })?;
        if org.role_of(lease.account()).is_none()
            || project.is_some_and(|project| !org.can_access_project(lease.account(), project))
        {
            return Err((
                StatusCode::FORBIDDEN,
                "not in scope for this office project",
            ));
        }
        let software = crate::client_admission::evaluate_client(
            org.software_policy.as_ref(),
            &client,
            crate::account::session_now_ms(),
        );
        if enforce_software
            && software.status == crate::client_admission::ClientAdmissionStatus::Blocked
        {
            return Err((
                StatusCode::UPGRADE_REQUIRED,
                "GaugeDesk client does not satisfy organization software policy",
            ));
        }
        Ok(lease.account().into())
    }

    /// Called only for a fresh admitted user act with its exact publication
    /// guard. Polls and retained queue steps never enter this activity boundary.
    pub(crate) fn record_office_admitted_activity(
        &mut self,
        authority: &super::lease::OfficeStaffActionAuthority,
        basis: gaugedesk_store::command_dispatch::DispatchReadBasis,
    ) -> Result<crate::identity::AuthenticatedActionContext, String> {
        let home = self.home_id().clone();
        let auth = self
            .office_staff_auth
            .as_mut()
            .ok_or("office source is unavailable")?;
        if auth.leases.home() != &home || auth.leases.process_epoch() != authority.process_epoch() {
            return Err("office activity belongs to another running Home".into());
        }
        auth.leases
            .touch_admitted(&mut self.store, authority.source_reference(), basis)
            .map_err(|_| "office activity could not be durably recorded".to_owned())?;
        self.office_staff_dispatch_context(
            authority.actor().as_str(),
            authority.source_reference(),
            authority.process_epoch(),
            authority.admission_reference(),
        )
        .ok_or_else(|| "office admission ended after recording user activity".into())
    }

    /// A signed retained command may name this live source, but cannot recreate
    /// it after restart or substitute a rotated admission for the same person.
    pub(crate) fn office_staff_dispatch_context(
        &self,
        actor: &str,
        lease_ref: &str,
        process_epoch: &str,
        admission_ref: &str,
    ) -> Option<crate::identity::AuthenticatedActionContext> {
        let auth = self.office_staff_auth.as_ref()?;
        if self.hosted_home_mode()
            || auth.leases.home() != self.home_id()
            || auth.leases.process_epoch() != process_epoch
        {
            return None;
        }
        let lease = auth.leases.current(self.store_ref(), lease_ref).ok()?;
        if lease.account() != actor {
            return None;
        }
        let standing = self
            .home_admissions
            .office_standing_by_reference(&lease, admission_ref)?;
        auth.leases
            .action_context(self.store_ref(), lease_ref, standing)
            .ok()
    }

    pub(crate) fn office_staff_action_context(
        &self,
        lease: &OfficeStaffLease,
        token: &crate::home_admission::HomeAdmissionToken,
    ) -> Option<crate::identity::AuthenticatedActionContext> {
        if lease.home() != self.home_id() {
            return None;
        }
        let auth = self.office_staff_auth.as_ref()?;
        let standing = self.home_admissions.office_standing(lease, token).ok()?;
        auth.leases
            .action_context(self.store_ref(), lease.reference(), standing)
            .ok()
            .filter(|context| context.actor() == &AuthorityId::new(lease.account()))
    }
}
