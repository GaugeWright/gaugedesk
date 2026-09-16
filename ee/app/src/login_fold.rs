//! The enterprise **login fold** (ADR 0122 §3): how this composition resolves
//! a verified corporate subject before any GaugeDesk session exists.
//!
//! The auth shell verifies the provider assertion. Resolving that external
//! subject to an independent account and applying the organization's explicit
//! admission policy are enterprise concerns and stay in this band, registered into the shell's
//! [`AuthShellState`](crate::auth_oidc::AuthShellState) as its
//! [`LoginFold`](crate::auth_oidc::LoginFold) hook by the route builder. The
//! shell mints a session only after this fold returns the account id and exact
//! corporate method.

use gaugedesk_app::account::{account_scope, session_now_ms};
use gaugedesk_app::account_auth::{
    create_custodied_account_root, current_command_record_facts, decide_link_external_subject,
    decide_verify_email, normalize_email_contact, AccountAuth, AccountAuthFact, AuthMethodStatus,
    ExternalSubjectKind, ExternalSubjectRecord, VerifiedEmailRecord,
};
use gaugedesk_app::auth_oidc::{
    LoginFold, LoginFoldRefusal, LoginResolution, PendingEnterpriseLogin,
    VerifiedEnterpriseIdentity,
};
use gaugedesk_app::org::{
    is_valid_role, tenant_scope, MembershipRecord, MembershipStatus, Org,
    OrganizationInvitationRecord, OrganizationInvitationStatus, RecordOp, SsoAdmissionMode,
    SsoProtocol, ORGANIZATION_INVITATION_KIND, ORG_ID,
};
use gaugedesk_app::tenancy::{Tenancy, TenantRef, TENANT_REF_KIND};
use gaugedesk_app::Workbench;
use gaugedesk_store::CommandRecordFact;

/// The hosted/enterprise fold: resolve the verified corporate subject to one
/// independent GaugeDesk account, then admit organization membership through
/// exactly the configured basis (`AUTH-7`).
pub fn hub_login_fold() -> LoginFold {
    std::sync::Arc::new(resolve_corporate_login)
}

/// Resolve one verified corporate assertion through the exact organization
/// connection selected on the authorize leg. Existing links authenticate only
/// their account; a first-time subject creates a new custodied account root and
/// link atomically with an explicitly admitted membership.
pub fn resolve_corporate_login(
    wb: &mut Workbench,
    pending: &PendingEnterpriseLogin,
    verified: &VerifiedEnterpriseIdentity,
) -> Result<LoginResolution, LoginFoldRefusal> {
    let org = Org::rebuild_in(wb.store_ref(), &pending.store_scope)
        .map_err(|_| LoginFoldRefusal::Unavailable)?;
    let connection = org
        .sso
        .as_ref()
        .filter(|connection| {
            connection.id == pending.connection_id
                && connection.protocol == pending.protocol
                && connection.current_revision() == pending.connection_revision
        })
        .ok_or(LoginFoldRefusal::StaleConnection)?;
    let connection_key = org.enterprise_connection_key(&connection.id);
    let subject = verified.authority.as_str();
    let subject_kind = match connection.protocol {
        SsoProtocol::Oidc => ExternalSubjectKind::EnterpriseOidc,
        SsoProtocol::Saml => ExternalSubjectKind::EnterpriseSaml,
    };
    let auth = AccountAuth::rebuild(wb.store_ref()).map_err(|_| LoginFoldRefusal::Unavailable)?;

    // A revoked exact link is a future-authentication denial. It may not be
    // bypassed by provisioning a fresh account for the same provider subject.
    if auth.external_subjects.values().any(|record| {
        record.connection_id == connection_key
            && record.issuer == connection.issuer
            && record.subject == subject
            && record.kind == subject_kind
            && record.status == AuthMethodStatus::Revoked
    }) {
        return Err(LoginFoldRefusal::NotAdmitted);
    }

    if let Some(link) =
        auth.active_external_subject(&connection_key, &connection.issuer, subject, subject_kind)
    {
        if !auth.roots.contains_key(&link.account_id) {
            return Err(LoginFoldRefusal::Unavailable);
        }
        if let Some(member) = org.member_by_authority(&link.account_id) {
            match member.status {
                MembershipStatus::Active => {
                    ensure_tenant_index(wb, &org, &link.account_id, member)?;
                    return Ok(login_resolution(
                        connection.protocol,
                        &connection_key,
                        &link.account_id,
                    ));
                }
                MembershipStatus::Deprovisioned => return Err(LoginFoldRefusal::NotAdmitted),
                MembershipStatus::Invited => {}
            }
        }
        let email = verified
            .verified_email
            .as_deref()
            .ok_or(LoginFoldRefusal::NotAdmitted)?;
        let admission = admission_basis(&org, email)?;
        let (member, invitation) = admission.materialize(&link.account_id, session_now_ms());
        commit_admission(wb, &org, &link.account_id, &[], member, invitation)?;
        return Ok(login_resolution(
            connection.protocol,
            &connection_key,
            &link.account_id,
        ));
    }

    let email = verified
        .verified_email
        .as_deref()
        .ok_or(LoginFoldRefusal::NotAdmitted)?;
    // Prove the entire admission basis and contact uniqueness before creating
    // root custody. A refusal must not leave even an orphaned encrypted key
    // envelope outside the append-only transaction.
    let admission = admission_basis(&org, email)?;
    let pending_email = VerifiedEmailRecord::new("pending-account", email, 0)
        .map_err(|_| LoginFoldRefusal::NotAdmitted)?;
    decide_verify_email(&auth, pending_email).map_err(|_| LoginFoldRefusal::NotAdmitted)?;
    let now_ms = session_now_ms();
    let (account_id, root_fact) =
        create_custodied_account_root(wb, now_ms).map_err(|_| LoginFoldRefusal::Unavailable)?;
    let mut auth_facts = vec![root_fact];
    auth_facts.extend(
        decide_verify_email(
            &auth,
            VerifiedEmailRecord::new(&account_id, email, now_ms)
                .map_err(|_| LoginFoldRefusal::NotAdmitted)?,
        )
        .map_err(|_| LoginFoldRefusal::NotAdmitted)?,
    );
    let link = ExternalSubjectRecord::new(
        &account_id,
        &connection_key,
        &connection.issuer,
        subject,
        subject_kind,
        now_ms,
    )
    .map_err(|_| LoginFoldRefusal::NotAdmitted)?;
    auth_facts.extend(
        decide_link_external_subject(&auth, link).map_err(|_| LoginFoldRefusal::NotAdmitted)?,
    );
    let (member, invitation) = admission.materialize(&account_id, now_ms);
    commit_admission(wb, &org, &account_id, &auth_facts, member, invitation)?;
    Ok(login_resolution(
        connection.protocol,
        &connection_key,
        &account_id,
    ))
}

fn login_resolution(
    protocol: SsoProtocol,
    connection_key: &str,
    account_id: &str,
) -> LoginResolution {
    let protocol = match protocol {
        SsoProtocol::Oidc => "oidc",
        SsoProtocol::Saml => "saml",
    };
    LoginResolution {
        account_id: account_id.to_owned(),
        session_method: format!("enterprise-{protocol}:{connection_key}"),
    }
}

#[derive(Clone)]
enum AdmissionBasis {
    Existing(MembershipRecord),
    Invitation {
        invitation: OrganizationInvitationRecord,
        organization_id: String,
    },
    VerifiedDomain {
        organization_id: String,
        email: String,
    },
}

impl AdmissionBasis {
    fn materialize(
        &self,
        account_id: &str,
        admitted_at_ms: u64,
    ) -> (MembershipRecord, Option<OrganizationInvitationRecord>) {
        match self {
            Self::Existing(existing) => {
                let mut member = existing.clone();
                member.authority = account_id.to_owned();
                member.status = MembershipStatus::Active;
                (member, None)
            }
            Self::Invitation {
                invitation: existing,
                organization_id,
            } => {
                let mut invitation = existing.clone();
                let member = MembershipRecord {
                    id: account_id.to_owned(),
                    op: RecordOp::Upsert,
                    org_id: organization_id.clone(),
                    authority: account_id.to_owned(),
                    email: invitation.email.clone(),
                    role: invitation.role.clone(),
                    status: MembershipStatus::Active,
                    managed_by_scim: false,
                    team: invitation.team.clone(),
                };
                invitation.status = OrganizationInvitationStatus::Accepted;
                invitation.responded_by = Some(account_id.to_owned());
                invitation.responded_at_ms = Some(admitted_at_ms);
                (member, Some(invitation))
            }
            Self::VerifiedDomain {
                organization_id,
                email,
            } => (
                MembershipRecord {
                    id: account_id.to_owned(),
                    op: RecordOp::Upsert,
                    org_id: organization_id.clone(),
                    authority: account_id.to_owned(),
                    email: email.clone(),
                    role: "member".to_owned(),
                    status: MembershipStatus::Active,
                    managed_by_scim: false,
                    team: None,
                },
                None,
            ),
        }
    }
}

fn admission_basis(org: &Org, email: &str) -> Result<AdmissionBasis, LoginFoldRefusal> {
    let email = normalize_email_contact(email).ok_or(LoginFoldRefusal::NotAdmitted)?;
    let mode = org
        .sso_admission
        .as_ref()
        .map(|record| record.mode)
        .ok_or(LoginFoldRefusal::NotAdmitted)?;
    let now_ms = session_now_ms();

    let basis = match mode {
        SsoAdmissionMode::InvitedOnly => {
            let matching_members = org
                .members
                .values()
                .filter(|member| {
                    member.status == MembershipStatus::Invited
                        && !member.managed_by_scim
                        && member.email.eq_ignore_ascii_case(&email)
                })
                .cloned()
                .collect::<Vec<_>>();
            let matching_invitations = org
                .invitations
                .values()
                .filter(|invitation| {
                    invitation.status == OrganizationInvitationStatus::Pending
                        && invitation.expires_at_ms > now_ms
                        && invitation.email.eq_ignore_ascii_case(&email)
                })
                .cloned()
                .collect::<Vec<_>>();
            if matching_members.len() + matching_invitations.len() != 1 {
                return Err(LoginFoldRefusal::NotAdmitted);
            }
            if let Some(member) = matching_members.into_iter().next() {
                AdmissionBasis::Existing(member)
            } else {
                let invitation = matching_invitations
                    .into_iter()
                    .next()
                    .ok_or(LoginFoldRefusal::NotAdmitted)?;
                AdmissionBasis::Invitation {
                    invitation,
                    organization_id: organization_id(org),
                }
            }
        }
        SsoAdmissionMode::VerifiedDomainJit => {
            if !org.domain_is_verified(&email) {
                return Err(LoginFoldRefusal::NotAdmitted);
            }
            AdmissionBasis::VerifiedDomain {
                organization_id: organization_id(org),
                email,
            }
        }
        SsoAdmissionMode::Scim => {
            let matching = org
                .members
                .values()
                .filter(|member| {
                    member.managed_by_scim && member.email.eq_ignore_ascii_case(&email)
                })
                .cloned()
                .collect::<Vec<_>>();
            if matching.len() != 1 {
                return Err(LoginFoldRefusal::NotAdmitted);
            }
            let existing = matching.into_iter().next().expect("exactly one match");
            if existing.status != MembershipStatus::Active {
                return Err(LoginFoldRefusal::NotAdmitted);
            }
            AdmissionBasis::Existing(existing)
        }
    };
    let (candidate, _) = basis.materialize("pending-account", now_ms);
    if !is_valid_role(&candidate.role) {
        return Err(LoginFoldRefusal::NotAdmitted);
    }
    if !org.seat_available_for(&candidate.id) {
        return Err(LoginFoldRefusal::NotAdmitted);
    }
    Ok(basis)
}

fn organization_id(org: &Org) -> String {
    org.scope
        .strip_prefix("org::")
        .filter(|tenant| tenant_scope(tenant) == org.scope)
        .unwrap_or(ORG_ID)
        .to_owned()
}

fn tenant_ref(org: &Org, member: &MembershipRecord) -> Option<TenantRef> {
    let tenant_id = org.scope.strip_prefix("org::")?;
    if tenant_scope(tenant_id) != org.scope {
        return None;
    }
    let display_name = org.org.as_ref()?.display_name.clone();
    Some(TenantRef {
        id: tenant_id.to_owned(),
        op: RecordOp::Upsert,
        display_name,
        role: member.role.clone(),
        personal: false,
    })
}

fn ensure_tenant_index(
    wb: &mut Workbench,
    org: &Org,
    account_id: &str,
    member: &MembershipRecord,
) -> Result<(), LoginFoldRefusal> {
    let Some(reference) = tenant_ref(org, member) else {
        return Ok(());
    };
    let scope = account_scope(account_id);
    let indexed = Tenancy::rebuild_in(wb.store_ref(), &scope)
        .map_err(|_| LoginFoldRefusal::Unavailable)?
        .tenants
        .get(&reference.id)
        .is_some_and(|current| {
            current.id == reference.id
                && current.op == reference.op
                && current.display_name == reference.display_name
                && current.role == reference.role
                && current.personal == reference.personal
        });
    if indexed {
        return Ok(());
    }
    let payload = serde_json::to_string(&reference).map_err(|_| LoginFoldRefusal::Unavailable)?;
    wb.store_mut()
        .append_record(&scope, TENANT_REF_KIND, &payload)
        .map(|_| ())
        .map_err(|_| LoginFoldRefusal::Unavailable)
}

fn commit_admission(
    wb: &mut Workbench,
    org: &Org,
    account_id: &str,
    auth_facts: &[AccountAuthFact],
    member: MembershipRecord,
    invitation: Option<OrganizationInvitationRecord>,
) -> Result<(), LoginFoldRefusal> {
    let mut facts = current_command_record_facts(wb.store_ref(), auth_facts)
        .map_err(|_| LoginFoldRefusal::Unavailable)?;
    facts.push(CommandRecordFact {
        scope_id: org.scope.clone(),
        kind: "membership".to_owned(),
        payload: serde_json::to_string(&member).map_err(|_| LoginFoldRefusal::Unavailable)?,
    });
    if let Some(invitation) = invitation {
        facts.push(CommandRecordFact {
            scope_id: org.scope.clone(),
            kind: ORGANIZATION_INVITATION_KIND.to_owned(),
            payload: serde_json::to_string(&invitation)
                .map_err(|_| LoginFoldRefusal::Unavailable)?,
        });
    }
    if let Some(reference) = tenant_ref(org, &member) {
        facts.push(CommandRecordFact {
            scope_id: account_scope(account_id),
            kind: TENANT_REF_KIND.to_owned(),
            payload: serde_json::to_string(&reference)
                .map_err(|_| LoginFoldRefusal::Unavailable)?,
        });
    }
    let borrowed = facts
        .iter()
        .map(|fact| {
            (
                fact.scope_id.as_str(),
                fact.kind.as_str(),
                fact.payload.as_str(),
            )
        })
        .collect::<Vec<_>>();
    wb.store_mut()
        .append_records_atomically(&borrowed)
        .map_err(|_| LoginFoldRefusal::Unavailable)?;
    gaugedesk_app::audit::record_in(wb, &org.scope, account_id, "member.sso-admit", &member.id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use gaugedesk_app::account_auth::{append_facts, AccountAuthFact};
    use gaugedesk_app::at_rest::LoopbackKeyWrap;
    use gaugedesk_app::content_vault::ContentVault;
    use gaugedesk_app::org::{
        BillingRecord, OrgRecord, SsoAdmissionRecord, SsoConnectionRecord, SSO_ADMISSION_KIND,
    };
    use gaugedesk_core::ids::AuthorityId;

    fn workbench() -> (Workbench, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(ContentVault::new(
            dir.path(),
            Box::new(LoopbackKeyWrap::new([7_u8; 32])),
        ));
        (
            Workbench::new(gaugedesk_store::Store::open_in_memory().unwrap())
                .with_content_vault(vault),
            dir,
        )
    }

    fn seed_org(
        wb: &mut Workbench,
        tenant: &str,
        mode: Option<SsoAdmissionMode>,
    ) -> PendingEnterpriseLogin {
        seed_org_with_protocol(wb, tenant, mode, SsoProtocol::Oidc)
    }

    fn seed_org_with_protocol(
        wb: &mut Workbench,
        tenant: &str,
        mode: Option<SsoAdmissionMode>,
        protocol: SsoProtocol,
    ) -> PendingEnterpriseLogin {
        let scope = tenant_scope(tenant);
        let organization = OrgRecord {
            id: tenant.to_owned(),
            op: RecordOp::Upsert,
            display_name: "Acme Research".into(),
            verified_domains: vec!["acme.example".into()],
            pending_domains: Vec::new(),
            default_region: None,
            kind: Default::default(),
        };
        let mut connection = SsoConnectionRecord {
            id: ORG_ID.into(),
            op: RecordOp::Upsert,
            protocol,
            issuer: "https://idp.example.test".into(),
            audiences: vec!["gaugedesk".into()],
            metadata: "https://idp.example.test/.well-known/openid-configuration".into(),
            ..Default::default()
        };
        connection.seal_revision();
        wb.store_mut()
            .append_record(
                &scope,
                "org",
                &serde_json::to_string(&organization).unwrap(),
            )
            .unwrap();
        wb.store_mut()
            .append_record(&scope, "sso", &serde_json::to_string(&connection).unwrap())
            .unwrap();
        if let Some(mode) = mode {
            wb.store_mut()
                .append_record(
                    &scope,
                    SSO_ADMISSION_KIND,
                    &serde_json::to_string(&SsoAdmissionRecord {
                        id: ORG_ID.into(),
                        op: RecordOp::Upsert,
                        mode,
                    })
                    .unwrap(),
                )
                .unwrap();
        }
        let connection_revision = connection.current_revision();
        PendingEnterpriseLogin {
            store_scope: scope,
            connection_id: connection.id,
            connection_revision,
            protocol: connection.protocol,
        }
    }

    fn identity(subject: &str, email: &str, verified: bool) -> VerifiedEnterpriseIdentity {
        VerifiedEnterpriseIdentity {
            authority: AuthorityId::new(subject),
            verified_email: verified.then(|| email.to_owned()),
        }
    }

    #[test]
    fn verified_domain_jit_creates_an_independent_account_and_is_idempotent() {
        let (mut wb, _dir) = workbench();
        let pending = seed_org(
            &mut wb,
            "organization:acme",
            Some(SsoAdmissionMode::VerifiedDomainJit),
        );
        let verified = identity("idp-subject-alice", "Alice@Acme.Example", true);

        let resolution = resolve_corporate_login(&mut wb, &pending, &verified).unwrap();
        assert_ne!(resolution.account_id, "idp-subject-alice");
        assert_eq!(
            resolution.session_method,
            "enterprise-oidc:org::organization:acme:org"
        );

        let auth = AccountAuth::rebuild(wb.store_ref()).unwrap();
        let root = auth.roots.get(&resolution.account_id).unwrap();
        assert!(wb
            .unseal_custodied_account_root(&resolution.account_id, &root.sealed_seed)
            .is_some());
        assert_eq!(auth.methods_for(&resolution.account_id).emails.len(), 1);
        let subject = auth
            .active_external_subject(
                "org::organization:acme:org",
                "https://idp.example.test",
                "idp-subject-alice",
                ExternalSubjectKind::EnterpriseOidc,
            )
            .unwrap();
        assert_eq!(subject.account_id, resolution.account_id);

        let org = Org::rebuild_in(wb.store_ref(), &pending.store_scope).unwrap();
        let member = org.member_by_authority(&resolution.account_id).unwrap();
        assert_eq!(member.role, "member");
        assert_eq!(member.status, MembershipStatus::Active);
        let tenancy =
            Tenancy::rebuild_in(wb.store_ref(), &account_scope(&resolution.account_id)).unwrap();
        assert_eq!(
            tenancy.tenants["organization:acme"].display_name,
            "Acme Research"
        );

        let root_count = auth.roots.len();
        let member_count = wb
            .store_ref()
            .records(&pending.store_scope, "membership")
            .unwrap()
            .len();
        let retry = resolve_corporate_login(&mut wb, &pending, &verified).unwrap();
        assert_eq!(retry, resolution);
        assert_eq!(
            AccountAuth::rebuild(wb.store_ref()).unwrap().roots.len(),
            root_count
        );
        assert_eq!(
            wb.store_ref()
                .records(&pending.store_scope, "membership")
                .unwrap()
                .len(),
            member_count
        );
    }

    #[test]
    fn saml_uses_the_same_admission_fold_and_records_its_exact_subject_kind() {
        let (mut wb, _dir) = workbench();
        let pending = seed_org_with_protocol(
            &mut wb,
            "organization:acme",
            Some(SsoAdmissionMode::VerifiedDomainJit),
            SsoProtocol::Saml,
        );
        let verified = identity("signed-name-id", "alice@acme.example", true);

        let resolution = resolve_corporate_login(&mut wb, &pending, &verified).unwrap();
        assert_eq!(
            resolution.session_method,
            "enterprise-saml:org::organization:acme:org"
        );
        let auth = AccountAuth::rebuild(wb.store_ref()).unwrap();
        let link = auth
            .active_external_subject(
                "org::organization:acme:org",
                "https://idp.example.test",
                "signed-name-id",
                ExternalSubjectKind::EnterpriseSaml,
            )
            .expect("the signed SAML subject is linked to the admitted account");
        assert_eq!(link.account_id, resolution.account_id);
        assert!(Org::rebuild_in(wb.store_ref(), &pending.store_scope)
            .unwrap()
            .member_by_authority(&resolution.account_id)
            .is_some());
    }

    #[test]
    fn absence_or_failure_of_the_explicit_admission_basis_writes_nothing() {
        for (mode, email, verified) in [
            (None, "alice@acme.example", true),
            (
                Some(SsoAdmissionMode::VerifiedDomainJit),
                "alice@outside.example",
                true,
            ),
            (
                Some(SsoAdmissionMode::VerifiedDomainJit),
                "alice@acme.example",
                false,
            ),
        ] {
            let (mut wb, _dir) = workbench();
            let pending = seed_org(&mut wb, "organization:acme", mode);
            let verified = identity("idp-subject-alice", email, verified);
            assert_eq!(
                resolve_corporate_login(&mut wb, &pending, &verified),
                Err(LoginFoldRefusal::NotAdmitted)
            );
            let auth = AccountAuth::rebuild(wb.store_ref()).unwrap();
            assert!(auth.roots.is_empty());
            assert!(auth.emails.is_empty());
            assert!(auth.external_subjects.is_empty());
            assert!(Org::rebuild_in(wb.store_ref(), &pending.store_scope)
                .unwrap()
                .members
                .is_empty());
        }
    }

    #[test]
    fn invited_only_preserves_the_admitted_role_and_consumes_the_invitation() {
        let (mut wb, _dir) = workbench();
        let pending = seed_org(
            &mut wb,
            "organization:acme",
            Some(SsoAdmissionMode::InvitedOnly),
        );
        let invitation = OrganizationInvitationRecord {
            id: "invitation-alice".into(),
            op: RecordOp::Upsert,
            org_id: "organization:acme".into(),
            email: "alice@acme.example".into(),
            role: "billing".into(),
            team: Some("finance".into()),
            proof_sha256: "hash-only-proof".into(),
            status: OrganizationInvitationStatus::Pending,
            issued_at_ms: session_now_ms(),
            expires_at_ms: session_now_ms() + 60_000,
            responded_by: None,
            responded_at_ms: None,
        };
        wb.store_mut()
            .append_record(
                &pending.store_scope,
                ORGANIZATION_INVITATION_KIND,
                &serde_json::to_string(&invitation).unwrap(),
            )
            .unwrap();

        let resolution = resolve_corporate_login(
            &mut wb,
            &pending,
            &identity("idp-subject-alice", "alice@acme.example", true),
        )
        .unwrap();
        let org = Org::rebuild_in(wb.store_ref(), &pending.store_scope).unwrap();
        let member = org.member_by_authority(&resolution.account_id).unwrap();
        assert_eq!(member.role, "billing");
        assert_eq!(member.team.as_deref(), Some("finance"));
        assert_eq!(
            org.invitations["invitation-alice"].status,
            OrganizationInvitationStatus::Accepted
        );
        assert_eq!(
            org.invitations["invitation-alice"].responded_by.as_deref(),
            Some(resolution.account_id.as_str())
        );
    }

    #[test]
    fn scim_requires_an_active_provisioned_placeholder_and_preserves_its_role() {
        let (mut wb, _dir) = workbench();
        let pending = seed_org(&mut wb, "organization:acme", Some(SsoAdmissionMode::Scim));
        let placeholder = MembershipRecord {
            id: "scim-employee-7".into(),
            op: RecordOp::Upsert,
            org_id: "organization:acme".into(),
            authority: "scim-employee-7".into(),
            email: "alice@acme.example".into(),
            role: "viewer".into(),
            status: MembershipStatus::Active,
            managed_by_scim: true,
            team: Some("research".into()),
        };
        wb.store_mut()
            .append_record(
                &pending.store_scope,
                "membership",
                &serde_json::to_string(&placeholder).unwrap(),
            )
            .unwrap();

        let resolution = resolve_corporate_login(
            &mut wb,
            &pending,
            &identity("idp-subject-alice", "alice@acme.example", true),
        )
        .unwrap();
        let org = Org::rebuild_in(wb.store_ref(), &pending.store_scope).unwrap();
        let member = &org.members["scim-employee-7"];
        assert_eq!(member.authority, resolution.account_id);
        assert_eq!(member.role, "viewer");
        assert_eq!(member.team.as_deref(), Some("research"));

        let (mut denied, _dir) = workbench();
        let denied_pending = seed_org(
            &mut denied,
            "organization:acme",
            Some(SsoAdmissionMode::Scim),
        );
        let mut inactive = placeholder;
        inactive.status = MembershipStatus::Deprovisioned;
        denied
            .store_mut()
            .append_record(
                &denied_pending.store_scope,
                "membership",
                &serde_json::to_string(&inactive).unwrap(),
            )
            .unwrap();
        assert_eq!(
            resolve_corporate_login(
                &mut denied,
                &denied_pending,
                &identity("idp-subject-alice", "alice@acme.example", true),
            ),
            Err(LoginFoldRefusal::NotAdmitted)
        );
        assert!(AccountAuth::rebuild(denied.store_ref())
            .unwrap()
            .roots
            .is_empty());
    }

    #[test]
    fn connection_revision_and_revoked_subjects_fail_closed() {
        let (mut wb, _dir) = workbench();
        let pending = seed_org(
            &mut wb,
            "organization:acme",
            Some(SsoAdmissionMode::VerifiedDomainJit),
        );
        let mut changed = Org::rebuild_in(wb.store_ref(), &pending.store_scope)
            .unwrap()
            .sso
            .unwrap();
        changed.audiences.push("replacement-client".into());
        changed.seal_revision();
        wb.store_mut()
            .append_record(
                &pending.store_scope,
                "sso",
                &serde_json::to_string(&changed).unwrap(),
            )
            .unwrap();
        assert_eq!(
            resolve_corporate_login(
                &mut wb,
                &pending,
                &identity("idp-subject-alice", "alice@acme.example", true),
            ),
            Err(LoginFoldRefusal::StaleConnection)
        );
        assert!(AccountAuth::rebuild(wb.store_ref())
            .unwrap()
            .roots
            .is_empty());

        let (mut revoked_wb, _dir) = workbench();
        let revoked_pending = seed_org(
            &mut revoked_wb,
            "organization:acme",
            Some(SsoAdmissionMode::VerifiedDomainJit),
        );
        let mut revoked = ExternalSubjectRecord::new(
            "existing-account",
            "org::organization:acme:org",
            "https://idp.example.test",
            "idp-subject-alice",
            ExternalSubjectKind::EnterpriseOidc,
            1,
        )
        .unwrap();
        revoked.status = AuthMethodStatus::Revoked;
        append_facts(
            revoked_wb.store_mut(),
            &[AccountAuthFact::ExternalSubject(revoked)],
        )
        .unwrap();
        assert_eq!(
            resolve_corporate_login(
                &mut revoked_wb,
                &revoked_pending,
                &identity("idp-subject-alice", "alice@acme.example", true),
            ),
            Err(LoginFoldRefusal::NotAdmitted)
        );
        assert!(AccountAuth::rebuild(revoked_wb.store_ref())
            .unwrap()
            .roots
            .is_empty());
    }

    #[test]
    fn ambiguous_invites_seat_exhaustion_and_email_collision_create_no_account() {
        let (mut ambiguous, _dir) = workbench();
        let ambiguous_pending = seed_org(
            &mut ambiguous,
            "organization:acme",
            Some(SsoAdmissionMode::InvitedOnly),
        );
        for id in ["invitation-one", "invitation-two"] {
            let invitation = OrganizationInvitationRecord {
                id: id.into(),
                op: RecordOp::Upsert,
                org_id: "organization:acme".into(),
                email: "alice@acme.example".into(),
                role: "member".into(),
                team: None,
                proof_sha256: format!("hash-{id}"),
                status: OrganizationInvitationStatus::Pending,
                issued_at_ms: session_now_ms(),
                expires_at_ms: session_now_ms() + 60_000,
                responded_by: None,
                responded_at_ms: None,
            };
            ambiguous
                .store_mut()
                .append_record(
                    &ambiguous_pending.store_scope,
                    ORGANIZATION_INVITATION_KIND,
                    &serde_json::to_string(&invitation).unwrap(),
                )
                .unwrap();
        }
        assert_eq!(
            resolve_corporate_login(
                &mut ambiguous,
                &ambiguous_pending,
                &identity("idp-subject-alice", "alice@acme.example", true),
            ),
            Err(LoginFoldRefusal::NotAdmitted)
        );
        assert!(AccountAuth::rebuild(ambiguous.store_ref())
            .unwrap()
            .roots
            .is_empty());

        let (mut full, _dir) = workbench();
        let full_pending = seed_org(
            &mut full,
            "organization:acme",
            Some(SsoAdmissionMode::VerifiedDomainJit),
        );
        full.store_mut()
            .append_record(
                &full_pending.store_scope,
                "billing",
                &serde_json::to_string(&BillingRecord {
                    id: ORG_ID.into(),
                    op: RecordOp::Upsert,
                    plan: "business".into(),
                    seats: 0,
                    managed_inference: None,
                })
                .unwrap(),
            )
            .unwrap();
        assert_eq!(
            resolve_corporate_login(
                &mut full,
                &full_pending,
                &identity("idp-subject-alice", "alice@acme.example", true),
            ),
            Err(LoginFoldRefusal::NotAdmitted)
        );
        assert!(AccountAuth::rebuild(full.store_ref())
            .unwrap()
            .roots
            .is_empty());

        let (mut collision, _dir) = workbench();
        let collision_pending = seed_org(
            &mut collision,
            "organization:acme",
            Some(SsoAdmissionMode::VerifiedDomainJit),
        );
        append_facts(
            collision.store_mut(),
            &[AccountAuthFact::Email(
                VerifiedEmailRecord::new("another-account", "alice@acme.example", 1).unwrap(),
            )],
        )
        .unwrap();
        assert_eq!(
            resolve_corporate_login(
                &mut collision,
                &collision_pending,
                &identity("idp-subject-alice", "alice@acme.example", true),
            ),
            Err(LoginFoldRefusal::NotAdmitted)
        );
        let auth = AccountAuth::rebuild(collision.store_ref()).unwrap();
        assert!(auth.roots.is_empty());
        assert!(auth.external_subjects.is_empty());
    }
}
