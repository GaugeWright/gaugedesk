//! Who owns a project ([DR-0268](../../../specs/decisions/0268-the-project-is-the-unit-of-trust.md) §6,
//! [DR-0309](../../../specs/decisions/0309-a-project-records-its-owner.md)).
//!
//! Every project has exactly one owner: an account or an organization. A
//! project created on this build records its creating account in
//! `extra.owner`. Older records carry none, and their owner is derived the way
//! the founder settled on 2026-10-01: the account that claimed this computer,
//! whose claim was the explicit act that gave it the computer's projects, or
//! the computer's local account where nobody claimed it.
//!
//! This is what admits a signed-in account to a project, beside
//! an explicit grant; an organization role no longer reaches every project.

use std::collections::{BTreeMap, BTreeSet};

use crate::library::ProjectRecord;
use crate::org::Org;
use crate::Workbench;

/// The `ProjectRecord.extra` key holding the owning account.
pub const PROJECT_OWNER_EXTRA: &str = "owner";

/// A project's one owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProjectOwner {
    Account(String),
    Organization(String),
}

/// Record `account` as the owner on a project record about to be written.
/// An empty or anonymous actor records nothing, so the legacy rule applies.
pub fn record_owner(extra: &mut BTreeMap<String, serde_json::Value>, account: &str) {
    if account.is_empty() || account == "anonymous" {
        return;
    }
    extra.insert(
        PROJECT_OWNER_EXTRA.to_owned(),
        serde_json::Value::String(account.to_owned()),
    );
}

pub(crate) fn recorded_owner(project: &ProjectRecord) -> Option<&str> {
    project
        .extra
        .get(PROJECT_OWNER_EXTRA)
        .and_then(serde_json::Value::as_str)
        .filter(|owner| !owner.is_empty())
}

/// The `ACCOUNT_SCOPE` record kind naming whose that scope is: on a claimed
/// desktop, the claimant's, which keeps the provider credentials, logins,
/// boxes and settings the computer held before they were keyed per account
/// (DR-0313).
pub const INSTALL_SCOPE_OWNER_KIND: &str = "install_scope_owner";

#[derive(serde::Serialize, serde::Deserialize)]
struct InstallScopeOwner {
    account: String,
}

/// Whether `project` takes the legacy owner rather than one its own record
/// implies: no recorded owner, and no organization, learner or preview.
pub(crate) fn takes_legacy_owner(project: &ProjectRecord) -> bool {
    recorded_owner(project).is_none()
        && !project.extra.contains_key("organization")
        && !crate::shipped_tutorials::is_tutorial_project(project)
        && crate::panel_preview::preview_marker(project).is_none()
}

/// The id of `account`'s own Personal on this host. Hashed, so no account id
/// reaches a path or a directory name.
pub fn personal_project_id(account: &str) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(format!("gaugedesk-personal:{account}").as_bytes());
    format!("personal-{}", hex::encode(&digest[..16]))
}

/// Immutable local ownership posture, with no cached ownership or grants.
/// Admission folds the caller's store under its own product read basis.
#[derive(Clone)]
pub(crate) struct ProjectOwnerResolver {
    local_account: String,
    legacy_agents: bool,
}

impl ProjectOwnerResolver {
    pub(crate) fn legacy_owner(&self, store: &gaugedesk_store::Store) -> String {
        // DR-0309 names the earlier explicit claim, never an organization
        // role. home_owner_account also recognizes a sole directory owner,
        // which is host-era compatibility and cannot establish project data
        // ownership. Unreadable or ambiguous claim evidence supplies no owner.
        let Ok(claims) = store.records(crate::org::ORG_SCOPE, crate::home_owner::CLAIM_KIND) else {
            return String::new();
        };
        match claims.as_slice() {
            [] => self.local_account.clone(),
            [claim] => match serde_json::from_str::<crate::home_owner::HomeOwnerClaim>(claim) {
                Ok(claim) => claim.account.unwrap_or_else(|| self.local_account.clone()),
                Err(_) => String::new(),
            },
            _ => String::new(),
        }
    }

    pub(crate) fn owner_in(
        &self,
        library: &crate::library::Library,
        project: &ProjectRecord,
        legacy: &str,
    ) -> ProjectOwner {
        if let Some(owner) = recorded_owner(project) {
            return ProjectOwner::Account(owner.to_owned());
        }
        if let Some(organization) = project
            .extra
            .get("organization")
            .and_then(serde_json::Value::as_str)
        {
            return ProjectOwner::Organization(organization.to_owned());
        }
        if crate::shipped_tutorials::is_tutorial_project(project) {
            if let Some(learner) = project
                .extra
                .get("product")
                .and_then(|product| product.get("learner"))
                .and_then(serde_json::Value::as_str)
            {
                return ProjectOwner::Account(learner.to_owned());
            }
        }
        // A Panel agent's preview project is hidden plumbing: it belongs to
        // whoever owns what it previews.
        if let Some(marker) = crate::panel_preview::preview_marker(project) {
            // One a member of a shared project started is that member's own
            // while it lasts, so it reaches it and nobody else does (DR-0453).
            if let Some(member) = marker.started_by.filter(|member| !member.is_empty()) {
                return ProjectOwner::Account(member);
            }
            let previewed = marker
                .placement_id
                .as_deref()
                .and_then(|placement| library.project_of_instance(placement))
                .and_then(|id| library.projects.get(id))
                .filter(|previewed| !crate::panel_preview::is_panel_preview_project(previewed));
            if let Some(previewed) = previewed {
                return self.owner_in(library, previewed, legacy);
            }
            if let Some(author) = self.agent_owner_in(library, &marker.agent_id, legacy) {
                return ProjectOwner::Account(author);
            }
        }
        ProjectOwner::Account(legacy.to_owned())
    }

    pub(crate) fn agent_owner_in(
        &self,
        library: &crate::library::Library,
        id: &str,
        legacy: &str,
    ) -> Option<String> {
        let agent = library.agents.get(id)?;
        agent
            .authoring_owner
            .clone()
            .or_else(|| {
                agent
                    .versions
                    .get(&agent.current_version)
                    .and_then(|version| version.source_owner_authority.clone())
            })
            .or_else(|| {
                self.legacy_agents.then(|| {
                    if crate::app_support::is_builtin_agent(id) {
                        self.local_account.clone()
                    } else {
                        legacy.to_owned()
                    }
                })
            })
            .filter(|owner| !owner.is_empty() && owner != "anonymous")
    }

    pub(crate) fn account_project_ids(
        &self,
        store: &gaugedesk_store::Store,
        account: &str,
        org: &Org,
    ) -> BTreeSet<String> {
        // Unreadable ownership evidence grants no project visibility.
        let Ok(library) = crate::library::Library::rebuild(store) else {
            return BTreeSet::new();
        };
        let mut ids =
            self.account_project_ids_in(&library, &self.legacy_owner(store), account, org);
        // A Hub holds only the reservation of an organization's shared
        // project; the project itself is on its Home. The reservation is read
        // from the organization's own directory scope, and unreadable
        // reservation evidence adds nothing.
        for organization in administered_organizations(account, org) {
            if org.scope != crate::org::tenant_scope(&organization) {
                continue;
            }
            if let Ok(Some(intent)) =
                crate::tenancy::organization_project_intent(store, &organization)
            {
                ids.insert(intent.project_id);
            }
        }
        ids
    }

    pub(crate) fn account_project_ids_in(
        &self,
        library: &crate::library::Library,
        legacy: &str,
        account: &str,
        org: &Org,
    ) -> BTreeSet<String> {
        let administers = administered_organizations(account, org);
        let mut ids: BTreeSet<String> = library
            .projects
            .values()
            .filter(|project| match self.owner_in(library, project, legacy) {
                ProjectOwner::Account(owner) => owner == account,
                ProjectOwner::Organization(organization) => administers.contains(&organization),
            })
            .map(|project| project.id.clone())
            .collect();
        ids.extend(org.granted_project_ids(account));
        ids
    }

    /// Current project members, read from this exact product basis. An account
    /// owns its project independently of organization membership. Legacy
    /// organization-issued grants require an active directory recipient.
    pub(crate) fn members_in(
        &self,
        library: &crate::library::Library,
        legacy: &str,
        project: &ProjectRecord,
        org: &Org,
    ) -> BTreeSet<String> {
        let mut members: BTreeSet<String> = org
            .members
            .values()
            .filter(|member| org.role_of(&member.authority).is_some())
            .filter(|member| {
                org.granted_project_ids(&member.authority)
                    .contains(&project.id)
            })
            .map(|member| member.authority.clone())
            .collect();
        match self.owner_in(library, project, legacy) {
            ProjectOwner::Account(owner) => {
                if !owner.is_empty() && owner != "anonymous" {
                    members.insert(owner);
                }
            }
            ProjectOwner::Organization(organization) => {
                members.extend(
                    org.members
                        .values()
                        .filter(|member| {
                            administered_organizations(&member.authority, org)
                                .contains(&organization)
                        })
                        .map(|member| member.authority.clone()),
                );
            }
        }
        members
    }
}

impl Workbench {
    /// A project that arrived as this computer's local account's passes to the
    /// signed-in account that accepted it (DR-0328 §4). An account's project,
    /// or one accepted signed out, stays as it arrived.
    pub(crate) fn take_accepted_project(&mut self, headers: &axum::http::HeaderMap, project: &str) {
        if !self.desktop_account_mode() {
            return;
        }
        let Some((account, _)) =
            crate::net_http::bearer(headers).and_then(|token| self.resolve_account_session(token))
        else {
            return;
        };
        let Some(mut record) = self.library.projects.get(project).cloned() else {
            return;
        };
        if recorded_owner(&record) == Some(self.authority().as_str()) {
            record_owner(&mut record.extra, &account);
            self.write_project_record(record);
        }
    }

    /// Whether a workspace change event names something the subscriber can
    /// see. Off a desktop every subscriber hears every change, as before.
    pub(crate) fn workspace_event_visible(
        &self,
        bearer: Option<&str>,
        event: &crate::stream::ServerEvent,
    ) -> bool {
        let crate::stream::ServerEvent::WorkspaceChanged { record, id, .. } = event else {
            return true;
        };
        if !self.desktop_account_mode() {
            return true;
        }
        let visibility = self.project_visibility(bearer);
        let project = match record.as_str() {
            "project" => self.library.projects.contains_key(id).then(|| id.clone()),
            "chat" => self.library.project_of_chat(id).map(str::to_owned),
            "instance" | "placement" => self.library.project_of_instance(id).map(str::to_owned),
            "agent" => {
                let actor = match bearer {
                    Some(token) => self
                        .resolve_account_session(token)
                        .map(|(account, _)| account),
                    None => Some(self.authority().as_str().to_owned()),
                };
                return crate::app_support::is_builtin_agent(id)
                    || !self.library.agents.contains_key(id)
                    || actor.is_some_and(|actor| self.agent_authoring_visible(id, Some(&actor)));
            }
            _ => None,
        };
        // A removed record no longer resolves; its id alone is all that crosses.
        project.is_none_or(|project| visibility.allows(&project))
    }

    /// The account a desktop request acts as for host-level records such as
    /// pairings: the account session's, or the local account when signed
    /// out. `None` off a desktop, where those records keep their own rules.
    pub(crate) fn pairing_actor(&self, headers: &axum::http::HeaderMap) -> Option<String> {
        if !self.desktop_account_mode() {
            return None;
        }
        match crate::net_http::bearer(headers) {
            // A session that resolves to no account owns nothing here.
            Some(token) => Some(
                self.resolve_account_session(token)
                    .map(|(account, _)| account)
                    .unwrap_or_default(),
            ),
            None => Some(self.authority().as_str().to_owned()),
        }
    }

    /// The account a pairing belongs to: the one it records, else the legacy
    /// owner, as for the projects it predates (DR-0309, DR-0328 §3).
    pub(crate) fn bridge_owner(&self, bridge: &crate::federation::BridgeRecord) -> String {
        bridge
            .account
            .clone()
            .filter(|account| !account.is_empty())
            .unwrap_or_else(|| self.legacy_project_owner())
    }

    /// The owner of a project with no recorded one: the account that claimed
    /// this computer, else the computer's local account.
    pub(crate) fn legacy_project_owner(&self) -> String {
        self.project_owner_resolver().legacy_owner(self.store_ref())
    }

    /// The account a single valid claim names, if this computer was claimed.
    fn claimed_account(&self) -> Option<String> {
        let claims = self
            .store_ref()
            .records(crate::org::ORG_SCOPE, crate::home_owner::CLAIM_KIND)
            .ok()?;
        match claims.as_slice() {
            [claim] => serde_json::from_str::<crate::home_owner::HomeOwnerClaim>(claim)
                .ok()?
                .account
                .filter(|account| !account.is_empty()),
            _ => None,
        }
    }

    /// The account the install's account scope belongs to, once recorded.
    pub(crate) fn install_scope_owner(&self) -> Option<String> {
        self.store_ref()
            .records(crate::account::ACCOUNT_SCOPE, INSTALL_SCOPE_OWNER_KIND)
            .ok()?
            .iter()
            .rev()
            .find_map(|raw| serde_json::from_str::<InstallScopeOwner>(raw).ok())
            .map(|owner| owner.account)
            .filter(|account| !account.is_empty())
    }

    /// Write down what a claim gave its account (DR-0309, DR-0313), so the
    /// ownership outlives the claim when it is removed (WS-588): the claimant
    /// becomes the recorded owner of every project and Agent that only the
    /// claim made its, and of the install's account scope. Idempotent, and it
    /// changes nobody's view. A computer nobody claimed, or whose claim
    /// evidence is ambiguous, needs nothing: its default is already the local
    /// account. Returns how many records it wrote.
    pub(crate) fn settle_claimed_ownership(&mut self) -> Result<usize, String> {
        if self.hosted_home_mode() || crate::workbench_auth::web_account_mode() {
            return Ok(0);
        }
        let Some(claimant) = self.claimed_account() else {
            return Ok(0);
        };
        let mut written = 0;
        let projects: Vec<ProjectRecord> = self
            .library
            .projects
            .values()
            .filter(|project| takes_legacy_owner(project))
            .cloned()
            .collect();
        for mut project in projects {
            record_owner(&mut project.extra, &claimant);
            self.write_project_record(project);
            written += 1;
        }
        let agents: Vec<crate::library::AgentRecord> = self
            .library
            .agents
            .values()
            .filter(|agent| {
                agent.authoring_owner.is_none()
                    && !crate::app_support::is_builtin_agent(&agent.id)
                    && agent
                        .versions
                        .get(&agent.current_version)
                        .is_none_or(|version| version.source_owner_authority.is_none())
            })
            .cloned()
            .collect();
        for mut agent in agents {
            agent.authoring_owner = Some(claimant.clone());
            self.write_agent_record(agent);
            written += 1;
        }
        if self.install_scope_owner().is_none() {
            let record = serde_json::to_string(&InstallScopeOwner {
                account: claimant.clone(),
            })
            .map_err(|error| error.to_string())?;
            self.store_mut()
                .append_record(
                    crate::account::ACCOUNT_SCOPE,
                    INSTALL_SCOPE_OWNER_KIND,
                    &record,
                )
                .map_err(|error| format!("{error:?}"))?;
            written += 1;
        }
        Ok(written)
    }

    /// The owner of `project`. `legacy` is [`Self::legacy_project_owner`],
    /// passed in so a caller folding every project reads it once.
    pub(crate) fn project_owner_with(&self, project: &ProjectRecord, legacy: &str) -> ProjectOwner {
        self.project_owner_in(&self.library, project, legacy)
    }

    fn project_owner_in(
        &self,
        library: &crate::library::Library,
        project: &ProjectRecord,
        legacy: &str,
    ) -> ProjectOwner {
        self.project_owner_resolver()
            .owner_in(library, project, legacy)
    }

    /// The owner of the project `id`, if it exists.
    pub(crate) fn project_owner(&self, id: &str) -> Option<ProjectOwner> {
        let project = self.library.projects.get(id)?;
        Some(self.project_owner_with(project, &self.legacy_project_owner()))
    }

    /// The refusal for a desktop account session acting on a project it does
    /// not own, where the act is the owner's alone: inviting into it, moving
    /// it, admitting runs on it, publishing from it (DR-0328 §4, §5). An
    /// organization's project keeps its organization's own checks, and the
    /// credential-free local channel keeps its view until it acts as the
    /// local account. An unknown project is left to the handler's own 404.
    pub(crate) fn project_owner_refusal(
        &self,
        headers: &axum::http::HeaderMap,
        project: &str,
    ) -> Option<axum::response::Response> {
        use axum::response::IntoResponse;
        if !self.desktop_account_mode() {
            return None;
        }
        let (account, _) = crate::net_http::bearer(headers)
            .and_then(|token| self.resolve_account_session(token))?;
        match self.project_owner(project)? {
            ProjectOwner::Account(owner) if owner == account => None,
            ProjectOwner::Organization(_) => None,
            ProjectOwner::Account(_) => Some(
                (
                    axum::http::StatusCode::FORBIDDEN,
                    axum::Json(serde_json::json!({
                        "error": "only this project's owner may do that"
                    })),
                )
                    .into_response(),
            ),
        }
    }

    /// The refusal for a desktop account session upgrading or deploying from
    /// a project it neither owns nor works in as a member: its owner may, and
    /// so may an account holding its grant with a role that authors there,
    /// while a viewer may not (DR-0453). The deployment stays the owner's and
    /// is signed by the owner's key; [`Self::project_member_requester`] names
    /// who asked. Otherwise as [`Self::project_owner_refusal`].
    pub(crate) fn project_deployer_refusal(
        &self,
        headers: &axum::http::HeaderMap,
        project: &str,
    ) -> Option<axum::response::Response> {
        use axum::response::IntoResponse;
        self.project_owner_refusal(headers, project)?;
        let member = crate::net_http::bearer(headers)
            .and_then(|token| self.resolve_account_session(token))
            .is_some_and(|(account, _)| self.project_member_authors(project, &account));
        (!member).then(|| {
            (
                axum::http::StatusCode::FORBIDDEN,
                axum::Json(serde_json::json!({
                    "error": "only this project's owner or one of its members may do that"
                })),
            )
                .into_response()
        })
    }

    /// The member who asks for a deployment act on `project` it does not own
    /// (DR-0453), for the record of who requested it. `None` for its owner,
    /// the local channel, and off a desktop.
    pub(crate) fn project_member_requester(
        &self,
        headers: &axum::http::HeaderMap,
        project: &str,
    ) -> Option<String> {
        if !self.desktop_account_mode() {
            return None;
        }
        let (account, _) = crate::net_http::bearer(headers)
            .and_then(|token| self.resolve_account_session(token))?;
        match self.project_owner(project)? {
            ProjectOwner::Account(owner) if owner == account => None,
            _ => self
                .project_member_authors(project, &account)
                .then_some(account),
        }
    }

    /// [`Self::project_deployer_refusal`] for the project a placement is on.
    pub(crate) fn placement_deployer_refusal(
        &self,
        headers: &axum::http::HeaderMap,
        placement: &str,
    ) -> Option<axum::response::Response> {
        let project = self.library.project_of_instance(placement)?.to_owned();
        self.project_deployer_refusal(headers, &project)
    }

    /// [`Self::project_deployer_refusal`] for the project a public deployment
    /// was published from, by its hosted id or its binding id.
    pub(crate) fn deployment_deployer_refusal(
        &self,
        headers: &axum::http::HeaderMap,
        deployment: &str,
    ) -> Option<axum::response::Response> {
        let project = self.deployment_project(deployment)?;
        self.project_deployer_refusal(headers, &project)
    }

    /// The project a public deployment was published from, by its hosted id
    /// or its binding id.
    pub(crate) fn deployment_project(&self, deployment: &str) -> Option<String> {
        self.library
            .public_deployments
            .values()
            .find(|binding| binding.id == deployment || binding.hosted_deployment_id == deployment)
            .map(|binding| binding.project_id.clone())
    }

    /// [`Self::project_owner_refusal`] for the project a public deployment
    /// was published from, by its hosted id or its binding id.
    pub(crate) fn deployment_owner_refusal(
        &self,
        headers: &axum::http::HeaderMap,
        deployment: &str,
    ) -> Option<axum::response::Response> {
        let project = self
            .library
            .public_deployments
            .values()
            .find(|binding| binding.id == deployment || binding.hosted_deployment_id == deployment)?
            .project_id
            .clone();
        self.project_owner_refusal(headers, &project)
    }

    /// [`Self::project_owner_refusal`] for the project a placement is on.
    pub(crate) fn placement_owner_refusal(
        &self,
        headers: &axum::http::HeaderMap,
        placement: &str,
    ) -> Option<axum::response::Response> {
        let project = self.library.project_of_instance(placement)?.to_owned();
        self.project_owner_refusal(headers, &project)
    }

    /// `account`'s Personal on this host, if it has one: the install's own
    /// Personal for the account DR-0309 gave it to, else one made for it.
    pub(crate) fn account_personal(&self, account: &str) -> Option<String> {
        let legacy = self.legacy_project_owner();
        let owned = |project: &&ProjectRecord| {
            project.is_default
                && self.project_owner_with(project, &legacy)
                    == ProjectOwner::Account(account.to_owned())
        };
        let mut personals = self.library.projects.values().filter(owned);
        let first = personals.next()?;
        // The install's Personal wins if an account somehow holds two.
        if first.id == crate::DEFAULT_PROJECT {
            return Some(first.id.clone());
        }
        Some(
            personals
                .find(|project| project.id == crate::DEFAULT_PROJECT)
                .unwrap_or(first)
                .id
                .clone(),
        )
    }

    /// Make sure `account` has a Personal of its own on this host, and name it
    /// (DR-0268 §5). Idempotent; an account DR-0309 gave the install's
    /// Personal keeps it.
    pub(crate) fn ensure_account_personal(&mut self, account: &str) -> Result<String, String> {
        if account.is_empty() || account == "anonymous" {
            return Err("an account is needed for a Personal project".to_owned());
        }
        if let Some(project) = self.account_personal(account) {
            return Ok(project);
        }
        let id = personal_project_id(account);
        crate::library_routes::create_personal_project(self, &id, account)?;
        Ok(id)
    }

    /// The Personal a new Agent is placed on: its owner's, else the
    /// install's.
    pub(crate) fn agent_owner_personal(&self, agent: &str) -> String {
        self.agent_authoring_owner(agent)
            .and_then(|owner| self.account_personal(&owner))
            .unwrap_or_else(|| crate::DEFAULT_PROJECT.to_owned())
    }

    /// The Personal a request works in when it is not the install's: a
    /// desktop account session's own, made if it has none (DR-0268 §5).
    /// `None` for the local channel, a phone and a hosted Home, which keep the
    /// install's until WS-588, and for the account DR-0309 gave it to.
    pub(crate) fn request_personal(
        &mut self,
        headers: &axum::http::HeaderMap,
    ) -> Result<Option<String>, String> {
        if !self.desktop_account_mode() {
            return Ok(None);
        }
        let account = match crate::net_http::bearer(headers) {
            Some(token) => match self.resolve_account_session(token) {
                Some((account, _)) => account,
                None => return Ok(None),
            },
            // Signed out, the window is the computer's local account. It works
            // in the install's Personal unless that is a claimant's.
            None if self.legacy_project_owner() == self.authority().as_str() => return Ok(None),
            None => self.authority().as_str().to_owned(),
        };
        let personal = self.ensure_account_personal(&account)?;
        Ok((personal != crate::DEFAULT_PROJECT).then_some(personal))
    }

    /// The placement a quick-start chat in Personal `project` starts on.
    pub(crate) fn personal_placement_of(&self, project: &str) -> Option<String> {
        if project == crate::DEFAULT_PROJECT {
            return Some(crate::app_support::DEFAULT_PLACEMENT.to_owned())
                .filter(|placement| self.library.instances.contains_key(placement));
        }
        Some(crate::library_routes::general_placement_id(project))
            .filter(|placement| self.library.instances.contains_key(placement))
    }

    /// The projects `account` reaches as itself: those it owns, those it
    /// holds a grant to in `org`, and the shared projects of an organization
    /// it is an owner or admin of in `org` (DR-0374).
    pub(crate) fn account_project_ids(&self, account: &str, org: &Org) -> BTreeSet<String> {
        self.project_owner_resolver()
            .account_project_ids(self.store_ref(), account, org)
    }

    pub(crate) fn project_owner_resolver(&self) -> ProjectOwnerResolver {
        ProjectOwnerResolver {
            local_account: self.authority().as_str().to_owned(),
            legacy_agents: !self.hosted_home_mode() && !crate::workbench_auth::web_account_mode(),
        }
    }
}

/// The organizations whose own shared projects `account` reaches through its
/// role in `org`: an active `owner` or `admin` membership reaches the shared
/// projects of the organization it names, and no other organization's and no
/// account's (DR-0374, amending DR-0268 §6). Any other role reaches a shared
/// project only through an explicit grant.
pub(crate) fn administered_organizations(account: &str, org: &Org) -> BTreeSet<String> {
    use gaugedesk_core::abac::Role;
    org.members
        .values()
        .filter(|member| {
            member.authority == account
                && member.status == crate::org::MembershipStatus::Active
                && [Role::owner(), Role::admin()].contains(&Role::new(member.role.as_str()))
        })
        .map(|member| member.org_id.clone())
        .collect()
}

/// Refuse a request carrying an account session that names a project the
/// account neither owns nor holds a grant to. Layered on the desktop's own
/// channel and its relay leg, which otherwise serve whoever reaches them.
///
/// Only a project the path resolves to is checked here. A credential-free
/// request is the local channel and keeps its view until the local account
/// has a Personal of its own (WS-588); a route naming no project is the
/// next step's (WS-655).
pub(crate) async fn account_project_gate(
    axum::extract::State(wb): axum::extract::State<crate::SharedWorkbench>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use crate::LockUnpoisoned;
    use axum::response::IntoResponse;
    // A phone's controller session has its own admission and is no account.
    let controller = crate::mobile_machine_session::session_token(request.headers()).is_some();
    let refused = !controller && {
        let wb = wb.lock_unpoisoned();
        let path = request.uri().path();
        wb.desktop_account_mode()
            && (wb.scope_project_of_path(path).is_some_and(|project| {
                // Signed out, this is the local account (DR-0328 §2).
                !wb.project_visibility_in(
                    crate::net_http::bearer(request.headers()),
                    &crate::workbench_auth::req_scope(request.headers()),
                )
                .allows(&project)
            }) || wb.authoring_chat_of_path(path).is_some_and(|chat| {
                // An edit chat names no project. An account session reaches
                // only the edit chats it may read — its own, of an Agent it
                // authors (DR-0453) — for a turn as for a read.
                crate::net_http::bearer(request.headers())
                    .and_then(|token| wb.resolve_account_session(token))
                    .is_some_and(|(account, _)| {
                        wb.authoring_chat_visible(&chat, Some(&account)) != Some(true)
                    })
            }))
    };
    if refused {
        return (
            axum::http::StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({ "error": "not in scope for this project" })),
        )
            .into_response();
    }
    next.run(request).await
}

#[cfg(test)]
#[path = "project_owner_tests.rs"]
pub(crate) mod tests;
