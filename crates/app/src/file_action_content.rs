//! Initial/reload observation of a recorded native file, not Saved admission.
use super::*;

#[derive(serde::Serialize)]
pub struct NativeFileContentObservation {
    pub home: String,
    pub chat: String,
    pub path: String,
    pub cut: String,
    pub content: Option<String>,
    pub content_hash: Option<String>,
    pub observer: String,
    pub restrictions: Option<gaugedesk_whip_runtime::ResourcePolicy>,
}

impl Workbench {
    /// Capture one recorded head and disclose only its exact retained bytes.
    /// An unavailable/erased/opaque version never falls back to the checkout.
    /// This query creates no action, draft, policy or product Saved fact.
    pub fn observe_native_file_content(
        &mut self,
        context: &AuthenticatedActionContext,
        chat: &str,
        path: &str,
    ) -> Result<NativeFileContentObservation, String> {
        let home = self.home_id().clone();
        let (authority, basis) = self
            .store_ref()
            .read_for_dispatch(
                &[
                    LIBRARY_SCOPE,
                    ORG_SCOPE,
                    crate::account_auth::ACCOUNT_AUTH_SCOPE,
                    crate::mobile_machine_session::SCOPE,
                ],
                |store| {
                    current_target_authority(
                        store,
                        &home,
                        context,
                        &NativeTargetIntent {
                            chat_id: chat,
                            path,
                            request_id: "retained-file-observation",
                        },
                        NativeActionKind::InspectHistory,
                    )
                },
            )
            .map_err(|e| format!("file read authority refused: {e:?}"))?;
        let target = self
            .engagements
            .get(chat)
            .ok_or("chat workspace is unavailable")?
            .native_file_read_target(&authority.workspace_path)
            .map_err(|e| format!("{e:?}"))?;
        let basis = authority
            .bind_deadline(basis)
            .map_err(|e| format!("file read deadline refused: {e:?}"))?;
        let observer = self
            .store_ref()
            .read_only_sibling()
            .map_err(|e| format!("retained policy observer unavailable: {e:?}"))?;
        let key = SigningKey::from_seed(&self.governance_seed()).map_err(|e| e.reason)?;
        let root = GovernanceRootVerifier::new(self.authority().clone(), key.public_key());
        self.store_mut()
            .with_dispatch_basis(&basis, || {
                let mut restrictions = None;
                let content = target
                    .read_authorized_base(|branch, selected, cut| {
                        if branch != target.branch()
                            || selected != target.path()
                            || cut != target.base()
                        {
                            return Err(whipplescript_store::StoreError::Conflict(
                                "file read coordinates changed".into(),
                            ));
                        }
                        restrictions =
                            version_authority::original_policy(&target, &observer, cut, &root)?;
                        if let Some(source) = &restrictions {
                            version_authority::authorize_reader(&authority, source)
                                .map_err(whipplescript_store::StoreError::Conflict)?;
                        }
                        Ok(())
                    })
                    .map_err(|e| format!("{e:?}"))?;
                if content.as_ref().is_some_and(|body| {
                    body.len() > crate::engagement_routes::MAX_VIEWABLE_FILE_BYTES
                }) {
                    return Err("retained content exceeds the viewer limit".into());
                }
                Ok(NativeFileContentObservation {
                    home: home.as_str().into(),
                    chat: chat.into(),
                    path: path.into(),
                    cut: target.base().into(),
                    content_hash: content.as_deref().map(whipplescript_store::stable_hash_hex),
                    content,
                    observer: context.actor().as_str().into(),
                    restrictions,
                })
            })
            .map_err(|e| format!("file read authority changed: {e:?}"))?
    }
}
