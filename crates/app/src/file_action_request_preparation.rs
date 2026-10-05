//! Original save coordinates, retained by the caller before submitting intent.
use super::*;

/// Coordinates, not admission evidence or permission. The Home is retained
/// beside the runtime identity so recovery does not follow a moved project.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EditorFileSaveRequestIdentity {
    pub home: String,
    pub issuer: String,
    pub scope: String,
    pub request_id: String,
}

impl EditorFileSaveRequestIdentity {
    pub fn as_request(&self) -> EditorFileSaveRequest<'_> {
        EditorFileSaveRequest {
            issuer: &self.issuer,
            scope: &self.scope,
            request_id: &self.request_id,
        }
    }
}

pub(super) fn identity(
    home: &str,
    issuer: &str,
    project: &str,
    chat: &str,
    request_id: &str,
) -> Result<EditorFileSaveRequestIdentity, String> {
    Ok(EditorFileSaveRequestIdentity {
        home: home.into(),
        issuer: issuer.into(),
        scope: serde_json::to_string(&("gaugedesk.editor-file.v1", project, chat))
            .map_err(|error| error.to_string())?,
        request_id: request_id.into(),
    })
}

impl Workbench {
    /// Prepare original coordinates before submission. This may initialize
    /// project signing custody under current authority, but retains no intent,
    /// policy or input. A lost response permits another preparation; once intent
    /// may have been submitted its retained identity must be investigated.
    pub fn prepare_editor_file_save_request(
        &mut self,
        context: &AuthenticatedActionContext,
        chat_id: &str,
        path: &str,
        request_id: &str,
    ) -> Result<EditorFileSaveRequestIdentity, String> {
        let home = self.home_id().clone();
        let account_scopes = account_authority_scopes(context)?;
        let (authority, basis) = self
            .store_ref()
            .read_for_dispatch(
                &[
                    LIBRARY_SCOPE,
                    ORG_SCOPE,
                    crate::account_auth::ACCOUNT_AUTH_SCOPE,
                    &account_scopes[0],
                    &account_scopes[1],
                    crate::mobile_machine_session::SCOPE,
                ],
                |store| {
                    current_target_authority(
                        store,
                        &home,
                        context,
                        &NativeTargetIntent {
                            chat_id,
                            request_id,
                            path,
                        },
                        NativeActionKind::FileSave,
                    )
                },
            )
            .map_err(|error| format!("file request authority refused: {error:?}"))?;
        crate::federation::require_project_writes_available(
            self.store_ref(),
            &authority.project_id,
        )
        .map_err(|e| format!("file request preparation paused: {e:?}"))?;
        let basis = authority
            .bind_deadline(basis)
            .map_err(|error| format!("file request deadline refused: {error:?}"))?;
        let (key, basis) = self.native_project_signer(&authority.project_id, basis)?;
        let issuer = crate::project_authority::authority(&key.public_key());
        let original = identity(
            home.as_str(),
            issuer.as_str(),
            &authority.project_id,
            chat_id,
            request_id,
        )?;
        self.store_mut()
            .with_dispatch_basis(&basis, || original)
            .map_err(|error| format!("file request authority changed: {error:?}"))
    }
}
