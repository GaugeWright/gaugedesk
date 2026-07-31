use tauri::{command, AppHandle, Runtime};

use crate::{
    AccountSessionResponse, ChallengeSignature, DeviceIdentity, DeviceIdentityExt,
    LaunchUrlResponse, MachineCredentialRegistryResponse, MachineCredentialResponse,
    RemoveMachineCredentialRequest, Result, SignChallengeRequest, StoreAccountSessionRequest,
    StoreMachineCredentialRequest,
};

#[command]
pub(crate) async fn get_identity<R: Runtime>(app: AppHandle<R>) -> Result<DeviceIdentity> {
    app.device_identity().get_identity().await
}

#[command]
pub(crate) async fn get_launch_url<R: Runtime>(app: AppHandle<R>) -> Result<LaunchUrlResponse> {
    app.device_identity().get_launch_url().await
}

#[command]
pub(crate) async fn sign_challenge<R: Runtime>(
    app: AppHandle<R>,
    payload: SignChallengeRequest,
) -> Result<ChallengeSignature> {
    app.device_identity().sign_challenge(payload).await
}

#[command]
pub(crate) async fn store_machine_credential<R: Runtime>(
    app: AppHandle<R>,
    payload: StoreMachineCredentialRequest,
) -> Result<()> {
    app.device_identity()
        .store_machine_credential(payload)
        .await
}

#[command]
pub(crate) async fn get_machine_credential<R: Runtime>(
    app: AppHandle<R>,
) -> Result<MachineCredentialResponse> {
    app.device_identity().get_machine_credential().await
}

#[command]
pub(crate) async fn clear_machine_credential<R: Runtime>(app: AppHandle<R>) -> Result<()> {
    app.device_identity().clear_machine_credential().await
}

#[command]
pub(crate) async fn list_machine_credentials<R: Runtime>(
    app: AppHandle<R>,
) -> Result<MachineCredentialRegistryResponse> {
    app.device_identity().list_machine_credentials().await
}

#[command]
pub(crate) async fn remove_machine_credential<R: Runtime>(
    app: AppHandle<R>,
    payload: RemoveMachineCredentialRequest,
) -> Result<()> {
    app.device_identity()
        .remove_machine_credential(payload)
        .await
}

#[command]
pub(crate) async fn store_account_session<R: Runtime>(
    app: AppHandle<R>,
    payload: StoreAccountSessionRequest,
) -> Result<()> {
    app.device_identity().store_account_session(payload).await
}

#[command]
pub(crate) async fn get_account_session<R: Runtime>(
    app: AppHandle<R>,
) -> Result<AccountSessionResponse> {
    app.device_identity().get_account_session().await
}

#[command]
pub(crate) async fn clear_account_session<R: Runtime>(app: AppHandle<R>) -> Result<()> {
    app.device_identity().clear_account_session().await
}
