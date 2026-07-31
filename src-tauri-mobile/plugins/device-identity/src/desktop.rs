use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Runtime};

use crate::{
    AccountSessionResponse, ChallengeSignature, DeviceIdentity, LaunchUrlResponse,
    MachineCredentialRegistryResponse, MachineCredentialResponse, RemoveMachineCredentialRequest,
    SignChallengeRequest, StoreAccountSessionRequest, StoreMachineCredentialRequest,
};

pub fn init<R: Runtime, C: DeserializeOwned>(
    app: &AppHandle<R>,
    _api: PluginApi<R, C>,
) -> crate::Result<DeviceIdentityPlugin<R>> {
    Ok(DeviceIdentityPlugin(app.clone()))
}

pub struct DeviceIdentityPlugin<R: Runtime>(#[allow(dead_code)] AppHandle<R>);

impl<R: Runtime> DeviceIdentityPlugin<R> {
    pub async fn get_identity(&self) -> crate::Result<DeviceIdentity> {
        Err(crate::Error::UnsupportedPlatform)
    }

    pub async fn get_launch_url(&self) -> crate::Result<LaunchUrlResponse> {
        Err(crate::Error::UnsupportedPlatform)
    }

    pub async fn sign_challenge(
        &self,
        _payload: SignChallengeRequest,
    ) -> crate::Result<ChallengeSignature> {
        Err(crate::Error::UnsupportedPlatform)
    }

    pub async fn store_machine_credential(
        &self,
        _payload: StoreMachineCredentialRequest,
    ) -> crate::Result<()> {
        Err(crate::Error::UnsupportedPlatform)
    }

    pub async fn get_machine_credential(&self) -> crate::Result<MachineCredentialResponse> {
        Err(crate::Error::UnsupportedPlatform)
    }

    pub async fn clear_machine_credential(&self) -> crate::Result<()> {
        Err(crate::Error::UnsupportedPlatform)
    }

    pub async fn list_machine_credentials(
        &self,
    ) -> crate::Result<MachineCredentialRegistryResponse> {
        Err(crate::Error::UnsupportedPlatform)
    }

    pub async fn remove_machine_credential(
        &self,
        _payload: RemoveMachineCredentialRequest,
    ) -> crate::Result<()> {
        Err(crate::Error::UnsupportedPlatform)
    }

    pub async fn store_account_session(
        &self,
        _payload: StoreAccountSessionRequest,
    ) -> crate::Result<()> {
        Err(crate::Error::UnsupportedPlatform)
    }

    pub async fn get_account_session(&self) -> crate::Result<AccountSessionResponse> {
        Err(crate::Error::UnsupportedPlatform)
    }

    pub async fn clear_account_session(&self) -> crate::Result<()> {
        Err(crate::Error::UnsupportedPlatform)
    }
}
