use serde::de::DeserializeOwned;
use tauri::{
    plugin::{PluginApi, PluginHandle},
    AppHandle, Runtime,
};

use crate::{
    AccountSessionResponse, ChallengeSignature, DeviceIdentity, LaunchUrlResponse,
    MachineCredentialRegistryResponse, MachineCredentialResponse, RemoveMachineCredentialRequest,
    SignChallengeRequest, StoreAccountSessionRequest, StoreMachineCredentialRequest,
};

#[cfg(target_os = "ios")]
tauri::ios_plugin_binding!(init_plugin_gaugedesk_device_identity);

pub fn init<R: Runtime, C: DeserializeOwned>(
    _app: &AppHandle<R>,
    api: PluginApi<R, C>,
) -> crate::Result<DeviceIdentityPlugin<R>> {
    #[cfg(target_os = "android")]
    let handle = api.register_android_plugin(
        "com.gaugewright.gaugedesk.deviceidentity",
        "DeviceIdentityPlugin",
    )?;
    #[cfg(target_os = "ios")]
    let handle = api.register_ios_plugin(init_plugin_gaugedesk_device_identity)?;
    Ok(DeviceIdentityPlugin(handle))
}

pub struct DeviceIdentityPlugin<R: Runtime>(PluginHandle<R>);

impl<R: Runtime> DeviceIdentityPlugin<R> {
    pub async fn get_identity(&self) -> crate::Result<DeviceIdentity> {
        self.0
            .run_mobile_plugin_async("getIdentity", ())
            .await
            .map_err(Into::into)
    }

    pub async fn get_launch_url(&self) -> crate::Result<LaunchUrlResponse> {
        self.0
            .run_mobile_plugin_async("getLaunchUrl", ())
            .await
            .map_err(Into::into)
    }

    pub async fn sign_challenge(
        &self,
        payload: SignChallengeRequest,
    ) -> crate::Result<ChallengeSignature> {
        self.0
            .run_mobile_plugin_async("signChallenge", payload)
            .await
            .map_err(Into::into)
    }

    pub async fn store_machine_credential(
        &self,
        payload: StoreMachineCredentialRequest,
    ) -> crate::Result<()> {
        self.0
            .run_mobile_plugin_async("storeMachineCredential", payload)
            .await
            .map_err(Into::into)
    }

    pub async fn get_machine_credential(&self) -> crate::Result<MachineCredentialResponse> {
        self.0
            .run_mobile_plugin_async("getMachineCredential", ())
            .await
            .map_err(Into::into)
    }

    pub async fn clear_machine_credential(&self) -> crate::Result<()> {
        self.0
            .run_mobile_plugin_async("clearMachineCredential", ())
            .await
            .map_err(Into::into)
    }

    pub async fn list_machine_credentials(
        &self,
    ) -> crate::Result<MachineCredentialRegistryResponse> {
        self.0
            .run_mobile_plugin_async("listMachineCredentials", ())
            .await
            .map_err(Into::into)
    }

    pub async fn remove_machine_credential(
        &self,
        payload: RemoveMachineCredentialRequest,
    ) -> crate::Result<()> {
        self.0
            .run_mobile_plugin_async("removeMachineCredential", payload)
            .await
            .map_err(Into::into)
    }

    pub async fn store_account_session(
        &self,
        payload: StoreAccountSessionRequest,
    ) -> crate::Result<()> {
        self.0
            .run_mobile_plugin_async("storeAccountSession", payload)
            .await
            .map_err(Into::into)
    }

    pub async fn get_account_session(&self) -> crate::Result<AccountSessionResponse> {
        self.0
            .run_mobile_plugin_async("getAccountSession", ())
            .await
            .map_err(Into::into)
    }

    pub async fn clear_account_session(&self) -> crate::Result<()> {
        self.0
            .run_mobile_plugin_async("clearAccountSession", ())
            .await
            .map_err(Into::into)
    }
}
