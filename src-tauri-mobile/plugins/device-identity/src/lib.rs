use tauri::{
    plugin::{Builder, TauriPlugin},
    Manager, Runtime,
};

mod commands;
#[cfg(desktop)]
mod desktop;
mod error;
#[cfg(mobile)]
mod mobile;
mod models;

pub use error::{Error, Result};
pub use models::*;

#[cfg(desktop)]
use desktop::DeviceIdentityPlugin;
#[cfg(mobile)]
use mobile::DeviceIdentityPlugin;

pub trait DeviceIdentityExt<R: Runtime> {
    fn device_identity(&self) -> &DeviceIdentityPlugin<R>;
}

impl<R: Runtime, T: Manager<R>> DeviceIdentityExt<R> for T {
    fn device_identity(&self) -> &DeviceIdentityPlugin<R> {
        self.state::<DeviceIdentityPlugin<R>>().inner()
    }
}

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("gaugedesk-device-identity")
        .invoke_handler(tauri::generate_handler![
            commands::get_identity,
            commands::get_launch_url,
            commands::sign_challenge,
            commands::store_machine_credential,
            commands::get_machine_credential,
            commands::clear_machine_credential,
            commands::list_machine_credentials,
            commands::remove_machine_credential,
            commands::store_account_session,
            commands::get_account_session,
            commands::clear_account_session
        ])
        .setup(|app, api| {
            #[cfg(mobile)]
            let identity = mobile::init(app, api)?;
            #[cfg(desktop)]
            let identity = desktop::init(app, api)?;
            app.manage(identity);
            Ok(())
        })
        .build()
}
