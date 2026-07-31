//! GaugeDesk native mobile shell.
//!
//! Mobile is a projection client: this crate owns the native webview and
//! platform integrations, but it never starts a co-resident GaugeDesk control
//! plane and never becomes project or transcript authority.

mod relay;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default();
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let builder = builder.plugin(tauri_plugin_barcode_scanner::init());

    builder
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_gaugedesk_device_identity::init())
        .manage(relay::RelayManager::default())
        .invoke_handler(tauri::generate_handler![
            relay::ensure_relay_route,
            relay::close_relay_route,
            relay::close_all_relay_routes,
        ])
        .run(tauri::generate_context!())
        .expect("error while running GaugeDesk mobile");
}
