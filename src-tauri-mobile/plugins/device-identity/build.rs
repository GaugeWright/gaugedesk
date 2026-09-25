const COMMANDS: &[&str] = &[
    "get_identity",
    "get_launch_url",
    "sign_challenge",
    "store_machine_credential",
    "get_machine_credential",
    "clear_machine_credential",
    "list_machine_credentials",
    "remove_machine_credential",
    "store_account_session",
    "get_account_session",
    "select_account_session",
    "clear_account_session",
];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .ios_path("ios")
        .build();
}
