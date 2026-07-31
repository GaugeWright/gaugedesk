const COMMANDS: &[&str] = &[
    "get_identity",
    "get_launch_url",
    "sign_challenge",
    "store_machine_credential",
    "get_machine_credential",
    "clear_machine_credential",
];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .ios_path("ios")
        .build();
}
