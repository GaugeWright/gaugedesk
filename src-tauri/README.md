# gaugewright desktop shell (Tauri v2)

Packages the Solid workbench (`../web`) as a desktop app and starts the
co-resident control plane on loopback. The webview connects over **HTTP, not
Tauri IPC** (`app-stack.md`) — the same client is the web build and (later) the
remote client; Tauri is packaging + a window, not a second transport.

## Status

**Built and testable here.** The Rust shell, generated icons, configuration, and
capabilities are present, and the shell compiles against the backend
(`gaugedesk_app::open_api::open_serve`). A full interactive launch still needs
a windowed desktop session.

## Build / run (where the toolchain exists)

```
cargo install tauri-cli --version '^2'   # once
# add icons/icon.png (and platform icons) — `cargo tauri icon <png>` generates them
cargo tauri dev      # runs vite dev + the window + control plane
cargo tauri build    # bundles the app
```

It is deliberately **outside the backend cargo workspace** (the root `Cargo.toml`
excludes it) so `cargo test` over `crates/*` stays self-contained and green.
