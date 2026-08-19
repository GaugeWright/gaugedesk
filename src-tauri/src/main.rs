//! gaugewright desktop shell (Tauri v2).
//!
//! One coherent workbench (`app-stack.md`): Tauri hosts the Solid island, and a
//! **co-resident control plane** runs on loopback. The webview talks to it over
//! **HTTP, not Tauri IPC** — so the exact same client works as a browser/web
//! build and (later) against a remote. Tauri here is packaging + a window, not a
//! second transport.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::Manager;
use tauri_plugin_deep_link::DeepLinkExt;

/// The signed updater installs files but deliberately does not decide when to
/// restart. The workbench invokes this only after an admitted update finishes.
#[tauri::command]
fn restart_app(app: tauri::AppHandle) {
    app.restart();
}

/// Open a URL in the person's **default browser** (LOGIN-7). The webview drops
/// `window.open` silently, and account sign-in must happen in the system
/// browser — never an embedded webview (ADR 0123, rejected there because it is
/// phishable and IdPs block it). Only web schemes: the webview must not be able
/// to launch arbitrary local handlers through this seam.
#[tauri::command]
fn open_external(app: tauri::AppHandle, url: String) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    external_open_allowed(&url)?;
    app.opener()
        .open_url(url, None::<&str>)
        .map_err(|e| e.to_string())
}

/// Whether the shell will hand `url` to the OS default browser: exactly the web
/// schemes, decided on a *parsed* URL rather than a string prefix, so anything
/// that does not parse to an http(s) place is refused rather than guessed at.
/// Pure in its input → unit-testable without a window.
fn external_open_allowed(url: &str) -> Result<(), String> {
    let parsed = tauri::Url::parse(url).map_err(|e| format!("not a URL: {e}"))?;
    match parsed.scheme() {
        "http" | "https" => Ok(()),
        other => Err(format!("refusing to open a {other}: URL in the browser")),
    }
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![restart_app, open_external])
        // LOGIN-7: the system-browser opener behind `open_external`. Sign-in and
        // "manage in the Hub" leave through it; the webview itself cannot open
        // anything (its `window.open` is a silent no-op).
        .plugin(tauri_plugin_opener::init())
        // FED-7: a `gaugewright://` invite link should reach the RUNNING app, not spawn a
        // duplicate. single-instance MUST be registered first; on Linux/Windows a deep link
        // launches a second instance whose argv carries the URL — focus the existing window and
        // forward that URL into it. macOS delivers to the running instance via `on_open_url`.
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.set_focus();
            }
            if let Some(url) = deep_link_from_argv(&argv) {
                forward_deep_link(app, &url);
            }
        }))
        // Native OS folder picker for "add files" (the webview opens a real
        // folder browser; the chosen absolute path is ingested over HTTP).
        .plugin(tauri_plugin_dialog::init())
        // The signed updater verifies GitHub Release artifacts against the public
        // key in tauri.conf.json. The workbench owns discovery and consent so it
        // can also apply an organization's allowed release channels.
        .plugin(tauri_plugin_updater::Builder::new().build())
        // FED-7: register the `gaugewright://` scheme (schemes declared in tauri.conf.json
        // `plugins.deep-link`), so the OS routes invite links to this app.
        .plugin(tauri_plugin_deep_link::init())
        .setup(|app| {
            // Spawn-vs-connect (DEPLOY-5): the **solo** shell spawns a co-resident control
            // plane; an **enterprise** deployment that names an org control plane
            // (`GAUGEDESK_ORG_CP`) skips the spawn — the webview connects to that org CP
            // through its own DEPLOY-5 seam (the persisted endpoint / `?cp=`). One shell,
            // two runtime configs.
            // ENTSEC-8 (ADR 0065) fail-loud guard: an enterprise/thin install pins
            // `GAUGEDESK_REQUIRE_ORG_CP=1`. If it is set but no org CP is configured, refuse to
            // silently fall back to spawning a co-resident on-disk store (which would write the
            // client's data — db, workspaces, transcripts — onto the consultant's unmanaged
            // endpoint, the exact leak thin mode exists to prevent). Hard-exit with a clear
            // operator message instead of degrading open.
            let org_cp = gaugedesk_app::var("ORG_CP");
            let require_org_cp = gaugedesk_app::var("REQUIRE_ORG_CP").as_deref() == Some("1");
            let decision =
                cp_launch_decision(org_cp.as_deref(), require_org_cp).unwrap_or_else(|msg| {
                    eprintln!("[gaugewright] FATAL: {msg}");
                    std::process::exit(1);
                });
            match decision {
                Some(bind) => {
                    // Start the control plane in the background before the window is
                    // interactive. Both stores live under the OS app-data dir
                    // (cwd `.gaugewright` in dev), resolved by the workspace crate.
                    std::thread::spawn(move || {
                        let root = open_control_plane_root();
                        let rt = tokio::runtime::Builder::new_multi_thread()
                            .enable_all()
                            .build()
                            .expect("tokio runtime");
                        rt.block_on(async move {
                            if let Err(e) = gaugedesk_app::open_api::open_serve(bind, &root).await
                            {
                                eprintln!("control plane exited: {e}");
                            }
                        });
                    });
                }
                None => {
                    // Enterprise: no co-resident control plane; the webview talks to the
                    // enrolled org control plane. Its endpoint is injected below as a
                    // document-start script before the first page parses (DEPLOY-5).
                    eprintln!("enterprise mode: connecting to the enrolled org control plane");
                }
            }

            // DEPLOY-5 first-load correctness: `tauri.conf.json` marks the main window
            // `create: false`, so setup owns its construction. Add the enterprise endpoint
            // seed as a Tauri initialization script: it runs after the JS global exists but
            // before the HTML document is parsed, so the web app's first
            // `resolveControlPlaneBase` call observes `gw.cp` without a refresh. Solo builds
            // add no script and retain the configured co-resident default.
            let window_config = app
                .config()
                .app
                .windows
                .iter()
                .find(|window| window.label == "main")
                .ok_or("tauri.conf.json is missing the main window")?;
            let mut window = tauri::WebviewWindowBuilder::from_config(app, window_config)?;
            if let Some(script) = webview_org_cp_script(org_cp.as_deref()) {
                window = window.initialization_script(script);
            }
            window.build()?;

            // FED-7: an OS-delivered `gaugewright://` link arrives here — on cold start (the link
            // launched the app) on every OS, and on the running app on macOS. Hand each URL to the
            // web client, which routes an `gaugewright://invite` into the same consent flow as a
            // pasted link. (The running-app case on Linux/Windows is handled by single-instance.)
            {
                let handle = app.handle().clone();
                app.deep_link().on_open_url(move |event| {
                    for url in event.urls() {
                        forward_deep_link(&handle, url.as_str());
                    }
                });
            }

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running gaugewright desktop");
}

fn open_control_plane_root() -> std::path::PathBuf {
    // Delegate to the workspace resolver (GAUGEDESK_ROOT → OS app-data dir →
    // `./.gaugewright`), which is the unit-tested source of truth. src-tauri sits
    // outside the cargo workspace, so this thin wrapper is not cargo-tested.
    gaugedesk_app::open_api::open_control_plane_root()
}

/// The co-resident control-plane bind address, or `None` when the shell should **not** spawn
/// one (DEPLOY-5). Solo → `Some(127.0.0.1:7878)`; an enterprise deployment that names an org
/// control plane (a non-empty `GAUGEDESK_ORG_CP`) → `None`, so the webview connects to that
/// org CP instead. Pure in its input, so the spawn-vs-connect decision is unit-testable.
fn local_cp_bind(org_cp: Option<&str>) -> Option<&'static str> {
    match org_cp {
        Some(s) if !s.trim().is_empty() => None,
        _ => Some("127.0.0.1:7878"),
    }
}

/// The spawn-vs-connect decision with the `ENTSEC-8` fail-loud guard. Normally this is just
/// [`local_cp_bind`]: solo spawns a local CP, an enterprise install (a named `GAUGEDESK_ORG_CP`)
/// connects to it. But when the install is **pinned to thin/enterprise** mode
/// (`require_org_cp`, from `GAUGEDESK_REQUIRE_ORG_CP=1`) and no org CP is configured, this
/// returns `Err` rather than silently spawning a co-resident on-disk store — so a misconfigured
/// launch fails loudly instead of leaking the client's data onto the consultant's endpoint. Pure
/// in its inputs, so the guard is unit-testable without env/Tauri.
fn cp_launch_decision(
    org_cp: Option<&str>,
    require_org_cp: bool,
) -> Result<Option<&'static str>, String> {
    let thin = matches!(org_cp, Some(s) if !s.trim().is_empty());
    if require_org_cp && !thin {
        return Err(
            "GAUGEDESK_REQUIRE_ORG_CP=1 but GAUGEDESK_ORG_CP is unset/empty — refusing to spawn \
             a local on-disk store (thin-client mode was required). Set GAUGEDESK_ORG_CP to the \
             org control plane, or unset GAUGEDESK_REQUIRE_ORG_CP to run solo."
                .to_string(),
        );
    }
    Ok(local_cp_bind(org_cp))
}

/// The webview **init script** that seeds the enrolled org control-plane endpoint (DEPLOY-5):
/// it persists `org_cp` under the `gw.cp` localStorage key the web client's
/// `resolveControlPlaneBase` reads, so the enterprise webview connects to the org CP. `None`
/// for solo (no/empty `GAUGEDESK_ORG_CP`), so the solo path injects nothing. The URL is
/// JSON-escaped, so an operator-configured endpoint cannot break out of the string. Pure in its
/// input → the produced script (and the key it writes) is unit-testable without a window.
fn webview_org_cp_script(org_cp: Option<&str>) -> Option<String> {
    let url = org_cp.map(str::trim).filter(|s| !s.is_empty())?;
    // serde_json::to_string yields a safely-quoted JS string literal (escapes quotes/backslashes).
    let lit = serde_json::to_string(url).ok()?;
    Some(format!(
        "try {{ window.localStorage.setItem('gw.cp', {lit}); }} catch (e) {{}}"
    ))
}

/// Hand an OS-delivered `gaugewright://` deep link to the web client (FED-7) by dispatching a
/// `gw-deep-link` DOM CustomEvent on the main window. A plain DOM event — not Tauri IPC — so the
/// shared web client stays transport-agnostic (a browser build simply never receives one); the
/// frontend routes the URL into the same invite-decode path as a pasted link.
fn forward_deep_link(app: &tauri::AppHandle, url: &str) {
    if let (Some(script), Some(w)) = (
        deep_link_dispatch_script(url),
        app.get_webview_window("main"),
    ) {
        let _ = w.eval(&script);
    }
}

/// The first `gaugewright://` URL in a process argv (FED-7): on Linux/Windows a deep link
/// launches a second instance with the URL as an argument, which single-instance forwards to the
/// running app. Pure in its input → unit-testable without a process.
fn deep_link_from_argv(argv: &[String]) -> Option<String> {
    argv.iter()
        .find(|a| a.starts_with("gaugewright://"))
        .cloned()
}

/// The webview init script that dispatches a `gw-deep-link` CustomEvent carrying `url` (FED-7).
/// JSON-escaped (via `serde_json`) so a crafted URL cannot break out of the string literal.
/// Pure in its input → the produced script is unit-testable without a window.
fn deep_link_dispatch_script(url: &str) -> Option<String> {
    let lit = serde_json::to_string(url).ok()?;
    Some(format!(
        "try {{ window.dispatchEvent(new CustomEvent('gw-deep-link', {{ detail: {lit} }})); }} catch (e) {{}}"
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        cp_launch_decision, deep_link_dispatch_script, deep_link_from_argv,
        external_open_allowed, local_cp_bind, webview_org_cp_script,
    };

    #[test]
    fn external_open_allows_exactly_the_web_schemes() {
        // LOGIN-7: the sign-in URL and the Hub are web places; both forms pass.
        assert!(external_open_allowed("https://hub.gaugewright.com/auth/login?k=v").is_ok());
        assert!(external_open_allowed("http://localhost:7443/").is_ok());
    }

    #[test]
    fn external_open_refuses_everything_that_is_not_a_web_url() {
        // A local handler launch (file:, mailto:, a custom scheme) must not be
        // reachable from the webview through this seam.
        assert!(external_open_allowed("file:///etc/passwd").is_err());
        assert!(external_open_allowed("mailto:a@b.c").is_err());
        assert!(external_open_allowed("gaugewright://invite?d=ab").is_err());
        // Not a URL at all — parsed, not prefix-matched.
        assert!(external_open_allowed("//scheme-relative.example").is_err());
        assert!(external_open_allowed("not a url").is_err());
        assert!(external_open_allowed("").is_err());
    }

    #[test]
    fn solo_spawns_the_co_resident_control_plane() {
        // No org CP configured (or an empty one) → solo: spawn the co-resident CP.
        assert_eq!(local_cp_bind(None), Some("127.0.0.1:7878"));
        assert_eq!(local_cp_bind(Some("")), Some("127.0.0.1:7878"));
        assert_eq!(local_cp_bind(Some("   ")), Some("127.0.0.1:7878"));
    }

    #[test]
    fn enterprise_skips_the_spawn_and_connects_to_the_org_cp() {
        // A named org control plane → enterprise: no co-resident spawn.
        assert_eq!(local_cp_bind(Some("https://cp.acme.example")), None);
    }

    #[test]
    fn require_org_cp_fails_loud_when_no_org_cp_is_configured() {
        // ENTSEC-8: pinned-thin install + no org CP → refuse, do NOT fall back to a local store.
        let err = cp_launch_decision(None, true).unwrap_err();
        assert!(
            err.contains("GAUGEDESK_ORG_CP"),
            "names the missing var: {err}"
        );
        assert!(cp_launch_decision(Some(""), true).is_err());
        assert!(cp_launch_decision(Some("   "), true).is_err());
    }

    #[test]
    fn require_org_cp_with_a_configured_cp_connects_thin() {
        // Pinned-thin AND an org CP configured → connect (no local spawn).
        assert_eq!(
            cp_launch_decision(Some("https://cp.acme.example"), true).unwrap(),
            None
        );
    }

    #[test]
    fn without_the_pin_the_decision_is_unchanged_solo_or_thin() {
        // No pin → the existing behavior: solo spawns, a named org CP connects.
        assert_eq!(
            cp_launch_decision(None, false).unwrap(),
            Some("127.0.0.1:7878")
        );
        assert_eq!(
            cp_launch_decision(Some(""), false).unwrap(),
            Some("127.0.0.1:7878")
        );
        assert_eq!(
            cp_launch_decision(Some("https://cp.acme.example"), false).unwrap(),
            None
        );
    }

    #[test]
    fn solo_seeds_no_org_cp_endpoint() {
        // DEPLOY-5: nothing injected on the solo path (the client uses the solo default).
        assert_eq!(webview_org_cp_script(None), None);
        assert_eq!(webview_org_cp_script(Some("")), None);
        assert_eq!(webview_org_cp_script(Some("   ")), None);
    }

    #[test]
    fn enterprise_seeds_the_org_cp_into_the_gw_cp_key() {
        // The injected script persists the endpoint under the exact key the web seam reads.
        let script = webview_org_cp_script(Some("https://cp.acme.example")).unwrap();
        assert!(script.contains("window.localStorage.setItem('gw.cp'"));
        assert!(script.contains("\"https://cp.acme.example\""));
    }

    #[test]
    fn the_seeded_endpoint_is_json_escaped_against_breakout() {
        // The value is wrapped in a double-quoted JS string literal, so a double-quote in the
        // endpoint must be escaped (else it could break out). serde_json does this.
        let script = webview_org_cp_script(Some("https://x\"+alert(1)+\"y")).unwrap();
        assert!(script.contains("setItem('gw.cp'"));
        // The embedded double-quotes are backslash-escaped, not left to close the literal early.
        assert!(script.contains("x\\\"+alert(1)+\\\"y"));
    }

    #[test]
    fn deep_link_from_argv_finds_the_scheme() {
        // FED-7: single-instance receives a second launch's argv; the deep link is the arg
        // starting with the app scheme (else None — an ordinary launch).
        assert_eq!(
            deep_link_from_argv(&["gaugedesk".into(), "gaugewright://invite?d=ab".into()]),
            Some("gaugewright://invite?d=ab".to_string())
        );
        assert_eq!(
            deep_link_from_argv(&["gaugedesk".into(), "--some-flag".into()]),
            None
        );
        assert_eq!(deep_link_from_argv(&[]), None);
    }

    #[test]
    fn deep_link_dispatch_script_dispatches_the_event() {
        let script = deep_link_dispatch_script("gaugewright://invite?d=ab").unwrap();
        assert!(script.contains("gw-deep-link"));
        assert!(script.contains("\"gaugewright://invite?d=ab\""));
    }

    #[test]
    fn deep_link_dispatch_script_is_json_escaped_against_breakout() {
        // A crafted URL with a double-quote must be escaped, not left to close the literal early.
        let script = deep_link_dispatch_script("gaugewright://x\");evil()//").unwrap();
        assert!(script.contains("gw-deep-link"));
        assert!(script.contains("x\\\");evil()//"));
    }
}
