//! Operating-system notifications for chats (DR-0266).
//!
//! The page decides which chats to notify for and what to say: it reads the
//! Home's notices and the person's preference for this device. The shell only
//! shows the notification. A click brings the window forward and hands the
//! chat back to the page as a plain `gw-chat-notification` event — the same
//! carriage a deep link takes, but not a link, so nothing outside the app can
//! raise it. The page then opens the chat through its ordinary selection,
//! with the same admission a click in the navigator gets.

#[cfg(not(target_os = "macos"))]
use std::sync::atomic::AtomicUsize;

/// The page event a clicked notification dispatches.
const CLICK_EVENT: &str = "gw-chat-notification";
const MAX_CHAT_ID: usize = 256;
const MAX_TITLE: usize = 120;
const MAX_BODY: usize = 240;

/// Off macOS, how many notifications may wait for a click at once. Waiting
/// holds a thread until the notification is clicked or dismissed, and one the
/// person leaves in the notification centre is never dismissed, so past this
/// many a notification is still shown but a click on it only activates the app.
#[cfg(not(target_os = "macos"))]
const MAX_WAITING: usize = 16;
#[cfg(not(target_os = "macos"))]
static WAITING: AtomicUsize = AtomicUsize::new(0);

/// A notification the page asked for, bounded before it reaches the OS.
#[derive(Debug, PartialEq, Eq)]
pub struct ChatNotification {
    chat: String,
    title: String,
    body: String,
}

impl ChatNotification {
    /// Refuses a missing or implausible chat id; clips the words and strips
    /// control characters, since the page is the only author and a long title
    /// is truncated by every OS anyway. Pure in its input.
    pub fn new(chat: String, title: String, body: String) -> Result<Self, String> {
        let chat = chat.trim();
        if chat.is_empty() || chat.len() > MAX_CHAT_ID || chat.chars().any(char::is_control) {
            return Err("not a chat id".into());
        }
        Ok(Self {
            chat: chat.to_owned(),
            title: clip(&title, MAX_TITLE, "GaugeDesk"),
            body: clip(&body, MAX_BODY, ""),
        })
    }
}

fn clip(text: &str, max: usize, empty: &str) -> String {
    let text: String = text.chars().filter(|c| !c.is_control()).collect();
    let text = text.trim();
    if text.is_empty() {
        return empty.to_owned();
    }
    if text.chars().count() <= max {
        return text.to_owned();
    }
    let mut clipped: String = text.chars().take(max - 1).collect();
    clipped.push('…');
    clipped
}

/// The script that hands a clicked notification's chat to the page, the id
/// JSON-escaped so it cannot close the literal early.
fn click_script(chat: &str) -> Option<String> {
    let lit = serde_json::to_string(chat).ok()?;
    Some(format!(
        "try {{ window.dispatchEvent(new CustomEvent('{CLICK_EVENT}', {{ detail: {lit} }})); }} catch (e) {{}}"
    ))
}

fn open_chat(app: &tauri::AppHandle, chat: &str) {
    use tauri::Manager;
    crate::show_workbench(app);
    if let (Some(script), Some(window)) = (click_script(chat), app.get_webview_window("main")) {
        let _ = window.eval(&script);
    }
}

/// Show `request` and open its chat when it is clicked. Returns at once.
pub fn post(app: &tauri::AppHandle, request: ChatNotification) {
    #[cfg(target_os = "macos")]
    macos::post(app, request);
    #[cfg(not(target_os = "macos"))]
    freedesktop_or_windows::post(app, request);
}

/// macOS posts through `UNUserNotificationCenter`. The older
/// `NSUserNotificationCenter`, which Tauri's plugin and `notify-rust` use by
/// default, still shows a banner on macOS 26 but reports neither its delivery
/// nor a click on it, so a notification posted there could never open its
/// chat. The newer centre needs a bundled app: an unbundled development build
/// shows no notification at all rather than crash.
#[cfg(target_os = "macos")]
mod macos {
    use super::{open_chat, ChatNotification};
    use std::collections::BTreeMap;
    use std::sync::atomic::AtomicU64;
    use std::sync::Mutex;

    static NEXT: AtomicU64 = AtomicU64::new(0);
    /// Each chat's newest notification, so the next one can withdraw it.
    static LATEST: Mutex<BTreeMap<String, String>> = Mutex::new(BTreeMap::new());

    pub fn post(app: &tauri::AppHandle, request: ChatNotification) {
        if mac_usernotifications::check_bundle().is_err() {
            static SAID: std::sync::Once = std::sync::Once::new();
            SAID.call_once(|| {
                eprintln!("chat notifications need the bundled app; this build shows none")
            });
            return;
        }
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            // macOS asks the person once, the first time; afterwards this
            // answers at once with what they chose.
            match mac_usernotifications::request_auth().await {
                Ok(true) => {}
                Ok(false) => return,
                Err(error) => {
                    eprintln!("could not ask to show notifications: {error}");
                    return;
                }
            }
            // One notification per chat, each shown as a banner. macOS updates
            // a delivered notification that is sent again under its identifier
            // without showing a banner, so each gets a fresh identifier and the
            // chat's previous one is withdrawn instead.
            let id = format!(
                "gaugedesk-chat:{}:{}",
                request.chat,
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            );
            let previous = LATEST
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(request.chat.clone(), id.clone());
            if let Some(previous) = previous {
                mac_usernotifications::close_delivered(&previous).await;
            }
            let sent = mac_usernotifications::Notification::new()
                .title(&request.title)
                .message(&request.body)
                .id(&id)
                .send()
                .await;
            let handle = match sent {
                Ok(handle) => handle,
                Err(error) => {
                    eprintln!("could not show a notification: {error}");
                    return;
                }
            };
            // Resolves when the notification is clicked or leaves the
            // notification centre; waiting holds no thread.
            if handle
                .response()
                .await
                .is_ok_and(|response| response.is_default_action())
            {
                open_chat(&app, &request.chat);
            }
        });
    }
}

#[cfg(not(target_os = "macos"))]
mod freedesktop_or_windows {
    use super::{open_chat, ChatNotification, MAX_WAITING, WAITING};
    use std::sync::atomic::Ordering;

    pub fn post(app: &tauri::AppHandle, request: ChatNotification) {
        let mut notification = notify_rust::Notification::new();
        notification.summary(&request.title).body(&request.body);
        // A freedesktop server reports a click on the body as the "default"
        // action only when the notification offers one.
        #[cfg(unix)]
        notification.appname("GaugeDesk").action("default", "Open");
        // A toast is attributed to the installed app's model id; a build run
        // from `target/` is not installed and has none, so Windows attributes
        // it to PowerShell instead.
        #[cfg(windows)]
        if super::installed() {
            notification.app_id(&app.config().identifier);
        }
        let app = app.clone();
        let chat = request.chat;
        std::thread::spawn(move || {
            let handle = match notification.show() {
                Ok(handle) => handle,
                Err(error) => {
                    eprintln!("could not show a notification: {error}");
                    return;
                }
            };
            if WAITING.fetch_add(1, Ordering::SeqCst) >= MAX_WAITING {
                WAITING.fetch_sub(1, Ordering::SeqCst);
                // Dropping the handle leaves it shown without waiting on it.
                drop(handle);
                return;
            }
            handle.wait_for_action(|action| {
                if action == "default" {
                    open_chat(&app, &chat);
                }
            });
            WAITING.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

#[cfg(windows)]
fn installed() -> bool {
    let Ok(exe) = tauri::utils::platform::current_exe() else {
        return false;
    };
    let Some(dir) = exe.parent() else {
        return false;
    };
    !(dir.ends_with("target/debug") || dir.ends_with("target/release"))
}

#[cfg(test)]
mod tests {
    use super::{click_script, ChatNotification};

    #[test]
    fn a_notification_needs_a_plausible_chat() {
        assert!(ChatNotification::new(" ".into(), "t".into(), "b".into()).is_err());
        assert!(ChatNotification::new("chat\n1".into(), "t".into(), "b".into()).is_err());
        assert!(ChatNotification::new("c".repeat(257), "t".into(), "b".into()).is_err());
        assert_eq!(
            ChatNotification::new(" chat-1 ".into(), "Plan".into(), "Finished.".into()).unwrap(),
            ChatNotification {
                chat: "chat-1".into(),
                title: "Plan".into(),
                body: "Finished.".into()
            }
        );
    }

    #[test]
    fn the_words_are_bounded_and_never_empty() {
        let n = ChatNotification::new("chat-1".into(), "\u{7}  ".into(), "x".repeat(500)).unwrap();
        assert_eq!(n.title, "GaugeDesk");
        assert_eq!(n.body.chars().count(), 240);
        assert!(n.body.ends_with('…'));
    }

    #[test]
    fn a_click_dispatches_the_chat_escaped() {
        let script = click_script("chat\");evil()//").unwrap();
        assert!(script.contains("gw-chat-notification"));
        assert!(script.contains("chat\\\");evil()//"));
    }
}
