//! The release canary's test entrances into the packaged desktop (DR-0457).
//!
//! The desktop chat-turn canary (DR-0454) signs the packaged app in as the
//! synthetic account and drives one chat turn in its real window. Two
//! entrances let it, and every release build carries both:
//!
//! - the **attempt**: `GAUGEDESK_TEST_SIGNIN_VERIFIER` names a PKCE verifier
//!   the canary minted. It is stored as this desktop's pending sign-in
//!   attempt, exactly as pressing Sign in stores one, so the one-time code the
//!   canary obtained by signing in with a passkey outside the app — bound to
//!   that verifier's challenge — is redeemed through the app's own callback.
//! - the **journey**: `GAUGEDESK_TEST_JOURNEY` names a plan, read once and
//!   removed, that the shell runs in the real window (`src-tauri/src/
//!   test_journey.js`), and the file the window's reports are appended to,
//!   one JSON object per line, through [`report`].
//!
//! Both are refused unless `GAUGEDESK_TEST_SIGNIN=1` is set together with an
//! explicit `GAUGEDESK_ROOT` naming a data directory that is absent or empty
//! at launch. With the switch set and no such directory, [`admit`] refuses and
//! the shell does not start: a switch that silently fell back to the person's
//! own data directory would sign *their* installation in to the canary's
//! account. Without the switch the entrance variables are ignored, and said
//! to be.
//!
//! [`TestSignin`] can be made only by [`admit`], so holding one is the proof
//! that the entrances were admitted; the seeding it offers is reachable no
//! other way.

use std::path::{Path, PathBuf};

use crate::SharedWorkbench;

/// The switch: `GAUGEDESK_TEST_SIGNIN=1`.
pub const SWITCH: &str = "TEST_SIGNIN";
/// The verifier of the attempt the canary began: `GAUGEDESK_TEST_SIGNIN_VERIFIER`.
pub const VERIFIER: &str = "TEST_SIGNIN_VERIFIER";
/// The journey plan: `GAUGEDESK_TEST_JOURNEY`.
pub const JOURNEY: &str = "TEST_JOURNEY";

/// What the environment asked for.
#[derive(Clone, Debug, Default)]
pub struct Request {
    pub switch: Option<String>,
    pub root: Option<PathBuf>,
    pub verifier: Option<String>,
    pub journey: Option<PathBuf>,
}

impl Request {
    pub fn from_env() -> Self {
        Self {
            switch: gaugedesk_env::var(SWITCH),
            root: gaugedesk_env::var_os("ROOT").map(PathBuf::from),
            verifier: gaugedesk_env::var(VERIFIER),
            journey: gaugedesk_env::var_os(JOURNEY).map(PathBuf::from),
        }
    }
}

/// Whether the entrances are open.
#[derive(Debug)]
pub enum Admission {
    /// The switch is not set. Every entrance is inert; `ignored` names the
    /// entrance variables that were set anyway.
    Off { ignored: Vec<&'static str> },
    /// The switch is set against a fresh data directory.
    On(TestSignin),
    /// The switch is set and cannot be honoured. The app must not start.
    Refused(String),
}

/// The admitted entrances. Only [`admit`] makes one.
#[derive(Clone, Debug)]
pub struct TestSignin {
    root: PathBuf,
    verifier: Option<String>,
    journey: Option<PathBuf>,
}

/// Decide from the environment.
pub fn admit_from_env() -> Admission {
    admit(Request::from_env())
}

/// Decide. Reads the filesystem only to ask whether `root` is fresh.
pub fn admit(request: Request) -> Admission {
    let Request {
        switch,
        root,
        verifier,
        journey,
    } = request;
    match switch.as_deref().map(str::trim) {
        None | Some("") => {
            let ignored = [
                verifier.as_ref().map(|_| VERIFIER),
                journey.as_ref().map(|_| JOURNEY),
            ]
            .into_iter()
            .flatten()
            .collect();
            return Admission::Off { ignored };
        }
        Some("1") => {}
        Some(_) => {
            return Admission::Refused(format!("GAUGEDESK_{SWITCH} must be 1 to enable it"));
        }
    }
    let Some(root) = root.filter(|root| !root.as_os_str().is_empty()) else {
        return Admission::Refused(format!(
            "GAUGEDESK_{SWITCH}=1 needs GAUGEDESK_ROOT naming a fresh data directory"
        ));
    };
    if let Err(reason) = fresh(&root) {
        return Admission::Refused(format!(
            "GAUGEDESK_{SWITCH}=1 needs a fresh GAUGEDESK_ROOT, and {} {reason}",
            root.display()
        ));
    }
    if let Some(verifier) = verifier.as_deref() {
        if !verifier_shaped(verifier) {
            return Admission::Refused(format!(
                "GAUGEDESK_{VERIFIER} is not a PKCE verifier (RFC 7636: 43 to 128 of A-Z a-z 0-9 - . _ ~)"
            ));
        }
    }
    if let Some(journey) = journey.as_deref() {
        if !journey.is_absolute() {
            return Admission::Refused(format!("GAUGEDESK_{JOURNEY} must be an absolute path"));
        }
    }
    Admission::On(TestSignin {
        root,
        verifier,
        journey,
    })
}

/// Absent, or an empty directory.
fn fresh(root: &Path) -> Result<(), &'static str> {
    match std::fs::read_dir(root) {
        Ok(mut entries) => match entries.next() {
            None => Ok(()),
            Some(_) => Err("is not empty"),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotADirectory => {
            Err("is not a directory")
        }
        Err(_) => Err("cannot be read"),
    }
}

/// RFC 7636 §4.1's verifier: 43 to 128 unreserved characters.
fn verifier_shaped(verifier: &str) -> bool {
    (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

/// The most a journey plan, or one report from it, may be.
const JOURNEY_LIMIT: usize = 64 * 1024;

/// A loaded journey: the file it reports to, and the plan the window runs,
/// as JSON. The shell puts the plan before its script as
/// `window.__gwTestJourney`.
#[derive(Debug)]
pub struct Journey {
    result: PathBuf,
    plan: String,
}

impl Journey {
    /// Parse a plan. It is a JSON object: `result` is the absolute path
    /// reports are appended to and stays here; `callback` must be the
    /// `gaugewright://auth/callback#code=` link the sign-in returned; the rest
    /// is the window's.
    fn from_plan(text: &str) -> Result<Self, String> {
        if text.len() > JOURNEY_LIMIT {
            return Err("the journey plan is too large".into());
        }
        let mut plan: serde_json::Map<String, serde_json::Value> = serde_json::from_str(text)
            .map_err(|error| format!("the journey plan is not a JSON object: {error}"))?;
        let result = plan
            .remove("result")
            .and_then(|value| value.as_str().map(PathBuf::from))
            .filter(|path| path.is_absolute())
            .ok_or("the journey plan names no absolute `result` path")?;
        let callback = plan.get("callback").and_then(serde_json::Value::as_str);
        if !callback.is_some_and(|link| link.starts_with("gaugewright://auth/callback#code=")) {
            return Err(
                "the journey plan's `callback` is not a gaugewright://auth/callback#code= link"
                    .into(),
            );
        }
        Ok(Self {
            result,
            // `serde_json` writes a value JavaScript reads as the same value,
            // every string escaped, so the plan cannot become code.
            plan: serde_json::Value::Object(plan).to_string(),
        })
    }

    /// The plan the window runs, as a JSON object without `result`.
    pub fn plan_json(&self) -> &str {
        &self.plan
    }

    /// Append one report from the window, stamped with when it arrived.
    pub fn report(&self, event: &serde_json::Value) -> Result<(), String> {
        use std::io::Write as _;
        let at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis() as u64)
            .unwrap_or(0);
        let line = serde_json::json!({ "at_ms": at_ms, "event": event }).to_string();
        if line.len() > JOURNEY_LIMIT {
            return Err("the report is too large".into());
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.result)
            .map_err(|error| format!("cannot open the journey result: {error}"))?;
        writeln!(file, "{line}")
            .map_err(|error| format!("cannot write the journey result: {error}"))
    }
}

/// Append a report to `journey`, refusing when there is none — which is every
/// launch without the switch, a fresh data directory and a plan.
pub fn report(journey: Option<&Journey>, event: &serde_json::Value) -> Result<(), String> {
    journey
        .ok_or("the test journey is not enabled")?
        .report(event)
}

impl TestSignin {
    /// Read the journey plan, when one was named, and remove it: it carries a
    /// one-time sign-in code.
    pub fn load_journey(&self) -> Result<Option<Journey>, String> {
        let Some(path) = self.journey.as_deref() else {
            return Ok(None);
        };
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("cannot read the journey plan {}: {error}", path.display()))?;
        let _ = std::fs::remove_file(path);
        Journey::from_plan(&text).map(Some)
    }

    /// The fresh data directory the entrances were admitted against.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The journey plan's path, when one was named.
    pub fn journey(&self) -> Option<&Path> {
        self.journey.as_deref()
    }

    /// Store the canary's verifier as this desktop's pending sign-in attempt,
    /// when one was named, and return the attempt's challenge. Call it after
    /// the workbench opens and before the control plane serves, so the window
    /// cannot reach the callback first.
    pub fn seed_pending_attempt(&self, wb: &SharedWorkbench) -> Result<Option<String>, String> {
        match self.verifier.as_deref() {
            Some(verifier) => crate::account_signin::seed_pending_attempt(wb, verifier).map(Some),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VERIFIER_VALUE: &str = "the-canary-verifier-0000000000000000000000000";

    fn request(switch: Option<&str>, root: Option<&Path>) -> Request {
        Request {
            switch: switch.map(str::to_owned),
            root: root.map(Path::to_path_buf),
            verifier: Some(VERIFIER_VALUE.to_owned()),
            journey: Some(PathBuf::from("/tmp/journey.json")),
        }
    }

    fn refused(admission: Admission) -> String {
        match admission {
            Admission::Refused(reason) => reason,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// The release build's default: no switch, nothing open, whatever else is
    /// set — and what was set anyway is named so the log can say so.
    #[test]
    fn without_the_switch_every_entrance_is_inert() {
        let dir = tempfile::tempdir().unwrap();
        for switch in [None, Some(""), Some("  ")] {
            match admit(request(switch, Some(dir.path()))) {
                Admission::Off { ignored } => assert_eq!(ignored, vec![VERIFIER, JOURNEY]),
                other => panic!("{switch:?} opened the entrances: {other:?}"),
            }
        }
        match admit(Request::default()) {
            Admission::Off { ignored } => assert!(ignored.is_empty()),
            other => panic!("an empty environment opened the entrances: {other:?}"),
        }
    }

    /// A switch that is set but cannot be honoured stops the app rather than
    /// falling back to the person's own data directory.
    #[test]
    fn the_switch_is_refused_without_a_fresh_explicit_root() {
        assert!(refused(admit(request(Some("1"), None))).contains("GAUGEDESK_ROOT"));
        assert!(refused(admit(request(Some("1"), Some(Path::new(""))))).contains("GAUGEDESK_ROOT"));

        let used = tempfile::tempdir().unwrap();
        std::fs::write(used.path().join("store.sqlite"), b"someone's data").unwrap();
        assert!(refused(admit(request(Some("1"), Some(used.path())))).contains("is not empty"));

        let file = used.path().join("store.sqlite");
        assert!(refused(admit(request(Some("1"), Some(&file)))).contains("is not a directory"));

        for switch in ["true", "yes", "0"] {
            assert!(refused(admit(request(
                Some(switch),
                Some(Path::new("/nonexistent/x"))
            )))
            .contains("must be 1"));
        }
    }

    #[test]
    fn a_malformed_verifier_or_a_relative_journey_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut short = request(Some("1"), Some(dir.path()));
        short.verifier = Some("short".into());
        assert!(refused(admit(short)).contains("PKCE verifier"));
        let mut odd = request(Some("1"), Some(dir.path()));
        odd.verifier = Some(format!("{}!", &VERIFIER_VALUE[..44]));
        assert!(refused(admit(odd)).contains("PKCE verifier"));
        let mut relative = request(Some("1"), Some(dir.path()));
        relative.journey = Some(PathBuf::from("journey.json"));
        assert!(refused(admit(relative)).contains("absolute"));
    }

    /// An absent directory and an empty one are both fresh.
    #[test]
    fn the_switch_opens_the_entrances_against_a_fresh_root() {
        let dir = tempfile::tempdir().unwrap();
        for root in [dir.path().to_path_buf(), dir.path().join("not-yet")] {
            match admit(request(Some("1"), Some(&root))) {
                Admission::On(admitted) => {
                    assert_eq!(admitted.root(), root);
                    assert_eq!(admitted.journey(), Some(Path::new("/tmp/journey.json")));
                }
                other => panic!("{} was not admitted: {other:?}", root.display()),
            }
        }
    }

    /// A launch without a loaded journey — every ordinary launch — refuses
    /// the window's report.
    #[test]
    fn a_report_is_refused_without_a_loaded_journey() {
        assert_eq!(
            report(None, &serde_json::json!({ "kind": "anything" })),
            Err("the test journey is not enabled".to_owned()),
        );
    }

    fn plan(result: &Path) -> String {
        serde_json::json!({
            "result": result,
            "callback": "gaugewright://auth/callback#code=abc",
            "message": "say \"hi\"</script><script>evil()</script>",
        })
        .to_string()
    }

    #[test]
    fn a_loaded_journey_reports_one_line_per_event_and_takes_its_plan_once() {
        let dir = tempfile::tempdir().unwrap();
        let plan_path = dir.path().join("plan.json");
        let result = dir.path().join("result.jsonl");
        std::fs::write(&plan_path, plan(&result)).unwrap();
        let mut request = request(Some("1"), Some(&dir.path().join("root")));
        request.journey = Some(plan_path.clone());
        let Admission::On(admitted) = admit(request) else {
            panic!("not admitted");
        };

        let journey = admitted.load_journey().unwrap().unwrap();
        assert!(
            !plan_path.exists(),
            "the plan carries a one-time code and is removed"
        );
        assert!(
            !journey.plan_json().contains(result.to_str().unwrap()),
            "the result path is the shell's, not the window's"
        );
        assert!(
            journey.plan_json().contains(r#"say \"hi\"</script>"#),
            "plan strings stay strings"
        );

        report(
            Some(&journey),
            &serde_json::json!({ "kind": "step", "step": "one" }),
        )
        .unwrap();
        report(
            Some(&journey),
            &serde_json::json!({ "kind": "outcome", "passed": true }),
        )
        .unwrap();
        let lines: Vec<serde_json::Value> = std::fs::read_to_string(&result)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[1]["event"]["passed"], true);
        assert!(lines[0]["at_ms"].as_u64().unwrap() > 0);
    }

    #[test]
    fn a_plan_without_an_absolute_result_or_a_sign_in_callback_is_refused() {
        assert!(Journey::from_plan("[]").is_err());
        assert!(Journey::from_plan(
            r#"{"result":"relative.jsonl","callback":"gaugewright://auth/callback#code=a"}"#
        )
        .is_err());
        assert!(Journey::from_plan(
            r#"{"result":"/tmp/r.jsonl","callback":"https://evil.example/#code=a"}"#
        )
        .is_err());
        assert!(Journey::from_plan(r#"{"result":"/tmp/r.jsonl"}"#).is_err());
        assert!(Journey::from_plan(
            r#"{"result":"/tmp/r.jsonl","callback":"gaugewright://auth/callback#code=a"}"#
        )
        .is_ok());
    }

    /// The seeded attempt is the one the app's own callback completes: the
    /// verifier is taken once, sealed, under the challenge it hashes to.
    #[test]
    fn the_seeded_attempt_is_the_one_the_callback_takes() {
        let dir = tempfile::tempdir().unwrap();
        let Admission::On(admitted) = admit(request(Some("1"), Some(dir.path()))) else {
            panic!("not admitted");
        };
        let wb = crate::open_workbench(admitted.root()).unwrap();
        let challenge = admitted.seed_pending_attempt(&wb).unwrap().unwrap();
        assert_eq!(
            challenge,
            crate::identity_oidc::s256_challenge(VERIFIER_VALUE)
        );
        assert_eq!(
            crate::account_signin::take_pending_verifier_for_test(&wb).as_deref(),
            Some(VERIFIER_VALUE),
        );
        assert_eq!(
            crate::account_signin::take_pending_verifier_for_test(&wb),
            None,
            "an attempt is taken once",
        );
    }
}
