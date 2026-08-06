use std::sync::{Mutex, MutexGuard};

static FAKE_AGENT_ENV_GUARD: Mutex<()> = Mutex::new(());

pub(crate) struct FakeAgentEnvGuard {
    _guard: MutexGuard<'static, ()>,
    previous: Option<String>,
}

pub(crate) fn fake_agent_env() -> FakeAgentEnvGuard {
    let guard = FAKE_AGENT_ENV_GUARD
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let previous = gaugedesk_env::var("FAKE_AGENT");
    std::env::set_var("GAUGEDESK_FAKE_AGENT", "1");
    FakeAgentEnvGuard {
        _guard: guard,
        previous,
    }
}

impl Drop for FakeAgentEnvGuard {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => std::env::set_var("GAUGEDESK_FAKE_AGENT", value),
            None => std::env::remove_var("GAUGEDESK_FAKE_AGENT"),
        }
    }
}

/// The inverse of [`fake_agent_env`]: hold the same lock and guarantee
/// `GAUGEDESK_FAKE_AGENT` is **unset** for the guard's lifetime. Onboarding is
/// gated off under the fake agent (ADR 0075), so a test exercising the real
/// onboarding path takes this to (a) serialize against the fake-agent tests and
/// (b) pin the env to the real runtime regardless of what ran before.
pub(crate) fn real_agent_env() -> FakeAgentEnvGuard {
    let guard = FAKE_AGENT_ENV_GUARD
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let previous = gaugedesk_env::var("FAKE_AGENT");
    std::env::remove_var("GAUGEDESK_FAKE_AGENT");
    FakeAgentEnvGuard {
        _guard: guard,
        previous,
    }
}
