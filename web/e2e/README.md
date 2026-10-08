# E2E user-story tests (Gherkin / playwright-bdd)

Browser tests that exercise the workbench as **user stories**. The stories are
Gherkin `.feature` files; `playwright-bdd` compiles them (the "pickle" step) and
Playwright runs them against the real control plane + the built web island.

```
features/            the user stories (Given/When/Then) — one file per capability
steps/               step definitions (drive the real UI, assert on rendered projections)
run.mjs              the `npm run e2e` entrypoint — resolves free ports, runs the pipeline
fed-control-plane.sh launches a control plane for tests (fresh state each run, port-scoped)
broker.sh            launches the rendezvous broker (federation scenarios)
panel-edge.mjs       a loopback publisher-protocol edge Panel deployments publish to
                     and drain from, plus test routes that play a visitor and seed a
                     deployment from before project bindings (PANEL-7)
```

## Two tiers

- **Default suite** (`npm run e2e`) — fast, deterministic, no network. Runs every
  story against the **mock-LLM** control plane (`GAUGEDESK_FAKE_AGENT=1`): a scripted
  transport writes a deterministic file + emits canned stream events, so the
  task → diff → keep flow is instant while the membrane/reducer path stays real.
  Excludes `@live`.
- **Live suite** (`npm run e2e:live`) — opt-in. Runs only `@live` scenarios against
  **WhippleScript with a real model** (the OpenAI Codex endpoint via OAuth). Slow, costs tokens — for the
  cases where the model's actual behavior drives the app (real tool-use → diff).

  It needs a credential you supply, and it refuses to launch without one:

  ```sh
  GW_E2E_LIVE_TOKEN="$(cat ~/codex-oauth-bundle.json)" npm run e2e:live
  ```

  The lane links that material through the production `POST /account/credentials`
  route after **every** per-scenario reset, because the control plane wipes its
  state root at startup and the reset wipes it again, so a credential linked
  interactively never survives to the first turn. `GW_E2E_LIVE_PROVIDER` selects
  the provider (default `openai-codex`) and also pins the turn's provider to it.
  For `openai-codex` the token is the GaugeDesk-owned OAuth bundle
  (`{"access","refresh","expires","accountId"}`; an expired `access` is fine, the
  turn refreshes it); for a BYOK provider it is that provider's API key. Nothing
  is committed and nothing is logged.
- **Enterprise-composition lane** (`npm run e2e:enterprise`) — the same default
  suite, but the preview origin serves the **combined enterprise workbench**
  (`ee/web`) instead of the open bundle. Every shipped surface — desktop
  packaging and the hosted desk — runs the enterprise composition (ADR 0098),
  and the open dev loop alone let an enterprise-only crash ship (the Devices
  modal, 2026-07-31), so this lane is how the suite exercises what actually
  ships. Features that exist only in the open bundle (the embed example page,
  the `?mobile=1` entry) carry the `@open-only` tag and are skipped here.

Both manage their own servers via Playwright `webServer`. `run.mjs` resolves a free
port set per run (control plane, federation peer, broker, `vite preview`) and exports
them, so a parallel run or a second worktree picks a disjoint set and the two never
collide. By default they use system Google Chrome (`channel: 'chrome'`), so no
browser download is needed; `GW_E2E_BROWSERS=chromium,webkit` runs Playwright's own
builds instead, one Playwright project each.

## What CI runs

The fleet runs this suite as two jobs (WS-871), through `scripts/e2e-job.mjs`:

- **`gaugewright/bar/e2e`** — every pull request and every head of `main`: the
  `@core` journeys (start a chat, send, keep talking, sign in, a signed-in desktop
  window, a refused action explained) in both compositions, in Chromium and in
  WebKit, the desktop webview's engine.
- **`gaugewright/bar/e2e-full`** — the newest `main` every two hours: every lane (open,
  enterprise, account-entry) in Chromium.

Which scenarios a lane runs is stated once, in `lanes.mjs`; `run.mjs` hands it to
bddgen as a tag expression. To run the per-change job's selection locally:
`GW_E2E_CORE=1 npm run e2e` (and again with `GW_E2E_COMPOSITION=enterprise`).

`scripts/check-product-contracts.mjs` accepts a scenario as a contract's evidence
only when one of those lanes runs it, so a scenario nothing runs proves nothing.

**`@quarantine`** takes a scenario out of every lane, and so out of contract
evidence. It is the last resort for a red that cannot be repaired at once: each
use carries a comment naming the tracker item that will lift it, and the item
says what is wrong. `GW_E2E_QUARANTINED=1` runs quarantined scenarios too.

## Adding a story

### Model Providers component checks

From the repository root:

```sh
web/node_modules/.bin/playwright test --config web/e2e/model-providers/playwright.config.ts
```

This isolated lane mounts the native Solid Model Providers page with synthetic,
typed authority replies. It checks proposal payloads, exact member/project caps,
credential-field disposal, scope and revision changes, disclosure persistence,
read-only controls and wide/narrow layouts. Its Vite entrypoint lives under
`ee/web/e2e/model-providers/` and is not a production composition. It is component
evidence, not authenticated backend, provider-verification or release evidence;
the Cloud model-provider HTTP suite owns those service-boundary checks.

### Workbench stories

The isolated GaugeApp workspace lane exercises the production controller and
native page/menu/chat controls with delayed synthetic authority replies:

```sh
web/node_modules/.bin/playwright test --config web/e2e/gaugeapp-workspace/playwright.config.ts
```

It covers one-time-result disposal, page/scope/authorization changes, denied
reads, late success/error and A → B → A, concurrent busy states, passkey abort,
personal-key field disposal and embedded payment-session cleanup. Its test-only
Stripe adapter makes no processor request. This is browser lifetime evidence,
not an authenticated service or payment-provider journey.

Its fixture server binds 127.0.0.1:7662 strictly and is never reused, so while
another checkout holds that port the run is refused. Set
`GAUGEDESK_GAUGEAPP_WORKSPACE_PORT` to a free port to run beside it.

1. Write/extend a `.feature` file with Given/When/Then.
2. Reuse a step in `steps/steps.ts`, or add a new one (drive the UI by visible
   label or `data-testid`; assert on rendered text/projections).
3. `npm run e2e`.

The Administration stories admit the enterprise owner twice, as production
does: the seeded `gw_session` cookie admits the tenant, and a sealed account
handoff through the run's hermetic Hub (`/account/hub-session/start` and
`/callback`) admits the same person, `e2e-account-root`, to Account Settings.
Neither substitutes for the other. The reset that seeds a withheld context
source writes it only for an authenticated current owner of a live project,
under that project's session hold.

The hermetic Hub lists that organization among `e2e-account-root`'s
memberships, so the workbench selects it as the account's organization. The
desktop-updater story stands in for the shell the way the signed-in desktop
story does: its IPC stand-in answers `home_session` with the session
`POST /test/desktop-home-session` mints for the owner (debug builds only),
and `null` to everything else. A window handed no Home session while signed
in reaches its Home remotely through the account plane, which in this fixture
is the Hub's unreachable registered Home, so it never read this Home's
software policy.
