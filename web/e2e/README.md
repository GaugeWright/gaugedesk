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
```

## Two tiers

- **Default suite** (`npm run e2e`) — fast, deterministic, no network. Runs every
  story against the **mock-LLM** control plane (`GAUGEWRIGHT_FAKE_AGENT=1`): a scripted
  transport writes a deterministic file + emits canned stream events, so the
  task → diff → keep flow is instant while the membrane/reducer path stays real.
  Excludes `@live`.
- **Live suite** (`npm run e2e:live`) — opt-in. Runs only `@live` scenarios against
  **WhippleScript with a real model** (the OpenAI Codex endpoint via OAuth). Slow, costs tokens — for the
  cases where the model's actual behavior drives the app (real tool-use → diff).
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
collide. They use system Google Chrome (`channel: 'chrome'`), so no browser download
is needed.

## Adding a story

1. Write/extend a `.feature` file with Given/When/Then.
2. Reuse a step in `steps/steps.ts`, or add a new one (drive the UI by visible
   label or `data-testid`; assert on rendered text/projections).
3. `npm run e2e`.
