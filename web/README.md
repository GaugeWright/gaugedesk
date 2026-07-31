# GaugeDesk (web island)

The client-owned Solid island — projection-first per `app-stack.md`:
the client **renders projections and submits commands; it never defines a
lifecycle transition** (`INV-5`).

## What's verified

- **`packages/control-plane-client/src/*`** — the projection-first transport.
  Parses control-plane payloads into **branded domain types** at the edge
  (`principles.md`, "Contracts at the boundary"); every mutation is a command,
  every displayed fact a projection; a 409 is a `Rejected` receipt, not a fact.
- **`packages/workbench-ui/src/transcript.ts`** — the live transcript as a **client reduction**
  of the server event stream: two tiers (operational vs admitted), coalesced
  deltas, and **repairable from a snapshot** (replay yields the same transcript).

These are framework-agnostic TypeScript. They type-check (`npm run typecheck`)
and are unit-tested (`npm test` → 4 passing). They are the doctrine-bearing core.

## The shell

`apps/workbench-web/src/App.tsx` (four-panel shell + human-task-queue bar +
facet-browser nav), `packages/workbench-ui/src/DiffView.tsx`,
`apps/workbench-web/src/main.tsx` (the root `index.html` entry), and
`packages/workbench-ui/src/styles.css` build the workbench against the
projection core. The transcript is fed by a **live SSE
stream** (`api.subscribe`), so model tokens render token-by-token; the task
composer drives a real WhippleScript turn; the content panel shows the diff with a
keep → `main` action.

**Built on Solid 1.x.** Solid 2.0 (`2.0.0-experimental.16`) ships no client DOM
renderer yet — only the reactive core + SSR — and `vite-plugin-solid` targets
1.x, so a DOM app isn't buildable on 2.0 today. The shell relies only on the
signals/store/`For`/`Show` surface that is stable across 1.x→2.0, so the 2.0
migration is mechanical once its DOM toolchain ships (`app-stack.md`).

## Commands

```
npm install          # Solid 1.x — peer deps resolve cleanly
npm run typecheck     # all app + package roots (api + state + shell)
npm run build         # vite production bundle
npm run build:apps:open        # staged standalone workbench + mobile entries
cd ../ee/web && npm run build  # combined enterprise Work + Administration entry
npm run build:apps:managed     # staged standalone managed-service entries
npm test              # transcript reduction unit tests
```
