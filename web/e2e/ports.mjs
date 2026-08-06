/**
 * The single source of truth for the e2e harness's ports (concurrency-safety).
 *
 * Every port the suite uses — the two open control planes, the enterprise control plane,
 * the rendezvous broker, and the Vite previews the browser loads (the workbench plus the
 * enterprise workbench composition) — is read from the environment so that
 * **two runs never collide**
 * (a second worktree / a parallel agent picks a disjoint set). `e2e/run.mjs` resolves a free
 * set once per run and exports these vars to every child (vite build, bddgen, playwright);
 * when they're unset (e.g. a bare `playwright test`) we fall back to the historical defaults,
 * so direct invocation still works.
 *
 * Derived values (CP base URLs, the preview origin, per-run state dirs) live here too, so the
 * playwright config, the step files, and vite all agree by construction.
 */

// State dirs go under the OS temp dir, not a hardcoded /tmp: on some
// machines /tmp is a RAM-backed tmpfs, and these dirs are keyed by a
// per-run port, so every run mints new ones and they accumulate (530 had
// piled up before this). Honoring TMPDIR lets them land on disk, where
// ordinary temp reaping can reclaim them.
import os from "node:os";

const num = (name, dflt) => {
    const v = process.env[name];
    const n = v ? Number(v) : NaN;
    return Number.isInteger(n) && n > 0 && n < 65536 ? n : dflt;
};

export const ports = {
    alice: num("GW_E2E_ALICE", 7878),
    bob: num("GW_E2E_BOB", 7879),
    broker: num("GW_E2E_BROKER", 7900),
    preview: num("GW_E2E_PREVIEW", 4173),
    // The self-hosted enterprise composition (`gaugedesk-enterprise-server`, ee/):
    // the /admin/* + SSO surface WITHOUT the managed planes — what the combined
    // enterprise workbench drives (enterprise coverage must not require private code).
    enterprise: num("GW_E2E_ENTERPRISE", 7882),
    // Static preview of the combined enterprise workbench bundle (ee/web).
    enterpriseApp: num("GW_E2E_ENTERPRISE_APP", 4174),
    // The stand-in Hub for the desktop account handoff (LOGIN-5, ADR 0123).
    hub: num("GW_E2E_HUB", 7910),
};

export const aliceCP = `http://127.0.0.1:${ports.alice}`;
export const bobCP = `http://127.0.0.1:${ports.bob}`;
export const brokerAddr = `ws://127.0.0.1:${ports.broker}`;
export const previewURL = `http://127.0.0.1:${ports.preview}`;
export const enterpriseCP = `http://127.0.0.1:${ports.enterprise}`;
export const hubURL = `http://127.0.0.1:${ports.hub}`;
/** The combined enterprise workbench (ee/web's built bundle, served whole-dist). */
export const enterpriseAppURL = `http://127.0.0.1:${ports.enterpriseApp}/apps/enterprise-workbench/`;

/** Per-run control-plane state dirs (keyed by port so concurrent runs don't share state). */
export const aliceState = `${os.tmpdir()}/gw-e2e-state-${ports.alice}`;
export const bobState = `${os.tmpdir()}/gw-e2e-state-${ports.bob}`;
export const enterpriseState = `${os.tmpdir()}/gw-e2e-state-${ports.enterprise}`;
