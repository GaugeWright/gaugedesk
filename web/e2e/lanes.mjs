/**
 * Which scenarios each lane of the browser suite runs — stated once.
 *
 * Three readers depend on the answer and must not disagree about it:
 *
 *   - `run.mjs` turns the lane it was asked for into the tag expression bddgen
 *     generates from (`GW_E2E_TAGS`, read by playwright.config.ts);
 *   - `scripts/e2e-job.sh`, the fleet's `gaugewright/bar/e2e` and
 *     `gaugewright/bar/e2e-full` jobs, runs the lanes named in `CI_LANES`;
 *   - `scripts/check-product-contracts.mjs` accepts a feature scenario as a
 *     contract's evidence only when some CI lane selects it, so a contract is
 *     never satisfied by a scenario nothing executes.
 *
 * A lane is a set of tags a scenario must carry and a set it must not. Tags are
 * inherited the Gherkin way: a scenario carries its feature's, its rule's and
 * its own.
 */

/** A scenario that fails for a reason not yet repaired. Excluded from every
 *  lane, and so from contract evidence, until its tracker item is closed. Each
 *  use names the item beside the tag. */
export const QUARANTINE = "@quarantine";

/** The core journeys: start a chat, send, keep talking, sign in, see a failure
 *  explained. The per-change job runs these on every pull request. */
export const CORE = "@core";

/**
 * The tags a lane requires and excludes.
 *
 * @param {object} lane
 * @param {boolean} [lane.live]          only real-model `@live-provider` scenarios
 * @param {boolean} [lane.enterprise]    the combined enterprise workbench at the preview origin
 * @param {boolean} [lane.accountEntry]  only `@account-entry`, with the account/Home split on
 * @param {boolean} [lane.core]          only `@core` journeys
 * @param {boolean} [lane.quarantined]   include `@quarantine` (to work on one; never in CI)
 */
export function laneTags({ live = false, enterprise = false, accountEntry = false, core = false, quarantined = false } = {}) {
    const require = [
        ...(live ? ["@live-provider"] : []),
        ...(accountEntry ? ["@account-entry"] : []),
        ...(core ? [CORE] : []),
    ];
    const exclude = [
        ...(live ? [] : ["@live-provider"]),
        ...(enterprise ? ["@open-only"] : ["@enterprise-composition"]),
        ...(accountEntry ? [] : ["@account-entry"]),
        ...(quarantined ? [] : [QUARANTINE]),
    ];
    return { require, exclude };
}

/** Whether a lane runs a scenario carrying `tags`. */
export function selects({ require, exclude }, tags) {
    const carried = new Set(tags);
    return require.every((tag) => carried.has(tag)) && !exclude.some((tag) => carried.has(tag));
}

/** The lane as a Cucumber tag expression, for playwright-bdd's `tags`. */
export function tagExpression({ require, exclude }) {
    return [...require, ...exclude.map((tag) => `not ${tag}`)].join(" and ");
}

/** The lane `run.mjs` was asked for, from its environment. */
export function laneFromEnv(env = process.env) {
    return {
        live: Boolean(env.GW_E2E_LIVE),
        enterprise: env.GW_E2E_COMPOSITION === "enterprise",
        accountEntry: env.GW_E2E_ACCOUNT_ENTRY === "1",
        core: env.GW_E2E_CORE === "1",
        quarantined: env.GW_E2E_QUARANTINED === "1",
    };
}

/**
 * The lanes the fleet runs. `core` is the per-change job on every pull request
 * and every head of main, in Chromium and in WebKit (the desktop shell's
 * webview); `full` is the newest main every two hours, in Chromium.
 */
export const CI_LANES = {
    core: [
        { name: "open", lane: { core: true } },
        { name: "enterprise", lane: { core: true, enterprise: true } },
    ],
    full: [
        { name: "open", lane: {} },
        { name: "enterprise", lane: { enterprise: true } },
        { name: "account-entry", lane: { enterprise: true, accountEntry: true } },
    ],
};

/** Whether any lane the fleet runs selects a scenario carrying `tags`. */
export function runInCI(tags) {
    return [...CI_LANES.core, ...CI_LANES.full].some(({ lane }) => selects(laneTags(lane), tags));
}
