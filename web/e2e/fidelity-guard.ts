import type { Page } from "@playwright/test";

const INTERCEPTION_METHODS = ["route", "routeFromHAR", "routeWebSocket"] as const;

/**
 * Make a declared real-transport scenario fail at the point where it attempts
 * to replace browser application transport. Each Playwright scenario owns its
 * page and context, so the guard cannot leak into another scenario.
 */
export function installTransportFidelityGuards(page: Page, tags: readonly string[]): void {
    const declaredFidelity = tags.filter((tag) =>
        ["@transport", "@authenticated", "@staging", "@production"].includes(tag)
    ).join(" ");

    for (const [label, target] of [
        ["page", page],
        ["browser context", page.context()],
    ] as const) {
        const methods = target as unknown as Record<string, unknown>;
        for (const method of INTERCEPTION_METHODS) {
            if (typeof methods[method] !== "function") continue;
            Object.defineProperty(target, method, {
                configurable: true,
                value: () => {
                    throw new Error(
                        `${declaredFidelity} scenarios may not call ${label}.${method}(); `
                        + "use @ui-mocked for presentation-only route simulation",
                    );
                },
            });
        }
    }
}
