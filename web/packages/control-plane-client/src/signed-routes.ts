/**
 * Reading project→Home routes from the **root-signed** directory record
 * (DESK-5c, [ADR 0131](../../../../specs/decisions/0131-a-home-authors-and-signs-its-own-reachability.md)
 * §2, [ADR 0132](../../../../specs/decisions/0132-a-browser-pins-the-account-root-key.md)).
 *
 * Two checks, and the second is the one that matters. `verifySignedPut` proves
 * the record is *self-consistent* — signed by whatever root it names. That alone
 * is worthless: a forger signs their own record with their own root and it
 * verifies perfectly. What makes it mean something is comparing that root
 * against the key this browser **pinned**, which is why the comparison lives
 * here rather than being folded into the verifier.
 *
 * The pin is trust-on-first-use, per ADR 0132: the first signed-in load for a
 * subject records the root it saw, and any later change is refused rather than
 * adopted — unless the pinned root itself signed the hand-over (DR-0361). A public key is not a credential, so keeping it is not the at-rest
 * exposure `ENTSEC-6` forbids.
 */

import { placementHolds } from "./directory-module";
import { parseOpaqueHomeRoutes, type OpaqueHomeRoute } from "./home-routing";

const PIN_PREFIX = "gw.root.";

/** The canonical blind-directory origin, matching the desktop's default. */
export const DIRECTORY_ORIGIN = "https://directory.gaugewright.com";

export interface SignedRouteOptions {
    /** The signed-in subject. Pins are per person: signing out and in as
     * someone else must not compare keys across them. */
    readonly subject: string;
    readonly directoryOrigin?: string;
    /** The wasm verifier — `verify_signed_put_json`. Injected so this is
     * testable, and so the signing contract stays owned by the Rust crate.
     * Async because a wasm module loads on demand; a synchronous stand-in
     * satisfies it unchanged. */
    readonly verify: (json: string) => boolean | Promise<boolean>;
    readonly fetchJson?: (url: string) => Promise<string | null>;
    readonly storage?: Pick<Storage, "getItem" | "setItem">;
    /** Check a route's placement; the wasm module's by default. Injected for tests. */
    readonly placementHolds?: (route: unknown, trustedProjectKey: string) => Promise<boolean>;
}

function store(options: SignedRouteOptions): Pick<Storage, "getItem" | "setItem"> | null {
    if (options.storage) return options.storage;
    try {
        return globalThis.localStorage ?? null;
    } catch {
        // Private browsing, or storage denied. A pin is an improvement, not a
        // requirement: without one the caller falls back to endpoint-only.
        return null;
    }
}

export function pinnedRootKey(options: SignedRouteOptions): string | null {
    return store(options)?.getItem(PIN_PREFIX + options.subject) ?? null;
}

/** Record the root key for a subject. Refuses to overwrite a different one:
 * a changed root is an alarm, not an update. */
export function pinRootKey(options: SignedRouteOptions, root: string): "pinned" | "matched" | "conflict" {
    const existing = pinnedRootKey(options);
    if (existing === root) return "matched";
    if (existing) return "conflict";
    store(options)?.setItem(PIN_PREFIX + options.subject, root);
    return "pinned";
}

/** Move a subject's pin to `root`. Only for a root reached from the pinned one
 * along hand-overs that root signed (DR-0361); the caller proves that. */
export function advancePinnedRootKey(options: SignedRouteOptions, root: string): void {
    store(options)?.setItem(PIN_PREFIX + options.subject, root);
}

export class RootKeyConflict extends Error {}

/**
 * Fetch and verify the signed record, returning its routes at `signed`
 * provenance — so their relay locators may be honoured.
 *
 * Returns `null` when there is no record to read, which is an ordinary state:
 * an account that has never published one is not under attack.
 */
export async function signedHomeRoutes(
    options: SignedRouteOptions,
): Promise<OpaqueHomeRoute[] | null> {
    const origin = (options.directoryOrigin ?? DIRECTORY_ORIGIN).replace(/\/+$/, "");
    const pinned = pinnedRootKey(options);
    // Without a pin there is nothing to check the record against, and reading it
    // would only launder the hub's word into something that looks verified.
    const root = pinned;
    if (!root) return null;

    const fetchJson = options.fetchJson ?? (async (url) => {
        const response = await fetch(url, { headers: { accept: "application/json" } });
        if (response.status === 404) return null;
        if (!response.ok) throw new Error(`directory read failed: ${response.status}`);
        return response.text();
    });

    const path = `${origin}/directory/${encodeURIComponent(root)}`;
    // Every computer the account is signed in on keeps its own entry under the
    // root (DR-0359 §2). A directory from before that serves no list, and its
    // one entry stands in for it.
    const listed = await fetchJson(`${path}/entries`);
    let puts: string[];
    if (listed !== null) {
        const value = JSON.parse(listed) as { puts?: unknown };
        if (!Array.isArray(value.puts) || !value.puts.every((put) => typeof put === "string")) {
            throw new Error("the directory served a malformed list of entries");
        }
        puts = value.puts as string[];
    } else {
        const single = await fetchJson(path);
        if (!single) return null;
        puts = [single];
    }
    // A computer that has withdrawn is listed by its retraction, which routes
    // nothing; an account whose computers have all withdrawn has published none.
    puts = puts.filter((put) => !isRetraction(put));
    if (puts.length === 0) return null;

    // Oldest first, so a newer computer's route for a project replaces an
    // older one's.
    const merged = new Map<string, OpaqueHomeRoute>();
    for (const body of puts) {
        for (const route of await verifiedRoutes(options, body, root)) {
            merged.delete(route.project);
            merged.set(route.project, route);
        }
    }
    return [...merged.values()];
}

function isRetraction(put: string): boolean {
    try {
        return (JSON.parse(put) as { entry?: { retracted?: unknown } }).entry?.retracted === true;
    } catch {
        return false;
    }
}

/** One signed put's routes, once it verifies and names the pinned root. Any
 * entry that does not refuses the whole read: nothing but the root writes under
 * it. */
async function verifiedRoutes(
    options: SignedRouteOptions,
    body: string,
    root: string,
): Promise<OpaqueHomeRoute[]> {
    if (!(await options.verify(body))) {
        throw new Error("the account directory record failed signature verification");
    }
    const put = JSON.parse(body) as {
        entry?: { directory?: { root_pubkey?: unknown; home_routes?: unknown } };
    };
    const named = put.entry?.directory?.root_pubkey;
    // The signature proves only self-consistency. This is what binds the record
    // to *this* account rather than to whoever signed it.
    if (typeof named !== "string" || named !== root) {
        throw new RootKeyConflict(
            "the directory record is signed by a different account root than the pinned one",
        );
    }
    const routes = put.entry?.directory?.home_routes;
    const placed: unknown[] = [];
    for (const route of Array.isArray(routes) ? routes : []) {
        // A route carrying its project's placement is held to it, against the
        // project key this root-signed record names (DR-0370).
        const projectKey = (route as { placement?: { project_key?: unknown } } | null)
            ?.placement?.project_key;
        if (typeof projectKey === "string" && !(await (options.placementHolds ?? placementHolds)(route, projectKey))) {
            continue;
        }
        placed.push(route);
    }
    return parseOpaqueHomeRoutes({ routes: placed }, "signed");
}
