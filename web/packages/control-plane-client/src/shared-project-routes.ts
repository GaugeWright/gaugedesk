/**
 * Routes to projects on someone else's Home that this browser accepted an
 * invitation to (DR-0370 §2, DR-0451).
 *
 * A project on a desktop is reached only through that desktop's relay, and a
 * relay locator carries a certificate pin, which a browser honours only from an
 * author it trusts (ADR 0131 §3). For someone else's project that author is the
 * project's own key: the invitation named it, acceptance pinned it here, and a
 * route is kept only while it carries a placement that key signed and a locator
 * signed by the host key the placement names. The Hub never carries one: it
 * writes only into the caller's own account, and its table is no author.
 *
 * The locator rotates daily, so the route is read again from the owning
 * account's directory entries, where that account's computer keeps publishing
 * it. Nothing there is trusted but a placement by the pinned key, and nothing
 * the directory says about any other project is read.
 *
 * The pin is per browser and per person. Another browser has none until the
 * person opens the invitation link there, which an accepted invitation answers
 * again for the account that took it.
 */

import type { HomeId, ProjectId } from "./control-plane-domain";
import { placementVerified } from "./directory-module";
import { parseOpaqueHomeRoute, type OpaqueHomeRoute } from "./home-routing";
import { DIRECTORY_ORIGIN } from "./signed-routes";

/** Every person's pins in this browser, by person, under one key, so a
 * browser that holds none can say so without asking who is signed in. */
const PINS_KEY = "gw.shared-projects.v1";

/** A route as the Home and the directory write it, placement included. */
export interface SharedRouteWire {
    readonly project: string;
    readonly home_id: string;
    readonly endpoint?: string;
    readonly relay?: unknown;
    readonly placement?: { readonly project_key?: unknown } & Record<string, unknown>;
}

/** What acceptance pinned for one project. */
export interface SharedProjectPin {
    readonly project: ProjectId;
    readonly homeId: HomeId;
    /** The project's authority key, which every kept route's placement names. */
    readonly projectKey: string;
    /** The owning account's directory root, where the route is read again. */
    readonly ownerRoot?: string;
    /** The newest route that held. */
    readonly route: SharedRouteWire;
}

export interface SharedRouteOptions {
    /** The signed-in person. Pins are per person, like the root pin. */
    readonly subject: string;
    readonly storage?: Pick<Storage, "getItem" | "setItem">;
    readonly directoryOrigin?: string;
    readonly fetchJson?: (url: string) => Promise<string | null>;
    /** Check a route's placement; the wasm module's, strictly, by default. */
    readonly placementVerified?: (route: unknown, projectKey: string) => Promise<boolean>;
}

type AllPins = Record<string, Record<string, SharedProjectPin>>;

/** Pins this page keeps when the browser will not store them, so the person
 * still reaches what they just accepted. */
let remembered: string | null = null;

function storage(options: { readonly storage?: Pick<Storage, "getItem" | "setItem"> }) {
    if (options.storage) return options.storage;
    try {
        return globalThis.localStorage ?? null;
    } catch {
        return null;
    }
}

function readAll(options: { readonly storage?: Pick<Storage, "getItem" | "setItem"> }): AllPins {
    let raw: string | null = null;
    try {
        raw = storage(options)?.getItem(PINS_KEY) ?? null;
    } catch {
        raw = null;
    }
    raw ??= options.storage ? null : remembered;
    if (!raw) return {};
    try {
        const value = JSON.parse(raw) as unknown;
        return value && typeof value === "object" ? value as AllPins : {};
    } catch {
        return {};
    }
}

function read(options: SharedRouteOptions): Record<string, SharedProjectPin> {
    return readAll(options)[options.subject] ?? {};
}

function write(options: SharedRouteOptions, pins: Record<string, SharedProjectPin>): void {
    const all = readAll(options);
    all[options.subject] = pins;
    const raw = JSON.stringify(all);
    if (!options.storage) remembered = raw;
    try {
        storage(options)?.setItem(PINS_KEY, raw);
    } catch {
        /* kept for this page only */
    }
}

/** Whether this browser keeps any shared project for anyone. A browser that
 * keeps none needs to ask nothing. */
export function holdsSharedProjects(
    options: { readonly storage?: Pick<Storage, "getItem" | "setItem"> } = {},
): boolean {
    return Object.values(readAll(options)).some((pins) => Object.keys(pins).length > 0);
}

/** The projects this person accepted on someone else's Home, in this browser. */
export function sharedProjectPins(options: SharedRouteOptions): SharedProjectPin[] {
    if (!options.subject) return [];
    return Object.values(read(options));
}

/**
 * Pin a project's key and its route, once the route's placement holds against
 * that key. A different key already pinned for the project is not replaced: a
 * changed project key moves only by a hand-over the old one signed (DR-0370 §5).
 */
export async function pinSharedProject(
    options: SharedRouteOptions,
    pin: SharedProjectPin,
): Promise<void> {
    if (!options.subject) throw new Error("no signed-in person to keep this project for");
    const pins = read(options);
    const held = pins[pin.project];
    if (held && held.projectKey !== pin.projectKey) {
        throw new Error(`project ${pin.project} is already pinned to a different key`);
    }
    if (!(await holds(options, pin.route, pin.project, pin.projectKey))) {
        throw new Error(`the route to project ${pin.project} is not signed by its key`);
    }
    pins[pin.project] = pin;
    write(options, pins);
}

async function holds(
    options: SharedRouteOptions,
    route: SharedRouteWire,
    project: string,
    projectKey: string,
): Promise<boolean> {
    if (route.project !== project || route.placement?.project_key !== projectKey) return false;
    return (options.placementVerified ?? placementVerified)(route, projectKey);
}

/** The newest route the owning account's directory entries hold for the
 * project under the pinned key, or `null` when they hold none or cannot be
 * read. */
async function republished(
    options: SharedRouteOptions,
    pin: SharedProjectPin,
): Promise<SharedRouteWire | null> {
    if (!pin.ownerRoot) return null;
    const origin = (options.directoryOrigin ?? DIRECTORY_ORIGIN).replace(/\/+$/, "");
    const fetchJson = options.fetchJson ?? (async (url: string) => {
        const response = await fetch(url, { headers: { accept: "application/json" } });
        if (response.status === 404) return null;
        if (!response.ok) throw new Error(`directory read failed: ${response.status}`);
        return response.text();
    });
    let listed: string | null;
    try {
        listed = await fetchJson(`${origin}/directory/${encodeURIComponent(pin.ownerRoot)}/entries`);
    } catch {
        return null;
    }
    if (!listed) return null;
    let puts: unknown[];
    try {
        const value = JSON.parse(listed) as { puts?: unknown };
        puts = Array.isArray(value.puts) ? value.puts : [];
    } catch {
        return null;
    }
    // Oldest first, so a later computer's entry for the project wins.
    let newest: SharedRouteWire | null = null;
    for (const put of puts) {
        if (typeof put !== "string") continue;
        let routes: unknown;
        try {
            routes = (JSON.parse(put) as { entry?: { directory?: { home_routes?: unknown } } })
                .entry?.directory?.home_routes;
        } catch {
            continue;
        }
        for (const route of Array.isArray(routes) ? routes as SharedRouteWire[] : []) {
            if (route?.project !== pin.project) continue;
            if (await holds(options, route, pin.project, pin.projectKey)) newest = route;
        }
    }
    return newest;
}

/**
 * The routes to every project this person accepted on someone else's Home, as
 * routes whose relay locators may be dialed. Each is read again from the
 * owning account's directory first; when that holds nothing newer the pinned
 * route stands, and the pool's reconnect asks again.
 */
export async function sharedProjectRoutes(options: SharedRouteOptions): Promise<OpaqueHomeRoute[]> {
    const pins = sharedProjectPins(options);
    if (pins.length === 0) return [];
    const routes: OpaqueHomeRoute[] = [];
    let changed = false;
    const next = read(options);
    for (const pin of pins) {
        const fresh = await republished(options, pin);
        const route = fresh ?? pin.route;
        if (fresh && JSON.stringify(fresh) !== JSON.stringify(pin.route)) {
            next[pin.project] = { ...pin, homeId: fresh.home_id as HomeId, route: fresh };
            changed = true;
        }
        try {
            // Held to its placement, so its pin may be honoured here.
            routes.push(parseOpaqueHomeRoute(route, "signed"));
        } catch {
            /* a malformed route reaches nothing; the rest still do */
        }
    }
    if (changed) write(options, next);
    return routes;
}

/**
 * `routes` with every shared project's route in place of any other route for
 * the same project. The Hub's table holds only an endpoint-less row for such a
 * project, which reaches nothing; the shared route is held to the project's own
 * key.
 */
export function withSharedRoutes(
    routes: readonly OpaqueHomeRoute[],
    shared: readonly OpaqueHomeRoute[],
): OpaqueHomeRoute[] {
    const merged = new Map(routes.map((route) => [route.project as string, route]));
    for (const route of shared) merged.set(route.project, route);
    return [...merged.values()];
}
