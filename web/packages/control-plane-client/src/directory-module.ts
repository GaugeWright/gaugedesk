/**
 * Wiring the directory verifier's wasm module (DESK-5g, ADR 0133).
 *
 * Same shape and same reasons as `tunnel-module.ts`: the module is a build
 * artifact, gitignored, so this package registers a loader rather than importing
 * it. What differs is the failure posture, and the difference matters.
 *
 * A missing tunnel makes a relay-only Home unreachable, which is loud. A missing
 * verifier would make every signed record **unverifiable**, and the fallback for
 * an unverifiable record is the hub table — so an absent module would quietly
 * downgrade every account to endpoint-only reachability and look like nothing
 * had happened. That is the shape of a check that fails open, so absence is
 * reported as absence and never as a verification result: `verifySignedPut`
 * throws rather than returning `false`, and the caller distinguishes *"this
 * record is forged"* from *"this build cannot tell"*.
 */

/** What the generated module exports. Declared so a change to the Rust
 * binding's names is a type error here rather than a runtime failure. */
export interface DirectoryModule {
    /** `gaugedesk_directory_protocol::verify_signed_put_json`. */
    verify_signed_put_json(json: string): boolean;
    /** `gaugedesk_directory_protocol::root_chain_reaches_json` (DR-0361).
     * Optional so a module built before it existed still verifies records; it
     * then follows no hand-over, and a changed root stays an alarm. */
    root_chain_reaches_json?(pinned: string, current: string, chainJson: string): boolean;
    /** `gaugedesk_directory_protocol::placement_verifies_json` (DR-0370). Optional
     *  so a module built before it still verifies records; a route's placement is
     *  then left to the root signature over the record that carries it. */
    placement_verifies_json?(routeJson: string, trustedProjectKey: string): boolean;
}

let loader: (() => Promise<DirectoryModule>) | null = null;
let loaded: Promise<DirectoryModule> | null = null;

/** Register how to obtain the verifier. The app calls this once with an import
 * of the generated artifact; a test calls it with a stand-in. */
export function setDirectoryModuleLoader(next: (() => Promise<DirectoryModule>) | null): void {
    loader = next;
    loaded = null;
}

/** Whether this build can verify a signed record at all. */
export function directoryVerifierAvailable(): boolean {
    return loader !== null;
}

async function load(): Promise<DirectoryModule> {
    if (!loader) {
        throw new Error(
            "the directory verifier is not available: no module loader registered "
                + "(run scripts/build-wasm.sh and register it at startup)",
        );
    }
    loaded ??= loader().catch((error) => {
        loaded = null;
        throw new Error(
            `the directory verifier module failed to load: ${
                error instanceof Error ? error.message : String(error)
            }`,
        );
    });
    return loaded;
}

/**
 * Verify a signed directory put against the root it names.
 *
 * This proves only **self-consistency** — that whoever signed the record holds
 * the key the record claims. Binding it to *this* account is the caller's job,
 * by comparing that root against the pinned one. Throws when the module is
 * absent, so a build that cannot verify never reports a record as unverified.
 */
export async function verifySignedPut(json: string): Promise<boolean> {
    return (await load()).verify_signed_put_json(json);
}

/**
 * Whether signed hand-overs in `chain` lead from the `pinned` root to `current`
 * (DR-0361). `false` from a module too old to say, so an unfollowed change
 * stays the alarm it always was.
 */
export async function rootChainReaches(
    pinned: string,
    current: string,
    chain: readonly unknown[],
): Promise<boolean> {
    const module = await load();
    return module.root_chain_reaches_json?.(pinned, current, JSON.stringify(chain)) ?? false;
}

/**
 * Whether a route's placement holds against the project key the reader trusts
 * (DR-0370). `true` from a module too old to check, since the root signature
 * over the record carrying the route already vouches for it.
 */
export async function placementHolds(route: unknown, trustedProjectKey: string): Promise<boolean> {
    const module = await load();
    return module.placement_verifies_json?.(JSON.stringify(route), trustedProjectKey) ?? true;
}

/**
 * Whether a route's placement holds against `trustedProjectKey`, for a route
 * only its placement vouches for: a project on someone else's Home, which no
 * root this browser trusts signed (DR-0370 §2). Unlike [`placementHolds`] a
 * build that cannot check says `false`, because nothing else stands behind
 * the route's certificate pin.
 */
export async function placementVerified(route: unknown, trustedProjectKey: string): Promise<boolean> {
    if (!directoryVerifierAvailable() || !trustedProjectKey) return false;
    try {
        const module = await load();
        return module.placement_verifies_json?.(JSON.stringify(route), trustedProjectKey) ?? false;
    } catch {
        return false;
    }
}
