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
