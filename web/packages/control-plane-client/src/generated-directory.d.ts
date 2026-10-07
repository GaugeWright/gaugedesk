/**
 * The generated directory verifier (DESK-5g, ADR 0133).
 *
 * Declared rather than inferred: `scripts/build-wasm.sh` produces it and it is
 * gitignored, so a fresh checkout has nothing to infer from. It lives here,
 * beside `directory-module.ts`, because more than one app registers it — desk
 * and native mobile both verify the root-signed record — and a module declared
 * once in each app would be two declarations of one module in the whole-tree
 * typecheck.
 */
declare module "@gaugewright/control-plane-client/generated/directory.js" {
    export default function init(input?: unknown): Promise<unknown>;
    export function verify_signed_put_json(json: string): boolean;
}
