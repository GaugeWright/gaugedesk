/**
 * The generated wasm tunnel module (DESK-7).
 *
 * Declared rather than inferred: `scripts/build-wasm.sh` produces it and
 * it is gitignored, so a fresh checkout has no file to infer from. Declaring the
 * shape keeps the registration typechecked — if the Rust binding's exported
 * names change, this stops compiling instead of failing in a browser.
 */
declare module "@gaugewright/control-plane-client/generated/tunnel.js" {
    export default function init(input?: unknown): Promise<unknown>;
    export class BrowserTunnel {
        constructor(homeFingerprint: string);
        static relayHandshake(
            endpoint: string,
            handle: string,
            proof: string,
            epoch: number,
        ): Uint8Array;
        receiveFrame(frame: Uint8Array): void;
        sendRequest(method: string, path: string, body?: string): void;
        takeOutgoing(): Uint8Array;
        pollStatus(): number | undefined;
        takeBody(): string;
        isHandshaking(): boolean;
        isPaired(): boolean;
    }
}

/**
 * The generated directory verifier (DESK-5g). Declared for the same reason as
 * the tunnel above: gitignored, so a fresh checkout has nothing to infer from.
 */
declare module "@gaugewright/control-plane-client/generated/directory.js" {
    export default function init(input?: unknown): Promise<unknown>;
    export function verify_signed_put_json(json: string): boolean;
}
