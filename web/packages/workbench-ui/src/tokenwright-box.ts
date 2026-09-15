/** Binding a TokenWright session to purpose-built controls.
 *
 * Pinned declarations provide labels; authority enters from exactly one place
 * — the current session grant. A command the grant does not carry never becomes
 * runnable.
 */

import {
    proposeTokenWrightDocumentChange,
    submitTokenWrightCommand,
    type TokenWrightReceipt,
    type TokenWrightSession,
    type RouteJson,
} from "@gaugewright/control-plane-client";
import { TOKENWRIGHT_COMMANDS } from "./tokenwright-environment";

/** Labels for the commands the box advertises, so a granted control reads as
 * itself rather than as its id. Carried data, not authority. */
const LABELS = new Map(TOKENWRIGHT_COMMANDS.map((command) => [command.id, command.label]));

export interface TokenWrightCommandBinding {
    readonly json: RouteJson;
    readonly session: TokenWrightSession;
    /** Read at press time, never captured. */
    readonly revisionOf: (documentId: string) => string | undefined;
    readonly onReceipt?: (receipt: TokenWrightReceipt) => void;
    /** Injectable so a test does not depend on `crypto.randomUUID`. */
    readonly newIdempotencyKey?: () => string;
}

export interface TokenWrightCommandAction {
    readonly label?: string;
    readonly run: () => Promise<void>;
}

function defaultKey(): string {
    return globalThis.crypto?.randomUUID?.() ?? `tokenwright-${Date.now()}-${Math.random()}`;
}

/** The commands this session may actually invoke, ready for the registry.
 *
 * Built from `session.documents[].commands` — the server's own statement of
 * what this actor may run against each document — and never from the carried
 * bundle, which knows what the box *can* do rather than what this session *may*.
 */
export function tokenwrightCommandsFrom(
    binding: TokenWrightCommandBinding,
): Readonly<Record<string, TokenWrightCommandAction>> {
    const commands: Record<string, TokenWrightCommandAction> = {};
    const newKey = binding.newIdempotencyKey ?? defaultKey;

    for (const grant of binding.session.documents) {
        for (const commandId of grant.commands) {
            commands[commandId] = {
                label: LABELS.get(commandId),
                run: async () => {
                    // Read now, not when the binding was built. A revision
                    // captured at build time is stale the moment anything else
                    // changes the document, and the box would answer `conflict`
                    // to a press the operator has no reason to think is stale.
                    const baseRevision = binding.revisionOf(grant.id);
                    if (baseRevision === undefined) {
                        throw new Error(`No revision for ${grant.id}; re-read the document first.`);
                    }
                    const receipt = await submitTokenWrightCommand(
                        binding.json,
                        {
                            session_id: binding.session.id,
                            environment: binding.session.environment,
                            scope: binding.session.scope,
                            document_id: grant.id,
                            command_id: commandId,
                            // TokenWright commands take no parameters at all;
                            // anything parameterised is an edit to `desired`.
                            payload: {},
                            base_revision: baseRevision,
                            client: "browser",
                        },
                        // A fresh key per press. Reusing one across presses
                        // would make the second press return the first receipt
                        // and do nothing, which reads as a dead button.
                        newKey(),
                    );
                    binding.onReceipt?.(receipt);
                    if (receipt.status === "rejected" || receipt.status === "conflict") {
                        throw new Error(
                            receipt.status === "conflict"
                                ? "The document changed while you were looking at it. Re-read it and try again."
                                : `The box refused this: ${receipt.command_id}`,
                        );
                    }
                },
            };
        }
    }
    return commands;
}

/** Select a model, which is a literal edit rather than a command.
 *
 * TokenWright's commands take no parameters, so selecting *which* model edits
 * the document's `desired` block. The TokenWright client refuses this when the
 * grant does not mark the document editable.
 */
export async function setTokenWrightDesired(
    json: RouteJson,
    input: {
        readonly session: TokenWrightSession;
        readonly documentId: string;
        readonly baseRevision: string;
        readonly desired: Record<string, unknown>;
    },
    idempotencyKey?: string,
): Promise<TokenWrightReceipt> {
    // Only the editable block. Echoing live projections creates a race when
    // authentication updates last_used_at between the read and the write.
    // baseRevision guards the editable basis; omitted projections stay owned
    // by the box (upstream d103aa38 / #556).
    return proposeTokenWrightDocumentChange(
        json,
        {
            session: input.session,
            documentId: input.documentId,
            baseRevision: input.baseRevision,
            content: { desired: input.desired },
        },
        idempotencyKey ?? defaultKey(),
    );
}
