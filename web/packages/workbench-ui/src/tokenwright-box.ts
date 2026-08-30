/** Binding a TokenWright session to the controls a View can run.
 *
 * The bundle describes presentation; this is where authority enters, and it
 * enters from exactly one place — the session grant. A command the grant does
 * not carry never becomes runnable, and the renderer draws it as an inert
 * "Unavailable in this session" control rather than a button that fails when
 * pressed.
 */

import {
    proposeManagementDocumentChange,
    submitManagementCommand,
    type ManagementEnvironmentReceipt,
    type ManagementEnvironmentSession,
    type RouteJson,
} from "@gaugewright/control-plane-client";
import type { EnvironmentViewCommand, EnvironmentViewRegistry } from "./EnvironmentDocumentView";
import { TOKENWRIGHT_COMMANDS } from "./tokenwright-environment";

/** Labels for the commands the box advertises, so a granted control reads as
 * itself rather than as its id. Carried data, not authority. */
const LABELS = new Map(TOKENWRIGHT_COMMANDS.map((command) => [command.id, command.label]));

export interface TokenWrightCommandBinding {
    readonly json: RouteJson;
    readonly session: ManagementEnvironmentSession;
    /** Read at press time, never captured. */
    readonly revisionOf: (documentId: string) => string | undefined;
    readonly onReceipt?: (receipt: ManagementEnvironmentReceipt) => void;
    /** Injectable so a test does not depend on `crypto.randomUUID`. */
    readonly newIdempotencyKey?: () => string;
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
): Readonly<Record<string, EnvironmentViewCommand>> {
    const commands: Record<string, EnvironmentViewCommand> = {};
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
                    const receipt = await submitManagementCommand(
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
 * TokenWright's commands take no parameters and the View vocabulary cannot bind
 * one, so the only way to say *which* model is to edit the document's `desired`
 * block. The guard in `proposeManagementDocumentChange` refuses this when the
 * grant does not mark the document editable.
 */
export async function setTokenWrightDesired(
    json: RouteJson,
    input: {
        readonly session: ManagementEnvironmentSession;
        readonly documentId: string;
        readonly baseRevision: string;
        readonly content: Record<string, unknown>;
        readonly desired: Record<string, unknown>;
    },
    idempotencyKey?: string,
): Promise<ManagementEnvironmentReceipt> {
    // The whole document goes back with only `desired` changed. The box refuses
    // a body that alters any projected field rather than applying it partially,
    // so sending a trimmed document would be rejected, not helpfully merged.
    return proposeManagementDocumentChange(
        json,
        {
            session: input.session,
            documentId: input.documentId,
            baseRevision: input.baseRevision,
            content: { ...input.content, desired: input.desired },
            client: "edit",
        },
        idempotencyKey ?? defaultKey(),
    );
}

/** The registry a TokenWright panel hands the shared renderer. */
export function tokenwrightRegistryFor(
    binding: TokenWrightCommandBinding,
    base: Omit<EnvironmentViewRegistry, "commands">,
): EnvironmentViewRegistry {
    return { ...base, commands: tokenwrightCommandsFrom(binding) };
}
