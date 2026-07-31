import type { EngagementId } from "./control-plane-domain";
import type { WorkbenchTransport } from "./control-plane-workbench";
import { newIdempotencyKey } from "./control-plane-transport";

export type BackgroundCommandStatus =
    | "queued"
    | "running"
    | "awaiting_human"
    | "cancel_requested"
    | "canceled"
    | "completed"
    | "failed";

export interface BackgroundCommand {
    readonly id: string;
    readonly chatId: EngagementId;
    readonly actor: string;
    readonly runAt: number;
    readonly status: BackgroundCommandStatus;
    readonly attempt: number;
    readonly error: string | null;
}

function parse(raw: unknown): BackgroundCommand {
    const value = (raw ?? {}) as Record<string, unknown>;
    if (
        typeof value.id !== "string" ||
        typeof value.chat_id !== "string" ||
        typeof value.actor !== "string" ||
        typeof value.run_at !== "number" ||
        typeof value.attempt !== "number" ||
        !["queued", "running", "awaiting_human", "cancel_requested", "canceled", "completed", "failed"].includes(
            String(value.status),
        )
    ) {
        throw new Error("background command response is malformed");
    }
    return {
        id: value.id,
        chatId: value.chat_id as EngagementId,
        actor: value.actor,
        runAt: value.run_at,
        status: value.status as BackgroundCommandStatus,
        attempt: value.attempt,
        error: typeof value.error === "string" ? value.error : null,
    };
}

export async function queueBackgroundCommand(
    transport: WorkbenchTransport,
    chat: EngagementId,
    prompt: string,
    runAt?: number,
    key = newIdempotencyKey(),
): Promise<BackgroundCommand> {
    const body = runAt === undefined ? { prompt } : { prompt, run_at: runAt };
    const raw = (await transport.json("POST", `/chats/${chat}/background`, body, {
        idempotencyKey: key,
    })) as { command?: unknown } & Record<string, unknown>;
    return parse(raw.command ?? raw);
}

export async function listBackgroundCommands(
    transport: WorkbenchTransport,
    chat: EngagementId,
): Promise<BackgroundCommand[]> {
    const raw = (await transport.json("GET", `/chats/${chat}/background`)) as {
        commands?: unknown[];
    };
    return (raw.commands ?? []).map(parse);
}

export async function cancelBackgroundCommand(
    transport: WorkbenchTransport,
    id: string,
): Promise<BackgroundCommand> {
    return parse(await transport.json("DELETE", `/background/${encodeURIComponent(id)}`));
}
