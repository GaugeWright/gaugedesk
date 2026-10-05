/** Secret-free outcome projection, shared by native capture and release validation. */
export interface ChatAcceptanceInput {
    transcript: unknown;
    session: unknown;
    context: unknown;
    file: string;
}
function record(value: unknown): Record<string, unknown> {
    return value !== null && typeof value === "object" ? value as Record<string, unknown> : {};
}
export function admittedChatObservation(input: ChatAcceptanceInput) {
    const session = record(input.session);
    const context = record(input.context);
    if (session.linked !== true || session.expired !== false || typeof session.person !== "string" || !session.person)
        throw new Error("the installed app must have a current signed-in account");
    if (typeof context.provider !== "string" || /fake|scripted|test/i.test(context.provider)
        || typeof context.model !== "string" || !context.model || typeof context.used_tokens !== "number" || context.used_tokens <= 0)
        throw new Error("the turn has no measured real-provider context");
    if (!Array.isArray(input.transcript)) throw new Error("the acceptance chat has no durable transcript");
    if (typeof input.file !== "string" || !input.file) throw new Error("select the synthetic file for acceptance");
    const transcript = input.transcript.map(record);
    if (transcript.some((entry) => entry.type === "error" || entry.type === "blocked"
        || (entry.type === "toolresult" && entry.ok !== true)))
        throw new Error("the acceptance chat contains a failed turn or tool");
    const completed: number[] = [];
    const writes: number[] = [];
    let user: number | undefined;
    let write: number | undefined;
    let tools = 0;
    const entryId = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value > 0;
    for (const entry of transcript) {
        if (entry.origin !== undefined) throw new Error("acceptance requires a fresh chat without inherited turns");
        if (entry.type === "user") {
            if (user !== undefined || !entryId(entry.entry_id)) throw new Error("each acceptance prompt must have a completed turn");
            user = entry.entry_id;
            write = undefined;
        } else if (entry.type === "toolresult" && entry.ok === true) {
            tools++;
            if (user !== undefined && (entry.tool === "write" || entry.tool === "edit")
                && (entry.canonical_target ?? entry.target) === input.file && entryId(entry.entry_id)) write = entry.entry_id;
        } else if (entry.type === "admitted" && entry.kind === "run" && entry.text === "run → Completed") {
            const receipt = record(entry.workspace_change);
            if (user === undefined || !entryId(entry.entry_id) || !entryId(write) || write <= user || write >= entry.entry_id
                || receipt.user_entry_id !== user || !entryId(receipt.summary_entry_id) || receipt.summary_entry_id <= entry.entry_id
                || typeof receipt.changed_count !== "number" || !Number.isSafeInteger(receipt.changed_count) || receipt.changed_count < 1)
                throw new Error("each completed turn must have an admitted workspace change and a successful write to the selected file");
            completed.push(entry.entry_id);
            writes.push(write);
            user = undefined;
            write = undefined;
        }
    }
    if (user !== undefined || completed.length < 1 || new Set(completed).size !== completed.length || new Set(writes).size !== writes.length)
        throw new Error("each acceptance prompt must have a completed turn with distinct durable entry IDs");
    return { account: session.person, completed_turns: completed, successful_writes: writes, successful_tools: tools,
        provider: context.provider, model: context.model, input_tokens: context.used_tokens };
}

export async function chatAcceptanceEvidence(
    input: ChatAcceptanceInput & { chat: string; file: string; content: string },
    nativeHash?: (text: string) => Promise<string>,
) {
    const observed = admittedChatObservation(input);
    const hash = nativeHash ?? (async (text: string) => {
        const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
        return [...new Uint8Array(bytes)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
    });
    return {
        schema: "gaugedesk.chat-acceptance-observation.v1",
        chat_sha256: await hash(input.chat), file_path_sha256: await hash(input.file),
        observed: {
            captured_at: new Date().toISOString(),
            account_sha256: await hash(observed.account), transcript_sha256: await hash(JSON.stringify(input.transcript)),
            completed_turns: observed.completed_turns, successful_writes: observed.successful_writes, successful_tools: observed.successful_tools,
            file_sha256: await hash(input.content), provider: observed.provider, model: observed.model,
            input_tokens: observed.input_tokens,
        },
    };
}
