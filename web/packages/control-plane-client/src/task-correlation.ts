/** A fact from the addressed task authority, never inferred from HTTP status. */
export interface TaskCorrelation {
    readonly client_request_id: string;
    readonly chat_id: string;
    readonly home_id?: string;
    readonly actor_id?: string;
    readonly outcome: "accepted" | "settled" | "refused";
}

/** Legacy responses carry no correlation. Malformed/unrelated facts do not retire work. */
export function taskCorrelation(value: unknown): TaskCorrelation | null {
    if (!value || typeof value !== "object") return null;
    const source = value as Record<string, unknown>;
    if (source.correlation) {
        const correlation = source.correlation;
        if (!correlation || typeof correlation !== "object") return null;
        return parseCorrelation(correlation as Record<string, unknown>);
    }
    return parseCorrelation(source, source.type === "user" ? "accepted" : source.outcome);
}

function parseCorrelation(source: Record<string, unknown>, outcome: unknown = source.outcome): TaskCorrelation | null {
    if (typeof source.client_request_id !== "string" || !source.client_request_id ||
        typeof source.chat_id !== "string" || !source.chat_id ||
        (outcome !== "accepted" && outcome !== "settled" && outcome !== "refused")) return null;
    const hasAuthor = source.home_id !== undefined || source.actor_id !== undefined;
    if (hasAuthor && (typeof source.home_id !== "string" || !source.home_id
        || typeof source.actor_id !== "string" || !source.actor_id)) return null;
    return { client_request_id: source.client_request_id, chat_id: source.chat_id, outcome,
        ...(hasAuthor ? { home_id: source.home_id as string, actor_id: source.actor_id as string } : {}) };

}
