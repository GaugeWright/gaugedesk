import type { GaugeAppSession, GaugeAppUpdateSnapshot } from "@gaugewright/control-plane-client";

export const GAUGEAPP_UPDATE_INTERVAL_MS = 4_000;
export const GAUGEAPP_UPDATE_RETRY_MS = 8_000;

export interface GaugeAppUpdateScheduler {
    set(callback: () => void, delayMs: number): unknown;
    clear(handle: unknown): void;
}

const browserScheduler: GaugeAppUpdateScheduler = {
    set: (callback, delayMs) => globalThis.setTimeout(callback, delayMs),
    clear: (handle) => globalThis.clearTimeout(handle as ReturnType<typeof setTimeout>),
};

const sessionIdentity = (session: GaugeAppSession) => JSON.stringify([
    session.app,
    session.actor,
    session.scope.kind,
    session.scope.id,
    session.id,
    session.generation,
]);

/**
 * A resumable invalidation reader, not a client-side authority. The cursor moves
 * only after the caller has reread server truth. Restarting under another
 * session invalidates the old run, so an A → B → A navigation cannot apply a
 * late B response to A.
 */
export function createGaugeAppUpdateChannel(options: {
    readonly session: () => GaugeAppSession | undefined;
    readonly read: (session: GaugeAppSession, after: string) => Promise<GaugeAppUpdateSnapshot>;
    readonly apply: (session: GaugeAppSession, snapshot: GaugeAppUpdateSnapshot) => Promise<void>;
    readonly recover?: (session: GaugeAppSession, error: unknown) => Promise<void> | void;
    /** Reports whether the active cursor is waiting on a failed read/refresh.
     * The caller can label its retained page models as stale without treating
     * browser cache as authority. Scope changes and stops clear the label. */
    readonly onDelayedChange?: (delayed: boolean) => void;
    readonly scheduler?: GaugeAppUpdateScheduler;
    readonly intervalMs?: number;
    readonly retryMs?: number;
}) {
    const scheduler = options.scheduler ?? browserScheduler;
    const intervalMs = options.intervalMs ?? GAUGEAPP_UPDATE_INTERVAL_MS;
    const retryMs = options.retryMs ?? GAUGEAPP_UPDATE_RETRY_MS;
    let timer: unknown;
    let run = 0;
    let cursor: string | undefined;
    let identity: string | undefined;
    let disposed = false;

    const clear = () => {
        if (timer !== undefined) scheduler.clear(timer);
        timer = undefined;
    };
    const current = (expectedRun: number, expectedIdentity: string) => {
        const session = options.session();
        return !disposed
            && run === expectedRun
            && session !== undefined
            && sessionIdentity(session) === expectedIdentity;
    };
    const schedule = (expectedRun: number, delayMs: number) => {
        clear();
        timer = scheduler.set(() => { void check(expectedRun); }, delayMs);
    };
    const check = async (expectedRun = run): Promise<void> => {
        clear();
        const session = options.session();
        if (disposed || expectedRun !== run || !session || !cursor || !identity) return;
        const expectedIdentity = identity;
        try {
            const snapshot = await options.read(session, cursor);
            if (!current(expectedRun, expectedIdentity)) return;
            if (snapshot.cursor !== cursor || snapshot.invalidations.length > 0) {
                await options.apply(session, snapshot);
                if (!current(expectedRun, expectedIdentity)) return;
                cursor = snapshot.cursor;
            }
            options.onDelayedChange?.(false);
            schedule(expectedRun, intervalMs);
        } catch (error) {
            if (!current(expectedRun, expectedIdentity)) return;
            options.onDelayedChange?.(true);
            try {
                await options.recover?.(session, error);
            } catch {
                // Recovery failure changes no cursor. A later admitted retry may
                // continue from the same position without inventing completion.
            }
            if (current(expectedRun, expectedIdentity)) schedule(expectedRun, retryMs);
        }
    };
    const start = () => {
        run += 1;
        clear();
        options.onDelayedChange?.(false);
        const session = options.session();
        identity = session ? sessionIdentity(session) : undefined;
        cursor = session?.update_cursor;
        if (session && cursor) schedule(run, intervalMs);
    };
    const stop = () => {
        run += 1;
        clear();
        options.onDelayedChange?.(false);
        identity = undefined;
        cursor = undefined;
    };
    const dispose = () => {
        disposed = true;
        stop();
    };

    return {
        start,
        stop,
        dispose,
        checkNow: () => check(run),
        cursor: () => cursor,
    };
}
