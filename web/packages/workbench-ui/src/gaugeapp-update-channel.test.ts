import { describe, expect, it, vi } from "vitest";
import type { GaugeAppSession, GaugeAppUpdateSnapshot } from "@gaugewright/control-plane-client";
import { createGaugeAppUpdateChannel, type GaugeAppUpdateScheduler } from "./gaugeapp-update-channel";

const session = (scope: string, cursor: string): GaugeAppSession => ({
    id: `session:${scope}`,
    generation: "authorization:1",
    app: "administration",
    scope: { kind: "tenant", id: scope },
    actor: "person:admin",
    capabilities: [],
    pages: [],
    commands: [],
    update_cursor: cursor,
});

function manualScheduler() {
    const pending = new Map<number, () => void>();
    let next = 0;
    const scheduler: GaugeAppUpdateScheduler = {
        set: (callback) => { const id = ++next; pending.set(id, callback); return id; },
        clear: (handle) => { pending.delete(handle as number); },
    };
    return { scheduler, pending, runNext: () => {
        const item = pending.entries().next().value as [number, () => void] | undefined;
        if (!item) throw new Error("no scheduled update");
        pending.delete(item[0]);
        item[1]();
    } };
}

const changed = (cursor: string): GaugeAppUpdateSnapshot => ({
    cursor,
    invalidations: [{ page_id: "people", resource_basis: `basis:${cursor}` }],
});

describe("GaugeApp update channel", () => {
    it("starts at the admitted cursor and advances only after server truth is reread", async () => {
        const clock = manualScheduler();
        let admitted = session("A", "cursor:1");
        const read = vi.fn(async (_admitted: GaugeAppSession, _after: string) => changed("cursor:2"));
        const apply = vi.fn(async () => undefined);
        const channel = createGaugeAppUpdateChannel({ session: () => admitted, read, apply, scheduler: clock.scheduler });
        channel.start();
        expect(clock.pending.size).toBe(1);
        clock.runNext();
        await vi.waitFor(() => expect(apply).toHaveBeenCalledOnce());
        expect(read).toHaveBeenCalledWith(admitted, "cursor:1");
        expect(channel.cursor()).toBe("cursor:2");
        expect(clock.pending.size).toBe(1);
    });

    it("replays the old cursor when applying an invalidation fails", async () => {
        const clock = manualScheduler();
        const admitted = session("A", "cursor:1");
        const read = vi.fn(async (_admitted: GaugeAppSession, _after: string) => changed("cursor:2"));
        const apply = vi.fn()
            .mockRejectedValueOnce(new Error("refresh failed"))
            .mockResolvedValueOnce(undefined);
        const channel = createGaugeAppUpdateChannel({ session: () => admitted, read, apply, scheduler: clock.scheduler });
        channel.start();
        clock.runNext();
        await vi.waitFor(() => expect(clock.pending.size).toBe(1));
        expect(channel.cursor()).toBe("cursor:1");
        clock.runNext();
        await vi.waitFor(() => expect(apply).toHaveBeenCalledTimes(2));
        expect(read.mock.calls.map((call) => call[1])).toEqual(["cursor:1", "cursor:1"]);
        expect(channel.cursor()).toBe("cursor:2");
    });

    it("drops a late result after scope changes, including A to B to A", async () => {
        const clock = manualScheduler();
        let admitted = session("A", "cursor:A1");
        let resolve!: (snapshot: GaugeAppUpdateSnapshot) => void;
        const read = vi.fn((_admitted: GaugeAppSession, _after: string) => new Promise<GaugeAppUpdateSnapshot>((done) => { resolve = done; }));
        const apply = vi.fn(async () => undefined);
        const channel = createGaugeAppUpdateChannel({ session: () => admitted, read, apply, scheduler: clock.scheduler });
        channel.start();
        clock.runNext();
        admitted = session("B", "cursor:B1");
        channel.start();
        admitted = session("A", "cursor:A2");
        channel.start();
        resolve(changed("cursor:A-late"));
        await Promise.resolve();
        await Promise.resolve();
        expect(apply).not.toHaveBeenCalled();
        expect(channel.cursor()).toBe("cursor:A2");
        expect(clock.pending.size).toBe(1);
    });

    it("keeps the cursor on read failure and delegates admission recovery", async () => {
        const clock = manualScheduler();
        const admitted = session("A", "cursor:1");
        const refusal = new Error("unauthorized");
        const recover = vi.fn(async () => undefined);
        const onDelayedChange = vi.fn();
        const channel = createGaugeAppUpdateChannel({
            session: () => admitted,
            read: async () => { throw refusal; },
            apply: async () => undefined,
            recover,
            onDelayedChange,
            scheduler: clock.scheduler,
        });
        channel.start();
        clock.runNext();
        await vi.waitFor(() => expect(recover).toHaveBeenCalledWith(admitted, refusal));
        expect(channel.cursor()).toBe("cursor:1");
        expect(onDelayedChange).toHaveBeenLastCalledWith(true);
        expect(clock.pending.size).toBe(1);
    });

    it("labels retained data delayed until the same cursor succeeds", async () => {
        const clock = manualScheduler();
        const admitted = session("A", "cursor:1");
        const onDelayedChange = vi.fn();
        const read = vi.fn()
            .mockRejectedValueOnce(new Error("temporarily unavailable"))
            .mockResolvedValueOnce({ cursor: "cursor:1", invalidations: [] });
        const channel = createGaugeAppUpdateChannel({
            session: () => admitted,
            read,
            apply: async () => undefined,
            onDelayedChange,
            scheduler: clock.scheduler,
        });
        channel.start();
        expect(onDelayedChange).toHaveBeenLastCalledWith(false);
        clock.runNext();
        await vi.waitFor(() => expect(onDelayedChange).toHaveBeenLastCalledWith(true));
        clock.runNext();
        await vi.waitFor(() => expect(onDelayedChange).toHaveBeenLastCalledWith(false));
        expect(channel.cursor()).toBe("cursor:1");

        channel.stop();
        expect(onDelayedChange).toHaveBeenLastCalledWith(false);
    });
});
