import { createRoot, createSignal } from "solid-js";
import { describe, expect, it } from "vitest";
import { createGaugeAppResource, refreshGaugeAppResources } from "./gaugeapp-resource";

async function settle() {
    for (let i = 0; i < 15; i++) await Promise.resolve();
}
function deferred<T>() {
    let resolve!: (value: T) => void;
    let reject!: (error: Error) => void;
    const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
    return { promise, resolve, reject };
}

describe("GaugeApp read isolation", () => {
    it("recovers an expired generation by renewing admission before retrying reads", async () => {
        let epoch = "first";
        let dispose!: () => void;
        const requests: string[] = [];
        const state = createRoot((release) => {
            dispose = release;
            const [session, admission] = createGaugeAppResource(() => "person", String, async () => ({ generation: epoch }));
            const [page, pages] = createGaugeAppResource(session, (s) => s.generation, async (s) => {
                requests.push(s.generation);
                if (s.generation !== epoch) throw new Error("expired admission");
                return `page at ${s.generation}`;
            });
            return { session, admission, page, pages };
        });
        await settle();
        expect(state.page()).toBe("page at first");
        epoch = "second";
        await expect(state.pages.refetch()).rejects.toThrow("expired admission");
        expect(state.page()).toBeUndefined();
        await refreshGaugeAppResources(state.admission.refetch, [state.pages.refetch]);
        await settle();
        expect(state.session()?.generation).toBe("second");
        expect(state.page()).toBe("page at second");
        expect(requests.at(-1)).toBe("second");
        dispose();
    });

    it("does not retry dependent reads after admission is revoked", async () => {
        let reads = 0;
        await expect(refreshGaugeAppResources(async () => { throw new Error("revoked"); }, [async () => { reads++; }])).rejects.toThrow("revoked");
        expect(reads).toBe(0);
    });

    it("contains a denied app without breaking other app or work state", async () => {
        let dispose!: () => void;
        const state = createRoot((release) => {
            dispose = release;
            const [selection, select] = createSignal("personal");
            const [commercial] = createGaugeAppResource(selection, String, async () => { throw new Error("403: organization required"); });
            const [account] = createGaugeAppResource(() => "person", String, async () => ({ name: "Avery" }));
            return { commercial, account, select, selection };
        });
        await settle();
        expect(() => state.commercial()).not.toThrow();
        expect(state.commercial()).toBeUndefined();
        expect(state.commercial.error?.message).toContain("403");
        expect(state.account()).toEqual({ name: "Avery" });
        state.select("organization");
        expect(state.selection()).toBe("organization");
        dispose();
    });

    it("hides a previous scope immediately and ignores its late response", async () => {
        const first = deferred<string>();
        const second = deferred<string>();
        let dispose!: () => void;
        const state = createRoot((release) => {
            dispose = release;
            const [scope, select] = createSignal("first");
            const [read] = createGaugeAppResource(scope, String, (id) => id === "first" ? first.promise : second.promise);
            return { read, select };
        });
        state.select("second");
        second.resolve("second-scope data");
        await settle();
        first.resolve("late first-scope data");
        await settle();
        expect(state.read()).toBe("second-scope data");
        dispose();
    });

    it("never carries cached values through a scope change, disabled source or denied reread", async () => {
        let deny = false;
        let dispose!: () => void;
        const next = deferred<string>();
        const state = createRoot((release) => {
            dispose = release;
            const [scope, select] = createSignal<string | null>("first");
            const [read, actions] = createGaugeAppResource(scope, String, async (id) => {
                if (deny) throw new Error("revoked");
                return id === "first" ? "private first-scope data" : next.promise;
            });
            return { read, select, actions };
        });
        await settle();
        expect(state.read()).toBe("private first-scope data");
        state.select("second");
        expect(state.read()).toBeUndefined();
        next.resolve("second-scope data");
        await settle();
        expect(state.read()).toBe("second-scope data");
        deny = true;
        await expect(state.actions.refetch()).rejects.toThrow("revoked");
        expect(state.read()).toBeUndefined();
        expect(state.read.error?.message).toBe("revoked");
        state.select(null);
        expect(state.read()).toBeUndefined();
        expect(state.read.error).toBeUndefined();
        dispose();
    });

    it("returns to live data after a recoverable service failure", async () => {
        let deny = true;
        let dispose!: () => void;
        const state = createRoot((release) => {
            dispose = release;
            return createGaugeAppResource(() => "scope", String, async () => {
                if (deny) throw new Error("temporarily unavailable");
                return "recovered";
            });
        });
        await settle();
        expect(state[0].error).toBeInstanceOf(Error);
        deny = false;
        await state[1].refetch();
        expect(state[0]()).toBe("recovered");
        expect(state[0].error).toBeUndefined();
        dispose();
    });
});
