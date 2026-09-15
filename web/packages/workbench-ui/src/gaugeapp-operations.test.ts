import { createRoot, createSignal } from "solid-js";
import { describe, expect, it } from "vitest";
import { createGaugeAppOperations } from "./gaugeapp-operations";

describe("GaugeApp operation lifetime", () => {
    it("invalidates immediately, aborts the browser ceremony, and never revives an old visit", () => {
        createRoot((dispose) => {
            const [key, select] = createSignal<string | undefined>("A");
            const requests = createGaugeAppOperations(key);
            const first = requests.begin();
            expect(requests.busy()).toBe(true);
            select("B");
            expect(first.signal.aborted).toBe(true);
            expect(first.current()).toBe(false);
            expect(requests.busy()).toBe(false);
            select("A");
            expect(first.current()).toBe(false);
            const next = requests.begin();
            first.finish();
            expect(requests.busy()).toBe(true);
            select(undefined);
            expect(next.current()).toBe(false);
            expect(() => requests.begin()).toThrow("no longer active");
            dispose();
        });
    });

    it("keeps same-context results through refresh, but drops their authority on disposal", () => {
        let dispose!: () => void;
        const requests = createRoot((release) => {
            dispose = release;
            return createGaugeAppOperations(() => "same admitted context");
        });
        const a = requests.begin();
        const b = requests.begin();
        a.finish();
        expect(requests.busy()).toBe(true);
        b.finish();
        expect(requests.busy()).toBe(false);
        expect(a.current()).toBe(true);
        dispose();
        expect(a.current()).toBe(false);
        expect(() => b.assertCurrent()).toThrow("no longer active");
    });
});
