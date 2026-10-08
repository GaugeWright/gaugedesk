import { describe, expect, it } from "vitest";
import { coalescedRead } from "./TaskBar";

describe("the task bar's coalesced reads (WS-891)", () => {
    it("answers every call made during a read with one read begun after it", async () => {
        const releases: (() => void)[] = [];
        let started = 0;
        const read = coalescedRead(() => {
            const index = started++;
            return new Promise<number>((resolve) => releases.push(() => resolve(index)));
        });
        const first = read();
        // Five refreshes while the first read runs.
        const later = Array.from({ length: 5 }, () => read());
        expect(started).toBe(1);
        releases[0]!();
        await expect(first).resolves.toBe(0);
        await new Promise((resolve) => setTimeout(resolve, 0));
        expect(started).toBe(2);
        releases[1]!();
        await expect(Promise.all(later)).resolves.toEqual([1, 1, 1, 1, 1]);
        // Idle again: the next call reads at once.
        const next = read();
        expect(started).toBe(3);
        releases[2]!();
        await expect(next).resolves.toBe(2);
    });

    it("reads again after a read that failed", async () => {
        let calls = 0;
        const read = coalescedRead(async () => {
            calls += 1;
            if (calls === 1) throw new Error("Home unreachable");
            return "read";
        });
        const failed = read();
        const retried = read();
        await expect(failed).rejects.toThrow("Home unreachable");
        await expect(retried).resolves.toBe("read");
        expect(calls).toBe(2);
    });
});
