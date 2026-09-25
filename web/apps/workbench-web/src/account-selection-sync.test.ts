import { describe, expect, it } from "vitest";
import { accountSelectionSync, type SelectionSyncHost } from "./account-selection-sync";

function tabs(): [SelectionSyncHost, SelectionSyncHost] {
    const values = new Map<string, string>();
    const listeners = [new Set<(event: StorageEvent) => void>(), new Set<(event: StorageEvent) => void>()];
    return [0, 1].map((index): SelectionSyncHost => ({
        localStorage: {
            getItem: (key) => values.get(key) ?? null,
            setItem: (key, value) => {
                values.set(key, value);
                for (const listener of listeners[1 - index]) {
                    listener({ key, newValue: value } as StorageEvent);
                }
            },
        },
        addEventListener: (_type, listener) => { listeners[index].add(listener); },
        removeEventListener: (_type, listener) => { listeners[index].delete(listener); },
    })) as [SelectionSyncHost, SelectionSyncHost];
}

describe("browser account selection across tabs", () => {
    it("wakes the tab holding another account, without treating storage as authority", () => {
        const [first, second] = tabs();
        let firstSelected = "account:alice";
        let secondSelected = "account:alice";
        let firstWakes = 0;
        let secondWakes = 0;
        const a = accountSelectionSync(first, () => firstSelected, () => { firstWakes++; });
        const b = accountSelectionSync(second, () => secondSelected, () => { secondWakes++; });
        a.publish(firstSelected);
        expect(secondWakes).toBe(0);
        secondSelected = "account:bob";
        b.publish(secondSelected);
        expect(firstWakes).toBe(1);
        expect(secondWakes).toBe(0);
        // A stale tab is already fencing/reloading and must not broadcast its
        // old selection back over the server's new cookie.
        a.publish(firstSelected);
        expect(secondWakes).toBe(0);
        a.close();
        b.close();
    });

    it("wakes a tab whose roster has not loaded yet", () => {
        const [first, second] = tabs();
        let wakes = 0;
        const a = accountSelectionSync(first, () => undefined, () => { wakes++; });
        const b = accountSelectionSync(second, () => "account:bob", () => undefined);
        b.publish("account:bob");
        expect(wakes).toBe(1);
        a.close();
        b.close();
    });
});
