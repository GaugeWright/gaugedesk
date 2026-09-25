/** A browser tab may still hold the old account's short-lived Home bearer
 * after another tab changes the shared HttpOnly account cookie. This
 * non-secret selected-account mirror wakes those tabs so they fence their
 * transports and reload from the cookie's newly selected account. */
const KEY = "gw.selected-account.v1";

export interface SelectionSyncHost {
    readonly localStorage: Pick<Storage, "getItem" | "setItem">;
    addEventListener(type: "storage", listener: (event: StorageEvent) => void): void;
    removeEventListener(type: "storage", listener: (event: StorageEvent) => void): void;
}

export function accountSelectionSync(
    host: SelectionSyncHost,
    selected: () => string | null | undefined,
    onChanged: () => void,
): { publish(person: string | null): void; close(): void } {
    let closed = false;
    const onStorage = (event: StorageEvent) => {
        if (closed || event.key !== KEY) return;
        const current = selected();
        if (current !== undefined && event.newValue === (current ?? "")) return;
        closed = true;
        onChanged();
    };
    host.addEventListener("storage", onStorage);
    return {
        publish(person) {
            if (closed) return;
            try {
                const value = person ?? "";
                if (host.localStorage.getItem(KEY) !== value) {
                    host.localStorage.setItem(KEY, value);
                }
            } catch {
                // Storage is a tab wakeup only. The cookie remains authority.
            }
        },
        close() {
            closed = true;
            host.removeEventListener("storage", onStorage);
        },
    };
}
