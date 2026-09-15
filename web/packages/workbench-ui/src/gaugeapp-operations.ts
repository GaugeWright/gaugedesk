import { createComputed, createMemo, createSignal, onCleanup, type Accessor } from "solid-js";

export function gaugeAppContextChanged(): DOMException {
    return new DOMException("This management context is no longer active.", "AbortError");
}

export interface GaugeAppOperation {
    readonly signal: AbortSignal;
    current(): boolean;
    assertCurrent(): void;
    finish(): void;
}

/** Browser request lifetime, not server authority or cancellation of an admitted
 * effect. Each visit has its own identity, including A → B → A. A completed
 * request can own a transient result, but only while that visit remains active. */
export function createGaugeAppOperations(source: Accessor<string | undefined>) {
    const key = createMemo(source);
    const identity = createMemo(() => ({ key: key() }));
    const pending = new Set<AbortController>();
    const [count, setCount] = createSignal(0);
    let disposed = false;
    const cancel = () => {
        for (const request of pending) request.abort();
        pending.clear();
        setCount(0);
    };
    createComputed(() => { identity(); cancel(); });
    onCleanup(() => { disposed = true; cancel(); });

    const begin = (): GaugeAppOperation => {
        const visit = identity();
        if (disposed || visit.key === undefined) throw gaugeAppContextChanged();
        const controller = new AbortController();
        pending.add(controller);
        setCount(pending.size);
        const current = () => !disposed && !controller.signal.aborted && identity() === visit;
        return {
            signal: controller.signal,
            current,
            assertCurrent: () => { if (!current()) throw gaugeAppContextChanged(); },
            finish: () => { if (pending.delete(controller)) setCount(pending.size); },
        };
    };
    return { identity, begin, busy: () => count() > 0 };
}
