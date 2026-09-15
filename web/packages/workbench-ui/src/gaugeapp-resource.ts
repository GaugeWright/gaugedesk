import { createResource, type Accessor } from "solid-js";

export interface GaugeAppResource<T> extends Accessor<T | undefined> {
    readonly error: Error | undefined;
    readonly loading: boolean;
}

/** Renew admission before retrying reads. Reusing the refused generation can
 * never recover from a server capability change, and a denied renewal must
 * not issue more reads using the old session. */
export async function refreshGaugeAppResources(
    renewSession: () => Promise<unknown>,
    readers: readonly (() => Promise<unknown>)[],
): Promise<void> {
    await renewSession();
    await Promise.all(readers.map((read) => read()));
}

/** A failed management read is a local state, not an exception through the
 * workbench. Cached results are visible only under the exact request identity;
 * selecting another scope or losing admission hides the old result at once. */
export function createGaugeAppResource<S, T>(
    source: Accessor<S | null | undefined | false>,
    key: (source: S) => string,
    fetcher: (source: S) => Promise<T>,
): readonly [GaugeAppResource<T>, { readonly refetch: () => Promise<T | undefined> }] {
    type Result = { key: string; value: T; error?: never } | { key: string; value?: never; error: Error };
    const [resource, actions] = createResource(source, async (request): Promise<Result> => {
        const requestKey = key(request);
        try {
            return { key: requestKey, value: await fetcher(request) };
        } catch (error) {
            return { key: requestKey, error: error instanceof Error ? error : new Error(String(error)) };
        }
    });
    const current = (): Result | undefined => {
        const request = source();
        if (request === null || request === undefined || request === false) return undefined;
        const result = resource();
        return result?.key === key(request) ? result : undefined;
    };
    const read = Object.defineProperties(() => current()?.value, {
        error: { get: () => current()?.error },
        loading: { get: () => resource.loading },
    }) as GaugeAppResource<T>;
    return [read, {
        refetch: async () => {
            const result = await actions.refetch();
            // Explicit action callers still see failure and can report it.
            if (result?.error) throw result.error;
            return result?.value;
        },
    }];
}
