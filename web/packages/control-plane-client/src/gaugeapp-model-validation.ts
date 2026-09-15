/** Wire validation, not defaults. A malformed required field must not become
 * an empty management page. Errors name fields only, never response values. */
export type ModelReader<T> = (value: unknown, path: string) => T;
export const invalidModel = (path: string): never => {
    throw new Error(`GaugeApp response is incompatible at ${path}. Refresh or update GaugeDesk.`);
};
export const objectValue = (value: unknown, path: string): Record<string, unknown> => {
    if (!value || typeof value !== "object" || Array.isArray(value)) return invalidModel(path);
    return value as Record<string, unknown>;
};
export const stringValue: ModelReader<string> = (value, path) =>
    typeof value === "string" ? value : invalidModel(path);
export const booleanValue: ModelReader<boolean> = (value, path) =>
    typeof value === "boolean" ? value : invalidModel(path);
export const integerValue: ModelReader<number> = (value, path) =>
    typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : invalidModel(path);
export const nullable = <T>(read: ModelReader<T>): ModelReader<T | null> =>
    (value, path) => value === null ? null : read(value, path);
export const arrayOf = <T>(read: ModelReader<T>): ModelReader<readonly T[]> => (value, path) => {
    if (!Array.isArray(value)) return invalidModel(path);
    return value.map((entry, index) => read(entry, `${path}[${index}]`));
};
export const oneOf = <const T extends readonly string[]>(...values: T): ModelReader<T[number]> =>
    (value, path) => typeof value === "string" && values.includes(value) ? value : invalidModel(path);
export const shape = <T extends Record<string, ModelReader<unknown>>>(fields: T): ModelReader<{
    readonly [K in keyof T]: ReturnType<T[K]>;
}> => (value, path) => {
    const source = objectValue(value, path);
    // Explicit construction also keeps unknown wire fields out of consumers.
    return Object.fromEntries(Object.entries(fields).map(([key, read]) =>
        [key, read(source[key], `${path}.${key}`)])) as { readonly [K in keyof T]: ReturnType<T[K]> };
};
export type GaugeAppJsonValue = null | boolean | number | string | readonly GaugeAppJsonValue[] | { readonly [key: string]: GaugeAppJsonValue };
export const jsonValue: ModelReader<GaugeAppJsonValue> = (value, path) => {
    if (value === null || typeof value === "boolean" || typeof value === "string") return value;
    if (typeof value === "number") return Number.isFinite(value) ? value : invalidModel(path);
    if (Array.isArray(value)) return value.map((entry) => jsonValue(entry, `${path}[]`));
    return Object.fromEntries(Object.entries(objectValue(value, path)).map(([key, entry]) => [key, jsonValue(entry, `${path}.*`)]));
};
