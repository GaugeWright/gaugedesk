import { observeNativeFileRequest, parseNativeFileRequestIdentity, prepareNativeFileSaveRequest, readNativeFileSavedContent,
    submitNativeFileSave, type NativeFileActionObservation, type NativeFileRequestIdentity,
    type NativeFileSaveReceipt } from "./native-file-actions";
import type { WorkbenchTransport } from "./control-plane-workbench";

/** owner is the verified account identity, never a bearer or a guessed JWT sub. */
export interface NativeSaveSlot { readonly owner: string; readonly chat: string; readonly path: string }
export interface RetainedNativeSave {
    readonly schema: "gaugedesk.native-save-journal.v1";
    readonly slot: NativeSaveSlot;
    readonly identity: NativeFileRequestIdentity;
    readonly dispatch_request_id: string;
    readonly phase: "prepared" | "submitted";
}
export interface NativeSaveJournal {
    load(slot: NativeSaveSlot): Promise<RetainedNativeSave | null>;
    reserve(row: RetainedNativeSave): Promise<{ readonly row: RetainedNativeSave; readonly created: boolean }>;
    markSubmitted(row: RetainedNativeSave): Promise<boolean>;
    discardPrepared(row: RetainedNativeSave): Promise<boolean>;
    /** Only the controller's fresh Saved acknowledgment calls this operation. */
    forgetSaved(row: RetainedNativeSave): Promise<boolean>;
    close(): Promise<void>;
}

const SCHEMA = "gaugedesk.native-save-journal.v1";
const STORE = "requests";
function object(value: unknown): value is Record<string, unknown> {
    return value !== null && typeof value === "object" && !Array.isArray(value);
}
function keys(value: Record<string, unknown>, expected: string): boolean {
    return Object.keys(value).sort().join(",") === expected;
}
function slot(value: unknown): NativeSaveSlot {
    if (!object(value) || !keys(value, "chat,owner,path")
        || [value.owner, value.chat, value.path].some((part) => typeof part !== "string" || !part.trim())) {
        throw new Error("A verified owner, chat and file path are required for save recovery");
    }
    return Object.freeze({ owner: value.owner as string, chat: value.chat as string, path: value.path as string });
}
function key(value: NativeSaveSlot): string {
    const parsed = slot(value);
    return JSON.stringify([parsed.owner, parsed.chat, parsed.path]);
}
function parse(value: unknown): RetainedNativeSave {
    if (!object(value) || !keys(value, "dispatch_request_id,identity,phase,schema,slot")
        || value.schema !== SCHEMA || !["prepared", "submitted"].includes(String(value.phase))
        || typeof value.dispatch_request_id !== "string" || !value.dispatch_request_id.trim()) {
        throw new Error("Retained native save request is unreadable; do not submit a replacement");
    }
    return Object.freeze({ schema: SCHEMA, slot: slot(value.slot), identity: parseNativeFileRequestIdentity(value.identity),
        dispatch_request_id: value.dispatch_request_id, phase: value.phase as RetainedNativeSave["phase"] });
}
function same(left: RetainedNativeSave, right: RetainedNativeSave): boolean {
    return key(left.slot) === key(right.slot) && left.dispatch_request_id === right.dispatch_request_id
        && left.identity.home === right.identity.home && left.identity.issuer === right.identity.issuer
        && left.identity.scope === right.identity.scope && left.identity.request_id === right.identity.request_id;
}

/** No memory fallback: failure to retain the request refuses submission.
 * A row contains only recovery metadata; an uncertain submitted row never ages
 * out or becomes a new intent merely because this client reopened. */
export function createNativeSaveJournal(options: { readonly database?: string; readonly indexedDB?: IDBFactory } = {}): NativeSaveJournal {
    const factory = options.indexedDB ?? globalThis.indexedDB;
    let opening: Promise<IDBDatabase> | null = null;
    let closed = false;
    const db = (): Promise<IDBDatabase> => {
        if (closed || !factory) return Promise.reject(new Error("Durable native save recovery is unavailable"));
        if (!opening) {
            const pending = new Promise<IDBDatabase>((resolve, reject) => {
                const request = factory.open(options.database ?? "gaugedesk.native-save-journal", 1);
                let refused = false;
                request.onupgradeneeded = () => { request.result.createObjectStore(STORE); };
                request.onblocked = () => { refused = true; reject(new Error("Native save journal upgrade is blocked")); };
                request.onerror = () => { refused = true; reject(request.error ?? new Error("Native save journal could not open")); };
                request.onsuccess = () => {
                    if (refused || closed) { request.result.close(); reject(new Error("Native save journal closed while opening")); return; }
                    request.result.onversionchange = () => { request.result.close(); opening = null; };
                    resolve(request.result);
                };
            });
            opening = pending.catch((error) => { opening = null; throw error; });
        }
        return opening;
    };
    const transaction = async <T>(mode: IDBTransactionMode,
        operate: (store: IDBObjectStore, done: (result: T) => void, fail: (error: unknown) => void) => void): Promise<T> => {
        const database = await db();
        return new Promise<T>((resolve, reject) => {
            const tx = database.transaction(STORE, mode, mode === "readwrite" ? { durability: "strict" } : undefined);
            let ready = false;
            let result: T;
            tx.oncomplete = () => ready ? resolve(result) : reject(new Error("Native save journal transaction produced no result"));
            tx.onabort = () => reject(tx.error ?? new Error("Native save journal transaction aborted"));
            tx.onerror = () => reject(tx.error ?? new Error("Native save journal transaction failed"));
            const fail = (error: unknown) => { try { tx.abort(); } catch { /* Already terminal. */ } reject(error); };
            if (mode === "readwrite" && tx.durability !== "strict") { fail(new Error("Strict native save persistence is unavailable")); return; }
            try { operate(tx.objectStore(STORE), (value) => { result = value; ready = true; }, fail); }
            catch (error) { fail(error); }
        });
    };
    const read = <T>(store: IDBObjectStore, address: string, fail: (error: unknown) => void,
        found: (row: RetainedNativeSave | null) => T) => {
        const request = store.get(address);
        request.onsuccess = () => {
            try {
                const row = request.result === undefined ? null : parse(request.result);
                if (row && key(row.slot) !== address) throw new Error("Native save journal slot is substituted");
                found(row);
            } catch (error) { fail(error); }
        };
    };
    return {
        load: (value) => {
            const address = key(value);
            return transaction("readonly", (store, done, fail) => read(store, address, fail, done));
        },
        reserve: (value) => {
            const candidate = parse(value);
            if (candidate.phase !== "prepared") return Promise.reject(new Error("A new save reservation must be prepared"));
            const address = key(candidate.slot);
            return transaction("readwrite", (store, done, fail) => read(store, address, fail, (existing) => {
                if (existing) { done({ row: existing, created: false }); return; }
                const request = store.add(candidate, address);
                request.onsuccess = () => done({ row: candidate, created: true });
            }));
        },
        markSubmitted: (value) => {
            const expected = parse(value);
            return transaction("readwrite", (store, done, fail) => read(store, key(expected.slot), fail, (existing) => {
                if (expected.phase !== "prepared" || existing?.phase !== "prepared" || !same(existing, expected)) { done(false); return; }
                const request = store.put({ ...existing, phase: "submitted" }, key(expected.slot));
                request.onsuccess = () => done(true);
            }));
        },
        discardPrepared: (value) => {
            const expected = parse(value);
            return transaction("readwrite", (store, done, fail) => read(store, key(expected.slot), fail, (existing) => {
                if (expected.phase !== "prepared" || existing?.phase !== "prepared" || !same(existing, expected)) { done(false); return; }
                const request = store.delete(key(expected.slot));
                request.onsuccess = () => done(true);
            }));
        },
        forgetSaved: (value) => {
            const expected = parse(value);
            return transaction("readwrite", (store, done, fail) => read(store, key(expected.slot), fail, (existing) => {
                if (expected.phase !== "submitted" || existing?.phase !== "submitted" || !same(existing, expected)) { done(false); return; }
                const request = store.delete(key(expected.slot));
                request.onsuccess = () => done(true);
            }));
        },
        close: async () => { closed = true; const pending = opening; opening = null; if (pending) (await pending).close(); },
    };
}

export interface NativeSaveHome { readonly home: string; readonly transport: WorkbenchTransport }
export type NativeSaveStart =
    | { readonly kind: "retained"; readonly row: RetainedNativeSave }
    | { readonly kind: "admitted"; readonly row: RetainedNativeSave; readonly receipt: NativeFileSaveReceipt }
    | { readonly kind: "uncertain"; readonly row: RetainedNativeSave; readonly error: unknown };
export type NativeSaveRead = { readonly kind: "observed"; readonly observation: NativeFileActionObservation }
    | { readonly kind: "unavailable"; readonly error: unknown };

/** One-shot submission and independent recovery. The caller supplies a
 * verified account slot and a transport bound to an exact Home, never the
 * current-project transport that can move while an action is outstanding. */
export function nativeSaveRequests(journal: NativeSaveJournal,
    connect: (home: string) => Promise<NativeSaveHome>, newKey: () => string = () => crypto.randomUUID()) {
    const bound = async (home: string) => {
        const connection = await connect(home);
        if (connection.home !== home) throw new Error("Native save transport belongs to another Home");
        return connection.transport;
    };
    const ownerRead = async (transport: WorkbenchTransport, row: RetainedNativeSave,
        view: "command" | "execution" | "saved") => {
        const observation = await observeNativeFileRequest(transport, row.identity, view);
        if (observation.observer !== row.slot.owner) throw new Error("Native save observation belongs to another actor");
        return observation;
    };
    return {
        begin: async (value: NativeSaveSlot, home: string, baseCut: string, content: string): Promise<NativeSaveStart> => {
            const originalSlot = slot(value);
            const existing = await journal.load(originalSlot);
            if (existing) return { kind: "retained", row: existing };
            if (typeof home !== "string" || !home.trim() || typeof baseCut !== "string" || !baseCut.trim()
                || typeof content !== "string") throw new Error("An original Home, base cut and draft are required");
            const transport = await bound(home);
            const identity = await prepareNativeFileSaveRequest(transport, home, originalSlot.chat, originalSlot.path, newKey());
            const reserved = await journal.reserve(parse({ schema: SCHEMA, slot: originalSlot, identity,
                dispatch_request_id: newKey(), phase: "prepared" }));
            if (!reserved.created) return { kind: "retained", row: reserved.row };
            if (!await journal.markSubmitted(reserved.row)) throw new Error("Native save reservation changed before transmission");
            const submitted = parse({ ...reserved.row, phase: "submitted" });
            try {
                const receipt = await submitNativeFileSave(transport, identity, { expected_actor: originalSlot.owner, chat: originalSlot.chat,
                    path: originalSlot.path, base_cut: baseCut, content, dispatch_request_id: submitted.dispatch_request_id });
                return { kind: "admitted", row: submitted, receipt };
            } catch (error) { return { kind: "uncertain", row: submitted, error }; }
        },
        recover: async (value: NativeSaveSlot): Promise<null | { readonly row: RetainedNativeSave;
            readonly command: NativeSaveRead; readonly execution: NativeSaveRead; readonly saved: NativeSaveRead }> => {
            const row = await journal.load(slot(value));
            if (!row) return null;
            const transport = await bound(row.identity.home);
            const read = async (view: "command" | "execution" | "saved"): Promise<NativeSaveRead> => {
                try { return { kind: "observed", observation: await ownerRead(transport, row, view) }; }
                catch (error) { return { kind: "unavailable", error }; }
            };
            const [command, execution, saved] = await Promise.all([read("command"), read("execution"), read("saved")]);
            return { row, command, execution, saved };
        },
        savedContent: async (expected: RetainedNativeSave, cut: string) => {
            const row = await journal.load(expected.slot);
            if (!row || row.phase !== "submitted" || !same(row, parse(expected))) {
                throw new Error("The original submitted save is unavailable");
            }
            const observed = await readNativeFileSavedContent(await bound(row.identity.home), row.identity, cut);
            if (observed.observer !== row.slot.owner) throw new Error("Native saved content belongs to another actor");
            return observed;
        },
        /** Called only after the editor has handled this exact saved cut. A
         * fresh authorized read must still name it; unavailable evidence keeps
         * the row. A stale callback cannot remove a newer request in the slot. */
        acknowledgeSaved: async (expected: RetainedNativeSave, cut: string): Promise<boolean> => {
            const current = await journal.load(expected.slot);
            if (!current || current.phase !== "submitted" || !same(current, parse(expected))) return false;
            if (typeof cut !== "string" || !cut.trim()) throw new Error("An exact saved cut is required");
            const saved = await ownerRead(await bound(current.identity.home), current, "saved");
            const namesCut = (saved.evidence as unknown[]).some((fact) => object(fact) && object(fact.result)
                && fact.result.protocol === "gaugedesk.native-editor-saved-result.v1" && fact.result.cut_id === cut
                && [fact.effect_id, fact.run_id, fact.result.product_command_id, fact.result.content_hash]
                    .every((part) => typeof part === "string" && !!part.trim()));
            if (!namesCut) return false;
            return journal.forgetSaved(current);
        },
    };
}
