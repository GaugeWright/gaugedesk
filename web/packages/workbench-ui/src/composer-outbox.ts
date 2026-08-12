/**
 * The composer's **outbox**: composed messages, durable before they are sent
 * (ADR 0137).
 *
 * A row here is authored intent that has not been admitted anywhere. It is not a
 * projection of runtime state and `INV-5` does not reach it — nothing rebuilds it
 * from records, because no record exists until it is submitted. From submission
 * on, the host's queue is the authority and the browser holds a projection again.
 *
 * `held` means *unsubmitted on purpose*. There is no host-side notion of holding;
 * a held row simply never leaves this store, which is why stashing needs no
 * protocol verb on any surface.
 */
import type { ImageRef } from "./attachments";

export interface OutboxRow {
    /** Minted when the message is composed and never reassigned. Submission is an
     *  idempotent upsert under this id, so a repeat can never run twice. */
    readonly id: string;
    /** The chat this was composed in. Rows are loaded per scope. */
    readonly scope: string;
    readonly text: string;
    readonly images: readonly ImageRef[];
    /** Held rows are stepped over by the drain and never submitted. */
    readonly held: boolean;
    /** Creation order within the scope. Explicit rather than inferred from the id,
     *  so the ordering rule survives any change to how ids are minted. */
    readonly seq: number;
    /** Epoch millis, for retention only. */
    readonly at: number;
    /** Written just before the row is handed to the transport, and cleared when
     *  the send resolves. A row found in this state on load is one whose fate is
     *  unknown — the client died between dispatch and acknowledgement — so it is
     *  set aside rather than resent, because resending is the one outcome that
     *  can duplicate a turn. */
    readonly dispatched?: boolean;
}

/** Where composed messages are kept before they are sent. Async on purpose: the
 *  only store that can hold attachments is IndexedDB, and a synchronous port
 *  would have ruled it out. */
export interface OutboxStore {
    load(scope: string): Promise<readonly OutboxRow[]>;
    put(row: OutboxRow): Promise<void>;
    remove(id: string): Promise<void>;
}

/** How long an unsent message is kept before it is treated as abandoned.
 *
 *  A durable store of unsent messages that nothing ever clears is a leak, and on
 *  a shared machine it is someone's text sitting in browser storage indefinitely
 *  (ADR 0137, consequences). Rows are also cleared the moment they are sent, and
 *  a person can always remove one from the queue — this is only the backstop for
 *  what neither of those catches. */
export const OUTBOX_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;

/** Ids only have to be unique and stable; ordering is carried by `seq`. */
export function newOutboxId(): string {
    const uuid = globalThis.crypto?.randomUUID?.();
    if (uuid) return uuid;
    return `ob-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

/** Session-scoped storage: nothing survives the tab.
 *
 *  The default, and what the audience embed should keep. A visitor's stashed text
 *  and images have no business outliving their visit in a browser they may not
 *  own. */
export function createMemoryOutboxStore(): OutboxStore {
    const rows = new Map<string, OutboxRow>();
    return {
        load: async (scope) => [...rows.values()].filter((row) => row.scope === scope),
        put: async (row) => {
            rows.set(row.id, row);
        },
        remove: async (id) => {
            rows.delete(id);
        },
    };
}

const STORE = "rows";
const SCOPE_INDEX = "by-scope";

function request<T>(req: IDBRequest<T>): Promise<T> {
    return new Promise((resolve, reject) => {
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error ?? new Error("outbox request failed"));
    });
}

/** Durable storage for owner surfaces. IndexedDB rather than `localStorage`
 *  because an attachment is bytes, and the message limits already in force
 *  (16 MiB per image, 32 MiB per message) are orders of magnitude past what a
 *  synchronous string store can hold. */
export function createIndexedDbOutboxStore(options: {
    readonly database?: string;
    readonly retentionMs?: number;
    readonly indexedDB?: IDBFactory;
} = {}): OutboxStore {
    // Product-named, because the database is operator-visible and this
    // repository implements GaugeDesk: the company name belongs to the company
    // and its shared infrastructure (AGENTS.md §7). Correcting it after release
    // would mean a migration or abandoning someone's queued messages.
    const name = options.database ?? "gaugedesk.composer-outbox";
    const retention = options.retentionMs ?? OUTBOX_RETENTION_MS;
    const factory = options.indexedDB ?? globalThis.indexedDB;
    let open: Promise<IDBDatabase> | null = null;

    const db = () => {
        if (!factory) return Promise.reject(new Error("this browser has no IndexedDB"));
        open ??= new Promise<IDBDatabase>((resolve, reject) => {
            const req = factory.open(name, 1);
            req.onupgradeneeded = () => {
                const store = req.result.createObjectStore(STORE, { keyPath: "id" });
                store.createIndex(SCOPE_INDEX, "scope", { unique: false });
            };
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => reject(req.error ?? new Error("outbox open failed"));
        });
        return open;
    };

    const tx = async (mode: IDBTransactionMode) => (await db()).transaction(STORE, mode).objectStore(STORE);

    return {
        load: async (scope) => {
            const store = await tx("readwrite");
            const all = (await request(store.index(SCOPE_INDEX).getAll(scope))) as OutboxRow[];
            // Retention is applied on read rather than on a timer: it is the only
            // moment the store is open anyway, and an abandoned row that is never
            // read again is one nobody is waiting on.
            const cutoff = Date.now() - retention;
            const live: OutboxRow[] = [];
            for (const row of all) {
                if (row.at < cutoff) store.delete(row.id);
                else live.push(row);
            }
            return live;
        },
        put: async (row) => {
            const store = await tx("readwrite");
            await request(store.put(row));
        },
        remove: async (id) => {
            const store = await tx("readwrite");
            await request(store.delete(id));
        },
    };
}
