import { observeNativeFileActor, readNativeFileContent } from "./native-file-actions";
import { nativeSaveRequests, type NativeSaveHome, type NativeSaveJournal,
    type NativeSaveSlot, type RetainedNativeSave } from "./native-file-save-journal";

/** A mounted client binding, not an authorization grant. The actor comes from
 * the actual Home; credentials and their generation stay with the app. Closing
 * a binding never cancels a submitted effect or deletes its recovery hint. */
export async function openNativeFileSaveSession(home: string, journal: NativeSaveJournal,
    connect: (home: string) => Promise<NativeSaveHome>, credentialsCurrent: () => boolean,
    newKey?: () => string) {
    if (typeof home !== "string" || !home.trim()) throw new Error("An original Home is required for native file saves");
    let closed = false;
    const current = () => !closed && credentialsCurrent();
    const assertCurrent = () => {
        if (!current()) throw new Error("Native file save session changed; reopen it to recover the original request");
    };
    const guard = async <T>(action: () => Promise<T>): Promise<T> => {
        assertCurrent();
        const value = await action();
        assertCurrent();
        return value;
    };
    const connectionFor = async (originalHome: string): Promise<NativeSaveHome> => {
        const connection = await guard(() => connect(originalHome));
        if (connection.home !== originalHome) throw new Error("Native save transport belongs to another Home");
        return connection;
    };
    const initial = await connectionFor(home);
    const identity = await guard(() => observeNativeFileActor(initial.transport, home));
    const verifyActor = async (connection: NativeSaveHome) => {
        const observed = await guard(() => observeNativeFileActor(connection.transport, connection.home));
        if (observed.actor !== identity.actor) {
            closed = true;
            throw new Error("Native file save session belongs to another actor; reopen it under the current account");
        }
    };
    // Cookies can change without a bearer update. Revalidate the actual Home
    // actor before transmitting and before accepting an asynchronous response.
    // The server's expected_actor check remains the authoritative effect fence.
    const withActor = async <T>(action: () => Promise<T>, connection = initial): Promise<T> => {
        await verifyActor(connection);
        const result = await guard(action);
        await verifyActor(connection);
        return result;
    };
    const bound = async (originalHome: string): Promise<NativeSaveHome> => {
        const connection = await connectionFor(originalHome);
        return { home: originalHome, transport: { base: connection.transport.base,
            json: (...args) => withActor(() => connection.transport.json(...args), connection) } };
    };
    const owned = (row: RetainedNativeSave) => {
        if (row.slot.owner !== identity.actor) throw new Error("Retained save belongs to another actor");
        return row;
    };
    const slot = (chat: string, path: string): NativeSaveSlot => ({ owner: identity.actor, chat, path });
    // Each asynchronous journal boundary repeats the local generation check:
    // a sign-in change during preflight cannot later reserve or transmit intent.
    const guardedJournal: NativeSaveJournal = {
        load: (value) => guard(() => journal.load(value)),
        reserve: (row) => guard(() => journal.reserve(owned(row))),
        markSubmitted: (row) => guard(() => journal.markSubmitted(owned(row))),
        discardPrepared: (row) => guard(() => journal.discardPrepared(owned(row))),
        forgetSaved: (row) => guard(() => journal.forgetSaved(owned(row))),
        close: () => guard(() => journal.close()),
    };
    const requests = nativeSaveRequests(guardedJournal, bound, newKey);
    return Object.freeze({
        home: identity.home,
        actor: identity.actor,
        current,
        readContent: (chat: string, path: string) =>
            withActor(() => readNativeFileContent(initial.transport, home, identity.actor, chat, path)),
        begin: (chat: string, path: string, baseCut: string, content: string) =>
            withActor(() => requests.begin(slot(chat, path), home, baseCut, content)),
        recover: (chat: string, path: string) => withActor(() => requests.recover(slot(chat, path))),
        savedContent: (row: RetainedNativeSave, cut: string) =>
            withActor(() => requests.savedContent(owned(row), cut)),
        acknowledgeSaved: (row: RetainedNativeSave, cut: string) =>
            withActor(() => requests.acknowledgeSaved(owned(row), cut)),
        discardPrepared: (row: RetainedNativeSave) => withActor(() => guardedJournal.discardPrepared(owned(row))),
        close: () => { closed = true; },
    });
}

export type NativeFileSaveSession = Awaited<ReturnType<typeof openNativeFileSaveSession>>;
