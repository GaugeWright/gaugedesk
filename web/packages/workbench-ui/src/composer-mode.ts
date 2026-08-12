/**
 * The composer's **default** delivery mode — what a chat you have not chosen for
 * opens as.
 *
 * The mode itself is per chat and lives in the composer controller, which keeps
 * it in memory keyed by scope: a stashing spell in one conversation must not
 * quietly redirect the next one. This is the other half of that (ADR-less, but
 * `DEC-9`): one standing user preference underneath the per-chat choice.
 *
 * Storage-shaped like `transcript-filter`, and for the same reason — the host
 * owns the signal and this module is pure given its storage, so a session with
 * no `window` is a null store rather than a special case.
 */
import { COMPOSER_MODES, type ComposerMode } from "./ChatComposer";

const STORAGE_KEY = "ui.composer-mode";

/** Steering is the default default: it is the only mode reachable in every
 *  Environment and at every moment, so it can never open a chat into a state
 *  that chat cannot act on. */
export const DEFAULT_COMPOSER_MODE: ComposerMode = "steer";

const KNOWN = new Set<string>(COMPOSER_MODES.map((entry) => entry.id));

/** Read the stored default. Anything unrecognised — an older writer, a newer
 *  one, a hand-edited value — falls back rather than throwing: a bad preference
 *  should cost you a default, not a composer. */
export function loadDefaultMode(storage: Pick<Storage, "getItem"> | null): ComposerMode {
    try {
        const raw = storage?.getItem(STORAGE_KEY);
        return raw && KNOWN.has(raw) ? (raw as ComposerMode) : DEFAULT_COMPOSER_MODE;
    } catch {
        return DEFAULT_COMPOSER_MODE;
    }
}

/** Persist the default. A storage failure (full / unavailable) is swallowed —
 *  the preference is session-only this run, which is what it already was. */
export function saveDefaultMode(
    storage: Pick<Storage, "setItem"> | null,
    mode: ComposerMode,
): void {
    try {
        storage?.setItem(STORAGE_KEY, mode);
    } catch {
        // storage unavailable → the default is session-only this run
    }
}
