/**
 * The deliverables card: what the agent wrote for the person in front of it,
 * offered from the chat with a download (ADR 0163).
 *
 * Rendered after the transcript so it reads as the conversation's outcome. The
 * listing is the same worktree-derived projection the Files panel reads, so it
 * survives a reload: a report produced before the tab closed is still offered
 * when the session resumes. Download is a click, deliberately — a download the
 * page starts on its own is what browsers block or flag, and a report that
 * fails to arrive exactly when the conversation ends is the failure this
 * surface exists to prevent.
 */
import { createEffect, createResource, createSignal, For, Show, type JSX } from "solid-js";
import { type Deliverable, deliverablesIn, newDeliverables } from "./deliverables";
import { type Session, useSession } from "./session-context";

export interface DeliverablesProps {
    /** Explicit leaf for hosts that mount without an ambient provider. */
    readonly session?: Session;
    /** The saver, injectable so the card is testable without a DOM. Defaults to
     *  an anchor click on an object URL, the one method every browser honours
     *  from a user gesture. */
    readonly save?: (deliverable: Deliverable, content: string) => void;
}

/** Hand the bytes to the browser as a file save. */
export function saveToBrowser(deliverable: Deliverable, content: string): void {
    const blob = new Blob([content], { type: deliverable.mediaType });
    const url = URL.createObjectURL(blob);
    try {
        const anchor = document.createElement("a");
        anchor.href = url;
        anchor.download = deliverable.filename;
        anchor.rel = "noopener";
        anchor.style.display = "none";
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
    } finally {
        // The click has consumed the URL synchronously in every browser that
        // honours `download`; revoking on the next tick keeps the slow ones safe.
        setTimeout(() => URL.revokeObjectURL(url), 1_000);
    }
}

export function Deliverables(props: DeliverablesProps): JSX.Element {
    const ambient = props.session ? undefined : useSession();
    const session = () => props.session ?? ambient!;
    const [listing] = createResource(
        () => [session().engagementId(), session().worktreeRev()] as const,
        async ([id]) => (id ? (await session().api.getTree(id)).filter((e) => !e.isDir).map((e) => e.path) : []),
    );
    const items = () => deliverablesIn(listing() ?? []);

    // Which of these arrived since the last listing — the ones to announce.
    const [previous, setPrevious] = createSignal<readonly string[]>([]);
    const [fresh, setFresh] = createSignal<ReadonlySet<string>>(new Set());
    createEffect(() => {
        const current = listing();
        if (!current) return;
        const added = newDeliverables(previous(), current);
        if (added.length > 0) setFresh(new Set(added.map((d) => d.path)));
        setPrevious(current);
    });

    const [busy, setBusy] = createSignal<string | null>(null);
    const [failure, setFailure] = createSignal<string | null>(null);
    const download = async (deliverable: Deliverable) => {
        const id = session().engagementId();
        if (!id || busy()) return;
        setBusy(deliverable.path);
        setFailure(null);
        try {
            const content = await session().api.getFile(id, deliverable.path);
            (props.save ?? saveToBrowser)(deliverable, content);
        } catch (error) {
            setFailure(error instanceof Error && error.message ? error.message : "The download failed.");
        } finally {
            setBusy(null);
        }
    };

    return (
        <Show when={items().length > 0}>
            <div class="deliverables" data-deliverables role="group" aria-label="files for you">
                <div class="deliverables-caption">For you</div>
                <For each={items()}>
                    {(deliverable) => (
                        <div
                            class="deliverable"
                            classList={{ fresh: fresh().has(deliverable.path) }}
                            data-deliverable={deliverable.path}
                        >
                            <span class="deliverable-name">{deliverable.filename}</span>
                            <button
                                type="button"
                                class="deliverable-download"
                                data-deliverable-download
                                disabled={busy() !== null}
                                onClick={() => void download(deliverable)}
                            >
                                {busy() === deliverable.path ? "Preparing…" : "Download"}
                            </button>
                        </div>
                    )}
                </For>
                <Show when={failure()}>
                    <div class="deliverables-failure" role="alert">{failure()}</div>
                </Show>
            </div>
        </Show>
    );
}
