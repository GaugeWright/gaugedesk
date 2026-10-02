/**
 * The card an `offer_download` call becomes in the chat (DR-0314): what the
 * agent offered, and a Download button. Saving is the person's click and
 * nothing else — a download the page starts on its own is what browsers block
 * or flag.
 */
import { createSignal, Show, type JSX } from "solid-js";
import type { OfferedDownload } from "./offered-download";

export function OfferedDownloadView(props: {
    offer: OfferedDownload;
    onDownload: (path: string) => Promise<void>;
}): JSX.Element {
    const [busy, setBusy] = createSignal(false);
    const [failure, setFailure] = createSignal("");
    const download = async () => {
        if (busy()) return;
        setBusy(true);
        setFailure("");
        try {
            await props.onDownload(props.offer.path);
        } catch (error) {
            setFailure(error instanceof Error && error.message ? error.message : "The download failed.");
        } finally {
            setBusy(false);
        }
    };
    return (
        <div class="offered-download" role="group" aria-label="file for you" data-offered-download={props.offer.path}>
            <div class="offered-download-row">
                <span class="offered-download-title">{props.offer.title}</span>
                <button type="button" class="offered-download-button" data-offered-download-button
                    disabled={busy()} onClick={() => void download()}>
                    {busy() ? "Preparing…" : "Download"}
                </button>
            </div>
            <Show when={props.offer.title !== props.offer.filename}>
                <span class="offered-download-name">{props.offer.filename}</span>
            </Show>
            <Show when={failure()}>
                <div class="offered-download-failure" role="alert">{failure()}</div>
            </Show>
        </div>
    );
}
