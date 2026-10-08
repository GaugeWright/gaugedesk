/**
 * Show the signed-in account's recovery code (DR-0361 §3).
 *
 * The code is the account's root in transcribable form: whoever holds it can
 * act as the account, and with it a person who has lost every computer gets
 * their account back. So it is shown on request, never stored by this page,
 * and the dialog says plainly what it is.
 */

import { createResource, createSignal, Show, type JSX } from "solid-js";

export function RecoveryCodeDialog(props: {
    account: string;
    load: () => Promise<string>;
    onClose: () => void;
}): JSX.Element {
    const [code] = createResource(async () => {
        try {
            return { code: await props.load(), error: "" };
        } catch (failure) {
            return {
                code: "",
                error: failure instanceof Error ? failure.message : "The recovery code could not be read.",
            };
        }
    });
    const [copied, setCopied] = createSignal(false);
    const copy = async () => {
        const value = code()?.code;
        if (!value) return;
        await navigator.clipboard.writeText(value);
        setCopied(true);
    };
    return (
        <div class="modal-overlay" data-recovery-code onClick={() => props.onClose()}>
            <div
                class="modal create-agent-dialog recovery-code"
                role="dialog"
                aria-modal="true"
                aria-labelledby="recovery-code-title"
                onClick={(event) => event.stopPropagation()}
                onKeyDown={(event) => event.key === "Escape" && props.onClose()}
            >
                <div class="modal-head">
                    <div>
                        <span class="create-agent-eyebrow">{props.account}</span>
                        <h3 id="recovery-code-title">Recovery code</h3>
                    </div>
                    <button type="button" class="create-agent-close" aria-label="Close" onClick={() => props.onClose()}>×</button>
                </div>
                <p class="create-agent-intro">
                    If you lose every computer signed in to this account, this code restores its keys on a new one.
                    Anyone who has it can act as your account, so write it down or keep it in a password manager,
                    and never share it.
                </p>
                <Show when={code()?.code} fallback={
                    <p class="create-agent-error" role="alert">{code()?.error}</p>
                }>
                    <pre class="recovery-code-value" data-recovery-code-value>{code()?.code}</pre>
                </Show>
                <div class="create-agent-actions">
                    <Show when={code()?.code}>
                        <button type="button" data-recovery-code-copy onClick={() => void copy()}>
                            {copied() ? "Copied" : "Copy"}
                        </button>
                    </Show>
                    <button type="button" class="create-agent-submit" onClick={() => props.onClose()}>Done</button>
                </div>
            </div>
        </div>
    );
}
