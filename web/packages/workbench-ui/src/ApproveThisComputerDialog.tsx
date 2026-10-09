/** A fresh account sign-in restores this computer's account keys (DR-0478). */

import { createSignal, Show, type JSX } from "solid-js";

export interface ApproveThisComputerApi {
    restoreFromRecoveryCode(code: string): Promise<void>;
}

export function ApproveThisComputerDialog(props: {
    account: string;
    api: ApproveThisComputerApi;
    onSignIn: () => void;
    onApproved: () => void;
    onClose: () => void;
}): JSX.Element {
    const [code, setCode] = createSignal("");
    const [busy, setBusy] = createSignal(false);
    const [error, setError] = createSignal("");

    const restore = async (event: SubmitEvent) => {
        event.preventDefault();
        if (busy()) return;
        setBusy(true);
        setError("");
        try {
            await props.api.restoreFromRecoveryCode(code());
            props.onApproved();
        } catch (failure) {
            setError(failure instanceof Error ? failure.message : "The recovery code was not taken.");
        } finally {
            setBusy(false);
        }
    };

    return (
        <div class="modal-overlay" data-approve-this-computer onClick={props.onClose}>
            <div
                class="modal create-agent-dialog approve-this-computer"
                role="dialog"
                aria-modal="true"
                aria-labelledby="approve-this-computer-title"
                onClick={(event) => event.stopPropagation()}
                onKeyDown={(event) => event.key === "Escape" && props.onClose()}
            >
                <div class="modal-head">
                    <div>
                        <span class="create-agent-eyebrow">This computer</span>
                        <h3 id="approve-this-computer-title">Connect this computer to {props.account}</h3>
                    </div>
                    <button type="button" class="create-agent-close" aria-label="Close" onClick={props.onClose}>×</button>
                </div>
                <p class="create-agent-intro">
                    Sign in with <strong>{props.account}</strong> again to restore this computer's account keys.
                    If another computer holds the keys, sign in there once after updating GaugeDesk,
                    then return here and sign in again. No device ticket or matching code is needed.
                </p>
                <div class="create-agent-actions">
                    <button type="button" class="create-agent-submit" data-approve-signin onClick={props.onSignIn}>
                        Sign in again
                    </button>
                </div>
                <form class="approve-this-computer-step" data-approve-recover onSubmit={(event) => void restore(event)}>
                    <h4>Lost access to your other computers?</h4>
                    <p>If the service has no key copy and no computer holding the keys remains, use the recovery code you saved.</p>
                    <input
                        data-approve-recovery-code
                        type="text"
                        autocomplete="off"
                        spellcheck={false}
                        placeholder="XXXX-XXXX-…"
                        value={code()}
                        disabled={busy()}
                        onInput={(event) => setCode(event.currentTarget.value)}
                    />
                    <div class="create-agent-actions">
                        <button type="submit" data-approve-recover-start disabled={busy() || !code().trim()}>
                            Restore with recovery code
                        </button>
                    </div>
                </form>
                <Show when={error()}><p class="create-agent-error" role="alert">{error()}</p></Show>
            </div>
        </div>
    );
}
