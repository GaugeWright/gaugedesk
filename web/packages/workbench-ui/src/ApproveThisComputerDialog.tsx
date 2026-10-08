/**
 * Approve this computer for an account whose keys another computer holds
 * (DR-0359, DR-0361).
 *
 * An account keeps one set of keys across its computers. A computer signed in
 * to an account it holds no keys for cannot make itself reachable for it, so
 * it asks: either a computer that holds them approves this one, with the
 * matching code on both screens that proves no one is in between, or the
 * account's recovery code restores them here.
 */

import { createSignal, onCleanup, Show, type JSX } from "solid-js";
import type { EnrollmentStatus, EnrollmentTicket } from "@gaugewright/control-plane-client";

export interface ApproveThisComputerApi {
    enrollJoin(ticket: EnrollmentTicket): Promise<string>;
    enrollJoinStatus(session: string): Promise<EnrollmentStatus>;
    restoreFromRecoveryCode(code: string): Promise<void>;
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export function ApproveThisComputerDialog(props: {
    /** How the account is named to the person. */
    account: string;
    api: ApproveThisComputerApi;
    /** This computer now holds the account's keys. */
    onApproved: () => void;
    onClose: () => void;
}): JSX.Element {
    const [ticket, setTicket] = createSignal("");
    const [status, setStatus] = createSignal<EnrollmentStatus | null>(null);
    const [code, setCode] = createSignal("");
    const [busy, setBusy] = createSignal(false);
    const [error, setError] = createSignal("");
    let session = "";
    onCleanup(() => {
        session = "";
    });

    const join = async (event: SubmitEvent) => {
        event.preventDefault();
        if (busy()) return;
        let parsed: EnrollmentTicket;
        try {
            parsed = JSON.parse(ticket()) as EnrollmentTicket;
        } catch {
            setError("That is not a device ticket. Copy the whole ticket the other computer shows.");
            return;
        }
        setBusy(true);
        setError("");
        try {
            const started = await props.api.enrollJoin(parsed);
            session = started;
            while (session === started) {
                const next = await props.api.enrollJoinStatus(started).catch(() => null);
                if (session !== started) return;
                if (next) {
                    setStatus(next);
                    if (next.phase === "completed") {
                        props.onApproved();
                        return;
                    }
                    if (next.phase === "failed" || next.phase === "expired") {
                        setError(next.error || "The approval did not finish. Start again from the other computer.");
                        return;
                    }
                }
                await sleep(1000);
            }
        } catch (failure) {
            setError(failure instanceof Error ? failure.message : "This computer could not join. Try again.");
        } finally {
            setBusy(false);
        }
    };

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

    const close = () => {
        session = "";
        props.onClose();
    };

    return (
        <div class="modal-overlay" data-approve-this-computer onClick={close}>
            <div
                class="modal create-agent-dialog approve-this-computer"
                role="dialog"
                aria-modal="true"
                aria-labelledby="approve-this-computer-title"
                onClick={(event) => event.stopPropagation()}
                onKeyDown={(event) => event.key === "Escape" && close()}
            >
                <div class="modal-head">
                    <div>
                        <span class="create-agent-eyebrow">This computer</span>
                        <h3 id="approve-this-computer-title">Approve this computer for {props.account}</h3>
                    </div>
                    <button type="button" class="create-agent-close" aria-label="Close" onClick={close}>×</button>
                </div>
                <p class="create-agent-intro">
                    Another computer holds the keys of <strong>{props.account}</strong>. Until one of them
                    approves this computer, you can work here, but you cannot reach this computer's projects
                    from your other devices.
                </p>

                <form class="approve-this-computer-step" data-approve-join onSubmit={(event) => void join(event)}>
                    <h4>Approve from your other computer</h4>
                    <ol>
                        <li>On a computer already signed in as {props.account}, open Settings ▸ Devices and choose <em>add a device</em>.</li>
                        <li>Paste the ticket it shows here.</li>
                        <li>Check that both computers show the same 6-digit code, then confirm on the other computer.</li>
                    </ol>
                    <textarea
                        data-approve-ticket
                        rows={3}
                        placeholder="paste the device ticket"
                        value={ticket()}
                        disabled={busy()}
                        onInput={(event) => setTicket(event.currentTarget.value)}
                    />
                    <Show when={status()?.sas}>
                        <p class="approve-this-computer-sas" data-approve-sas>
                            This computer shows <strong>{status()?.sas}</strong>. Confirm on the other computer if it shows the same.
                        </p>
                    </Show>
                    <div class="create-agent-actions">
                        <button type="submit" class="create-agent-submit" data-approve-join-start disabled={busy() || !ticket().trim()}>
                            {busy() && status() ? "Waiting for the other computer…" : "Join"}
                        </button>
                    </div>
                </form>

                <form class="approve-this-computer-step" data-approve-recover onSubmit={(event) => void restore(event)}>
                    <h4>Or use your recovery code</h4>
                    <p>If you no longer have a computer with this account's keys, enter the recovery code you saved.</p>
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
