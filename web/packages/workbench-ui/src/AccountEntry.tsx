import { createSignal, Show, type JSX } from "solid-js";

export interface AccountRecoveryActions {
    start(email: string): Promise<{ readonly challengeId: string; readonly expiresIn: number }>;
    finish(challengeId: string, emailCode: string, recoveryCode: string): Promise<void>;
    complete(): void;
}

export interface PasskeyAccountActions {
    signIn(email: string): Promise<void>;
    beginCreation(email: string): Promise<{ readonly challengeId: string; readonly expiresIn: number }>;
    finishCreation(challengeId: string, code: string, displayName: string): Promise<void>;
    complete(): void;
}

export interface AccountEntryProps {
    /** Consumer account entry, normally the configured Google OIDC connection. */
    personalLabel: string;
    onPersonal: () => void;
    /** Omit where the account authority does not provide provider-neutral recovery. */
    recovery?: AccountRecoveryActions;
    /** Omit where the account authority does not provide passkey accounts. */
    passkey?: PasskeyAccountActions;
    /** Omit where this composition has no organization-discovery authority. */
    workEmailAction?: string;
}

/**
 * This deliberately uses an ordinary HTML form. The browser owns the address
 * only while it is being typed; organization discovery, domain verification,
 * connection selection, and admission all stay with the POST authority.
 */
export function AccountEntry(props: AccountEntryProps): JSX.Element {
    const [recovering, setRecovering] = createSignal(false);
    const [email, setEmail] = createSignal("");
    const [challenge, setChallenge] = createSignal<{ id: string; expiresIn: number }>();
    const [emailCode, setEmailCode] = createSignal("");
    const [recoveryCode, setRecoveryCode] = createSignal("");
    const [busy, setBusy] = createSignal(false);
    const [status, setStatus] = createSignal("");
    const [passkeyMode, setPasskeyMode] = createSignal<"sign-in" | "create" | null>(null);
    const [passkeyEmail, setPasskeyEmail] = createSignal("");
    const [displayName, setDisplayName] = createSignal("");
    const [creationChallenge, setCreationChallenge] = createSignal<{ id: string; expiresIn: number }>();
    const [creationCode, setCreationCode] = createSignal("");

    const closeRecovery = () => {
        setRecovering(false);
        setChallenge(undefined);
        setEmailCode("");
        setRecoveryCode("");
        setStatus("");
    };
    const closePasskey = () => {
        setPasskeyMode(null);
        setPasskeyEmail("");
        setDisplayName("");
        setCreationChallenge(undefined);
        setCreationCode("");
        setStatus("");
    };
    const openRecovery = () => {
        closePasskey();
        setRecovering(true);
    };
    const openPasskey = (mode: "sign-in" | "create") => {
        closeRecovery();
        setPasskeyMode(mode);
    };
    const startRecovery = async (event: SubmitEvent) => {
        event.preventDefault();
        if (!props.recovery || busy() || !email().trim()) return;
        setBusy(true);
        setStatus("");
        try {
            const started = await props.recovery.start(email().trim());
            setChallenge({ id: started.challengeId, expiresIn: started.expiresIn });
            const minutes = Math.max(1, Math.ceil(started.expiresIn / 60));
            setStatus(`Enter the code from your email and one unused recovery code. The email code expires in ${minutes} minute${minutes === 1 ? "" : "s"}.`);
        } catch (error) {
            setStatus(error instanceof Error ? error.message : "Could not start account recovery.");
        } finally {
            setBusy(false);
        }
    };
    const finishRecovery = async (event: SubmitEvent) => {
        event.preventDefault();
        const current = challenge();
        if (!props.recovery || !current || busy() || !emailCode().trim() || !recoveryCode().trim()) return;
        setBusy(true);
        setStatus("");
        try {
            await props.recovery.finish(current.id, emailCode().trim(), recoveryCode().trim());
            closeRecovery();
            props.recovery.complete();
        } catch (error) {
            // A recovery challenge admits exactly one attempt. Clear both proofs
            // and require a fresh email challenge; never leave a recovery code in
            // a mounted input after submission.
            setChallenge(undefined);
            setEmailCode("");
            setStatus(error instanceof Error ? error.message : "Account recovery failed. Start again.");
        } finally {
            setRecoveryCode("");
            setBusy(false);
        }
    };
    const signInPasskey = async (event: SubmitEvent) => {
        event.preventDefault();
        if (!props.passkey || busy() || !passkeyEmail().trim()) return;
        setBusy(true);
        setStatus("Waiting for your passkey…");
        try {
            await props.passkey.signIn(passkeyEmail().trim());
            closePasskey();
            props.passkey.complete();
        } catch (error) {
            setStatus(error instanceof Error ? error.message : "Passkey sign-in failed.");
        } finally {
            setBusy(false);
        }
    };
    const beginPasskeyCreation = async (event: SubmitEvent) => {
        event.preventDefault();
        if (!props.passkey || busy() || !passkeyEmail().trim() || !displayName().trim()) return;
        setBusy(true);
        setStatus("");
        try {
            const started = await props.passkey.beginCreation(passkeyEmail().trim());
            setCreationChallenge({ id: started.challengeId, expiresIn: started.expiresIn });
            const minutes = Math.max(1, Math.ceil(started.expiresIn / 60));
            setStatus(`Enter the code from your email. It expires in ${minutes} minute${minutes === 1 ? "" : "s"}.`);
        } catch (error) {
            setStatus(error instanceof Error ? error.message : "Could not start account creation.");
        } finally {
            setBusy(false);
        }
    };
    const finishPasskeyCreation = async (event: SubmitEvent) => {
        event.preventDefault();
        const current = creationChallenge();
        if (!props.passkey || !current || busy() || !creationCode().trim()) return;
        setBusy(true);
        setStatus("Waiting for your passkey…");
        try {
            await props.passkey.finishCreation(
                current.id,
                creationCode().trim(),
                displayName().trim(),
            );
            closePasskey();
            props.passkey.complete();
        } catch (error) {
            // Email tickets and WebAuthn ceremonies are single-use. Retain the
            // non-secret address/name but require a fresh delivered code.
            setCreationChallenge(undefined);
            setCreationCode("");
            setStatus(error instanceof Error ? error.message : "Account creation failed. Start again.");
        } finally {
            setBusy(false);
        }
    };

    return (
        <div class="account-entry" data-account-entry>
            <section class="account-entry__route" aria-labelledby="personal-account-label">
                <div class="account-entry__copy">
                    <h2 id="personal-account-label">Personal account</h2>
                    <p>Use your individual GaugeDesk account.</p>
                </div>
                <div class="account-entry__personal">
                    <Show when={props.passkey}>
                        <button class="account-entry__button account-entry__button--primary"
                            data-passkey-sign-in-open type="button"
                            onClick={() => passkeyMode() === "sign-in" ? closePasskey() : openPasskey("sign-in")}>
                            {passkeyMode() === "sign-in" ? "Cancel passkey sign-in" : "Sign in with a passkey"}
                        </button>
                        <button class="account-entry__quiet" data-passkey-create-open type="button"
                            onClick={() => passkeyMode() === "create" ? closePasskey() : openPasskey("create")}>
                            {passkeyMode() === "create" ? "Cancel account creation" : "Create an account"}
                        </button>
                    </Show>
                    <button
                        class={props.passkey ? "account-entry__quiet" : "account-entry__button account-entry__button--primary"}
                        data-home-sign-in
                        type="button"
                        onClick={() => props.onPersonal()}
                    >
                        {props.personalLabel}
                    </button>
                    <Show when={props.recovery}>
                        <button class="account-entry__quiet" data-account-recovery-open type="button"
                            onClick={() => recovering() ? closeRecovery() : openRecovery()}>
                            {recovering() ? "Cancel recovery" : "Use a recovery code"}
                        </button>
                    </Show>
                </div>
                <Show when={recovering() && props.recovery}>
                    <div class="account-entry__recovery" data-account-recovery>
                        <Show when={challenge()} fallback={
                            <form class="account-entry__work" onSubmit={startRecovery}>
                                <label class="account-entry__field">
                                    <span class="account-entry__label">Verified email</span>
                                    <input name="recovery-email" type="email" autocomplete="email" required
                                        value={email()} onInput={(event) => setEmail(event.currentTarget.value)} />
                                </label>
                                <button class="account-entry__button" type="submit" disabled={busy() || !email().trim()}>
                                    {busy() ? "Sending…" : "Send code"}
                                </button>
                            </form>
                        }>
                            <form class="account-entry__recovery-proofs" onSubmit={finishRecovery}>
                                <label class="account-entry__field">
                                    <span class="account-entry__label">Email code</span>
                                    <input name="email-code" inputmode="numeric" autocomplete="one-time-code" required
                                        value={emailCode()} onInput={(event) => setEmailCode(event.currentTarget.value)} />
                                </label>
                                <label class="account-entry__field">
                                    <span class="account-entry__label">Recovery code</span>
                                    <input name="recovery-code" autocomplete="off" required
                                        value={recoveryCode()} onInput={(event) => setRecoveryCode(event.currentTarget.value)} />
                                </label>
                                <button class="account-entry__button account-entry__button--primary" type="submit"
                                    disabled={busy() || !emailCode().trim() || !recoveryCode().trim()}>
                                    {busy() ? "Recovering…" : "Recover account"}
                                </button>
                            </form>
                        </Show>
                        <Show when={status()}><p class="account-entry__status" role="status">{status()}</p></Show>
                    </div>
                </Show>
                <Show when={passkeyMode() === "sign-in" && props.passkey}>
                    <form class="account-entry__work" data-passkey-sign-in onSubmit={signInPasskey}>
                        <label class="account-entry__field">
                            <span class="account-entry__label">Account email</span>
                            <input name="passkey-email" type="email" autocomplete="username webauthn" required
                                value={passkeyEmail()} onInput={(event) => setPasskeyEmail(event.currentTarget.value)} />
                        </label>
                        <button class="account-entry__button account-entry__button--primary" type="submit"
                            disabled={busy() || !passkeyEmail().trim()}>
                            {busy() ? "Waiting…" : "Continue with passkey"}
                        </button>
                        <Show when={status()}><p class="account-entry__status" role="status">{status()}</p></Show>
                    </form>
                </Show>
                <Show when={passkeyMode() === "create" && props.passkey}>
                    <div class="account-entry__recovery" data-passkey-create>
                        <Show when={creationChallenge()} fallback={
                            <form class="account-entry__recovery-proofs" onSubmit={beginPasskeyCreation}>
                                <label class="account-entry__field">
                                    <span class="account-entry__label">Your name</span>
                                    <input name="passkey-display-name" autocomplete="name" required
                                        value={displayName()} onInput={(event) => setDisplayName(event.currentTarget.value)} />
                                </label>
                                <label class="account-entry__field">
                                    <span class="account-entry__label">Email</span>
                                    <input name="passkey-create-email" type="email" autocomplete="email" required
                                        value={passkeyEmail()} onInput={(event) => setPasskeyEmail(event.currentTarget.value)} />
                                </label>
                                <button class="account-entry__button" type="submit"
                                    disabled={busy() || !displayName().trim() || !passkeyEmail().trim()}>
                                    {busy() ? "Sending…" : "Send verification code"}
                                </button>
                            </form>
                        }>
                            <form class="account-entry__work" onSubmit={finishPasskeyCreation}>
                                <label class="account-entry__field">
                                    <span class="account-entry__label">Email code</span>
                                    <input name="passkey-email-code" inputmode="numeric" autocomplete="one-time-code" required
                                        value={creationCode()} onInput={(event) => setCreationCode(event.currentTarget.value)} />
                                </label>
                                <button class="account-entry__button account-entry__button--primary" type="submit"
                                    disabled={busy() || !creationCode().trim()}>
                                    {busy() ? "Creating…" : "Create passkey account"}
                                </button>
                            </form>
                        </Show>
                        <Show when={status()}><p class="account-entry__status" role="status">{status()}</p></Show>
                    </div>
                </Show>
            </section>

            <Show when={props.workEmailAction}>
                <section class="account-entry__route" aria-labelledby="work-account-label">
                    <div class="account-entry__copy">
                        <h2 id="work-account-label">Work account</h2>
                        <p>Find your organization’s sign-in.</p>
                    </div>
                    <form class="account-entry__work" method="post" action={props.workEmailAction}>
                        <label class="account-entry__field">
                            <span class="account-entry__label">Work email</span>
                            <input
                                data-work-email
                                name="email"
                                type="email"
                                autocomplete="email"
                                required
                                placeholder="you@company.com"
                            />
                        </label>
                        <button
                            class="account-entry__button"
                            data-work-email-submit
                            type="submit"
                        >
                            Continue
                        </button>
                    </form>
                    <p class="account-entry__privacy">
                        Used only to find your organization’s verified sign-in.
                    </p>
                </section>
            </Show>
        </div>
    );
}
