/**
 * The sign-in card: one address field, and the server decides where it goes.
 *
 * This replaces a card that asked the person to classify themselves first —
 * "Personal account" and "Work account" as two standing sections, each with its
 * own field and button. Nobody arrives thinking of themselves as a route. They
 * arrive with an address, and which sign-in it belongs to is a fact the account
 * service already holds, so asking is both a question and a way to get it wrong.
 *
 * What auto-detection can and cannot be here is set by the server, not by taste.
 * `POST /auth/work-email` (`auth_oidc.rs:294`) resolves an address to an
 * organization connection and redirects, or answers one flat 404 covering
 * "invalid, absent, incomplete, unsupported, and ambiguous" — deliberately, so
 * discovery cannot be used to enumerate organizations or accounts. So the
 * organization branch is genuinely detected, and the personal branch is
 * deliberately *not*: we never say whether an address has an account. It offers
 * the passkey ceremony and account creation side by side, and WebAuthn's own
 * conditional UI resolves which applies without either of us announcing it.
 *
 * The consumer providers sit as a row of marks below a rule, not as sections.
 * ADR 0146: the account is the person, an authenticator is replaceable, and a
 * provider "may be linked afterward, or offered during setup as an optional
 * convenience, but it is never called or modeled as the account". A convenience
 * is not a peer of the thing it is a convenience for, so it gets a mark rather
 * than a sentence — and three marks in a row cost exactly what one does, which
 * is why this takes a list instead of naming Google.
 */

import { createSignal, For, Show, type JSX } from "solid-js";

// The company mark, rendered here from `brand/logos/` by the GaugeWright
// repository's `tools/palette.mjs`, exactly as the brand tokens beside it are.
// It is not drawn in this file and not copied into it: a local edit fails
// `scripts/check-brand-tokens.mjs`, which carries its digest.
import markUrl from "./assets/gaugewright-mark-64.png";

/** Where an address resolves. The organization case carries a display name
 *  because the server already knows it once discovery has matched. */
export type SignInRoute =
    /** `label` only where the resolver actually knows the organization's name.
     *  Discovery against `/auth/work-email` does not: it redirects or answers a
     *  flat 404, and the redirect's destination is not readable. */
    | { kind: "organization"; label?: string; go: () => void }
    | { kind: "personal" };

export interface SignInPasskeyActions {
    signIn(email: string): Promise<void>;
    beginCreation(email: string): Promise<{ readonly challengeId: string; readonly expiresIn: number }>;
    /** Resolves with the account's recovery codes — the only copy there will
     *  ever be, which is why {@link complete} is not called until the person has
     *  been shown them and said so. */
    finishCreation(challengeId: string, code: string, displayName: string): Promise<readonly string[]>;
    complete(): void;
}

/** A consumer identity provider offered on this card. `label` is the accessible
 *  name — the mark is decorative, so the button carries the words. */
export interface SignInProvider {
    id: "google" | "apple" | "microsoft";
    label: string;
    begin: () => void;
}

export interface SignInRecoveryActions {
    start(email: string): Promise<{ readonly challengeId: string; readonly expiresIn: number }>;
    finish(challengeId: string, emailCode: string, recoveryCode: string): Promise<void>;
    complete(): void;
}

export interface SignInCardProps {
    /** Resolve an address to its route. Rejects only on a transport failure; a
     *  no-organization answer is `{ kind: "personal" }`, never an error. */
    resolve(email: string): Promise<SignInRoute>;
    passkey?: SignInPasskeyActions;
    /** Consumer-OIDC conveniences, in the order they should read. Pass only the
     *  ones this control plane has a connection for; an empty list hides the row
     *  and its rule rather than leaving a labelled gap. */
    providers?: readonly SignInProvider[];
    recovery?: SignInRecoveryActions;
    /** The card's own heading and opening line. They belong to the card because
     *  the mark, the title and the lede are one masthead; splitting them across
     *  the host left the product's name printed twice on the same screen. */
    title: string;
    lede?: string;
    /** Trailing line for the local route — "set up a model credential instead". */
    footnote?: JSX.Element;
}

type Step =
    | { at: "identify" }
    | { at: "organization"; email: string; label?: string; go: () => void }
    | { at: "personal"; email: string }
    | { at: "create"; email: string; challenge?: { id: string; expiresIn: number } }
    | { at: "codes"; email: string; codes: readonly string[] }
    | { at: "recover"; email: string; challenge?: { id: string; expiresIn: number } };



/** The provider marks. Google and Microsoft carry their brand colours because
 *  their guidelines require the mark as issued; Apple's is monochrome by
 *  specification and so takes `currentColor`. Decorative — the button holds the
 *  label — so each is `aria-hidden`.
 *
 *  Before this ships, the three vendors' sign-in branding requirements decide
 *  the final treatment (minimum sizes, clear space, and whether a mark-only
 *  button is permitted at all); these are drawn to the right shapes, not yet to
 *  a cleared spec. */
function ProviderMark(props: { id: SignInProvider["id"] }): JSX.Element {
    return (
        <svg class="signin__mark" viewBox="0 0 24 24" aria-hidden="true">
            <Show when={props.id === "google"}>
                <path fill="#4285F4" d="M23.06 12.25c0-.85-.08-1.67-.22-2.45H12v4.64h6.2a5.3 5.3 0 0 1-2.3 3.48v2.9h3.72c2.18-2 3.44-4.96 3.44-8.57z" />
                <path fill="#34A853" d="M12 24c3.11 0 5.72-1.03 7.62-2.79l-3.72-2.89c-1.03.69-2.35 1.1-3.9 1.1-3 0-5.54-2.02-6.45-4.74H1.7v2.98A11.5 11.5 0 0 0 12 24z" />
                <path fill="#FBBC05" d="M5.55 14.68a6.9 6.9 0 0 1 0-4.41V7.29H1.7a11.51 11.51 0 0 0 0 10.37l3.85-2.98z" />
                <path fill="#EA4335" d="M12 4.75c1.69 0 3.21.58 4.4 1.72l3.3-3.3C17.71 1.24 15.1 0 12 0 7.4 0 3.42 2.64 1.7 6.49l3.85 2.98C6.46 6.77 9 4.75 12 4.75z" />
            </Show>
            <Show when={props.id === "microsoft"}>
                <path fill="#F25022" d="M2 2h9.2v9.2H2z" />
                <path fill="#7FBA00" d="M12.8 2H22v9.2h-9.2z" />
                <path fill="#00A4EF" d="M2 12.8h9.2V22H2z" />
                <path fill="#FFB900" d="M12.8 12.8H22V22h-9.2z" />
            </Show>
            <Show when={props.id === "apple"}>
                <path
                    fill="currentColor"
                    d="M16.36 12.62c-.02-2.3 1.88-3.4 1.96-3.46-1.07-1.56-2.73-1.78-3.32-1.8-1.42-.14-2.76.83-3.48.83-.72 0-1.82-.81-2.99-.79-1.54.02-2.96.89-3.75 2.27-1.6 2.77-.41 6.87 1.15 9.12.76 1.1 1.67 2.34 2.86 2.29 1.15-.05 1.58-.74 2.97-.74s1.78.74 2.99.72c1.24-.02 2.02-1.12 2.78-2.23.87-1.28 1.23-2.52 1.25-2.58-.03-.01-2.4-.92-2.42-3.63zM14.1 5.4c.63-.77 1.06-1.83.94-2.9-.91.04-2.01.61-2.67 1.37-.59.68-1.1 1.76-.96 2.8 1.01.08 2.05-.51 2.69-1.27z"
                />
            </Show>
        </svg>
    );
}

export function SignInCard(props: SignInCardProps): JSX.Element {
    const [step, setStep] = createSignal<Step>({ at: "identify" });
    const [email, setEmail] = createSignal("");
    const [displayName, setDisplayName] = createSignal("");
    const [code, setCode] = createSignal("");
    const [recoveryCode, setRecoveryCode] = createSignal("");
    const [busy, setBusy] = createSignal(false);
    const [status, setStatus] = createSignal("");

    /** The current step when it is `kind`, else undefined — the shape `<Show>`
     *  wants, so each branch gets its own narrowed step instead of a boolean. */
    // A function declaration, not a generic arrow: in a .tsx file
    // `<K extends …>(x: K) => …` typechecks, but Babel's JSX transform reads the
    // leading `<K …>` as an element and Solid then calls this as a component
    // ("current is not a function", from devComponent). TypeScript alone will not
    // catch it — only running the page does.
    function at<K extends Step["at"]>(kind: K) {
        const current = step();
        return current.at === kind ? (current as Extract<Step, { at: K }>) : undefined;
    }

    const restart = () => {
        setStep({ at: "identify" });
        setStatus("");
        setCode("");
        setRecoveryCode("");
    };

    /** One place for "run this, say what happened, stay honest about failure" —
     *  the surface this replaces let a rejected click report nothing at all. */
    const run = async (describe: string, act: () => Promise<void>) => {
        if (busy()) return;
        setBusy(true);
        setStatus("");
        try {
            await act();
        } catch (error) {
            setStatus(error instanceof Error ? error.message : `Could not ${describe}.`);
        } finally {
            setBusy(false);
        }
    };

    const identify = (event: SubmitEvent) => {
        event.preventDefault();
        const address = email().trim();
        if (!address) return;
        void run("look up that address", async () => {
            const route = await props.resolve(address);
            setStep(
                route.kind === "organization"
                    ? { at: "organization", email: address, label: route.label, go: route.go }
                    : { at: "personal", email: address },
            );
        });
    };

    const signInWithPasskey = (address: string) =>
        void run("sign in with that passkey", async () => {
            await props.passkey!.signIn(address);
            props.passkey!.complete();
        });

    const startCreation = (address: string) =>
        void run("start account creation", async () => {
            const started = await props.passkey!.beginCreation(address);
            setStep({ at: "create", email: address, challenge: { id: started.challengeId, expiresIn: started.expiresIn } });
            const minutes = Math.max(1, Math.ceil(started.expiresIn / 60));
            setStatus(`Enter the code we emailed to ${address}. It expires in ${minutes} minute${minutes === 1 ? "" : "s"}.`);
        });

    const finishCreation = (event: SubmitEvent, current: Extract<Step, { at: "create" }>) => {
        event.preventDefault();
        if (!current.challenge || !code().trim() || !displayName().trim()) return;
        void run("create that account", async () => {
            try {
                const codes = await props.passkey!.finishCreation(
                    current.challenge!.id,
                    code().trim(),
                    displayName().trim(),
                );
                // The account exists and the session is live, but the codes are in
                // this response and nowhere else. Show them before handing over.
                setStep({ at: "codes", email: current.email, codes });
                return;
            } catch (error) {
                // Email tickets and WebAuthn ceremonies are single-use: drop the
                // spent challenge so the retry starts a fresh one rather than
                // replaying a code the server has already refused.
                setStep({ at: "create", email: current.email });
                setCode("");
                throw error;
            }
        });
    };

    const startRecovery = (address: string) =>
        void run("start recovery", async () => {
            const started = await props.recovery!.start(address);
            setStep({ at: "recover", email: address, challenge: { id: started.challengeId, expiresIn: started.expiresIn } });
            setStatus("Enter the code from your email and one unused recovery code.");
        });

    const finishRecovery = (event: SubmitEvent, current: Extract<Step, { at: "recover" }>) => {
        event.preventDefault();
        if (!current.challenge || !code().trim() || !recoveryCode().trim()) return;
        void run("recover that account", async () => {
            try {
                await props.recovery!.finish(current.challenge!.id, code().trim(), recoveryCode().trim());
            } catch (error) {
                setStep({ at: "recover", email: current.email });
                setCode("");
                throw error;
            } finally {
                // Never leave a recovery code in a mounted input after submission.
                setRecoveryCode("");
            }
            props.recovery!.complete();
        });
    };

    return (
        <div class="signin" data-signin>
            <header class="signin__head">
                <img class="signin__brand" src={markUrl} alt="" width="40" height="40" />
                <span class="signin__headtext">
                    <h1 class="signin__title">{props.title}</h1>
                    <span class="signin__orn" role="presentation"><i /></span>
                </span>
            </header>
            <Show when={props.lede}><p class="signin__lede">{props.lede}</p></Show>
            <Show when={step().at === "identify"}>
                <form class="signin__act" data-signin-identify onSubmit={identify}>
                    <label class="signin__field">
                        <span class="signin__label">Email</span>
                        <input
                            data-signin-email
                            type="email"
                            name="email"
                            // `webauthn` lets the browser offer a passkey for this
                            // origin inline, which is what resolves the personal
                            // branch without the server admitting an account exists.
                            autocomplete="username webauthn"
                            placeholder="you@example.com"
                            required
                            autofocus
                            value={email()}
                            onInput={(event) => setEmail(event.currentTarget.value)}
                        />
                    </label>
                    <button class="signin__primary" data-signin-continue type="submit" disabled={busy() || !email().trim()}>
                        {busy() ? "Checking…" : "Continue"}
                    </button>
                    <Show when={props.passkey}>
                        <button
                            class="signin__quiet"
                            data-signin-create-open
                            type="button"
                            disabled={busy()}
                            onClick={() => {
                                const address = email().trim();
                                if (!address) {
                                    setStatus("Enter your email address first.");
                                    return;
                                }
                                setStep({ at: "create", email: address });
                            }}
                        >
                            New here? Create an account with a passkey
                        </button>
                    </Show>
                </form>

                <Show when={(props.providers?.length ?? 0) > 0}>
                    <div class="signin__rule"><span>or</span></div>
                    <div class="signin__providers" data-signin-providers>
                        <For each={props.providers}>
                            {(provider) => (
                                <button
                                    class="signin__provider"
                                    data-signin-provider={provider.id}
                                    type="button"
                                    aria-label={provider.label}
                                    title={provider.label}
                                    onClick={() => provider.begin()}
                                >
                                    <ProviderMark id={provider.id} />
                                </button>
                            )}
                        </For>
                    </div>
                </Show>
            </Show>

            <Show when={at('organization')}>
                {(current) => (
                        <div class="signin__act" data-signin-organization>
                            <p class="signin__resolved">
                                <span>
                                    <Show when={current().label} fallback={<strong>Your organization</strong>}>
                                        <strong>{current().label}</strong>
                                    </Show>
                                    {" "}uses single sign-on for {current().email}.
                                </span>
                                <button class="signin__change" type="button" onClick={restart}>Change</button>
                            </p>
                            <button class="signin__primary" type="button" onClick={() => current().go()}>
                                {current().label
                                    ? `Continue to ${current().label}`
                                    : "Continue to your organization's sign-in"}
                            </button>
                        </div>
                    )}
            </Show>

            <Show when={at('personal')}>
                {(current) => (
                        <div class="signin__act" data-signin-personal>
                            <p class="signin__resolved">
                                <span>{current().email}</span>
                                <button class="signin__change" type="button" onClick={restart}>Change</button>
                            </p>
                            <Show when={props.passkey}>
                                <button
                                    class="signin__primary"
                                    data-signin-passkey
                                    type="button"
                                    disabled={busy()}
                                    onClick={() => signInWithPasskey(current().email)}
                                >
                                    {busy() ? "Waiting for your passkey…" : "Continue with a passkey"}
                                </button>
                                <button
                                    class="signin__quiet"
                                    data-signin-create
                                    type="button"
                                    disabled={busy()}
                                    onClick={() => startCreation(current().email)}
                                >
                                    Create an account with a passkey
                                </button>
                            </Show>
                        </div>
                    )}
            </Show>

            <Show when={at('create')}>
                {(current) => (
                        <form class="signin__act" data-signin-create-form onSubmit={(event) => finishCreation(event, current())}>
                            <p class="signin__resolved">
                                <span>{current().email}</span>
                                <button class="signin__change" type="button" onClick={restart}>Change</button>
                            </p>
                            <label class="signin__field">
                                <span class="signin__label">Your name</span>
                                <input
                                    name="display-name"
                                    autocomplete="name"
                                    required
                                    value={displayName()}
                                    onInput={(event) => setDisplayName(event.currentTarget.value)}
                                />
                            </label>
                            <Show
                                when={current().challenge}
                                fallback={
                                    <button
                                        class="signin__primary"
                                        type="button"
                                        disabled={busy() || !displayName().trim()}
                                        onClick={() => startCreation(current().email)}
                                    >
                                        {busy() ? "Sending…" : "Email me a code"}
                                    </button>
                                }
                            >
                                <label class="signin__field">
                                    <span class="signin__label">Email code</span>
                                    <input
                                        name="email-code"
                                        inputmode="numeric"
                                        autocomplete="one-time-code"
                                        required
                                        value={code()}
                                        onInput={(event) => setCode(event.currentTarget.value)}
                                    />
                                </label>
                                <button class="signin__primary" type="submit" disabled={busy() || !code().trim()}>
                                    {busy() ? "Creating…" : "Create account"}
                                </button>
                            </Show>
                        </form>
                    )}
            </Show>

            <Show when={at('codes')}>
                {(current) => (
                    <div class="signin__act" data-signin-codes>
                        <p class="signin__resolved"><span>Account created for {current().email}</span></p>
                        <p class="signin__status">
                            Save these recovery codes somewhere safe. With a verified email
                            they are the way back into your account if you lose your
                            passkey — and this is the only time they are shown.
                        </p>
                        <ul class="signin__codes">
                            <For each={current().codes}>{(code) => <li>{code}</li>}</For>
                        </ul>
                        <button
                            class="signin__primary"
                            data-signin-codes-saved
                            type="button"
                            onClick={() => props.passkey!.complete()}
                        >
                            I've saved them
                        </button>
                        <button
                            class="signin__quiet"
                            type="button"
                            onClick={() => {
                                void navigator.clipboard
                                    ?.writeText(current().codes.join("\n"))
                                    .then(() => setStatus("Copied."))
                                    .catch(() => setStatus("Could not copy — select and copy them by hand."));
                            }}
                        >
                            Copy all
                        </button>
                    </div>
                )}
            </Show>

            <Show when={at('recover')}>
                {(current) => (
                        <form class="signin__act" data-signin-recover onSubmit={(event) => finishRecovery(event, current())}>
                            <p class="signin__resolved">
                                <span>{current().email}</span>
                                <button class="signin__change" type="button" onClick={restart}>Change</button>
                            </p>
                            <Show
                                when={current().challenge}
                                fallback={
                                    <button class="signin__primary" type="button" disabled={busy()}
                                        onClick={() => startRecovery(current().email)}>
                                        {busy() ? "Sending…" : "Email me a code"}
                                    </button>
                                }
                            >
                                <label class="signin__field">
                                    <span class="signin__label">Email code</span>
                                    <input name="email-code" inputmode="numeric" autocomplete="one-time-code" required
                                        value={code()} onInput={(event) => setCode(event.currentTarget.value)} />
                                </label>
                                <label class="signin__field">
                                    <span class="signin__label">Recovery code</span>
                                    <input name="recovery-code" autocomplete="off" required
                                        value={recoveryCode()} onInput={(event) => setRecoveryCode(event.currentTarget.value)} />
                                </label>
                                <button class="signin__primary" type="submit"
                                    disabled={busy() || !code().trim() || !recoveryCode().trim()}>
                                    {busy() ? "Recovering…" : "Recover account"}
                                </button>
                            </Show>
                        </form>
                    )}
            </Show>

            <Show when={status()}>
                <p class="signin__status" role="status" data-signin-status>{status()}</p>
            </Show>

            <div class="signin__foot">
                <Show when={props.recovery && step().at === "personal"}>
                    <button class="signin__quiet" type="button" disabled={busy()}
                        onClick={() => startRecovery((step() as Extract<Step, { at: "personal" }>).email)}>
                        Use a recovery code
                    </button>
                </Show>
            </div>

            {/* Only on the opening step. Past it the person has chosen a route —
                and on the codes step they have just made an account, where an
                offer to skip signing up is nonsense. */}
            <Show when={props.footnote && step().at === "identify"}>
                <div class="signin__rule"><span>or</span></div>
                <div class="signin__foot">{props.footnote}</div>
            </Show>
        </div>
    );
}
