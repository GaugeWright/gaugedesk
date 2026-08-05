/**
 * **First-run credential flow** (ADR 0075 §6 / Phase 0): the *separate, minimal,
 * static* welcome shown before anything else when the account has no LLM
 * credential. It exists because nothing agent-driven — not even the whip
 * onboarding tracker — can run before a credential exists, so this one step
 * cannot itself be agent-driven.
 *
 * Two separate connections are presented, and keeping them visibly separate is
 * the point (they were conflated before — "Sign in with OpenAI" read as the
 * app's sign-in):
 *
 * 1. **Your account** — GaugeWright sign-in (Google), which identifies the
 *    person. Offered only when the composition's control plane serves the OIDC
 *    login shell (`/auth/login` lives in `ee/app`); the core desktop build
 *    omits {@link FirstRunAccount} and states that it runs locally instead.
 * 2. **Model access** — an API key or the OpenAI (codex) authorization, which
 *    lets agents run. The OpenAI flow authorizes a model backend; it is not an
 *    account sign-in, and the copy says so.
 *
 * Deliberately self-contained, not the full {@link AccountPanel}: welcome →
 * connect a model → get out of the way. It links a credential directly over
 * `/account/*`, then calls `onConnected` so the host re-checks and dismisses.
 * A quiet "I'll do this later" escape hatch keeps it from trapping anyone if
 * detection is ever wrong.
 *
 * A thin renderer (INV-5): the token is write-only (sealed server-side, SEC-4);
 * it is never read back.
 */

import { createSignal, onCleanup, Show, type JSX } from "solid-js";
import { waitForCodexLink } from "./codex-link-poll";
import type { CodexLoginStart, CodexStatus } from "@gaugewright/control-plane-client";

/** The slice of the control-plane API this flow needs. */
export interface FirstRunApi {
    codexLoginStart(): Promise<CodexLoginStart>;
    codexLoginCancel(): Promise<void>;
    codexStatus(): Promise<CodexStatus>;
    accountLinkCredential(provider: string, token: string): Promise<void>;
}

/**
 * GaugeWright account sign-in wiring for the welcome step. Provided only by
 * compositions whose control plane serves the OIDC login shell; omitted on the
 * core desktop build, which has no account plane to sign in to.
 */
export interface FirstRunAccount {
    /** Button label, e.g. "Sign in with Google" / "Enter local dev account". */
    label: string;
    /** Whether an account session exists (reactive). */
    signedIn: () => boolean;
    /** The signed-in subject for display, when the client knows it (reactive). */
    subject?: () => string | null;
    /** Navigate to the control plane's OIDC login. */
    begin: () => void;
}

/** The providers a first-run user can paste a key for (mirrors AccountPanel). */
const KEY_PROVIDERS: readonly { id: string; label: string }[] = [
    { id: "anthropic", label: "Anthropic (Claude)" },
    { id: "openai", label: "OpenAI" },
];

export function FirstRunOverlay(props: {
    api: FirstRunApi;
    /** Product name to greet with (e.g. "GaugeDesk"). */
    productName: string;
    /** Whether this runtime offers an OpenAI authorization flow. */
    codexLoginAvailable?: boolean;
    /** Account sign-in for this composition; omitted where none exists. */
    account?: FirstRunAccount;
    /** A credential was just linked — the host refetches status, which dismisses us. */
    onConnected: () => void;
    /** "I'll do this later" — dismiss for the session without connecting. */
    onDismiss: () => void;
}): JSX.Element {
    const [provider, setProvider] = createSignal(KEY_PROVIDERS[0].id);
    const [token, setToken] = createSignal("");
    const [busy, setBusy] = createSignal(false);
    const [status, setStatus] = createSignal("");
    const [authUrl, setAuthUrl] = createSignal("");
    const [deviceCode, setDeviceCode] = createSignal("");

    const linkKey = async (e: Event) => {
        e.preventDefault();
        if (!token().trim() || busy()) return;
        setBusy(true);
        setStatus("connecting…");
        try {
            await props.api.accountLinkCredential(provider(), token().trim());
            setToken("");
            setStatus("connected");
            props.onConnected();
        } catch (err) {
            setStatus(`couldn't connect — ${String(err)}`);
        } finally {
            setBusy(false);
        }
    };

    // The sign-in completes in the external tab and the credential lands
    // server-side, so watch the status projection and advance on our own; the
    // Continue button stays as the manual escape hatch.
    let disposed = false;
    onCleanup(() => {
        disposed = true;
    });
    let watchingLink = false;
    const watchForLink = async () => {
        if (watchingLink) return;
        watchingLink = true;
        try {
            const linked = await waitForCodexLink(() => props.api.codexStatus(), {
                cancelled: () => disposed,
            });
            if (linked && !disposed) props.onConnected();
        } finally {
            watchingLink = false;
        }
    };

    const linkCodex = async () => {
        if (busy()) return;
        setBusy(true);
        setStatus("starting OpenAI authorization…");
        setAuthUrl("");
        setDeviceCode("");
        try {
            const login = await props.api.codexLoginStart();
            const url = login.mode === "browser" ? login.url : login.login.verificationUrl;
            setAuthUrl(url);
            if (login.mode === "device") setDeviceCode(login.login.userCode);
            window.open(url, "_blank", "noopener,noreferrer");
            setStatus(login.mode === "device"
                ? `enter code ${login.login.userCode} on the OpenAI page — this screen continues by itself`
                : "finish authorizing in the new tab — this screen continues by itself");
            void watchForLink();
        } catch (err) {
            setStatus(`couldn't start the OpenAI authorization — ${String(err)}`);
        } finally {
            setBusy(false);
        }
    };

    const cancelCodex = async () => {
        try {
            await props.api.codexLoginCancel();
            setAuthUrl("");
            setDeviceCode("");
            setStatus("OpenAI authorization cancelled");
        } catch (err) {
            setStatus(`couldn't cancel the authorization — ${String(err)}`);
        }
    };

    const accountSubject = () => props.account?.subject?.() ?? null;

    return (
        <div class="firstrun-scrim" data-firstrun role="dialog" aria-modal="true" aria-label="welcome — sign in and connect a model">
            <div class="firstrun-card">
                <h1 class="firstrun-title">Welcome to {props.productName}</h1>
                <p class="firstrun-lede">
                    Two separate connections set up {props.productName}: your GaugeWright
                    account identifies you, and a model credential lets agents run.
                </p>

                <section class="firstrun-section" data-firstrun-account aria-label="your GaugeWright account">
                    <h2 class="firstrun-section-label">Your account</h2>
                    <Show
                        when={props.account}
                        fallback={
                            <p class="firstrun-note" data-firstrun-account-note>
                                This {props.productName} runs on your computer and needs no
                                account sign-in. Everything below only connects a model.
                            </p>
                        }
                    >
                        {(account) => (
                            <Show
                                when={account().signedIn()}
                                fallback={
                                    <>
                                        <button
                                            class="firstrun-connect"
                                            data-firstrun-account-signin
                                            type="button"
                                            onClick={() => account().begin()}
                                        >
                                            {account().label}
                                        </button>
                                        <p class="firstrun-note">
                                            Signing in identifies you to GaugeWright — your
                                            projects, Homes, and invitations.
                                        </p>
                                    </>
                                }
                            >
                                <p class="firstrun-account-state" data-firstrun-account-signed-in>
                                    <span class="firstrun-account-check" aria-hidden="true">✓</span>
                                    {accountSubject()
                                        ? `Signed in as ${accountSubject()}`
                                        : "Signed in to your GaugeWright account"}
                                </p>
                            </Show>
                        )}
                    </Show>
                </section>

                <section class="firstrun-section" aria-label="model access">
                    <h2 class="firstrun-section-label">Model access</h2>
                    <p class="firstrun-note">
                        Connect a model so agents can run. You can add more or change this
                        later in account settings.
                    </p>

                    <form class="firstrun-key" onSubmit={linkKey}>
                        <label class="firstrun-field">
                            <span class="firstrun-label">Provider</span>
                            <select
                                class="firstrun-select"
                                data-firstrun-provider
                                value={provider()}
                                onChange={(e) => setProvider(e.currentTarget.value)}
                                disabled={busy()}
                            >
                                {KEY_PROVIDERS.map((p) => (
                                    <option value={p.id}>{p.label}</option>
                                ))}
                            </select>
                        </label>
                        <label class="firstrun-field">
                            <span class="firstrun-label">API key</span>
                            <input
                                class="firstrun-input"
                                data-firstrun-token
                                type="password"
                                autocomplete="off"
                                placeholder="paste your API key"
                                value={token()}
                                onInput={(e) => setToken(e.currentTarget.value)}
                                disabled={busy()}
                            />
                        </label>
                        <button
                            class="firstrun-connect"
                            data-firstrun-connect
                            type="submit"
                            disabled={busy() || !token().trim()}
                        >
                            Connect
                        </button>
                    </form>

                    <Show when={props.codexLoginAvailable ?? true}>
                        <div class="firstrun-or">or</div>

                        <button
                            class="firstrun-codex"
                            data-firstrun-codex
                            type="button"
                            onClick={linkCodex}
                            disabled={busy()}
                        >
                            Connect your OpenAI account
                        </button>
                        <p class="firstrun-note">
                            This authorizes OpenAI model access for agents. It is not a
                            {" "}{props.productName} sign-in.
                        </p>
                        <Show when={authUrl()}>
                            <div class="firstrun-codex-follow">
                                <Show when={deviceCode()}>
                                    <span>Code: <code data-firstrun-codex-device-code>{deviceCode()}</code></span>
                                </Show>
                                <a href={authUrl()} target="_blank" rel="noopener noreferrer">
                                    Open the authorization page
                                </a>
                                <button
                                    class="firstrun-codex-continue"
                                    data-firstrun-codex-continue
                                    type="button"
                                    onClick={() => props.onConnected()}
                                >
                                    Continue
                                </button>
                                <Show when={deviceCode()}>
                                    <button
                                        class="firstrun-codex-continue"
                                        data-firstrun-codex-cancel
                                        type="button"
                                        onClick={cancelCodex}
                                    >
                                        Cancel
                                    </button>
                                </Show>
                            </div>
                        </Show>
                    </Show>
                    <Show when={!(props.codexLoginAvailable ?? true)}>
                        <p class="firstrun-note" data-codex-oauth-unavailable>
                            GaugeWright sign-in and OpenAI authorization are separate. Connect
                            an API key here, or enable OpenAI account authorization for this
                            runtime.
                        </p>
                    </Show>
                </section>

                <Show when={status()}>
                    <p class="firstrun-status" data-firstrun-status>{status()}</p>
                </Show>

                <button
                    class="firstrun-later"
                    data-firstrun-later
                    type="button"
                    onClick={() => props.onDismiss()}
                >
                    I'll do this later
                </button>
            </div>
        </div>
    );
}
