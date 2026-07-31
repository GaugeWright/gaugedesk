import { invoke } from "@tauri-apps/api/core";
import { getCurrent, onOpenUrl } from "@tauri-apps/plugin-deep-link";
import { openUrl } from "@tauri-apps/plugin-opener";
import {
    deviceId,
    exchangeMobileAccountHandoff,
    publicKey,
    type DeviceIdentity,
    type HomeId,
    type OpaqueHomeRoute,
} from "@gaugewright/control-plane-client";
import { controlPlaneBase } from "./mobile-control-plane";
import {
    parseMobileTargetReference,
    type MobileTargetReference,
} from "./mobile-home-cache";

export const MOBILE_MACHINE_ENDPOINT_KEY = "gw.mobile.machine";
export const MOBILE_AUTH_VERIFIER_KEY = "gw.mobile.auth-verifier.v1";
export const MOBILE_ACCOUNT_BASE =
    (import.meta.env?.VITE_ACCOUNT_BASE as string | undefined)
    ?? "https://auth.gaugewright.com";

export interface MobileRuntime {
    readonly identity: DeviceIdentity;
    readonly endpoint: string | null;
    readonly native: boolean;
    readonly selfApprovePairing: boolean;
    readonly credentials: readonly MachineCredential[];
    readonly accountToken: string | null;
    readonly pendingAccountCode: string | null;
    readonly pendingTarget: MobileTargetReference | null;
    readonly pendingInvitation: MachineControllerInvitation | null;
    signChallenge(challenge: string): Promise<string>;
    storeCredential(credential: MachineCredential): Promise<void>;
    removeCredential(machine: string): Promise<void>;
    clearCredentials(): Promise<void>;
    storeAccountToken(idToken: string): Promise<void>;
    clearAccountToken(): Promise<void>;
}

interface NativeDeviceIdentity {
    readonly id: string;
    readonly publicKey: string;
    readonly algorithm: "ES256";
}

interface NativeChallengeSignature {
    readonly algorithm: "ES256";
    readonly signature: string;
}

export interface MachineCredential {
    readonly endpoint: string;
    readonly machine: string;
    readonly grantId: string;
    readonly credential: string;
}

export interface MachineControllerInvitation {
    readonly version: 1;
    readonly invitationId: string;
    readonly secret: string;
    readonly machine: string;
    readonly endpoint: string;
    readonly expiresAt: number;
}

interface NativeMachineCredentialRegistryResponse {
    readonly version: number;
    readonly credentials: unknown;
}

interface NativeLaunchUrlResponse {
    readonly url: string | null;
}

interface NativeAccountSessionResponse {
    readonly idToken: string | null;
}

const NATIVE_CALL_TIMEOUT_MS = 15_000;

async function boundedNativeCall<T>(
    operation: string,
    promise: Promise<T>,
    timeoutMs = NATIVE_CALL_TIMEOUT_MS,
): Promise<T> {
    let timeout: ReturnType<typeof setTimeout> | undefined;
    try {
        return await Promise.race([
            promise,
            new Promise<never>((_, reject) => {
                timeout = setTimeout(
                    () => reject(new Error(`${operation} timed out`)),
                    timeoutMs,
                );
            }),
        ]);
    } finally {
        if (timeout !== undefined) clearTimeout(timeout);
    }
}

function decodeBase64Url(value: string): string {
    const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
    const bytes = Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
    return new TextDecoder().decode(bytes);
}

export function parseMachineInvitationLink(raw: string): MachineControllerInvitation | null {
    try {
        const url = new URL(raw);
        // Android WebView treats non-special schemes as opaque URLs and reports
        // `//machine-enroll` as the pathname, while Chromium/Node expose it as
        // the hostname. Accept only that exact route in either standards shape.
        const route = url.hostname || url.pathname.replace(/^\/\//, "");
        if (url.protocol !== "gaugewright:" || route !== "machine-enroll") return null;
        const encoded = url.searchParams.get("d");
        if (!encoded) return null;
        const invitation = JSON.parse(decodeBase64Url(encoded)) as MachineControllerInvitation;
        if (
            invitation.version !== 1
            || !invitation.invitationId
            || !invitation.secret
            || !invitation.machine
            || normalizeMachineEndpoint(invitation.endpoint) !== invitation.endpoint.replace(/\/+$/, "")
            || invitation.expiresAt <= Date.now() / 1_000
        ) {
            return null;
        }
        return { ...invitation, endpoint: invitation.endpoint.replace(/\/+$/, "") };
    } catch {
        return null;
    }
}

export async function onMachineInvitation(
    handler: (invitation: MachineControllerInvitation) => void,
): Promise<() => void> {
    return onOneUseNativeLink(
        parseMachineInvitationLink,
        (invitation) => invitation.invitationId,
        handler,
    );
}

export function parseMobileAuthCallback(raw: string): string | null {
    try {
        const url = new URL(raw);
        const opaqueRoute = url.pathname.replace(/^\/\//, "");
        const matchesRoute =
            (url.hostname === "auth" && url.pathname === "/callback")
            || opaqueRoute === "auth/callback";
        if (url.protocol !== "gaugewright:" || !matchesRoute) return null;
        const code = new URLSearchParams(url.hash.replace(/^#/, "")).get("code")?.trim();
        return code && /^[A-Za-z0-9_-]{43}$/.test(code) ? code : null;
    } catch {
        return null;
    }
}

export async function onMobileAuthCallback(
    handler: (code: string) => void,
): Promise<() => void> {
    return onOneUseNativeLink(parseMobileAuthCallback, (code) => code, handler);
}

async function onOneUseNativeLink<T>(
    parse: (raw: string) => T | null,
    keyOf: (value: T) => string,
    handler: (value: T) => void,
): Promise<() => void> {
    const seen = new Set<string>();
    const emit = (urls: readonly string[]) => {
        for (const url of urls) {
            const value = parse(url);
            if (value === null) continue;
            const key = keyOf(value);
            if (seen.has(key)) continue;
            seen.add(key);
            handler(value);
        }
    };
    const stop = await onOpenUrl(emit);
    const timers = new Set<number>();
    const refreshCurrent = () => {
        if (document.visibilityState !== "visible") return;
        const refresh = window.setTimeout(() => {
            timers.delete(refresh);
            void Promise.all([
                getCurrent().catch(() => null),
                invoke<NativeLaunchUrlResponse>(
                    "plugin:gaugedesk-device-identity|get_launch_url",
                ).catch(() => ({ url: null })),
            ]).then(([current, native]) => {
                emit([
                    ...(current ?? []),
                    ...(native.url ? [native.url] : []),
                ]);
            });
        }, 100);
        timers.add(refresh);
    };
    const onVisibility = () => refreshCurrent();
    window.addEventListener("focus", refreshCurrent);
    document.addEventListener("visibilitychange", onVisibility);
    // A custom-scheme handoff can update iOS's retained URL without producing
    // either a live plugin event or a focus transition. Poll only while visible
    // so one-use invitations and account callbacks cannot disappear in that OS
    // lifecycle gap.
    const poll = window.setInterval(refreshCurrent, 1_000);
    refreshCurrent();
    return () => {
        stop();
        window.removeEventListener("focus", refreshCurrent);
        document.removeEventListener("visibilitychange", onVisibility);
        window.clearInterval(poll);
        for (const timer of timers) window.clearTimeout(timer);
    };
}

export async function onMobileTargetReference(
    handler: (target: MobileTargetReference) => void,
): Promise<() => void> {
    let lastUrl: string | null = null;
    let lastAt = 0;
    const emit = (urls: readonly string[]) => {
        for (const url of urls) {
            const target = parseMobileTargetReference(url);
            if (!target) continue;
            const now = Date.now();
            if (url === lastUrl && now - lastAt < 1_000) continue;
            lastUrl = url;
            lastAt = now;
            handler(target);
        }
    };
    const stop = await onOpenUrl(emit);
    const timers = new Set<number>();
    const refreshCurrent = () => {
        const refresh = window.setTimeout(() => {
            timers.delete(refresh);
            void Promise.all([
                getCurrent().catch(() => null),
                invoke<NativeLaunchUrlResponse>(
                    "plugin:gaugedesk-device-identity|get_launch_url",
                ).catch(() => ({ url: null })),
            ]).then(([current, native]) => {
                emit([
                    ...(current ?? []),
                    ...(native.url ? [native.url] : []),
                ]);
            });
        }, 100);
        timers.add(refresh);
    };
    const onVisibility = () => {
        if (document.visibilityState === "visible") refreshCurrent();
    };
    window.addEventListener("focus", refreshCurrent);
    document.addEventListener("visibilitychange", onVisibility);
    // Android can make the Activity visible before its launch intent is
    // observable through the plugin command. Re-read once after listeners are
    // mounted so a cold reference link cannot fall into that startup gap.
    refreshCurrent();
    return () => {
        stop();
        window.removeEventListener("focus", refreshCurrent);
        document.removeEventListener("visibilitychange", onVisibility);
        for (const timer of timers) window.clearTimeout(timer);
    };
}

export async function beginMobileAccountLogin(
    accountBase: string,
    native = isNativeMobile(),
): Promise<void> {
    const base = accountBase.replace(/\/+$/, "");
    if (native) {
        const verifierBytes = crypto.getRandomValues(new Uint8Array(32));
        const verifier = [...verifierBytes]
            .map((byte) => byte.toString(16).padStart(2, "0"))
            .join("");
        const digest = await crypto.subtle.digest(
            "SHA-256",
            new TextEncoder().encode(verifier),
        );
        const challenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
            .replace(/\+/g, "-")
            .replace(/\//g, "_")
            .replace(/=+$/, "");
        localStorage.setItem(MOBILE_AUTH_VERIFIER_KEY, verifier);
        const login = `${base}/auth/login?return_to=${encodeURIComponent(
            "gaugewright://auth/callback",
        )}&handoff_challenge=${encodeURIComponent(challenge)}`;
        await openUrl(login);
    } else if (typeof window !== "undefined") {
        window.location.assign(`${base}/auth/login`);
    }
}

export async function redeemMobileAccountHandoff(
    accountBase: string,
    code: string,
    storage: Pick<Storage, "getItem" | "removeItem"> = localStorage,
): Promise<string> {
    const verifier = storage.getItem(MOBILE_AUTH_VERIFIER_KEY);
    if (!verifier) throw new Error("This sign-in was not started on this device.");
    try {
        return await exchangeMobileAccountHandoff(accountBase, code, verifier);
    } finally {
        // Presentation is single-use and the server may have consumed the code
        // even if its response was lost. Retaining the verifier could only
        // create a misleading or replay-shaped retry.
        storage.removeItem(MOBILE_AUTH_VERIFIER_KEY);
    }
}

export function isNativeMobile(): boolean {
    return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

interface NativeRelayRouteResponse {
    readonly endpoint: string;
}

/** Resolve ADR 0116's opaque relay locator into a device-loopback endpoint.
 * Browsers retain the direct HTTPS fallback; native shells prefer the shared
 * cert-pinned relay without changing the control-plane API. */
export async function resolveMobileRouteEndpoint(
    route: OpaqueHomeRoute,
    call: typeof invoke = invoke,
): Promise<string> {
    if (!route.relay || !isNativeMobile()) {
        if (!route.endpoint) {
            throw new Error("This relay-only Machine requires the native GaugeDesk app");
        }
        return route.endpoint;
    }
    const result = await boundedNativeCall(
        "Opening the Home relay",
        call<NativeRelayRouteResponse>("ensure_relay_route", {
            request: {
                homeId: route.homeId,
                endpoint: route.relay.endpoint,
                handle: route.relay.handle,
                proof: route.relay.proof,
                routeEpoch: route.relay.routeEpoch,
                homeFingerprint: route.relay.homeFingerprint,
            },
        }),
    );
    if (!/^http:\/\/127\.0\.0\.1:\d+$/.test(result.endpoint)) {
        throw new Error("Native relay returned a non-loopback endpoint");
    }
    return result.endpoint;
}

export async function closeMobileRelayRoute(
    homeId: HomeId,
    call: typeof invoke = invoke,
): Promise<void> {
    if (!isNativeMobile()) return;
    await boundedNativeCall(
        "Closing the Home relay",
        call("close_relay_route", { homeId }),
    );
}

export function normalizeMachineEndpoint(raw: string): string {
    const endpoint = raw.trim().replace(/\/+$/, "");
    let url: URL;
    try {
        url = new URL(endpoint);
    } catch {
        throw new Error("Use an HTTPS Machine endpoint");
    }
    if (url.protocol !== "https:" || url.username !== "" || url.password !== "") {
        throw new Error("Use an HTTPS Machine endpoint");
    }
    return endpoint;
}

/** Only the direct-session protocol's explicit grant/device refusal authorizes
 * deleting a durable local credential. Transient challenge expiry and missing
 * routes leave it intact for repair/retry. */
export function machineCredentialIsRejected(reason: string): boolean {
    return /\b403\b/.test(reason);
}

export function savedMachineEndpoint(storage: Pick<Storage, "getItem"> = localStorage): string | null {
    const raw = storage.getItem(MOBILE_MACHINE_ENDPOINT_KEY);
    if (raw === null) return null;
    try {
        return normalizeMachineEndpoint(raw);
    } catch {
        return null;
    }
}

export function saveMachineEndpoint(
    raw: string,
    storage: Pick<Storage, "setItem"> = localStorage,
): string {
    const endpoint = normalizeMachineEndpoint(raw);
    storage.setItem(MOBILE_MACHINE_ENDPOINT_KEY, endpoint);
    return endpoint;
}

export function clearMachineEndpoint(
    storage: Pick<Storage, "removeItem"> = localStorage,
): void {
    storage.removeItem(MOBILE_MACHINE_ENDPOINT_KEY);
}

export function parseMachineCredentialRegistry(
    raw: NativeMachineCredentialRegistryResponse,
): MachineCredential[] {
    if (raw.version !== 1 || !Array.isArray(raw.credentials)) {
        throw new Error("Native Machine credential registry is malformed");
    }
    const byMachine = new Map<string, MachineCredential>();
    for (const item of raw.credentials) {
        const credential = item as Partial<MachineCredential>;
        if (
            typeof credential.machine !== "string"
            || !credential.machine
            || typeof credential.endpoint !== "string"
            || typeof credential.grantId !== "string"
            || !credential.grantId
            || typeof credential.credential !== "string"
            || !credential.credential
        ) {
            throw new Error("Native Machine credential registry is malformed");
        }
        const normalized = {
            machine: credential.machine,
            endpoint: normalizeMachineEndpoint(credential.endpoint),
            grantId: credential.grantId,
            credential: credential.credential,
        };
        if (byMachine.has(normalized.machine)) {
            throw new Error(`Native Machine credential registry repeats ${normalized.machine}`);
        }
        byMachine.set(normalized.machine, normalized);
    }
    return [...byMachine.values()].sort((left, right) =>
        left.machine.localeCompare(right.machine),
    );
}

export async function loadMobileRuntime(
    call: typeof invoke = invoke,
): Promise<MobileRuntime> {
    if (!isNativeMobile()) {
        return {
            identity: {
                id: deviceId("device:web-harness"),
                deviceKey: publicKey("devkey-web-harness"),
            },
            endpoint: controlPlaneBase(),
            native: false,
            selfApprovePairing: true,
            credentials: [],
            accountToken: null,
            pendingAccountCode: null,
            pendingTarget: null,
            pendingInvitation: null,
            signChallenge: async () => {
                throw new Error("Browser harness does not own a native device key");
            },
            storeCredential: async () => undefined,
            removeCredential: async () => undefined,
            clearCredentials: async () => undefined,
            storeAccountToken: async () => undefined,
            clearAccountToken: async () => undefined,
        };
    }

    const identity = await boundedNativeCall(
        "Opening the native device identity",
        call<NativeDeviceIdentity>(
            "plugin:gaugedesk-device-identity|get_identity",
        ),
    );
    if (
        typeof identity.id !== "string"
        || typeof identity.publicKey !== "string"
        || identity.algorithm !== "ES256"
    ) {
        throw new Error("Native device identity is malformed");
    }
    const [stored, storedAccount] = await Promise.all([
        boundedNativeCall(
            "Opening the Machine credential registry",
            call<NativeMachineCredentialRegistryResponse>(
                "plugin:gaugedesk-device-identity|list_machine_credentials",
            ),
        ),
        boundedNativeCall(
            "Opening the account session",
            call<NativeAccountSessionResponse>(
                "plugin:gaugedesk-device-identity|get_account_session",
            ),
        ),
    ]);
    const credentials = parseMachineCredentialRegistry(stored);
    const [currentLinks, nativeLaunch] = await Promise.all([
        getCurrent().catch(() => null),
        boundedNativeCall(
            "Opening the native launch URL",
            call<NativeLaunchUrlResponse>(
                "plugin:gaugedesk-device-identity|get_launch_url",
            ),
        ).catch(() => ({ url: null })),
    ]);
    const launchLinks = [...(currentLinks ?? []), ...(nativeLaunch.url ? [nativeLaunch.url] : [])];
    const pendingInvitation = launchLinks
        ?.map(parseMachineInvitationLink)
        .find((invitation): invitation is MachineControllerInvitation => invitation !== null)
        ?? null;
    const pendingAccountCode = launchLinks
        .map(parseMobileAuthCallback)
        .find((code): code is string => code !== null)
        ?? null;
    const pendingTarget = launchLinks
        .map(parseMobileTargetReference)
        .find((target): target is MobileTargetReference => target !== null)
        ?? null;
    return {
        identity: {
            id: deviceId(identity.id),
            deviceKey: publicKey(identity.publicKey),
        },
        endpoint:
            pendingInvitation?.endpoint
            ?? savedMachineEndpoint()
            ?? credentials[0]?.endpoint
            ?? null,
        native: true,
        selfApprovePairing: false,
        credentials,
        accountToken: storedAccount.idToken,
        pendingAccountCode,
        pendingTarget,
        pendingInvitation,
        signChallenge: async (challenge) => {
            const signed = await boundedNativeCall(
                "Signing the Machine challenge",
                call<NativeChallengeSignature>(
                    "plugin:gaugedesk-device-identity|sign_challenge",
                    { payload: { challenge } },
                ),
            );
            if (signed.algorithm !== "ES256" || typeof signed.signature !== "string") {
                throw new Error("Native challenge signature is malformed");
            }
            return signed.signature;
        },
        storeCredential: async (next) => {
            await boundedNativeCall(
                "Saving the Machine credential",
                call(
                    "plugin:gaugedesk-device-identity|store_machine_credential",
                    { payload: { ...next } },
                ),
            );
        },
        removeCredential: async (machine) => {
            await boundedNativeCall(
                "Removing the Machine credential",
                call(
                    "plugin:gaugedesk-device-identity|remove_machine_credential",
                    { payload: { machine } },
                ),
            );
        },
        clearCredentials: async () => {
            await boundedNativeCall(
                "Clearing the Machine credential registry",
                call("plugin:gaugedesk-device-identity|clear_machine_credential"),
            );
        },
        storeAccountToken: async (idToken) => {
            await boundedNativeCall(
                "Saving the account session",
                call(
                    "plugin:gaugedesk-device-identity|store_account_session",
                    { payload: { idToken } },
                ),
            );
        },
        clearAccountToken: async () => {
            await boundedNativeCall(
                "Clearing the account session",
                call("plugin:gaugedesk-device-identity|clear_account_session"),
            );
        },
    };
}
