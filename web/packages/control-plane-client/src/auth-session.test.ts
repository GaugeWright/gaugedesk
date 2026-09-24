import { afterEach, describe, expect, it, vi } from "vitest";
import {
    bearer,
    beginLogin,
    claimConsumerSignup,
    completeConsumerSignupEmail,
    startConsumerSignupEmail,
    consumeAccountSignupTicket,
    consumeCallbackToken,
    decodeSubject,
    finishConsumerSignupAccount,
    endSession,
    exchangeMobileAccountHandoff,
    finishAccountRecovery,
    parseCallbackFragment,
    refreshHostedAccountSession,
    refreshMobileAccountToken,
    setBearer,
    signInWithPasskey,
    signedIn,
    startAccountRecovery,
    startPasskeyAccountCreation,
    finishPasskeyAccountCreation,
    workEmailLoginTarget,
} from "./auth-session";

afterEach(() => vi.unstubAllGlobals());

describe("account login navigation", () => {
    it("normalizes the control-plane base for personal sign-in", () => {
        const location = { href: "https://desk.example/" };
        vi.stubGlobal("window", { location });

        beginLogin("https://auth.example///");

        expect(location.href).toBe("https://auth.example/auth/login");
    });

    it("keeps work-email discovery input out of the target URL", () => {
        expect(workEmailLoginTarget("https://auth.example///")).toBe(
            "https://auth.example/auth/work-email",
        );
    });
});

/** Build an unsigned JWT-shaped string with the given payload (base64url, no padding) —
 *  enough to exercise the display-only `sub` decode (the client never verifies). */
function fakeJwt(payload: object): string {
    const b64url = (o: object) =>
        btoa(JSON.stringify(o)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    return `${b64url({ alg: "RS256" })}.${b64url(payload)}.sig`;
}

describe("parseCallbackFragment", () => {
    it("pulls the id-token out of the callback fragment", () => {
        expect(parseCallbackFragment("#id_token=abc.def.ghi&token_type=Bearer")).toBe("abc.def.ghi");
        expect(parseCallbackFragment("id_token=xyz")).toBe("xyz"); // tolerates a missing leading '#'
    });

    it("returns null when no token is present", () => {
        expect(parseCallbackFragment("")).toBeNull();
        expect(parseCallbackFragment("#")).toBeNull();
        expect(parseCallbackFragment("#error=access_denied")).toBeNull();
        expect(parseCallbackFragment("#id_token=")).toBeNull();
    });

    it("removes only OIDC fields and leaves another fragment capability for its owner", () => {
        const replaceState = vi.fn();
        vi.stubGlobal("window", {
            location: {
                hash: "#proposal_proof=one-time-proof&id_token=abc.def.ghi&token_type=Bearer",
                pathname: "/",
                search: "?proposal=engagement-1",
            },
        });
        vi.stubGlobal("history", { replaceState });

        expect(consumeCallbackToken()).toBe(true);
        expect(bearer()).toBe("abc.def.ghi");
        expect(replaceState).toHaveBeenCalledWith(
            null,
            "",
            "/?proposal=engagement-1#proposal_proof=one-time-proof",
        );
        setBearer(null);
    });
});

describe("decodeSubject", () => {
    it("decodes the sub claim for display", () => {
        expect(decodeSubject(fakeJwt({ sub: "alice@example.test", aud: "x" }))).toBe(
            "alice@example.test",
        );
    });

    it("returns null for a non-JWT or a token without a sub", () => {
        expect(decodeSubject("not-a-jwt")).toBeNull();
        expect(decodeSubject("a.b")).toBeNull(); // wrong segment count
        expect(decodeSubject(fakeJwt({ aud: "x" }))).toBeNull(); // no sub
        expect(decodeSubject("a.!!!notbase64!!!.c")).toBeNull();
    });
});

describe("bearer is in-memory only (ENTSEC-6)", () => {
    it("never writes the token to a Storage, even when one is available", () => {
        // Install recording Storage stubs (the test env is `node`, no DOM): if setBearer ever
        // persisted the credential, these would capture the write.
        const writes: Record<string, string> = {};
        const stub = {
            store: writes,
            getItem: (k: string) => writes[k] ?? null,
            setItem: (k: string, v: string) => { writes[k] = v; },
            removeItem: (k: string) => { delete writes[k]; },
        };
        const g = globalThis as unknown as { localStorage?: unknown; sessionStorage?: unknown };
        const prevLocal = g.localStorage;
        const prevSession = g.sessionStorage;
        g.localStorage = stub;
        g.sessionStorage = stub;
        try {
            setBearer("header.payload.sig");
            expect(bearer()).toBe("header.payload.sig"); // held in the in-memory signal
            expect(signedIn()).toBe(true);
            // The credential must NOT be at rest anywhere a later local access / XSS could scrape.
            expect(Object.keys(writes)).toHaveLength(0);

            setBearer(null);
            expect(bearer()).toBeNull();
            expect(signedIn()).toBe(false);
            expect(Object.keys(writes)).toHaveLength(0);
        } finally {
            g.localStorage = prevLocal;
            g.sessionStorage = prevSession;
        }
    });
});

describe("endSession", () => {
    it("expires the hosted cookie before clearing the in-memory bearer", async () => {
        setBearer("header.payload.sig");
        const fetch = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
            new Response(null, { status: 204 }));
        vi.stubGlobal("fetch", fetch);

        await endSession("https://auth.example/");

        expect(fetch).toHaveBeenCalledOnce();
        expect(fetch.mock.calls[0]?.[0]).toBe("https://auth.example/auth/logout");
        expect(fetch.mock.calls[0]?.[1]).toMatchObject({ method: "POST", credentials: "include" });
        expect(new Headers(fetch.mock.calls[0]?.[1]?.headers).get("idempotency-key")).toBeTruthy();
        expect(bearer()).toBeNull();
    });

    it("keeps local auth state when the server could not clear its cookie", async () => {
        setBearer("header.payload.sig");
        vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 502 })));

        await expect(endSession("https://auth.example")).rejects.toThrow("Sign out failed (502)");
        expect(bearer()).toBe("header.payload.sig");
        setBearer(null);
    });
});

describe("provider-neutral account recovery", () => {
    it("starts and finishes the single-use server ceremony without retaining a bearer", async () => {
        setBearer(null);
        const fetch = vi.fn()
            .mockResolvedValueOnce(new Response(JSON.stringify({ challenge_id: "challenge-1", expires_in: 600 }), {
                status: 202,
                headers: { "content-type": "application/json" },
            }))
            .mockResolvedValueOnce(new Response(JSON.stringify({ account_id: "person-one" }), {
                status: 200,
                headers: { "content-type": "application/json", "set-cookie": "ignored-by-js" },
            }));
        vi.stubGlobal("fetch", fetch);

        await expect(startAccountRecovery("https://auth.example/", "person@example.test"))
            .resolves.toEqual({ challengeId: "challenge-1", expiresIn: 600 });
        await expect(finishAccountRecovery(
            "https://auth.example/", "challenge-1", "123456", "GW-RECOVERY-CODE",
        )).resolves.toBe("person-one");

        expect(fetch.mock.calls.map(([url]) => url)).toEqual([
            "https://auth.example/auth/account/recovery/start",
            "https://auth.example/auth/account/recovery/finish",
        ]);
        expect(fetch.mock.calls.every(([, init]) => init?.credentials === "include")).toBe(true);
        expect(JSON.parse(String(fetch.mock.calls[1]?.[1]?.body))).toEqual({
            challenge_id: "challenge-1",
            email_code: "123456",
            recovery_code: "GW-RECOVERY-CODE",
        });
        expect(bearer()).toBeNull();
    });

    it("fails closed on malformed success and gives rate-limit guidance", async () => {
        vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ challenge_id: "missing-expiry" }), {
            status: 202,
            headers: { "content-type": "application/json" },
        })));
        await expect(startAccountRecovery("https://auth.example", "person@example.test"))
            .rejects.toThrow("response is malformed");

        vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 429 })));
        await expect(finishAccountRecovery("https://auth.example", "c", "e", "r"))
            .rejects.toThrow("temporarily limited");
    });
});

const bytes = (...value: number[]): ArrayBuffer => new Uint8Array(value).buffer;
const byteValues = (value: BufferSource | undefined): number[] => {
    if (!value) return [];
    return Array.from(value instanceof ArrayBuffer
        ? new Uint8Array(value)
        : new Uint8Array(value.buffer, value.byteOffset, value.byteLength));
};

const registrationCredential = {
    id: "registration-credential",
    rawId: bytes(250, 251),
    type: "public-key",
    authenticatorAttachment: "platform",
    response: {
        attestationObject: bytes(1, 2),
        clientDataJSON: bytes(3, 4),
        getTransports: () => ["internal"],
    },
    getClientExtensionResults: () => ({ credProps: { rk: true } }),
} as unknown as PublicKeyCredential;

const authenticationCredential = {
    id: "authentication-credential",
    rawId: bytes(252, 253),
    type: "public-key",
    authenticatorAttachment: "platform",
    response: {
        authenticatorData: bytes(5, 6),
        clientDataJSON: bytes(7, 8),
        signature: bytes(9, 10),
        userHandle: bytes(11, 12),
    },
    getClientExtensionResults: () => ({ appid: false }),
} as unknown as PublicKeyCredential;

describe("provider-neutral passkey account entry", () => {
    it("verifies email and registers the first passkey through four server-owned steps", async () => {
        setBearer(null);
        const fetch = vi.fn()
            .mockResolvedValueOnce(new Response(JSON.stringify({ challenge_id: "email-1", expires_in: 600 }), {
                status: 202,
                headers: { "content-type": "application/json" },
            }))
            .mockResolvedValueOnce(new Response(JSON.stringify({ email_verification: "verified-email-1" }), {
                status: 200,
                headers: { "content-type": "application/json" },
            }))
            .mockResolvedValueOnce(new Response(JSON.stringify({
                ceremony_id: "registration-1",
                public_key: {
                    challenge: "AQI",
                    rp: { name: "GaugeWright", id: "auth.example" },
                    user: { id: "AwQ", name: "person@example.test", displayName: "Person One" },
                    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
                    excludeCredentials: [{ type: "public-key", id: "BQY" }],
                },
            }), { status: 200, headers: { "content-type": "application/json" } }))
            .mockResolvedValueOnce(new Response(JSON.stringify({
                account_id: "person-one",
                recovery_codes: ["HKPR-7T2M-QJ4X", "B9WD-LN3F-VZ6K"],
            }), {
                status: 200,
                headers: { "content-type": "application/json", "set-cookie": "opaque-session" },
            }));
        vi.stubGlobal("fetch", fetch);
        const create = vi.fn(async (_options: CredentialCreationOptions): Promise<Credential | null> =>
            registrationCredential);

        await expect(startPasskeyAccountCreation(
            "https://auth.example/",
            "person@example.test",
        )).resolves.toEqual({ challengeId: "email-1", expiresIn: 600 });
        await expect(finishPasskeyAccountCreation(
            "https://auth.example/",
            "email-1",
            "123456",
            "Person One",
            { create, get: vi.fn() },
        )).resolves.toEqual({
            accountId: "person-one",
            recoveryCodes: ["HKPR-7T2M-QJ4X", "B9WD-LN3F-VZ6K"],
        });

        expect(fetch.mock.calls.map(([url]) => url)).toEqual([
            "https://auth.example/auth/account/email/start",
            "https://auth.example/auth/account/email/complete",
            "https://auth.example/auth/account/passkey/register/start",
            "https://auth.example/auth/account/passkey/register/finish",
        ]);
        expect(fetch.mock.calls.every(([, init]) => init?.credentials === "include")).toBe(true);
        expect(fetch.mock.calls.every(([, init]) =>
            Boolean(new Headers(init?.headers).get("idempotency-key")))).toBe(true);
        expect(fetch.mock.calls.map(([, init]) => JSON.parse(String(init?.body)))).toEqual([
            { email: "person@example.test" },
            { challenge_id: "email-1", code: "123456" },
            { email_verification: "verified-email-1", display_name: "Person One" },
            {
                ceremony_id: "registration-1",
                label: "Passkey",
                credential: {
                    id: "-vs",
                    transports: ["internal"],
                    attestationObject: "AQI",
                    clientDataJSON: "AwQ",
                },
            },
        ]);
        const creation = create.mock.calls[0]?.[0] as CredentialCreationOptions;
        expect(byteValues(creation.publicKey?.challenge)).toEqual([1, 2]);
        expect(byteValues(creation.publicKey?.user.id)).toEqual([3, 4]);
        expect(byteValues(creation.publicKey?.excludeCredentials?.[0]?.id)).toEqual([5, 6]);
        expect(bearer()).toBeNull();
    });

    it("refuses an account the server created without recovery codes", async () => {
        // ADR 0146 §2 recovery needs a verified email *and* an unused recovery
        // code, so an account issued none can never be recovered. Every passkey
        // account was in that state until the ceremony began minting a batch;
        // resolving here would report success for an account with one
        // authenticator and no way back if it is lost.
        const fetch = vi.fn()
            .mockResolvedValueOnce(new Response(JSON.stringify({ email_verification: "verified-1" }), {
                status: 200, headers: { "content-type": "application/json" },
            }))
            .mockResolvedValueOnce(new Response(JSON.stringify({
                ceremony_id: "ceremony-1",
                public_key: {
                    challenge: "AQI",
                    rp: { name: "GaugeWright", id: "auth.example" },
                    user: { id: "AwQ", name: "person@example.test", displayName: "Person One" },
                    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
                },
            }), { status: 200, headers: { "content-type": "application/json" } }))
            .mockResolvedValueOnce(new Response(JSON.stringify({ account_id: "person-one" }), {
                status: 200, headers: { "content-type": "application/json" },
            }));
        vi.stubGlobal("fetch", fetch);
        const create = vi.fn(async (_options: CredentialCreationOptions): Promise<Credential | null> =>
            registrationCredential);

        await expect(finishPasskeyAccountCreation(
            "https://auth.example/",
            "email-1",
            "123456",
            "Person One",
            { create, get: vi.fn() },
        )).rejects.toThrow(/no recovery codes/i);
    });

    it("creates a Microsoft-first account by proving the address with a code", async () => {
        // DR-0189 §4. Entra ID emits no `email_verified`, so the one-click
        // entrance is closed to it and the address is proved the other way step
        // 1 admits. The account still lands in one append with a recovery batch
        // and no passkey — the only difference from Google is which proof
        // supplied the verified address.
        const fetch = vi.fn()
            .mockResolvedValueOnce(new Response(JSON.stringify({
                email: "work.person@example.test",
                display_name: "Work Person",
                provider: "microsoft",
                provider_label: "Microsoft",
                email_proof: "code",
            }), { status: 200, headers: { "content-type": "application/json" } }))
            .mockResolvedValueOnce(new Response(JSON.stringify({
                challenge_id: "email-challenge-1",
                expires_in: 600,
            }), { status: 202, headers: { "content-type": "application/json" } }))
            .mockResolvedValueOnce(new Response(JSON.stringify({
                account_id: "work-person",
                recovery_codes: ["HKPR-7T2M-QJ4X", "B9WD-LN3F-VZ6K"],
            }), {
                status: 200,
                headers: { "content-type": "application/json", "set-cookie": "opaque-session" },
            }));
        vi.stubGlobal("fetch", fetch);

        await expect(claimConsumerSignup("https://auth.example/", "ticket-ms")).resolves.toEqual({
            email: "work.person@example.test",
            displayName: "Work Person",
            provider: "microsoft",
            providerLabel: "Microsoft",
            emailProof: "code",
        });
        await expect(startConsumerSignupEmail(
            "https://auth.example/",
            "ticket-ms",
            "work.person@example.test",
        )).resolves.toEqual({ challengeId: "email-challenge-1", expiresIn: 600 });
        await expect(completeConsumerSignupEmail(
            "https://auth.example/",
            "ticket-ms",
            "email-challenge-1",
            "123456",
        )).resolves.toMatchObject({
            recoveryCodes: ["HKPR-7T2M-QJ4X", "B9WD-LN3F-VZ6K"],
        });

        // The address is never sent as a signup fact; it is sent to be proved,
        // and the account is created by the route that spends the proof.
        const paths = fetch.mock.calls.map(([url]) => String(url));
        expect(paths[1]).toContain("/auth/account/consumer-signup/email/start");
        expect(paths[2]).toContain("/auth/account/consumer-signup/email/complete");
        expect(paths.some((path) => path.includes("/register/start"))).toBe(false);
    });

    it("refuses a claim that says it is attested but carries no address", async () => {
        // An attested claim whose address is missing is a malformed response, not
        // an invitation to create an account over an empty string.
        const fetch = vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({
            display_name: "Nobody",
            provider: "google",
            email_proof: "attested",
        }), { status: 200, headers: { "content-type": "application/json" } }));
        vi.stubGlobal("fetch", fetch);
        await expect(claimConsumerSignup("https://auth.example/", "ticket-bad"))
            .rejects.toThrow(/malformed/i);
    });

    it("creates a Google-first account without ever sending an email code", async () => {
        // ADR 0146 §1 step 1 is "verify an email address", not "send a code" —
        // the provider already attested one, so the two email calls the passkey
        // entrance makes are absent here and the ticket stands in their place.
        // Everything after is the same route on the same server, because there
        // is only one place an account is created.
        const fetch = vi.fn()
            .mockResolvedValueOnce(new Response(JSON.stringify({
                email: "person@example.test",
                display_name: "Person One",
                provider: "google",
            }), { status: 200, headers: { "content-type": "application/json" } }))
            .mockResolvedValueOnce(new Response(JSON.stringify({
                ceremony_id: "registration-1",
                public_key: {
                    challenge: "AQI",
                    rp: { name: "GaugeWright", id: "auth.example" },
                    user: { id: "AwQ", name: "person@example.test", displayName: "Person One" },
                    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
                },
            }), { status: 200, headers: { "content-type": "application/json" } }))
            .mockResolvedValueOnce(new Response(JSON.stringify({
                account_id: "person-one",
                recovery_codes: ["HKPR-7T2M-QJ4X", "B9WD-LN3F-VZ6K"],
                native_return: "gaugewright://auth/callback#code=handoff-1",
            }), {
                status: 200,
                headers: { "content-type": "application/json", "set-cookie": "opaque-session" },
            }));
        vi.stubGlobal("fetch", fetch);
        const create = vi.fn(async (_options: CredentialCreationOptions): Promise<Credential | null> =>
            registrationCredential);

        await expect(claimConsumerSignup("https://auth.example/", "ticket-1")).resolves.toEqual({
            email: "person@example.test",
            displayName: "Person One",
            providerLabel: "Google",
            emailProof: "attested",
            provider: "google",
        });
        await expect(finishConsumerSignupAccount(
            "https://auth.example/",
            "ticket-1",
            "Person One",
            { create, get: vi.fn() },
        )).resolves.toEqual({
            accountId: "person-one",
            recoveryCodes: ["HKPR-7T2M-QJ4X", "B9WD-LN3F-VZ6K"],
            // Returned, not followed: the page shows the codes first, because
            // following this raises the desktop window over the one tab that
            // will ever hold them.
            nativeReturn: "gaugewright://auth/callback#code=handoff-1",
        });

        expect(fetch.mock.calls.map(([url]) => url)).toEqual([
            "https://auth.example/auth/account/consumer-signup/claim",
            "https://auth.example/auth/account/consumer-signup/register/start",
            // The same finish as the email entrance. A provider-specific twin
            // would be a second place to get the atomic append wrong.
            "https://auth.example/auth/account/passkey/register/finish",
        ]);
        expect(fetch.mock.calls.map(([, init]) => JSON.parse(String(init?.body)))).toEqual([
            { ticket: "ticket-1" },
            { ticket: "ticket-1", display_name: "Person One" },
            {
                ceremony_id: "registration-1",
                label: "Passkey",
                credential: {
                    id: "-vs",
                    transports: ["internal"],
                    attestationObject: "AQI",
                    clientDataJSON: "AwQ",
                },
            },
        ]);
        // The session is the server's HttpOnly cookie, never a JS bearer.
        expect(bearer()).toBeNull();
    });

    it("refuses a Google-first account the server created without recovery codes", async () => {
        // The same guard as the passkey entrance, run here rather than trusted
        // from there: an account whose only authenticator is a Google login the
        // person could lose, with no codes, is unrecoverable.
        const fetch = vi.fn()
            .mockResolvedValueOnce(new Response(JSON.stringify({
                ceremony_id: "registration-1",
                public_key: {
                    challenge: "AQI",
                    rp: { name: "GaugeWright", id: "auth.example" },
                    user: { id: "AwQ", name: "person@example.test", displayName: "Person One" },
                    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
                },
            }), { status: 200, headers: { "content-type": "application/json" } }))
            .mockResolvedValueOnce(new Response(JSON.stringify({
                account_id: "person-one",
                recovery_codes: [],
            }), { status: 200, headers: { "content-type": "application/json" } }));
        vi.stubGlobal("fetch", fetch);
        await expect(finishConsumerSignupAccount(
            "https://auth.example/",
            "ticket-1",
            "Person One",
            {
                create: vi.fn(async (): Promise<Credential | null> => registrationCredential),
                get: vi.fn(),
            },
        )).rejects.toThrow(/no recovery codes/i);
    });

    it("takes a signup ticket out of the fragment and out of history", () => {
        // The ticket is a bearer for one verified email and one provider
        // subject. It must not survive in the address bar for the next person
        // at that machine, and it must never have been in a query string at all.
        const replaceState = vi.fn();
        vi.stubGlobal("window", {
            location: { hash: "#account_signup=ticket-1&other=keep", pathname: "/", search: "" },
        });
        vi.stubGlobal("history", { replaceState });

        expect(consumeAccountSignupTicket()).toBe("ticket-1");
        expect(replaceState).toHaveBeenCalledWith(null, "", "/#other=keep");

        vi.stubGlobal("window", { location: { hash: "#id_token=x", pathname: "/", search: "" } });
        expect(consumeAccountSignupTicket()).toBeNull();
    });

    it("signs in with a passkey through a fresh server ceremony", async () => {
        setBearer(null);
        const fetch = vi.fn()
            .mockResolvedValueOnce(new Response(JSON.stringify({
                ceremony_id: "authentication-1",
                public_key: {
                    challenge: "DQ4",
                    rpId: "auth.example",
                    allowCredentials: [{ type: "public-key", id: "DxA" }],
                    userVerification: "required",
                },
            }), { status: 200, headers: { "content-type": "application/json" } }))
            .mockResolvedValueOnce(new Response(JSON.stringify({ account_id: "person-one" }), {
                status: 200,
                headers: { "content-type": "application/json", "set-cookie": "opaque-session" },
            }));
        vi.stubGlobal("fetch", fetch);
        const get = vi.fn(async (_options: CredentialRequestOptions): Promise<Credential | null> =>
            authenticationCredential);

        await expect(signInWithPasskey(
            "https://auth.example/",
            "person@example.test",
            { create: vi.fn(), get },
        )).resolves.toBe("person-one");

        expect(fetch.mock.calls.map(([url]) => url)).toEqual([
            "https://auth.example/auth/account/passkey/login/start",
            "https://auth.example/auth/account/passkey/login/finish",
        ]);
        expect(fetch.mock.calls.map(([, init]) => JSON.parse(String(init?.body)))).toEqual([
            { email: "person@example.test" },
            {
                ceremony_id: "authentication-1",
                credential: {
                    id: "_P0",
                    authenticatorData: "BQY",
                    clientDataJSON: "Bwg",
                    signature: "CQo",
                    userHandle: "Cww",
                },
            },
        ]);
        const request = get.mock.calls[0]?.[0] as CredentialRequestOptions;
        expect(byteValues(request.publicKey?.challenge)).toEqual([13, 14]);
        expect(byteValues(request.publicKey?.allowCredentials?.[0]?.id)).toEqual([15, 16]);
        expect(bearer()).toBeNull();
    });

    it("fails closed before browser ceremony on malformed authority responses", async () => {
        vi.stubGlobal("fetch", vi.fn(async () => new Response("not json", {
            status: 200,
            headers: { "content-type": "application/json" },
        })));
        await expect(startPasskeyAccountCreation("https://auth.example", "person@example.test"))
            .rejects.toThrow("response is malformed");

        vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({
            ceremony_id: "authentication-1",
            public_key: { challenge: "%%%" },
        }), { status: 200, headers: { "content-type": "application/json" } })));
        const get = vi.fn();
        await expect(signInWithPasskey(
            "https://auth.example",
            "person@example.test",
            { create: vi.fn(), get },
        )).rejects.toThrow("WebAuthn response is malformed");
        expect(get).not.toHaveBeenCalled();
    });

    it("does not finish a ceremony the browser cancelled", async () => {
        const fetch = vi.fn(async () => new Response(JSON.stringify({
            ceremony_id: "authentication-1",
            public_key: { challenge: "AQI", allowCredentials: [] },
        }), { status: 200, headers: { "content-type": "application/json" } }));
        vi.stubGlobal("fetch", fetch);

        await expect(signInWithPasskey(
            "https://auth.example",
            "person@example.test",
            { create: vi.fn(), get: vi.fn(async () => null) },
        )).rejects.toThrow("Passkey sign-in was cancelled");
        expect(fetch).toHaveBeenCalledOnce();
    });
});

describe("native account session transport", () => {
    it("exchanges the device-bound handoff through the shared request owner", async () => {
        const fetch = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
            new Response(JSON.stringify({ account_session: "opaque-account-session" }), {
                status: 200,
                headers: { "content-type": "application/json" },
            }));
        vi.stubGlobal("fetch", fetch);

        await expect(exchangeMobileAccountHandoff(
            "https://auth.example/",
            "handoff-code",
            "device-verifier",
        )).resolves.toBe("opaque-account-session");

        expect(fetch.mock.calls[0]?.[0]).toBe("https://auth.example/auth/mobile/exchange");
        const init = fetch.mock.calls[0]?.[1];
        expect(JSON.parse(String(init?.body))).toEqual({
            code: "handoff-code",
            verifier: "device-verifier",
        });
        expect(new Headers(init?.headers).get("idempotency-key")).toBeTruthy();
        expect(init?.credentials).toBe("include");
    });

    it("renews with the exact stable bearer and rejects malformed success", async () => {
        const fetch = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
            new Response(JSON.stringify({ refreshed: true }), {
                status: 200,
                headers: { "content-type": "application/json" },
            }));
        vi.stubGlobal("fetch", fetch);

        await expect(refreshMobileAccountToken(
            "https://auth.example",
            "current-token",
        )).resolves.toBe("current-token");

        const init = fetch.mock.calls[0]?.[1];
        expect(new Headers(init?.headers).get("authorization")).toBe("Bearer current-token");
        expect(new Headers(init?.headers).get("idempotency-key")).toBeTruthy();

        vi.stubGlobal("fetch", vi.fn(async () =>
            new Response(JSON.stringify({ person: "account-root" }), {
                status: 200,
                headers: { "content-type": "application/json" },
            })));
        await expect(refreshMobileAccountToken(
            "https://auth.example",
            "current-token",
        )).rejects.toThrow("response is malformed");
    });
});

describe("hosted account session refresh", () => {
    it("holds the refreshed id-token in memory as the Home credential (ADR 0147 §1)", async () => {
        setBearer(null);
        const idToken = fakeJwt({ sub: "person:one" });
        const fetch = vi.fn(async (
            _input: RequestInfo | URL,
            _init?: RequestInit,
        ) =>
            new Response(
                JSON.stringify({ refreshed: true, person: "person:one", id_token: idToken }),
                { status: 200, headers: { "content-type": "application/json" } },
            ));
        vi.stubGlobal("fetch", fetch);

        await expect(refreshHostedAccountSession("https://auth.example/")).resolves.toBe(true);
        expect(fetch.mock.calls[0]?.[0]).toBe("https://auth.example/auth/refresh");
        const init = fetch.mock.calls[0]?.[1];
        expect(init?.method).toBe("GET");
        expect(init?.credentials).toBe("include");
        // The opaque session cookie authenticates the refresh — no bearer header is sent.
        expect(new Headers(init?.headers).has("authorization")).toBe(false);
        // The short-lived id-token is now held in memory (never at rest) for the Home bearer.
        expect(bearer()).toBe(idToken);
        setBearer(null);
    });

    it("still reports success when a deployment returns no id-token yet", async () => {
        setBearer(null);
        const fetch = vi.fn(async () =>
            new Response(JSON.stringify({ refreshed: true, person: "person:one" }), {
                status: 200,
                headers: { "content-type": "application/json" },
            }));
        vi.stubGlobal("fetch", fetch);

        await expect(refreshHostedAccountSession("https://auth.example/")).resolves.toBe(true);
        expect(bearer()).toBeNull();

        fetch.mockResolvedValueOnce(new Response(null, { status: 401 }));
        await expect(refreshHostedAccountSession("https://auth.example")).resolves.toBe(false);
    });
});
