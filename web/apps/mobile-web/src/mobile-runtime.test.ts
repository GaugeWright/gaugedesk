import { afterEach, describe, expect, it, vi } from "vitest";
import {
    clearMachineEndpoint,
    loadMobileRuntime,
    MOBILE_AUTH_VERIFIER_KEY,
    MOBILE_MACHINE_ENDPOINT_KEY,
    machineCredentialIsRejected,
    normalizeMachineEndpoint,
    parseMobileAuthCallback,
    parseMachineCredentialRegistry,
    parseMachineInvitationLink,
    savedMachineEndpoint,
    saveMachineEndpoint,
    redeemMobileAccountHandoff,
} from "./mobile-runtime";

afterEach(() => vi.unstubAllGlobals());

describe("mobile runtime enrollment", () => {
    it("accepts only a one-time native handoff code", () => {
        const code = "a".repeat(43);
        expect(
            parseMobileAuthCallback(
                `gaugewright://auth/callback#code=${code}`,
            ),
        ).toBe(code);
        expect(
            parseMobileAuthCallback(
                `gaugewright://machine-enroll#code=${code}`,
            ),
        ).toBeNull();
        expect(
            parseMobileAuthCallback(`https://attacker.example/#code=${code}`),
        ).toBeNull();
        expect(parseMobileAuthCallback("gaugewright://auth/callback#id_token=stolen"))
            .toBeNull();
    });

    it("redeems a handoff only with this device's verifier and consumes it", async () => {
        const accountSession = "s".repeat(43);
        const values = new Map([[MOBILE_AUTH_VERIFIER_KEY, "verifier"]]);
        const storage = {
            getItem: (key: string) => values.get(key) ?? null,
            removeItem: (key: string) => values.delete(key),
        };
        vi.stubGlobal("fetch", vi.fn(async (_url: string, init: RequestInit) => {
            expect(JSON.parse(String(init.body))).toEqual({
                code: "a".repeat(43),
                verifier: "verifier",
            });
            return new Response(JSON.stringify({ account_session: accountSession }), {
                status: 200,
                headers: { "content-type": "application/json" },
            });
        }));
        await expect(
            redeemMobileAccountHandoff(
                "https://auth.gaugewright.com",
                "a".repeat(43),
                storage,
            ),
        ).resolves.toBe(accountSession);
        expect(values.has(MOBILE_AUTH_VERIFIER_KEY)).toBe(false);
    });

    it("parses a cold-launch Machine invitation deep link", () => {
        const invitation = {
            version: 1,
            invitationId: "invite-1",
            secret: "secret",
            machine: "home:local",
            endpoint: "https://machine.example",
            expiresAt: Math.floor(Date.now() / 1_000) + 60,
        };
        const encoded = btoa(JSON.stringify(invitation))
            .replace(/\+/g, "-")
            .replace(/\//g, "_")
            .replace(/=+$/, "");
        expect(parseMachineInvitationLink(`gaugewright://machine-enroll?d=${encoded}`))
            .toEqual(invitation);
    });

    it("rejects arbitrary and expired QR payloads as Machine invitations", () => {
        expect(parseMachineInvitationLink("https://gaugewright.com")).toBeNull();
        const expired = {
            version: 1,
            invitationId: "invite-expired",
            secret: "secret",
            machine: "machine:local",
            endpoint: "https://machine.example",
            expiresAt: Math.floor(Date.now() / 1_000) - 1,
        };
        const encoded = btoa(JSON.stringify(expired))
            .replace(/\+/g, "-")
            .replace(/\//g, "_")
            .replace(/=+$/, "");
        expect(
            parseMachineInvitationLink(`gaugewright://machine-enroll?d=${encoded}`),
        ).toBeNull();
    });

    it("normalizes and persists only secure Machine endpoints", () => {
        const values = new Map<string, string>();
        const storage = {
            getItem: (key: string) => values.get(key) ?? null,
            setItem: (key: string, value: string) => values.set(key, value),
        };

        expect(saveMachineEndpoint(" https://machine.example/ ", storage)).toBe(
            "https://machine.example",
        );
        expect(values.get(MOBILE_MACHINE_ENDPOINT_KEY)).toBe("https://machine.example");
        expect(savedMachineEndpoint(storage)).toBe("https://machine.example");
        expect(() => normalizeMachineEndpoint("http://machine.example")).toThrow(
            "HTTPS Project Host endpoint",
        );
        expect(() => normalizeMachineEndpoint("http://127.0.0.1:7878")).toThrow(
            "HTTPS Project Host endpoint",
        );
        clearMachineEndpoint({ removeItem: (key) => values.delete(key) });
        expect(savedMachineEndpoint(storage)).toBeNull();
    });

    it("parses a versioned Machine-keyed registry without cross-entry overwrite", () => {
        expect(parseMachineCredentialRegistry({
            version: 1,
            credentials: [
                {
                    endpoint: "https://two.example/",
                    machine: "home:two",
                    grantId: "grant-two",
                    credential: "secret-two",
                },
                {
                    endpoint: "https://one.example",
                    machine: "home:one",
                    grantId: "grant-one",
                    credential: "secret-one",
                },
            ],
        })).toEqual([
            {
                endpoint: "https://one.example",
                machine: "home:one",
                grantId: "grant-one",
                credential: "secret-one",
            },
            {
                endpoint: "https://two.example",
                machine: "home:two",
                grantId: "grant-two",
                credential: "secret-two",
            },
        ]);
        expect(() => parseMachineCredentialRegistry({
            version: 1,
            credentials: [
                {
                    endpoint: "https://one.example",
                    machine: "home:one",
                    grantId: "grant-one",
                    credential: "secret-one",
                },
                {
                    endpoint: "https://forged.example",
                    machine: "home:one",
                    grantId: "grant-forged",
                    credential: "secret-forged",
                },
            ],
        })).toThrow("repeats home:one");
    });

    it("deletes a direct credential only on an explicit grant/device refusal", () => {
        expect(machineCredentialIsRejected("POST /mobile/sessions: 403")).toBe(true);
        expect(machineCredentialIsRejected("POST /mobile/sessions: 410 challenge expired"))
            .toBe(false);
        expect(machineCredentialIsRejected("POST /mobile/sessions: 404")).toBe(false);
        expect(machineCredentialIsRejected("TypeError: Failed to fetch")).toBe(false);
    });

    it("uses a native public identity without exposing a private key", async () => {
        vi.stubGlobal("window", { __TAURI_INTERNALS__: {} });
        vi.stubGlobal("localStorage", { getItem: () => "https://machine.example" });
        const call = vi.fn(async (command: string) => {
            if (command.endsWith("get_identity")) {
                return {
                    id: "device:native",
                    publicKey: "02abcdef",
                    algorithm: "ES256" as const,
                };
            }
            if (command.endsWith("list_machine_credentials")) {
                return { version: 1, credentials: [] };
            }
            if (command.endsWith("get_account_session")) {
                return { idToken: null };
            }
            if (command.endsWith("get_launch_url")) {
                return { url: null };
            }
            throw new Error(`unexpected command: ${command}`);
        });

        const runtime = await loadMobileRuntime(call as never);
        expect(runtime.identity).toEqual({
            id: "device:native",
            deviceKey: "02abcdef",
        });
        expect(runtime.endpoint).toBe("https://machine.example");
        expect(runtime.native).toBe(true);
        expect(runtime.selfApprovePairing).toBe(false);
        expect(runtime.credentials).toEqual([]);
        expect(runtime.accountToken).toBeNull();
        expect(runtime.pendingAccountCode).toBeNull();
        expect(runtime.pendingInvitation).toBeNull();
        expect(call).toHaveBeenCalledWith("plugin:gaugedesk-device-identity|get_identity");
        expect(call).toHaveBeenCalledWith(
            "plugin:gaugedesk-device-identity|list_machine_credentials",
        );
        expect(call).toHaveBeenCalledWith(
            "plugin:gaugedesk-device-identity|get_account_session",
        );
        expect(call).toHaveBeenCalledWith(
            "plugin:gaugedesk-device-identity|get_launch_url",
        );
    });

    it("clears the account session without touching either direct Machine grant", async () => {
        vi.stubGlobal("window", { __TAURI_INTERNALS__: {} });
        vi.stubGlobal("localStorage", { getItem: () => null });
        const credentials = [
            {
                endpoint: "https://one.example",
                machine: "home:one",
                grantId: "grant:one",
                credential: "secret:one",
            },
            {
                endpoint: "https://two.example",
                machine: "home:two",
                grantId: "grant:two",
                credential: "secret:two",
            },
        ];
        const call = vi.fn(async (command: string) => {
            if (command.endsWith("get_identity")) {
                return {
                    id: "device:native",
                    publicKey: "02abcdef",
                    algorithm: "ES256" as const,
                };
            }
            if (command.endsWith("list_machine_credentials")) {
                return { version: 1, credentials };
            }
            if (command.endsWith("get_account_session")) {
                return {
                    idToken: "opaque-account-session",
                    selected: "account:one",
                    accounts: [{ account: "account:one" }, { account: "account:two" }],
                };
            }
            if (command.endsWith("get_launch_url")) return { url: null };
            if (command.endsWith("clear_account_session")) return null;
            if (command.endsWith("select_account_session")) {
                return { idToken: "other-session", selected: "account:two", accounts: [] };
            }
            throw new Error(`unexpected command: ${command}`);
        });

        const runtime = await loadMobileRuntime(call as never);
        expect(runtime.accountId).toBe("account:one");
        expect(runtime.retainedAccounts).toEqual(["account:one", "account:two"]);
        await runtime.selectAccount("account:two");
        await runtime.clearAccountToken();

        expect(runtime.credentials).toEqual(credentials);
        expect(call).toHaveBeenCalledWith(
            "plugin:gaugedesk-device-identity|clear_account_session",
        );
        expect(call).toHaveBeenCalledWith(
            "plugin:gaugedesk-device-identity|select_account_session",
            { payload: { account: "account:two" } },
        );
        expect(
            call.mock.calls.some(([command]) =>
                String(command).includes("remove_machine_credential")
                || String(command).includes("clear_machine_credential"),
            ),
        ).toBe(false);
    });

    it("migrates a legacy opaque token only after the Hub identifies its account", async () => {
        vi.stubGlobal("window", { __TAURI_INTERNALS__: {} });
        vi.stubGlobal("localStorage", { getItem: () => null });
        vi.stubGlobal("fetch", vi.fn(async (_url: string, init: RequestInit) => {
            expect(new Headers(init.headers).get("authorization"))
                .toBe("Bearer legacy-opaque-session");
            return new Response(JSON.stringify({ account: "account:original" }), {
                status: 200,
                headers: { "content-type": "application/json" },
            });
        }));
        const call = vi.fn(async (command: string) => {
            if (command.endsWith("get_identity")) {
                return { id: "device:native", publicKey: "02abcdef", algorithm: "ES256" };
            }
            if (command.endsWith("list_machine_credentials")) {
                return { version: 1, credentials: [] };
            }
            if (command.endsWith("get_account_session")) {
                return { idToken: "legacy-opaque-session" };
            }
            if (command.endsWith("get_launch_url")) return { url: null };
            if (command.endsWith("store_account_session")) return null;
            throw new Error(`unexpected command: ${command}`);
        });

        const runtime = await loadMobileRuntime(call as never);
        expect(runtime.accountId).toBe("account:original");
        expect(runtime.retainedAccounts).toEqual(["account:original"]);
        expect(call).toHaveBeenCalledWith(
            "plugin:gaugedesk-device-identity|store_account_session",
            { payload: { account: "account:original", idToken: "legacy-opaque-session" } },
        );
    });

    it("refuses a renewed token for a different selected account before saving it", async () => {
        vi.stubGlobal("window", { __TAURI_INTERNALS__: {} });
        vi.stubGlobal("localStorage", { getItem: () => null });
        vi.stubGlobal("fetch", vi.fn(async () => new Response(
            JSON.stringify({ account: "account:two" }),
            { status: 200, headers: { "content-type": "application/json" } },
        )));
        const call = vi.fn(async (command: string) => {
            if (command.endsWith("get_identity")) {
                return { id: "device:native", publicKey: "02abcdef", algorithm: "ES256" };
            }
            if (command.endsWith("list_machine_credentials")) {
                return { version: 1, credentials: [] };
            }
            if (command.endsWith("get_account_session")) {
                return { idToken: "session-one", selected: "account:one", accounts: [{ account: "account:one" }] };
            }
            if (command.endsWith("get_launch_url")) return { url: null };
            throw new Error(`unexpected command: ${command}`);
        });
        const runtime = await loadMobileRuntime(call as never);
        await expect(runtime.storeAccountToken("session-two", "account:one"))
            .rejects.toThrow("different account");
        expect(call.mock.calls.some(([command]) =>
            String(command).endsWith("store_account_session"))).toBe(false);
    });

    it("keeps an unidentified legacy session out of protected account caches", async () => {
        vi.stubGlobal("window", { __TAURI_INTERNALS__: {} });
        vi.stubGlobal("localStorage", { getItem: () => null });
        vi.stubGlobal("fetch", vi.fn(async () => new Response(
            JSON.stringify({ error: "this bearer is not recognised" }),
            { status: 401, headers: { "content-type": "application/json" } },
        )));
        const call = vi.fn(async (command: string) => {
            if (command.endsWith("get_identity")) {
                return { id: "device:native", publicKey: "02abcdef", algorithm: "ES256" };
            }
            if (command.endsWith("list_machine_credentials")) {
                return { version: 1, credentials: [] };
            }
            if (command.endsWith("get_account_session")) {
                return { idToken: "unidentified-legacy-session" };
            }
            if (command.endsWith("get_launch_url")) return { url: null };
            throw new Error(`unexpected command: ${command}`);
        });

        const runtime = await loadMobileRuntime(call as never);
        expect(runtime.accountToken).toBe("unidentified-legacy-session");
        expect(runtime.accountId).toBeNull();
        expect(runtime.retainedAccounts).toEqual([]);
        expect(call.mock.calls.some(([command]) =>
            String(command).endsWith("store_account_session"))).toBe(false);
    });

    it("bounds native bridge calls instead of leaving the app loading forever", async () => {
        vi.useFakeTimers();
        vi.stubGlobal("window", { __TAURI_INTERNALS__: {} });
        const pending = new Promise<never>(() => undefined);

        const result = expect(loadMobileRuntime(() => pending)).rejects.toThrow(
            "Opening the native device identity timed out",
        );
        await vi.advanceTimersByTimeAsync(15_000);

        await result;
        vi.useRealTimers();
    });
});
