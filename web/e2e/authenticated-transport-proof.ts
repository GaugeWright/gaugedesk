import type { APIRequestContext, APIResponse, Page, Response } from "@playwright/test";
import { aliceCP, bobCP, enterpriseCP } from "./ports.mjs";

const APPLICATION_SERVICE_ORIGINS = new Set(
    [aliceCP, bobCP, enterpriseCP].map((value) => new URL(value).origin),
);
const API_METHODS = ["fetch", "get", "post", "put", "patch", "delete", "head"] as const;

type HeaderInput =
    | Record<string, string>
    | ReadonlyArray<{ name: string; value: string }>
    | undefined;

type ApiMethod = (...args: unknown[]) => Promise<APIResponse>;

export type TransportProof = {
    assertSuccessfulApplicationRequest(): Promise<void>;
    assertSuccessfulCredentialedRequest(): Promise<void>;
    restore(): void;
};

function headerEntries(headers: HeaderInput): ReadonlyArray<readonly [string, string]> {
    if (!headers) return [];
    if (Array.isArray(headers)) return headers.map(({ name, value }) => [name, value]);
    return Object.entries(headers);
}

export function hasProductionCredential(headers: HeaderInput): boolean {
    for (const [rawName, rawValue] of headerEntries(headers)) {
        const name = rawName.toLowerCase();
        const value = rawValue.trim();
        if (name === "authorization" && value.length > 0) return true;
        if (name === "cookie" && /(?:^|;\s*)gw_session=[^;\s]+/.test(value)) return true;
    }
    return false;
}

function isApplicationUrl(input: unknown): boolean {
    try {
        const value = typeof input === "string" || input instanceof URL
            ? String(input)
            : (input as { url(): string }).url();
        return APPLICATION_SERVICE_ORIGINS.has(new URL(value).origin);
    } catch {
        return false;
    }
}

function successful(status: number): boolean {
    return status >= 200 && status < 400;
}

/**
 * Observe actual browser and APIRequestContext traffic for one BDD scenario.
 * A credential-shaped setup is not enough: at least one application response
 * must succeed after the request crossed transport with the credential.
 */
export function installTransportProof(
    page: Page,
    request: APIRequestContext,
): TransportProof {
    const successfulApplicationRequests = new Set<string>();
    const successfulCredentialedRequests = new Set<string>();
    const pending: Array<Promise<void>> = [];
    const originals = new Map<string, ApiMethod>();

    const observeBrowserResponse = (response: Response) => {
        const observed = (async () => {
            if (!successful(response.status()) || !isApplicationUrl(response.url())) return;
            const operation = `${response.request().method()} ${response.url()}`;
            successfulApplicationRequests.add(operation);
            const headers = await response.request().allHeaders();
            if (hasProductionCredential(headers)) {
                successfulCredentialedRequests.add(operation);
            }
        })();
        pending.push(observed);
    };
    page.on("response", observeBrowserResponse);

    const requestMethods = request as unknown as Record<string, unknown>;
    for (const method of API_METHODS) {
        const original = requestMethods[method];
        if (typeof original !== "function") continue;
        const callable = original as ApiMethod;
        originals.set(method, callable);
        Object.defineProperty(request, method, {
            configurable: true,
            value: async (...args: unknown[]) => {
                const response = await callable.apply(request, args);
                const options = args[1] as { headers?: HeaderInput } | undefined;
                if (successful(response.status()) && isApplicationUrl(args[0])) {
                    const operation = `${method.toUpperCase()} ${String(args[0])}`;
                    successfulApplicationRequests.add(operation);
                    if (hasProductionCredential(options?.headers)) {
                        successfulCredentialedRequests.add(operation);
                    }
                }
                return response;
            },
        });
    }

    return {
        async assertSuccessfulApplicationRequest() {
            await Promise.all(pending);
            if (successfulApplicationRequests.size === 0) {
                throw new Error(
                    "real-transport scenario completed without a successful "
                    + "control-plane request",
                );
            }
        },
        async assertSuccessfulCredentialedRequest() {
            await Promise.all(pending);
            if (successfulCredentialedRequests.size === 0) {
                throw new Error(
                    "@authenticated scenario completed without a successful application "
                    + "request carrying gw_session or Authorization",
                );
            }
        },
        restore() {
            page.off("response", observeBrowserResponse);
            for (const [method, original] of originals) {
                Object.defineProperty(request, method, {
                    configurable: true,
                    value: original,
                });
            }
        },
    };
}
