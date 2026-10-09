import { defineConfig } from "vite";
import solid from "vite-plugin-solid";
import { fileURLToPath } from "node:url";

type FixtureMessage = { sequence: number; role: "user" | "assistant"; text: string };

const transcripts = new Map<string, FixtureMessage[]>();

type AccountLifecycleState = {
    display_name: string;
    authenticator_ids: string[];
    consumer_oidc_id: string;
    consumer_oidc_pending: boolean;
    consumer_oidc_linked: boolean;
    recovery_batches: Array<{ id: string; created_at: number; remaining_codes: number }>;
    session_ids: string[];
    membership_ids: string[];
    invitations: Array<{ tenant_id: string; display_name: string; role: string }>;
};
const accounts = new Map<string, AccountLifecycleState>();
// The commercial product ledger as an authority holds it, so a browser reload
// rereads it rather than browser signals (WS-493). Retire and restore apply
// at once and delete waits for a reviewed acceptance, as the Cloud's command
// policies say; a product an engagement references is never deleted.
type CommercialProductLedger = {
    revision: number;
    product_a_status: "active" | "retired";
    created: { id: string; status: "active" | "retired"; [field: string]: unknown } | null;
    pending_delete: { id: string; product_id: string; expected_basis: string } | null;
};
const commercialProducts = new Map<string, CommercialProductLedger>();
const projectHostSettings = new Map<string, Record<string, string>>();
const appearancePreferences = new Map<string, Record<string, unknown>>();
const initialAccount = (key: string): AccountLifecycleState => ({
    display_name: `Person ${key}`,
    authenticator_ids: [`passkey-${key}`, `passkey-backup-${key}`],
    consumer_oidc_id: `consumer-google-${key}`,
    consumer_oidc_pending: false,
    consumer_oidc_linked: false,
    recovery_batches: [],
    session_ids: [`session-current-${key}`, `session-phone-${key}`, `session-browser-${key}`],
    membership_ids: [`personal-${key}`, `organization-${key}`],
    invitations: [
        { tenant_id: `invited-${key}`, display_name: "Invited organization", role: "member" },
        { tenant_id: `declined-${key}`, display_name: "Second invitation", role: "viewer" },
    ],
});

const readBody = (request: import("node:http").IncomingMessage) => new Promise<unknown>((resolve) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
    request.on("end", () => {
        try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); }
        catch { resolve(null); }
    });
});

const persistentAgent = {
    name: "persistent-gaugeapp-agent-fixture",
    configureServer(server: { middlewares: { use(handler: (request: import("node:http").IncomingMessage, response: import("node:http").ServerResponse, next: () => void) => void): void } }) {
        server.middlewares.use((request, response, next) => {
            const url = new URL(request.url ?? "/", "http://fixture.local");
            if (url.pathname === "/__fixture/appearance") {
                const key = url.searchParams.get("key")?.trim() ?? "";
                if (!key || key.length > 128) {
                    response.statusCode = 400;
                    response.end(JSON.stringify({ error: "invalid fixture appearance key" }));
                    return;
                }
                const current = appearancePreferences.get(key) ?? {
                    version: 1, interface_scale: "standard", contrast: "standard", motion: "system",
                };
                response.setHeader("content-type", "application/json");
                if (request.method === "GET") {
                    response.end(JSON.stringify({ saved: appearancePreferences.has(key), value: current }));
                    return;
                }
                if (request.method !== "POST") {
                    response.statusCode = 405;
                    response.end(JSON.stringify({ error: "unsupported fixture method" }));
                    return;
                }
                void readBody(request).then((raw) => {
                    const body = raw as Record<string, unknown> | null;
                    if (!body || body.version !== 1
                        || !["standard", "large"].includes(String(body.interface_scale))
                        || !["standard", "high"].includes(String(body.contrast))
                        || !["system", "reduced"].includes(String(body.motion))) {
                        response.statusCode = 422;
                        response.end(JSON.stringify({ error: "invalid fixture appearance preference" }));
                        return;
                    }
                    appearancePreferences.set(key, body);
                    response.end(JSON.stringify({ saved: true, value: body }));
                });
                return;
            }
            if (url.pathname === "/__fixture/project-host-settings") {
                const key = url.searchParams.get("key")?.trim() ?? "";
                if (!key || key.length > 128) {
                    response.statusCode = 400;
                    response.end(JSON.stringify({ error: "invalid fixture Project Host key" }));
                    return;
                }
                const current = projectHostSettings.get(key) ?? {};
                response.setHeader("content-type", "application/json");
                if (request.method === "GET") {
                    response.end(JSON.stringify(current));
                    return;
                }
                if (request.method !== "POST") {
                    response.statusCode = 405;
                    response.end(JSON.stringify({ error: "unsupported fixture method" }));
                    return;
                }
                void readBody(request).then((raw) => {
                    const body = raw as { key?: unknown; value?: unknown } | null;
                    if (typeof body?.key !== "string" || typeof body.value !== "string") {
                        response.statusCode = 422;
                        response.end(JSON.stringify({ error: "invalid Project Host setting" }));
                        return;
                    }
                    current[body.key] = body.value;
                    projectHostSettings.set(key, current);
                    response.end(JSON.stringify(current));
                });
                return;
            }
            if (url.pathname === "/__fixture/commercial-products") {
                const key = url.searchParams.get("key")?.trim() ?? "";
                if (!key || key.length > 128) {
                    response.statusCode = 400;
                    response.end(JSON.stringify({ error: "invalid fixture commercial key" }));
                    return;
                }
                const current = commercialProducts.get(key) ?? { revision: 1, product_a_status: "active", created: null, pending_delete: null };
                commercialProducts.set(key, current);
                response.setHeader("content-type", "application/json");
                if (request.method === "GET") {
                    response.end(JSON.stringify(current));
                    return;
                }
                if (request.method !== "POST") {
                    response.statusCode = 405;
                    response.end(JSON.stringify({ error: "unsupported fixture method" }));
                    return;
                }
                void readBody(request).then((raw) => {
                    const body = raw as { operation?: string; payload?: Record<string, unknown> } | null;
                    const payload = body?.payload ?? {};
                    const refuse = (status: number, error: string) => {
                        response.statusCode = status;
                        response.end(JSON.stringify({ error }));
                    };
                    const known = (id: unknown) => id === "product-a" || (current.created !== null && id === current.created.id);
                    switch (body?.operation) {
                        case "commercial-product.create": {
                            const product = payload.product as CommercialProductLedger["created"];
                            if (!product || typeof product.id !== "string" || known(product.id)) return refuse(409, "product already exists");
                            current.created = product;
                            current.revision += 1;
                            break;
                        }
                        case "commercial-product.retire":
                        case "commercial-product.restore": {
                            if (!known(payload.id)) return refuse(404, "no such product");
                            const status = body.operation.endsWith("retire") ? "retired" : "active";
                            if (payload.id === "product-a") current.product_a_status = status;
                            else current.created = { ...current.created!, status };
                            current.revision += 1;
                            break;
                        }
                        case "commercial-product.delete": {
                            if (!known(payload.id)) return refuse(404, "no such product");
                            // The seeded product carries the draft engagement.
                            if (payload.id === "product-a") return refuse(409, "an engagement references this product");
                            if (current.pending_delete) return refuse(409, "a deletion is already pending review");
                            current.pending_delete = {
                                id: `proposal-delete-${String(payload.id)}-${current.revision}`,
                                product_id: String(payload.id),
                                expected_basis: String(payload.expected_basis ?? ""),
                            };
                            break;
                        }
                        case "fixture.review": {
                            const pending = current.pending_delete;
                            if (!pending || pending.id !== payload.proposal_id) return refuse(409, "proposal is no longer pending");
                            // Discarding applies nothing, so only an acceptance must
                            // still match the basis the deletion was prepared on.
                            if (payload.decision === "accept" && pending.expected_basis !== String(payload.basis ?? "")) {
                                return refuse(409, "the product changed after this deletion was prepared");
                            }
                            current.pending_delete = null;
                            if (payload.decision === "accept") {
                                if (current.created?.id === pending.product_id) current.created = null;
                                current.revision += 1;
                            }
                            break;
                        }
                        default:
                            return refuse(422, "unsupported commercial product operation");
                    }
                    response.end(JSON.stringify(current));
                });
                return;
            }
            if (url.pathname === "/__fixture/account-lifecycle") {
                const key = url.searchParams.get("key")?.trim() ?? "";
                if (!key || key.length > 128) {
                    response.statusCode = 400;
                    response.end(JSON.stringify({ error: "invalid fixture account key" }));
                    return;
                }
                const current = accounts.get(key) ?? initialAccount(key);
                accounts.set(key, current);
                response.setHeader("content-type", "application/json");
                if (request.method === "GET") {
                    response.end(JSON.stringify(current));
                    return;
                }
                if (request.method !== "POST") {
                    response.statusCode = 405;
                    response.end(JSON.stringify({ error: "unsupported fixture method" }));
                    return;
                }
                void readBody(request).then((raw) => {
                    const body = raw as { operation?: string; payload?: Record<string, unknown> } | null;
                    const payload = body?.payload ?? {};
                    switch (body?.operation) {
                        case "account.profile.set":
                            current.display_name = String(payload.display_name ?? "").trim();
                            break;
                        case "account.authenticator.remove":
                            if (payload.id === current.consumer_oidc_id) current.consumer_oidc_linked = false;
                            else current.authenticator_ids = current.authenticator_ids.filter((id) => id !== payload.id);
                            break;
                        case "fixture.consumer-oidc.begin":
                            if (current.consumer_oidc_linked) {
                                response.statusCode = 409;
                                response.end(JSON.stringify({ error: "consumer identity already linked" }));
                                return;
                            }
                            current.consumer_oidc_pending = true;
                            break;
                        case "fixture.consumer-oidc.callback":
                            if (!current.consumer_oidc_pending) {
                                response.statusCode = 409;
                                response.end(JSON.stringify({ error: "consumer link ceremony is not pending" }));
                                return;
                            }
                            current.consumer_oidc_pending = false;
                            current.consumer_oidc_linked = true;
                            break;
                        case "account.recovery-codes.reissue":
                            current.recovery_batches = [{ id: `batch-${Date.now()}`, created_at: Math.floor(Date.now() / 1_000), remaining_codes: 8 }];
                            break;
                        case "account.session.revoke":
                            current.session_ids = current.session_ids.filter((id) => id !== payload.id);
                            break;
                        case "account.session.revoke-current":
                            current.session_ids = current.session_ids.filter((id) => !id.startsWith("session-current-"));
                            break;
                        case "account.session.revoke-others":
                            current.session_ids = current.session_ids.filter((id) => id.startsWith("session-current-"));
                            break;
                        case "account.membership.leave":
                            current.membership_ids = current.membership_ids.filter((id) => id !== payload.tenant_id);
                            break;
                        case "account.invitation.accept": {
                            const invitation = current.invitations.find((item) => item.tenant_id === payload.tenant_id);
                            current.invitations = current.invitations.filter((item) => item.tenant_id !== payload.tenant_id);
                            if (invitation && !current.membership_ids.includes(invitation.tenant_id)) current.membership_ids.push(invitation.tenant_id);
                            break;
                        }
                        case "account.invitation.decline":
                            current.invitations = current.invitations.filter((item) => item.tenant_id !== payload.tenant_id);
                            break;
                        default:
                            response.statusCode = 422;
                            response.end(JSON.stringify({ error: "unsupported account lifecycle operation" }));
                            return;
                    }
                    accounts.set(key, current);
                    response.end(JSON.stringify(current));
                });
                return;
            }
            if (url.pathname !== "/__fixture/gaugeapp-agent") return next();
            const key = url.searchParams.get("key")?.trim() ?? "";
            if (!key || key.length > 256) {
                response.statusCode = 400;
                response.end(JSON.stringify({ error: "invalid fixture transcript key" }));
                return;
            }
            response.setHeader("content-type", "application/json");
            if (request.method === "GET") {
                response.end(JSON.stringify({ messages: transcripts.get(key) ?? [] }));
                return;
            }
            if (request.method === "DELETE") {
                transcripts.set(key, []);
                response.end(JSON.stringify({ erased: true }));
                return;
            }
            if (request.method !== "POST") {
                response.statusCode = 405;
                response.end(JSON.stringify({ error: "unsupported fixture method" }));
                return;
            }
            const chunks: Buffer[] = [];
            request.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
            request.on("end", () => {
                let message = "";
                try {
                    const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
                    if (typeof body.message === "string") message = body.message.trim();
                } catch { /* fail below */ }
                if (!message || message.length > 2_000) {
                    response.statusCode = 400;
                    response.end(JSON.stringify({ error: "invalid fixture message" }));
                    return;
                }
                const current = transcripts.get(key) ?? [];
                const sequence = current.length;
                current.push(
                    { sequence, role: "user", text: message },
                    { sequence: sequence + 1, role: "assistant", text: `Server reply to ${message}` },
                );
                transcripts.set(key, current);
                response.end(JSON.stringify({ message: `Server reply to ${message}`, proposals: [] }));
            });
        });
    },
};

export default defineConfig({
    root: fileURLToPath(new URL(".", import.meta.url)), plugins: [persistentAgent, solid()],
    resolve: { dedupe: ["solid-js"], alias: [{ find: /^@stripe\/connect-js(?:\/pure)?$/, replacement: fileURLToPath(new URL("./stripe.ts", import.meta.url)) }] },
    server: { host: "127.0.0.1", port: 7662, strictPort: true, fs: { allow: [fileURLToPath(new URL("../../../..", import.meta.url))] } },
});
