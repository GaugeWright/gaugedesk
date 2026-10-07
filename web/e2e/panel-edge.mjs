/**
 * A loopback stand-in for the public edge's publisher protocol, so the Panel
 * agent journey (PANEL-7) can be driven in the browser past "Deploy": publish,
 * the live status the dialog reads back, a visitor's collected result, and the
 * drain into the project's Inbox.
 *
 * It is a fixture, not an edge. It holds only what the Home's publisher client
 * sends and reads — the public-credential registry, releases, deployments and
 * their sealed collections — in memory, and accepts every signed command
 * without verifying the signature: the client half of the contract is what the
 * suite exercises; the hosted half is covered by the edge-runtime's own tests.
 *
 * One route is not part of the protocol. `POST /__test/visitor-result`, given
 * `{ deployment_id, text }`, does what a visitor's session does when its agent
 * writes a collected file: seals the text to every recipient key the
 * deployment was published with, under the deployment as its admission scope,
 * and deposits it for the Home's next drain. The sealing is the same ECIES the
 * session host uses (`collection_recipient.rs`): P-256 ECDH with an ephemeral
 * key, a SHA-256 wrapping key bound to scope, point and recipient, and
 * AES-256-GCM as `nonce(12) || ciphertext || tag(16)`, so the Home opens it with
 * its real opener.
 *
 * `POST /__test/legacy-deployment`, given `{ deployment_id, panel_ceiling,
 * credential_class }`, seeds a hosted deployment as one published before local
 * project bindings existed: live, with an active release and an owner key in
 * the registry, and no binding on any Home. That is the state a legacy import
 * starts from.
 *
 * `GET /__test/requests` returns every protocol request it has served, so a
 * step can assert what the Home sent — above all that an import only read.
 *
 *     EDGE_PORT=7920 node e2e/panel-edge.mjs
 */

import { createCipheriv, createECDH, createHash, randomBytes } from "node:crypto";
import { createServer } from "node:http";

const port = Number(process.env.EDGE_PORT);
if (!Number.isInteger(port) || port <= 0) {
    console.error("[panel-edge] EDGE_PORT is required");
    process.exit(1);
}

const KDF_DOMAIN = Buffer.from("gaugewright/collection/ecies/v1");

/** @type {Map<string, any>} */
const credentials = new Map();
/** @type {Map<string, Buffer>} */
const releases = new Map();
/** @type {Map<string, any>} */
const deployments = new Map();
/** @type {{ method: string, path: string }[]} */
const requests = [];
let nextCredential = 1;

function aeadSeal(key, plaintext) {
    const nonce = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", key, nonce);
    const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return Buffer.concat([nonce, body, cipher.getAuthTag()]);
}

function component(digest, value) {
    const length = Buffer.alloc(8);
    length.writeBigUInt64BE(BigInt(Buffer.byteLength(value)));
    digest.update(length);
    digest.update(value);
}

/** Seal `plaintext` to every recipient, bound to `scope` and this point. */
function seal(plaintext, scope, envelope, recipients) {
    const dataKey = randomBytes(32);
    const pointId = `${envelope.session_id}:${envelope.revision}`;
    const wraps = recipients.map((recipient) => {
        const ephemeral = createECDH("prime256v1");
        ephemeral.generateKeys();
        const shared = ephemeral.computeSecret(Buffer.from(recipient, "hex"));
        const digest = createHash("sha256");
        digest.update(KDF_DOMAIN);
        for (const value of [scope, pointId, recipient]) component(digest, value);
        digest.update(shared);
        return {
            recipient_public_key: recipient,
            ephemeral_public_key: ephemeral.getPublicKey("hex", "uncompressed"),
            wrapped_key: aeadSeal(digest.digest(), dataKey).toString("hex"),
        };
    });
    return {
        envelope,
        ciphertext: aeadSeal(dataKey, plaintext).toString("hex"),
        wraps,
        byte_len: plaintext.length,
    };
}

function inspection(deployment) {
    return {
        deployment: {
            config: deployment.config,
            active_release_id: deployment.active_release_id,
            lifecycle: deployment.lifecycle,
            activation_revision: deployment.activation_revision,
            spent_cents: 0,
            reserved_cents: 0,
            sessions: deployment.sessions,
            settled_turns: 0,
        },
        audience: [],
    };
}

async function readBody(request) {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    return Buffer.concat(chunks);
}

function json(body) {
    try {
        return JSON.parse(body.toString("utf8"));
    } catch {
        return null;
    }
}

/** @returns {[number, unknown]} */
function route(method, path, body) {
    if (method === "GET" && path === "/health") return [200, { ok: true }];
    if (method === "GET" && path === "/__test/requests") return [200, { requests }];
    if (method === "POST" && path === "/__test/visitor-result") {
        const input = json(body);
        const deployment = input && deployments.get(input.deployment_id);
        const collection = deployment?.config.collection;
        if (!deployment || !collection) return [404, { error: "no collecting deployment" }];
        deployment.sessions += 1;
        const envelope = {
            schema_ref: collection.schema_ref,
            session_id: `visitor-${deployment.sessions}`,
            release_id: deployment.active_release_id,
            revision: 1,
            produced_at_unix_ms: Date.now(),
        };
        const sealed = seal(
            Buffer.from(String(input.text ?? ""), "utf8"),
            input.deployment_id,
            envelope,
            collection.recipient_public_keys ?? [],
        );
        deployment.deposits.push({
            session_id: envelope.session_id,
            release_id: envelope.release_id,
            schema_ref: envelope.schema_ref,
            recipient_ref: collection.recipient_ref,
            revision: envelope.revision,
            byte_len: sealed.byte_len,
            deposited_at_unix_ms: Date.now(),
            sealed,
        });
        return [200, { session_id: envelope.session_id }];
    }

    if (method === "POST" && path === "/__test/legacy-deployment") {
        const input = json(body) ?? {};
        const credentialClass = input.credential_class ?? "openai-api-key";
        const provider = credentialClass.startsWith("anthropic") ? "anthropic" : "openai";
        const credential = {
            credential_ref: `credential:public:e2e:${provider}:${nextCredential++}`,
            provider,
            credential_class: credentialClass,
            label: "Key from before projects",
            created_at_unix_ms: Date.now(),
        };
        credentials.set(credential.credential_ref, credential);
        const releaseId = `sha256:${createHash("sha256").update(`legacy:${input.deployment_id}`).digest("hex")}`;
        releases.set(releaseId, Buffer.from(JSON.stringify({ host_policy: { credential_class: credentialClass } })));
        deployments.set(input.deployment_id, {
            lifecycle: "active",
            activation_revision: 4,
            sessions: 2,
            deposits: [],
            active_release_id: releaseId,
            config: {
                deployment_id: input.deployment_id,
                enabled: true,
                allowed_origins: ["https://legacy.example"],
                panel_ceiling: input.panel_ceiling ?? ["gw-chat"],
                max_spend_cents: 2_500,
                max_session_spend_cents: 250,
                max_turn_spend_cents: 25,
                reserve_cents_per_turn: 5,
                per_visitor_turn_limit: 9,
                max_concurrent_sessions: 4,
                funding_ref: credential.credential_ref,
                credential_class: credentialClass,
                credential_ref: credential.credential_ref,
                audience: { anonymous_allowed: true },
                pricing: {},
                retention: {
                    idle_ttl_seconds: 3_600,
                    absolute_ttl_seconds: 86_400,
                    transcript_retained: true,
                    workspace_retained: true,
                },
                white_label: false,
            },
        });
        return [200, { release_id: releaseId, credential_ref: credential.credential_ref }];
    }

    requests.push({ method, path });

    if (path === "/v1/public-credentials") {
        if (method === "GET") return [200, { credentials: [...credentials.values()] }];
        if (method === "POST") {
            const input = json(body) ?? {};
            const record = {
                credential_ref: `credential:public:e2e:${input.provider}:${nextCredential++}`,
                provider: input.provider,
                credential_class: input.credential_class,
                label: input.label,
                created_at_unix_ms: Date.now(),
            };
            credentials.set(record.credential_ref, record);
            return [200, { credential: record }];
        }
        if (method === "DELETE") {
            credentials.delete(json(body)?.credential_ref);
            return [200, { revoked: true }];
        }
    }

    const release = path.match(/^\/v1\/releases\/([^/]+)$/);
    if (release) {
        const id = decodeURIComponent(release[1]);
        if (method === "PUT") {
            releases.set(id, body);
            return [200, { stored: true }];
        }
        if (method === "GET" && releases.has(id)) {
            return [200, { ...json(releases.get(id)), release_id: id }];
        }
        return [404, { error: "no such release" }];
    }

    const collections = path.match(/^\/v1\/deployments\/([^/]+)\/collections$/);
    if (collections) {
        const deployment = deployments.get(collections[1]);
        if (!deployment) return [404, { error: "no such deployment" }];
        if (method === "GET") {
            return [200, { deployment_id: collections[1], waiting: deployment.deposits.length, artifacts: deployment.deposits }];
        }
        if (method === "POST") {
            const acknowledged = new Set(json(body)?.acknowledge ?? []);
            const before = deployment.deposits.length;
            deployment.deposits = deployment.deposits.filter((item) => !acknowledged.has(item.session_id));
            return [200, { acknowledged: before - deployment.deposits.length, retained: deployment.deposits.length }];
        }
    }

    const control = path.match(/^\/v1\/deployments\/([^/]+)\/control$/);
    if (control && method === "POST") {
        const deployment = deployments.get(control[1]);
        if (!deployment) return [404, { error: "no such deployment" }];
        const command = json(body)?.command;
        deployment.lifecycle = command === "pause" ? "paused" : command === "revoke" ? "revoked" : "active";
        deployment.activation_revision += 1;
        return [200, inspection(deployment)];
    }

    const activate = path.match(/^\/v1\/deployments\/([^/]+)\/activate$/);
    if (activate && method === "POST") {
        const deployment = deployments.get(activate[1]);
        if (!deployment) return [404, { error: "no such deployment" }];
        deployment.active_release_id = json(body)?.release_id ?? deployment.active_release_id;
        deployment.activation_revision += 1;
        return [200, inspection(deployment)];
    }

    const deploymentPath = path.match(/^\/v1\/deployments\/([^/]+)$/);
    if (deploymentPath) {
        const id = deploymentPath[1];
        const existing = deployments.get(id);
        if (method === "GET") {
            return existing ? [200, inspection(existing)] : [404, { error: "not found" }];
        }
        if (method === "PUT") {
            const input = json(body);
            if (!input?.config || !input.initial_release_id) return [400, { error: "missing config" }];
            const deployment = existing ?? { lifecycle: "active", activation_revision: 0, sessions: 0, deposits: [] };
            deployment.config = input.config;
            deployment.active_release_id = input.initial_release_id;
            deployment.activation_revision += 1;
            deployments.set(id, deployment);
            return [200, inspection(deployment)];
        }
    }

    return [404, { error: `unknown fixture route ${method} ${path}` }];
}

createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://fixture");
    const body = await readBody(request);
    const [status, payload] = route(request.method ?? "GET", url.pathname, body);
    const bytes = Buffer.from(JSON.stringify(payload));
    response.writeHead(status, { "content-type": "application/json", "content-length": bytes.length });
    response.end(bytes);
}).listen(port, "127.0.0.1", () => console.log(`[panel-edge] listening on 127.0.0.1:${port}`));
