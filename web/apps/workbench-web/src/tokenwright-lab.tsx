/**
 * Bench for `TokenWrightBoxPanel` — the surface an operator works in.
 *
 * Served in development only (`/tokenwright-lab.html`); no shipped bundle names
 * this entry. Two modes:
 *
 * - **fixtures** (default): a canned Home returning three documents, so the
 *   panel renders every state — a loaded model, orphaned weights, a critical
 *   posture finding, a revealed key — with no relay in the path. This is the
 *   mode for judging the UI itself.
 * - **live** (`?home=<base>`): the real transport against a control plane on
 *   that origin, which the preview server proxies to.
 */
import { render } from "solid-js/web";
import { TokenWrightBoxPanel } from "@gaugewright/workbench-ui";
import { browserRouteJson, type RouteJson } from "@gaugewright/control-plane-client";
import "@gaugewright/workbench-ui/styles.css";

const params = new URLSearchParams(location.search);
const liveBase = params.get("home");

/** A Home that answers the three box routes from fixtures, so the panel can be
 *  judged without a relay. Mutable where a control would change state, so
 *  pressing a button visibly does something. */
function fixtureHome(): RouteJson {
    const inference = {
        desired: { model: "tinyllama", models: ["tinyllama", "qwen2.5-7b", "llama-3.1-8b"], autostart: true, direct_access: false, engine: "freetoken" },
        engine: { name: "FreeToken", version: "0.3.2", status: "running", listen: "127.0.0.1:8721", uptime: "3d 14h", restarts: 1, last_error: null as string | null },
        model: { id: "tinyllama", quantization: "q4_k_m", context_length: 2048, size_mib: 608, loaded_at: new Date(Date.now() - 3.6e6).toISOString() },
        models: [
            { id: "tinyllama", size_mib: 608, quantization: "q4_k_m", state: "loaded", digest_verified: true },
            { id: "qwen2.5-7b", size_mib: 4470, quantization: "q4_k_m", state: "available", digest_verified: true },
            { id: "phi-4", size_mib: 8900, quantization: "q8_0", state: "orphaned", digest_verified: true },
        ],
        hardware: { gpu: "NVIDIA GeForce RTX 5090", driver: "580.65.06", cuda: "13.0", vram_used_mib: 22140, vram_total_mib: 32607, ram_total_mib: 196608 },
        storage: { disk_total_mib: 3814697, disk_free_mib: 1201203, orphaned_mib: 8900 },
        throughput: { tokens_per_second: 41.7, active_requests: 1, max_concurrent: 4, rejected_overload_total: 3, requests_total: 18422 },
        serving: null as null | { kv_cache_used_pct: number | null; running: number | null; queued: number | null; native: Record<string, number> },
        events: [
            { at: new Date(Date.now() - 12000).toISOString(), level: "info", message: "generation complete (1.7s, 214 tokens)" },
            { at: new Date(Date.now() - 300000).toISOString(), level: "warn", message: "concurrency limit reached; one request rejected" },
            { at: new Date(Date.now() - 3.6e6).toISOString(), level: "info", message: "loaded tinyllama (q4_k_m, 608 MiB)" },
        ],
    };
    const posture = {
        checked_at: new Date(Date.now() - 90000).toISOString(),
        summary: { critical: 1, warning: 1, advisory: 2, checks_passed: 14 },
        findings: [
            { id: "POSTURE-FIREWALL-INACTIVE", severity: "critical", title: "The firewall is not running", remediation: "Enable it. Default-deny inbound is what makes the zero-listener arrangement hold when something else opens a port by accident." },
            { id: "POSTURE-UNATTENDED-UPGRADES-OFF", severity: "warning", title: "Unattended security upgrades are disabled", remediation: "Enable unattended-upgrades. 0 security updates are already pending." },
            { id: "POSTURE-STATE-ROOT-PLAINTEXT", severity: "advisory", title: "The box's state root is not on an encrypted volume", remediation: "Move the state root onto a LUKS volume if the box can be physically removed." },
            { id: "POSTURE-AUDIT-UNANCHORED", severity: "advisory", title: "3 trail entries are not yet covered by an anchor the Home holds", remediation: "They are anchored on the next relay reconnect." },
        ],
        network: { listeners: [], firewall: { backend: "ufw", active: false, default_incoming: "deny", allow_rules: 1 }, wireguard: { enabled: false, interface: null, listen_port: null, peers: 0, public_key: null } },
        services: [
            { unit: "tokenwright.service", state: "active", user: "tokenwright", no_new_privileges: true, protect_system: "strict", network_restricted: false },
            { unit: "tokenwright-engine.service", state: "active", user: "tokenwright-engine", no_new_privileges: true, protect_system: "strict", network_restricted: true },
        ],
        audit: { entries: 1284, head: "3f9c2a…", chain_verified: true, anchored_count: 1281, last_anchored_at: new Date(Date.now() - 240000).toISOString() },
    };
    const access = {
        pairing: { home: "local-user", paired_at: new Date(Date.now() - 6.9e7).toISOString(), fingerprint: "sha256:cfc34f343d1c496594c82f5a3956cf5b9a67057187bf73164245d684d129e1ee" },
        relay: { status: "parked", endpoint: "wss://relay.gaugewright.com", route_epoch: 4, last_connected_at: new Date(Date.now() - 30000).toISOString() },
        direct: { enabled: false, base_url: null as string | null },
        keys: [
            { id: "key_1c93", name: "paired-home", prefix: "tw_Nsq", created_at: new Date(Date.now() - 6.9e7).toISOString(), last_used_at: new Date(Date.now() - 4000).toISOString(), state: "active" },
            { id: "key_7e30", name: "workbench-web", prefix: "tw_H2k", created_at: new Date(Date.now() - 8.6e6).toISOString(), last_used_at: new Date(Date.now() - 900000).toISOString(), state: "active" },
        ],
        reveal: null as null | { key: string; secret: string },
    };
    const revisions: Record<string, number> = { "tokenwright.inference": 1, "tokenwright.posture": 1, "tokenwright.access": 1 };
    const rev = (id: string) => `rev${revisions[id]}${"0".repeat(60)}`.slice(0, 64);
    const content = (id: string): unknown =>
        id === "tokenwright.inference" ? inference : id === "tokenwright.posture" ? posture : access;

    const boxes = [{ fingerprint: access.pairing.fingerprint, relay_endpoint: access.relay.endpoint, paired_at: access.pairing.paired_at, home_id: "local-user", key_id: "key_1c93", sealed: true }];

    /** Bring the running engine in line with the requested one, the way a
     *  restart does — including the served-engine sparseness a real box shows. */
    function realiseEngine(): void {
        const wanted = inference.desired.engine;
        const served = wanted !== "freetoken";
        inference.engine.name = ({ freetoken: "FreeToken", vllm: "vLLM", sglang: "SGLang" } as Record<string, string>)[wanted] ?? wanted;
        inference.engine.version = served ? (wanted === "vllm" ? "0.28.0" : "0.5.10") : "0.3.2";
        const id = inference.desired.model;
        inference.model = served
            ? { id, quantization: null, context_length: null, size_mib: null, loaded_at: null } as unknown as typeof inference.model
            : { id, quantization: "q4_k_m", context_length: 2048, size_mib: 608, loaded_at: new Date().toISOString() } as typeof inference.model;
        // A served engine reports its scheduler state; an embedded one has none.
        inference.serving = served
            ? {
                kv_cache_used_pct: wanted === "vllm" ? 63 : 41,
                running: 3, queued: wanted === "vllm" ? 1 : 0,
                native: wanted === "vllm"
                    ? { "Preemptions": 4, "Prefix-cache hit rate": 0.55 }
                    : { "Radix-cache hit rate": 0.31, "Generation throughput (tok/s)": 118.4 },
              }
            : null;
    }

    return async (method, path, body) => {
        await new Promise((r) => setTimeout(r, 120));
        if (method === "GET" && path === "/account/boxes") return { boxes };
        const m = /\/surface\/environments\/tokenwright\/(\w+)/.exec(path);
        if (!m) throw new Error(`fixture has no route for ${method} ${path}`);
        const surface = m[1]!;
        if (surface === "sessions") {
            return { session: {
                id: "sess_key_1c93", environment: "tokenwright", scope: { kind: "box", id: "self" },
                actor: "paired-home", capabilities: ["AdministerBox", "RunTurn"],
                documents: [
                    { id: "tokenwright.inference", readable: true, editable: true, freshness: "live", commands: ["tokenwright.engine.stop", "tokenwright.engine.restart", "tokenwright.engine.update", "tokenwright.model.reconcile", "tokenwright.model.unload", "tokenwright.models.reconcile", "tokenwright.models.prune"] },
                    { id: "tokenwright.posture", readable: true, editable: false, freshness: "live", commands: ["tokenwright.posture.rescan", "tokenwright.wireguard.enable", "tokenwright.wireguard.disable"] },
                    { id: "tokenwright.access", readable: true, editable: true, freshness: "live", commands: ["tokenwright.key.acknowledge", "tokenwright.unpair"] },
                ],
            } };
        }
        if (surface === "documents") {
            const id = /documents\/([\w.]+)/.exec(path)![1]!;
            return { document: { id, schema: `gw://schemas/tokenwright/${id.split(".")[1]}/v1`, revision: rev(id), content: content(id) } };
        }
        if (surface === "commands") {
            const b = body as { command_id: string; document_id: string };
            // Make the controls visibly change fixture state, the way a box would.
            if (b.command_id === "tokenwright.engine.stop") { inference.engine.status = "stopped" as typeof inference.engine.status; }
            if (b.command_id === "tokenwright.engine.restart" || b.command_id === "tokenwright.engine.start" || b.command_id === "tokenwright.model.reconcile") {
                // A restart realises the requested engine — and a served engine
                // reports the model id only, so the box's own driver leaves the
                // rest null. This is what makes the served path visible in the
                // bench: switch to vLLM, restart, watch the Model card go sparse.
                realiseEngine();
                inference.engine.status = "running" as typeof inference.engine.status;
            }
            if (b.command_id === "tokenwright.model.unload") { inference.model = { id: null, quantization: null, context_length: null, size_mib: null, loaded_at: null } as unknown as typeof inference.model; }
            if (b.command_id === "tokenwright.models.prune") { inference.models = inference.models.filter((x) => x.state !== "orphaned"); inference.storage.orphaned_mib = 0; }
            revisions[b.document_id] = (revisions[b.document_id] ?? 1) + 1;
            return { receipt: { id: "rcpt_demo", command_id: b.command_id, status: "applied", at: new Date().toISOString(), detail: null } };
        }
        if (surface === "changes") {
            const b = body as { content: { desired: typeof inference.desired } };
            inference.desired = { ...inference.desired, ...b.content.desired };
            revisions["tokenwright.inference"] = (revisions["tokenwright.inference"] ?? 1) + 1;
            return { receipt: { id: "rcpt_demo", command_id: "literal.edit", status: "applied", at: new Date().toISOString(), detail: "tokenwright.inference" }, revision: rev("tokenwright.inference") };
        }
        throw new Error(`fixture has no route for ${method} ${path}`);
    };
}

const home = liveBase !== null ? browserRouteJson(liveBase) : fixtureHome();

const mount = document.getElementById("root");
if (mount) render(() => <TokenWrightBoxPanel json={home} />, mount);
