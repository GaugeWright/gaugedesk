/**
 * The pure folds behind {@link TokenWrightBoxPanel}: what a row may claim, and
 * which controls make sense given the state the box just reported.
 *
 * Kept out of the component so the decisions that matter — "is Stop offered
 * while the engine is stopped?" — are testable without a renderer.
 */

export type EngineStatus = "running" | "starting" | "stopped" | "failed" | "updating";

export interface InferenceDocument {
    readonly desired: {
        readonly model: string | null;
        readonly models: readonly string[];
        readonly autostart: boolean;
        readonly direct_access: boolean;
        readonly engine: string;
    };
    readonly engine: {
        readonly name: string;
        readonly version: string;
        readonly status: EngineStatus;
        readonly listen: string;
        readonly uptime: string | null;
        readonly restarts: number;
        readonly last_error: string | null;
    };
    readonly model: {
        readonly id: string | null;
        readonly quantization: string | null;
        readonly context_length: number | null;
        readonly size_mib: number | null;
        readonly loaded_at: string | null;
    };
    readonly models: readonly {
        readonly id: string;
        readonly size_mib: number;
        readonly quantization: string;
        readonly state: "loaded" | "available" | "downloading" | "incomplete" | "orphaned" | "quarantined";
        readonly digest_verified: boolean | null;
    }[];
    readonly hardware: {
        readonly gpu: string;
        readonly driver: string;
        readonly cuda: string;
        readonly vram_used_mib: number;
        readonly vram_total_mib: number;
        readonly ram_total_mib: number;
    };
    readonly storage: {
        readonly disk_total_mib: number;
        readonly disk_free_mib: number;
        readonly orphaned_mib: number;
    };
    readonly throughput: {
        readonly tokens_per_second: number;
        readonly active_requests: number;
        readonly max_concurrent: number;
        readonly rejected_overload_total: number;
        readonly requests_total: number;
    };
    /** A served engine's own scheduler state, normalised — null for an embedded
     *  engine and while the engine is down. `native` is a curated bag of
     *  engine-specific metrics that do not map to the shared fields. */
    readonly serving: {
        readonly kv_cache_used_pct: number | null;
        readonly running: number | null;
        readonly queued: number | null;
        readonly native: Readonly<Record<string, number>>;
    } | null;
    readonly events: readonly { readonly at: string; readonly level: "info" | "warn" | "error"; readonly message: string }[];
}

export interface PostureDocument {
    readonly checked_at: string;
    readonly summary: { readonly critical: number; readonly warning: number; readonly advisory: number; readonly checks_passed: number };
    readonly findings: readonly {
        readonly id: string;
        readonly severity: "critical" | "warning" | "advisory";
        readonly title: string;
        readonly remediation: string;
        readonly subject?: string;
    }[];
    readonly network: {
        readonly listeners: readonly unknown[];
        readonly firewall: { readonly backend: string; readonly active: boolean; readonly default_incoming: string; readonly allow_rules: number };
        readonly wireguard: { readonly enabled: boolean; readonly interface: string | null; readonly listen_port: number | null; readonly peers: number; readonly public_key: string | null };
    };
    readonly services: readonly { readonly unit: string; readonly state: string; readonly user: string; readonly no_new_privileges: boolean; readonly protect_system: string; readonly network_restricted: boolean }[];
    readonly audit: { readonly entries: number; readonly head: string | null; readonly chain_verified: boolean; readonly anchored_count: number; readonly last_anchored_at: string | null };
}

export interface AccessDocument {
    readonly pairing: { readonly home: string; readonly paired_at: string; readonly fingerprint: string };
    readonly relay: { readonly status: string; readonly endpoint: string | null; readonly route_epoch: number; readonly last_connected_at: string | null };
    readonly direct: { readonly enabled: boolean; readonly base_url: string | null };
    readonly keys: readonly { readonly id: string; readonly name: string; readonly prefix: string; readonly created_at: string; readonly last_used_at: string | null; readonly state: string }[];
    readonly reveal: { readonly key: string; readonly secret: string } | null;
}

/** A colour-coded status, never colour alone. */
export interface Tone {
    readonly tone: "ok" | "warn" | "bad" | "muted" | "info";
    readonly label: string;
}

export function engineTone(status: EngineStatus): Tone {
    switch (status) {
        case "running": return { tone: "ok", label: "running" };
        case "starting": return { tone: "info", label: "starting" };
        case "updating": return { tone: "info", label: "updating" };
        case "stopped": return { tone: "muted", label: "stopped" };
        case "failed": return { tone: "bad", label: "failed" };
    }
}

export function modelStateTone(state: InferenceDocument["models"][number]["state"]): Tone {
    switch (state) {
        case "loaded": return { tone: "ok", label: "loaded" };
        case "available": return { tone: "muted", label: "available" };
        case "downloading": return { tone: "info", label: "downloading" };
        case "incomplete": return { tone: "warn", label: "incomplete" };
        case "orphaned": return { tone: "warn", label: "orphaned" };
        case "quarantined": return { tone: "bad", label: "quarantined" };
    }
}

export function severityTone(severity: "critical" | "warning" | "advisory"): Tone {
    switch (severity) {
        case "critical": return { tone: "bad", label: "critical" };
        case "warning": return { tone: "warn", label: "warning" };
        case "advisory": return { tone: "info", label: "advisory" };
    }
}

/**
 * Which engine controls are worth showing. Offering Stop on a stopped engine is
 * a button that can only produce a `rejected` receipt.
 */
export function engineControls(status: EngineStatus): readonly string[] {
    switch (status) {
        case "running": return ["tokenwright.engine.stop", "tokenwright.engine.restart"];
        case "starting": return ["tokenwright.engine.stop"];
        case "stopped": return ["tokenwright.engine.start"];
        case "failed": return ["tokenwright.engine.start"];
        case "updating": return [];
    }
}

/** Whether "Apply requested model" would do anything. */
export function modelApplyPending(doc: InferenceDocument): boolean {
    return doc.desired.model !== null && doc.desired.model !== doc.model.id;
}

/** Declared models that are not yet on disk — what "Fetch declared" would fetch. */
export function undeclaredOnDisk(doc: InferenceDocument): readonly string[] {
    const present = new Set(doc.models.map((m) => m.id));
    return doc.desired.models.filter((id) => !present.has(id));
}

export function orphanedMib(doc: InferenceDocument): number {
    return doc.models.filter((m) => m.state === "orphaned").reduce((sum, m) => sum + m.size_mib, 0);
}

export function mib(value: number | null | undefined): string {
    if (value === null || value === undefined) return "—";
    if (value >= 1024) return `${(value / 1024).toFixed(value >= 10240 ? 0 : 1)} GiB`;
    return `${value} MiB`;
}

export function percent(used: number, total: number): number {
    if (!total) return 0;
    return Math.max(0, Math.min(100, Math.round((used / total) * 100)));
}

/** Relative time in words for a one-line row; absolute goes in a tooltip. */
export function ago(iso: string | null | undefined, now: number = Date.now()): string {
    if (!iso) return "never";
    const then = Date.parse(iso);
    if (Number.isNaN(then)) return iso;
    const seconds = Math.max(0, Math.floor((now - then) / 1000));
    if (seconds < 45) return "just now";
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h ago`;
    return `${Math.floor(hours / 24)}d ago`;
}

/**
 * The engines a box can be told to run, and how they behave.
 *
 * Mirrors `desired.engine`'s enum in the inference schema and `KNOWN` in the
 * box's `engines.py`. It is a small, stable set and it is spelled out here
 * rather than read from the schema at runtime, the way the command labels are —
 * a drift shows up as a missing option, not a broken page.
 */
export const KNOWN_ENGINES = ["freetoken", "vllm", "sglang"] as const;

export type EngineId = (typeof KNOWN_ENGINES)[number];

/** How an engine runs, which is what decides the controls that make sense. */
export function isServedEngine(engine: string): boolean {
    // `freetoken` is embedded — the unit imports it and drives it in-process.
    // Every other engine is a *server* the unit launches (vLLM, SGLang): it
    // holds exactly the model it was started with, and cannot run without one.
    // The document may carry the observed name ("vLLM") or the requested id
    // ("vllm"); both normalise the same way.
    const id = engine.trim().toLowerCase();
    return id !== "" && id !== "freetoken";
}

const ENGINE_LABELS: Record<string, string> = {
    freetoken: "FreeToken",
    vllm: "vLLM",
    sglang: "SGLang",
};

export function engineLabel(engine: string): string {
    return ENGINE_LABELS[engine.trim().toLowerCase()] ?? engine;
}

/** Whether the requested engine differs from the one that answered — a change
 *  that has not taken effect yet, or one that will not start. */
export function engineChangePending(requested: string, running: string): boolean {
    return requested.trim().toLowerCase() !== running.trim().toLowerCase();
}
