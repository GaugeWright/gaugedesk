export const LATENCY_EVENT = "gaugewright:latency";

export type BrowserLatencyPhase =
    | "bootstrap_start"
    | "bootstrap_response"
    | "socket_connect_start"
    | "session_ready_received"
    | "panels_bound"
    | "prompt_submitted"
    | "command_sent"
    | "first_event_received"
    | "first_text_received"
    | "first_text_rendered"
    | "terminal_received";

export interface BrowserLatencyObservation {
    readonly phase: BrowserLatencyPhase;
    readonly monotonic_ms: number;
    readonly trace_id?: string;
    readonly request_id?: string;
    readonly sequence?: number;
}

const SERVER_LATENCY_PHASES = [
    "command_received",
    "reservation_start",
    "reservation_complete",
    "runtime_turn_start",
    "model_round_start",
    "direct_provider_fetch_start",
    "direct_provider_headers",
    "direct_provider_first_body_byte",
    "direct_provider_first_text_delta",
    "direct_provider_body_complete",
    "runtime_first_delta",
    "websocket_first_delta_sent",
    "model_round_complete",
    "drive_complete",
    "runtime_turn_complete",
    "settlement_start",
    "settlement_complete",
] as const;

export type ServerLatencyPhase = (typeof SERVER_LATENCY_PHASES)[number];

export interface ServerLatencyObservation {
    readonly source: "session";
    readonly span: "public_turn" | "runtime";
    readonly phase: ServerLatencyPhase;
    readonly elapsed_ms: number;
    readonly request_id: string;
}

const DEPLOYMENT_LATENCY_PHASES = [
    "request_received",
    "deployment_loaded",
    "admission_complete",
    "session_lookup_complete",
    "runtime_bootstrap_start",
    "runtime_bootstrap_complete",
    "binding_persisted",
    "capability_persisted",
    "response_ready",
] as const;

export type DeploymentLatencyPhase =
    (typeof DEPLOYMENT_LATENCY_PHASES)[number];

export interface DeploymentLatencyObservation {
    readonly source: "deployment";
    readonly span: "bootstrap";
    readonly phase: DeploymentLatencyPhase;
    readonly elapsed_ms: number;
    readonly trace_id: string;
}

export type LatencyObservation =
    | BrowserLatencyObservation
    | ServerLatencyObservation
    | DeploymentLatencyObservation;

export type LatencyObserver = (observation: LatencyObservation) => void;

function deliver(
    observer: LatencyObserver | undefined,
    observation: LatencyObservation,
): void {
    if (!observer) return;
    try {
        observer(observation);
    } catch {
        // Diagnostics are deliberately lossy and never become a serving-path
        // dependency.
    }
}

export function observeBrowserLatency(
    observer: LatencyObserver | undefined,
    phase: BrowserLatencyPhase,
    fields: Pick<
        BrowserLatencyObservation,
        "trace_id" | "request_id" | "sequence"
    > = {},
): void {
    deliver(observer, {
        phase,
        monotonic_ms:
            typeof globalThis.performance?.now === "function"
                ? globalThis.performance.now()
                : Date.now(),
        ...fields,
    });
}

export function relayServerLatency(
    observer: LatencyObserver | undefined,
    value: Record<string, unknown>,
): boolean {
    const elapsed = Number(value.elapsed_ms);
    if (
        value.source === "deployment" &&
        value.span === "bootstrap" &&
        typeof value.phase === "string" &&
        DEPLOYMENT_LATENCY_PHASES.includes(
            value.phase as DeploymentLatencyPhase,
        ) &&
        typeof value.trace_id === "string" &&
        /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value.trace_id) &&
        Number.isFinite(elapsed) &&
        elapsed >= 0 &&
        elapsed <= 86_400_000
    ) {
        deliver(observer, {
            source: "deployment",
            span: "bootstrap",
            phase: value.phase as DeploymentLatencyPhase,
            elapsed_ms: elapsed,
            trace_id: value.trace_id,
        });
        return true;
    }
    if (
        value.source !== "session" ||
        (value.span !== "public_turn" && value.span !== "runtime") ||
        typeof value.phase !== "string" ||
        !SERVER_LATENCY_PHASES.includes(value.phase as ServerLatencyPhase) ||
        typeof value.request_id !== "string" ||
        !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value.request_id) ||
        !Number.isFinite(elapsed) ||
        elapsed < 0 ||
        elapsed > 86_400_000
    ) {
        return false;
    }
    deliver(observer, {
        source: "session",
        span: value.span,
        phase: value.phase as ServerLatencyPhase,
        elapsed_ms: elapsed,
        request_id: value.request_id,
    });
    return true;
}
