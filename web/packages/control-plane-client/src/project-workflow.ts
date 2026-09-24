import type { WorkbenchTransport } from "./control-plane-workbench";

/** An ordinary `.whip` file at one saved revision, and its typed inputs. */
export interface ProjectWorkflowLaunchIntent {
    target: string;
    path: string;
    cut: string;
    inputs: Record<string, unknown>;
    /** Created once for this exact launch and retained across delivery retries. */
    requestId: string;
}
/** Admission evidence only. The Home steps the run; the client never does. */
export interface ProjectWorkflowLaunchResult {
    project: string;
    workspace: string;
    instanceId: string;
}

function record(value: unknown): Record<string, unknown> {
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Invalid workflow response");
    return value as Record<string, unknown>;
}
function identity(value: unknown): string {
    if (typeof value !== "string" || !value.trim()) throw new Error("Missing workflow identity");
    return value;
}

export async function launchProjectWorkflow(transport: WorkbenchTransport, project: string, intent: ProjectWorkflowLaunchIntent): Promise<ProjectWorkflowLaunchResult> {
    identity(intent.requestId);
    const raw = record(await transport.json("POST", `/projects/${encodeURIComponent(project)}/workflows`, {
        target: intent.target, path: intent.path, cut: intent.cut, inputs: intent.inputs,
    }, { idempotencyKey: intent.requestId }));
    const admission = record(raw.admission);
    const result = { project: identity(raw.project), workspace: identity(raw.workspace), instanceId: identity(admission.instance_ref) };
    if (result.project !== project) throw new Error("Launch differs from its requested project");
    return result;
}

/** Start, or find, the signed-in person's run of a tutorial GaugeDesk ships
 *  (WHIP-5). The Home supplies source, revision and learner; asking again
 *  answers with the run that exists, so no request key is needed. */
export async function startShippedTutorial(transport: WorkbenchTransport, name: string): Promise<ProjectWorkflowLaunchResult> {
    identity(name);
    const raw = record(await transport.json("POST", `/tutorials/${encodeURIComponent(name)}/start`));
    const admission = record(raw.admission);
    return { project: identity(raw.project), workspace: identity(raw.workspace), instanceId: identity(admission.instance_ref) };
}

/** A declared workflow input's type, as the Run form draws it. */
export type WorkflowInputType =
    | { kind: "string" | "int" | "float" | "bool" | "json" }
    | { kind: "literal"; value: string }
    | { kind: "enum"; name?: string; variants: string[] }
    | { kind: "optional"; of: WorkflowInputType }
    | { kind: "object"; name?: string; fields: { name: string; type: WorkflowInputType }[] };

/** What running a chat's `.whip` file would launch: the kept version on its
 *  target's Main, and the inputs that version declares. */
export interface ChatWhipDescription {
    project: string;
    target: string;
    path: string;
    /** The revision a Run launches; a chat's unkept edits are never run. */
    cut: string;
    workflow: string;
    inputs: { name: string; type: WorkflowInputType }[];
    /** The signed-in person asking, so a person input can default to them. */
    actor?: string;
}

/** One run of a chat's `.whip` file: what its status and history show. */
export interface ChatWhipRunView {
    /** The file, as the chat names it (`targets/<target>/<path>`). */
    path: string;
    requestId: string;
    launchedBy: string;
    /** Whether the signed-in person launched it. */
    byYou: boolean;
    state: "running" | "completed" | "failed" | "cancelled" | "unknown";
    startedAt: string | null;
    cut: string;
}

const RUN_STATES = new Set(["running", "completed", "failed", "cancelled"]);

/** The runs of this chat's `.whip` files — or of one of them — newest first. */
export async function listChatWhipRuns(transport: WorkbenchTransport, chat: string, path?: string): Promise<ChatWhipRunView[]> {
    const query = path ? `?path=${encodeURIComponent(path)}` : "";
    const raw = record(await transport.json("GET", `/chats/${encodeURIComponent(chat)}/whips/runs${query}`));
    if (!Array.isArray(raw.runs)) throw new Error("Missing workflow runs");
    return raw.runs.map((value) => {
        const run = record(value);
        const state = typeof run.state === "string" && RUN_STATES.has(run.state) ? run.state : "unknown";
        return {
            path: identity(run.path),
            requestId: identity(run.request_id),
            launchedBy: identity(run.launched_by),
            byYou: run.by_you === true,
            state: state as ChatWhipRunView["state"],
            startedAt: typeof run.started_at === "string" ? run.started_at : null,
            cut: identity(run.cut),
        };
    });
}

function inputType(value: unknown, depth = 0): WorkflowInputType {
    const raw = record(value);
    if (depth > 8) return { kind: "json" };
    switch (raw.kind) {
        case "string": case "int": case "float": case "bool": case "json":
            return { kind: raw.kind };
        case "literal":
            if (typeof raw.value !== "string") throw new Error("Invalid literal input");
            return { kind: "literal", value: raw.value };
        case "enum":
            if (!Array.isArray(raw.variants) || raw.variants.some((v) => typeof v !== "string")) throw new Error("Invalid enum input");
            return { kind: "enum", name: typeof raw.name === "string" ? raw.name : undefined, variants: raw.variants as string[] };
        case "optional":
            return { kind: "optional", of: inputType(raw.of, depth + 1) };
        case "object":
            if (!Array.isArray(raw.fields)) throw new Error("Invalid object input");
            return {
                kind: "object",
                name: typeof raw.name === "string" ? raw.name : undefined,
                fields: raw.fields.map((field) => {
                    const f = record(field);
                    return { name: identity(f.name), type: inputType(f.type, depth + 1) };
                }),
            };
        default:
            // An input kind this client does not know is still runnable as JSON.
            return { kind: "json" };
    }
}

export async function describeChatWhip(transport: WorkbenchTransport, chat: string, path: string): Promise<ChatWhipDescription> {
    const raw = record(await transport.json("GET", `/chats/${encodeURIComponent(chat)}/whips/inputs?path=${encodeURIComponent(path)}`));
    if (!Array.isArray(raw.inputs)) throw new Error("Missing workflow inputs");
    return {
        project: identity(raw.project),
        target: identity(raw.target),
        path: identity(raw.path),
        cut: identity(raw.cut),
        workflow: identity(raw.workflow),
        inputs: raw.inputs.map((input) => {
            const i = record(input);
            return { name: identity(i.name), type: inputType(i.type) };
        }),
        actor: typeof raw.actor === "string" && raw.actor ? raw.actor : undefined,
    };
}

/** Run a chat's `.whip` file at the revision it was described at. */
export async function runChatWhip(
    transport: WorkbenchTransport,
    chat: string,
    run: { path: string; cut: string; inputs: Record<string, unknown>; requestId: string },
): Promise<ProjectWorkflowLaunchResult> {
    identity(run.requestId);
    const raw = record(await transport.json("POST", `/chats/${encodeURIComponent(chat)}/whips/run`, {
        path: run.path, cut: run.cut, inputs: run.inputs,
    }, { idempotencyKey: run.requestId }));
    const admission = record(raw.admission);
    return { project: identity(raw.project), workspace: identity(raw.workspace), instanceId: identity(admission.instance_ref) };
}
