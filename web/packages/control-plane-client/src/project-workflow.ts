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
