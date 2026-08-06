/**
 * gaugewright Pi plugin — the in-process egress membrane.
 *
 * This is the plugin surface Pi sees (`pi-rpc.md`, "Roles"). It enforces the
 * agent's `.agent-config.json` `policy` on Pi's `tool_call` hook — the
 * **no-prompt static path** of the boundary membrane — so an out-of-policy
 * effect is blocked *before* it executes. The Rust host (`gaugedesk-boundary`)
 * holds the same policy model; this plugin is its enforcement point inside Pi.
 *
 * Posture (mirrors `gaugedesk_boundary::Posture`):
 *   - trust-by-default : in-workspace effects proceed; external ones blocked.
 *   - prompt-on-risk   : risky effects ask via `ctx.ui` (→ extension_ui_request).
 *   - policy-only-block: only allow-listed tools proceed.
 *
 * One unmediated effect path voids the boundary model — every tool call routes
 * through `classify` here.
 *
 * Loaded with `pi --mode rpc -e plugin/gaugewright-plugin.ts`. The host reads the
 * resulting block/allow decisions off the event stream as runtime-session
 * observations; product truth is still admitted only by the owner.
 */

import { existsSync, readFileSync } from "node:fs";
import { isAbsolute, join, relative, resolve } from "node:path";
import type { ExtensionAPI, ExtensionContext, ToolCallEvent, ToolCallEventResult } from "@mariozechner/pi-coding-agent";

type Posture = "trust-by-default" | "prompt-on-risk" | "policy-only-block";

interface Policy {
    posture?: Posture;
    allow_tools?: string[];
    block_tools?: string[];
    allow_network?: boolean;
}
interface AgentConfig {
    policy?: Policy;
}

/** Tools that leave the workspace boundary (network). Everything else is in-workspace. */
const EXTERNAL_TOOLS = new Set(["fetch", "web", "curl", "http", "download"]);

/** Pi's built-in file-mutating tools (the ones the write-gate catches). */
function isWriteTool(tool: string): boolean {
    return tool === "write" || tool === "edit";
}

/**
 * The agent's **method-definition surface** (ADR 0029): the Pi-native files that
 * define the agent. A write here is edit-authored (INV-24). Mirrors
 * `gaugedesk_boundary::is_method_surface_path`.
 *
 * Source of truth for the layout: the `definition` module in `crates/boundary`
 * (SYSTEM_PATH / INSTRUCTIONS_PATH / CONFIG_PATH / READONLY_ROOTS). This is a
 * cross-language copy — keep it in sync with that module by hand.
 */
function isMethodSurfacePath(path: string): boolean {
    const p = path.replace(/^\.\//, "");
    return (
        p === ".agent-config.json" ||
        p === "AGENTS.md" ||
        p === "CLAUDE.md" ||
        p.startsWith(".pi/") ||
        p.includes("/.pi/") ||
        p.endsWith("/AGENTS.md") ||
        p.endsWith("/CLAUDE.md") ||
        p.endsWith("/.agent-config.json")
    );
}

/**
 * The engagement's authoring mode, from the host (`GAUGEDESK_CHAT_MODE`). Edit may
 * edit the agent's own definition; anything else is read-only to it (fail-closed).
 */
function isEditMode(): boolean {
    return process.env.GAUGEDESK_CHAT_MODE === "edit";
}

function loadPolicy(cwd: string): Policy {
    const path = join(cwd, ".agent-config.json");
    if (!existsSync(path)) return {};
    try {
        const cfg = JSON.parse(readFileSync(path, "utf8")) as AgentConfig;
        return cfg.policy ?? {};
    } catch {
        // A malformed policy fails closed: deny everything but in-workspace reads.
        return { posture: "policy-only-block", allow_tools: ["read", "ls", "grep", "find"] };
    }
}

/** The path a file tool targets, if any (write/edit carry `input.path`). */
function targetPath(event: ToolCallEvent): string | undefined {
    const input = (event as { input?: Record<string, unknown> }).input;
    const p = input?.["path"];
    return typeof p === "string" ? p : undefined;
}

/** True if `p` resolves outside the workspace root `cwd` — an external write. */
function escapesWorkspace(cwd: string, p: string): boolean {
    const abs = isAbsolute(p) ? p : resolve(cwd, p);
    const rel = relative(resolve(cwd), abs);
    return rel.startsWith("..") || isAbsolute(rel);
}

type Decision = { allow: true } | { block: string } | { stage: string };

function classify(policy: Policy, cwd: string, event: ToolCallEvent): Decision {
    const tool = event.toolName;
    const posture: Posture = policy.posture ?? "trust-by-default";
    const allow = new Set(policy.allow_tools ?? []);
    const block = new Set(policy.block_tools ?? []);

    // An explicit block always wins — even trust-by-default cannot override it.
    if (block.has(tool)) return { block: "tool blocked by policy" };

    // A write/edit that resolves outside the workspace is an external effect.
    const path = targetPath(event);

    // INV-24: the method-definition surface is edit-authored. A write to it from
    // a use-mode engagement is blocked even under trust-by-default — the agent
    // cannot rewrite its own system prompt or loosen its own policy (ADR 0029).
    if (!isEditMode() && isWriteTool(tool) && path !== undefined && isMethodSurfacePath(path)) {
        return { block: "method definition is read-only in use mode" };
    }
    const leavesWorkspace = EXTERNAL_TOOLS.has(tool) || (path !== undefined && escapesWorkspace(cwd, path));

    if (leavesWorkspace) {
        if (policy.allow_network) return { allow: true };
        return posture === "prompt-on-risk"
            ? { stage: "external effect: needs approval" }
            : { block: "external effect not permitted (no network basis)" };
    }

    // In-workspace: explicit allow, or the posture's default.
    if (allow.has(tool)) return { allow: true };
    switch (posture) {
        case "trust-by-default":
            return { allow: true };
        case "prompt-on-risk":
            return { stage: "unlisted tool: confirm in-workspace effect" };
        case "policy-only-block":
            return { block: "tool not in allow-list" };
    }
}

export default function gaugewrightPlugin(pi: ExtensionAPI): void {
    pi.on("tool_call", async (event: ToolCallEvent, ctx: ExtensionContext): Promise<ToolCallEventResult | void> => {
        const policy = loadPolicy(ctx.cwd);
        const decision = classify(policy, ctx.cwd, event);

        if ("allow" in decision) {
            // allow-and-record: the host observes the tool_execution_* stream.
            return;
        }
        if ("block" in decision) {
            return { block: true, reason: `gaugewright membrane: ${decision.block}` };
        }
        // stage: ask the user (→ extension_ui_request the host answers via a grant).
        if (ctx.hasUI) {
            const ok = await ctx.ui.confirm("gaugewright: approve effect?", `${event.toolName}: ${decision.stage}`);
            return ok ? undefined : { block: true, reason: `gaugewright membrane: ${decision.stage} (declined)` };
        }
        // No UI (headless without a host answer): fail closed.
        return { block: true, reason: `gaugewright membrane: ${decision.stage} (no approver)` };
    });
}
