/** ADR 0107's reserved, read-only Administration bundle. */

import { parseEnvironmentManifest, type EnvironmentManifest } from "@gaugewright/workbench-ui";
import manifestSource from "./admin-files/manifest.json?raw";
import agentSystem from "./admin-files/agent/SYSTEM.md?raw";
import agentSkill from "./admin-files/agent/skills/administration/SKILL.md?raw";
import agentTools from "./admin-files/agent/TOOLS.json?raw";
import helpIndex from "./admin-files/help/README.md?raw";
import helpAccess from "./admin-files/help/access.md?raw";
import helpAudit from "./admin-files/help/audit.md?raw";
import helpBilling from "./admin-files/help/billing.md?raw";
import helpClients from "./admin-files/help/clients.md?raw";
import helpMachines from "./admin-files/help/machines.md?raw";
import helpBackups from "./admin-files/help/backups.md?raw";
import helpDeployments from "./admin-files/help/deployments.md?raw";
import helpAutomations from "./admin-files/help/automations.md?raw";
import helpIdentity from "./admin-files/help/identity.md?raw";
import helpOrganization from "./admin-files/help/organization.md?raw";
import helpOverview from "./admin-files/help/overview.md?raw";
import helpPolicy from "./admin-files/help/policy.md?raw";
import helpSoftware from "./admin-files/help/software.md?raw";
import viewAccess from "./admin-files/views/access.mdx?raw";
import viewAudit from "./admin-files/views/audit.mdx?raw";
import viewBilling from "./admin-files/views/billing.mdx?raw";
import viewClients from "./admin-files/views/clients.mdx?raw";
import viewIdentity from "./admin-files/views/identity.mdx?raw";
import viewMachines from "./admin-files/views/machines.mdx?raw";
import viewBackups from "./admin-files/views/backups.mdx?raw";
import viewDeployments from "./admin-files/views/deployments.mdx?raw";
import viewAutomations from "./admin-files/views/automations.mdx?raw";
import viewOrganization from "./admin-files/views/organization.mdx?raw";
import viewOverview from "./admin-files/views/overview.mdx?raw";
import viewPolicy from "./admin-files/views/policy.mdx?raw";
import viewSoftwarePolicy from "./admin-files/views/software-policy.mdx?raw";

export type AdminConfigPath =
    | "overview.json"
    | "organization.json"
    | "access.json"
    | "identity.json"
    | "policy.json"
    | "software-policy.json"
    | "clients.json"
    | "machines.json"
    | "backups.json"
    | "deployments.json"
    | "automations.json"
    | "audit.json"
    | "billing.json";

export type AdminHelpPath =
    | ".environment/help/README.md"
    | ".environment/help/overview.md"
    | ".environment/help/organization.md"
    | ".environment/help/access.md"
    | ".environment/help/identity.md"
    | ".environment/help/policy.md"
    | ".environment/help/software.md"
    | ".environment/help/clients.md"
    | ".environment/help/machines.md"
    | ".environment/help/backups.md"
    | ".environment/help/deployments.md"
    | ".environment/help/automations.md"
    | ".environment/help/audit.md"
    | ".environment/help/billing.md";

export type AdminInternalPath = `.environment/${string}`;
export type AdminWorkspacePath = AdminConfigPath | AdminInternalPath;

export const ADMIN_HELP_INDEX: AdminHelpPath = ".environment/help/README.md";

export const ADMIN_HELP_BY_FILE: Readonly<Record<AdminConfigPath, AdminHelpPath>> = {
    "overview.json": ".environment/help/overview.md",
    "organization.json": ".environment/help/organization.md",
    "access.json": ".environment/help/access.md",
    "identity.json": ".environment/help/identity.md",
    "policy.json": ".environment/help/policy.md",
    "software-policy.json": ".environment/help/software.md",
    "clients.json": ".environment/help/clients.md",
    "machines.json": ".environment/help/machines.md",
    "backups.json": ".environment/help/backups.md",
    "deployments.json": ".environment/help/deployments.md",
    "automations.json": ".environment/help/automations.md",
    "audit.json": ".environment/help/audit.md",
    "billing.json": ".environment/help/billing.md",
};

export const WRITABLE_ADMIN_FILES: ReadonlySet<AdminConfigPath> = new Set([
    "organization.json",
    "policy.json",
    "software-policy.json",
    "billing.json",
]);

export const ADMIN_AGENT_TOOL_IDS = [
    "environment.files.list",
    "environment.files.read",
    "environment.projections.query",
    "environment.changes.propose",
    "question.ask",
] as const;

export type AdminAgentToolId = (typeof ADMIN_AGENT_TOOL_IDS)[number];

export interface AdminAgentToolDeclaration {
    readonly id: AdminAgentToolId;
    readonly effect: "read" | "proposal" | "human";
    readonly description: string;
}

const parsedAgentTools = JSON.parse(agentTools) as {
    readonly schema: string;
    readonly tools: readonly AdminAgentToolDeclaration[];
};

export const ADMIN_AGENT_TOOLS = parsedAgentTools.tools;
export const ADMIN_AGENT_SYSTEM_MD = agentSystem;
export const ADMIN_AGENT_SKILL_MD = agentSkill;
export const ADMIN_MANIFEST: EnvironmentManifest = parseEnvironmentManifest(JSON.parse(manifestSource));

export const ADMIN_VIEW_SOURCES: Readonly<Record<string, string>> = {
    "views/overview.mdx": viewOverview,
    "views/organization.mdx": viewOrganization,
    "views/access.mdx": viewAccess,
    "views/identity.mdx": viewIdentity,
    "views/policy.mdx": viewPolicy,
    "views/software-policy.mdx": viewSoftwarePolicy,
    "views/clients.mdx": viewClients,
    "views/machines.mdx": viewMachines,
    "views/backups.mdx": viewBackups,
    "views/deployments.mdx": viewDeployments,
    "views/automations.mdx": viewAutomations,
    "views/audit.mdx": viewAudit,
    "views/billing.mdx": viewBilling,
};

export const ADMIN_STATIC_FILES: readonly { readonly path: AdminInternalPath; readonly content: string }[] = [
    { path: ".environment/manifest.json", content: manifestSource },
    ...Object.entries(ADMIN_VIEW_SOURCES).map(([path, content]) => ({
        path: `.environment/${path}` as AdminInternalPath,
        content,
    })),
    { path: ".environment/help/README.md", content: helpIndex },
    { path: ".environment/help/overview.md", content: helpOverview },
    { path: ".environment/help/organization.md", content: helpOrganization },
    { path: ".environment/help/access.md", content: helpAccess },
    { path: ".environment/help/identity.md", content: helpIdentity },
    { path: ".environment/help/policy.md", content: helpPolicy },
    { path: ".environment/help/software.md", content: helpSoftware },
    { path: ".environment/help/clients.md", content: helpClients },
    { path: ".environment/help/machines.md", content: helpMachines },
    { path: ".environment/help/backups.md", content: helpBackups },
    { path: ".environment/help/deployments.md", content: helpDeployments },
    { path: ".environment/help/automations.md", content: helpAutomations },
    { path: ".environment/help/audit.md", content: helpAudit },
    { path: ".environment/help/billing.md", content: helpBilling },
    { path: ".environment/agent/SYSTEM.md", content: agentSystem },
    { path: ".environment/agent/skills/administration/SKILL.md", content: agentSkill },
    { path: ".environment/agent/TOOLS.json", content: agentTools },
];

export function adminHelpPath(path: AdminConfigPath): AdminHelpPath {
    return ADMIN_HELP_BY_FILE[path];
}

export function adminFileIsEditable(path: string): boolean {
    return WRITABLE_ADMIN_FILES.has(path as AdminConfigPath);
}
