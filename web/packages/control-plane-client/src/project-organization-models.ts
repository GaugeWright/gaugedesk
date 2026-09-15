import type { RouteJson } from "./control-plane-transport";

export interface OrganizationModelAuthorityBinding {
    readonly authority: string;
    readonly organization: string;
    readonly environment: string;
}

export interface OrganizationModelPrivateBroker {
    readonly authority: string;
    readonly name: string;
    readonly operator: string;
}

export interface OrganizationModelOption {
    readonly connection: string;
    readonly name: string;
    readonly provider: string;
    readonly models: readonly string[];
    readonly organizationDefault: string | null;
    readonly privateBroker: OrganizationModelPrivateBroker;
}

export interface ProjectOrganizationModelOptions {
    readonly binding: OrganizationModelAuthorityBinding;
    readonly actor: string;
    readonly project: { readonly authority: string; readonly id: string };
    readonly home: string;
    readonly resourceBasis: string;
    readonly options: readonly OrganizationModelOption[];
}

export interface ProjectOrganizationModelSelection {
    readonly binding: OrganizationModelAuthorityBinding;
    readonly project: { readonly authority: string; readonly id: string };
    readonly home: string;
    readonly connection: string;
    readonly model: string;
    readonly provider: string;
    readonly privateBroker: OrganizationModelPrivateBroker;
    readonly resourceBasis: string;
    readonly selectedBy: string;
}

function object(value: unknown, name: string): Record<string, unknown> {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw new Error(`${name} is malformed`);
    }
    return value as Record<string, unknown>;
}

function closed(value: unknown, keys: readonly string[], name: string): Record<string, unknown> {
    const row = object(value, name);
    const actual = Object.keys(row).sort();
    const expected = [...keys].sort();
    if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
        throw new Error(`${name} is malformed`);
    }
    return row;
}

function text(value: unknown, name: string): string {
    if (typeof value !== "string" || !value.trim()) throw new Error(`${name} is malformed`);
    return value;
}

/**
 * Strictly read the secret-free authority projection used by Project Model
 * access. Unknown fields fail closed so an authority cannot accidentally ship
 * endpoints, grant records, custody data, or another scope through this small
 * surface.
 */
export function parseProjectOrganizationModelOptions(
    value: unknown,
    expectedProject: string,
): ProjectOrganizationModelOptions {
    const reply = closed(
        value,
        ["v", "binding", "actor", "project", "home", "resource_basis", "options"],
        "organization model options response",
    );
    if (reply.v !== 2) throw new Error("organization model options response is incompatible");
    const binding = closed(
        reply.binding,
        ["authority", "organization", "environment"],
        "organization model authority binding",
    );
    const project = closed(reply.project, ["authority", "id"], "organization model project");
    const projectId = text(project.id, "organization model project id");
    if (projectId !== expectedProject) throw new Error("organization model options returned a different project");
    const values = Array.isArray(reply.options) ? reply.options : null;
    if (!values) throw new Error("organization model options are malformed");
    const seen = new Set<string>();
    const options = values.map((value, index) => {
        const row = closed(
            value,
            ["connection", "name", "provider", "models", "organization_default", "private_broker"],
            `organization model option ${index}`,
        );
        const connection = text(row.connection, `organization model option ${index} connection`);
        if (seen.has(connection)) throw new Error("organization model options repeat a connection");
        seen.add(connection);
        if (!Array.isArray(row.models) || row.models.length === 0) {
            throw new Error(`organization model option ${index} models are malformed`);
        }
        const models = row.models.map((model, modelIndex) =>
            text(model, `organization model option ${index} model ${modelIndex}`));
        if (new Set(models).size !== models.length) {
            throw new Error(`organization model option ${index} repeats a model`);
        }
        const organizationDefault = row.organization_default === null
            ? null
            : text(row.organization_default, `organization model option ${index} default`);
        if (organizationDefault !== null && !models.includes(organizationDefault)) {
            throw new Error(`organization model option ${index} default is unavailable`);
        }
        const broker = closed(
            row.private_broker,
            ["authority", "name", "operator"],
            `organization model option ${index} private broker`,
        );
        return {
            connection,
            name: text(row.name, `organization model option ${index} name`),
            provider: text(row.provider, `organization model option ${index} provider`),
            models,
            organizationDefault,
            privateBroker: {
                authority: text(broker.authority, `organization model option ${index} broker authority`),
                name: text(broker.name, `organization model option ${index} broker name`),
                operator: text(broker.operator, `organization model option ${index} broker operator`),
            },
        };
    });
    const resourceBasis = text(reply.resource_basis, "organization model options basis");
    if (!resourceBasis.startsWith("organization-model-eligibility:v2:")) {
        throw new Error("organization model options basis is incompatible");
    }
    return {
        binding: {
            authority: text(binding.authority, "organization model authority"),
            organization: text(binding.organization, "organization model organization"),
            environment: text(binding.environment, "organization model environment"),
        },
        actor: text(reply.actor, "organization model actor"),
        project: {
            authority: text(project.authority, "organization model project authority"),
            id: projectId,
        },
        home: text(reply.home, "organization model project Home"),
        resourceBasis,
        options,
    };
}

export async function projectOrganizationModelOptions(
    json: RouteJson,
    project: string,
): Promise<ProjectOrganizationModelOptions> {
    const value = await json(
        "GET",
        `/projects/${encodeURIComponent(project)}/organization-model-options`,
    );
    return parseProjectOrganizationModelOptions(value, project);
}

function parseBinding(value: unknown): OrganizationModelAuthorityBinding {
    const binding = closed(
        value,
        ["authority", "organization", "environment"],
        "organization model authority binding",
    );
    return {
        authority: text(binding.authority, "organization model authority"),
        organization: text(binding.organization, "organization model organization"),
        environment: text(binding.environment, "organization model environment"),
    };
}

export function parseProjectOrganizationModelSelection(
    value: unknown,
    expectedProject: string,
): ProjectOrganizationModelSelection | null {
    const envelope = closed(value, ["selection"], "organization model selection response");
    if (envelope.selection === null) return null;
    const selection = closed(
        envelope.selection,
        ["binding", "project", "home", "connection", "model", "provider", "private_broker", "resource_basis", "selected_by"],
        "organization model selection",
    );
    const project = closed(selection.project, ["authority", "id"], "organization model selection project");
    const projectId = text(project.id, "organization model selection project id");
    if (projectId !== expectedProject) {
        throw new Error("organization model selection returned a different project");
    }
    const resourceBasis = text(selection.resource_basis, "organization model selection basis");
    if (!resourceBasis.startsWith("organization-model-eligibility:v2:")) {
        throw new Error("organization model selection basis is incompatible");
    }
    const broker = closed(
        selection.private_broker,
        ["authority", "name", "operator"],
        "organization model selection private broker",
    );
    return {
        binding: parseBinding(selection.binding),
        project: {
            authority: text(project.authority, "organization model selection project authority"),
            id: projectId,
        },
        home: text(selection.home, "organization model selection Home"),
        connection: text(selection.connection, "organization model selection connection"),
        model: text(selection.model, "organization model selection model"),
        provider: text(selection.provider, "organization model selection provider"),
        privateBroker: {
            authority: text(broker.authority, "organization model selection broker authority"),
            name: text(broker.name, "organization model selection broker name"),
            operator: text(broker.operator, "organization model selection broker operator"),
        },
        resourceBasis,
        selectedBy: text(selection.selected_by, "organization model selection actor"),
    };
}

export async function projectOrganizationModelSelection(
    json: RouteJson,
    project: string,
): Promise<ProjectOrganizationModelSelection | null> {
    const value = await json(
        "GET",
        `/projects/${encodeURIComponent(project)}/organization-model-selection`,
    );
    return parseProjectOrganizationModelSelection(value, project);
}

export async function selectProjectOrganizationModel(
    json: RouteJson,
    project: string,
    input: {
        readonly binding: OrganizationModelAuthorityBinding;
        readonly connection: string;
        readonly model: string;
        readonly privateBroker: string;
        readonly admitPrivatePlaintext: true;
    },
): Promise<ProjectOrganizationModelSelection> {
    const value = await json(
        "PUT",
        `/projects/${encodeURIComponent(project)}/organization-model-selection`,
        {
            binding: input.binding,
            connection: input.connection,
            model: input.model,
            private_broker: input.privateBroker,
            admit_private_plaintext: input.admitPrivatePlaintext,
        },
    );
    const selection = parseProjectOrganizationModelSelection(value, project);
    if (!selection) throw new Error("organization model selection was not stored");
    return selection;
}

export async function clearProjectOrganizationModelSelection(
    json: RouteJson,
    project: string,
): Promise<void> {
    const value = await json(
        "DELETE",
        `/projects/${encodeURIComponent(project)}/organization-model-selection`,
    );
    if (parseProjectOrganizationModelSelection(value, project) !== null) {
        throw new Error("organization model selection was not cleared");
    }
}
