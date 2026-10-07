import { createComponent, ErrorBoundary } from "solid-js";
import { render } from "solid-js/web";
import { afterEach, expect, it, vi } from "vitest";
import type { ProjectOrganizationModelOptions } from "@gaugewright/control-plane-client";
import { ProjectModelAccessContent, type ProjectModelAccessApi } from "./ProjectModelAccessPanel";

let dispose: (() => void) | undefined;
afterEach(() => { dispose?.(); document.body.replaceChildren(); });

const options: ProjectOrganizationModelOptions = {
    binding: { authority: "hub", organization: "org", environment: "test" },
    actor: "owner", project: { authority: "home", id: "project" }, home: "home", resourceBasis: "basis",
    options: [{ connection: "connection", name: "Organization connection", provider: "openai",
        models: ["model-a", "model-b"], organizationDefault: "model-b",
        privateBroker: { authority: "broker", name: "Office broker", operator: "Organization" } }],
};

function mount(overrides: Partial<ProjectModelAccessApi> = {}) {
    const api: ProjectModelAccessApi = {
        projectCredentials: vi.fn(async () => []), linkProjectCredential: vi.fn(async () => {}),
        unlinkProjectCredential: vi.fn(async () => {}),
        projectOrganizationModelOptions: vi.fn(async () => options),
        projectOrganizationModelSelection: vi.fn(async () => null),
        selectProjectOrganizationModel: vi.fn(), clearProjectOrganizationModelSelection: vi.fn(async () => {}),
        ...overrides,
    };
    const host = document.createElement("div");
    document.body.append(host);
    const onError = vi.fn(() => "uncaught resource error");
    dispose = render(() => createComponent(ErrorBoundary, {
        fallback: onError,
        get children() {
            return createComponent(ProjectModelAccessContent, { api, project: "project", projectName: "Project" });
        },
    }), host);
    return { host, api, onError };
}

it.each([new TypeError("Failed to fetch"), new Error("403 Forbidden")])(
    "renders unavailable safely when organization options reject: %s", async (error) => {
        const { host, onError } = mount({ projectOrganizationModelOptions: async () => { throw error; } });
        await vi.waitFor(() => expect(host.textContent).toContain("Organization model access is unavailable right now."));
        expect(onError).not.toHaveBeenCalled();
        expect(host.querySelector("[data-organization-model-picker]")).toBeNull();
        expect(host.querySelector("[data-project-credential-token]")).not.toBeNull();
    },
);

it("guards a rejected current organization selection too", async () => {
    const { host, onError } = mount({ projectOrganizationModelSelection: async () => { throw new Error("403 Forbidden"); } });
    await vi.waitFor(() => expect(host.textContent).toContain("Organization model access is unavailable right now."));
    expect(onError).not.toHaveBeenCalled();
    expect(host.querySelector("[data-organization-model-picker]")).toBeNull();
});

it("shows loading until both organization reads resolve, then offers the admitted defaults", async () => {
    let resolveOptions!: (value: ProjectOrganizationModelOptions) => void;
    let resolveSelection!: (value: null) => void;
    const { host, api, onError } = mount({
        projectOrganizationModelOptions: () => new Promise((resolve) => { resolveOptions = resolve; }),
        projectOrganizationModelSelection: () => new Promise((resolve) => { resolveSelection = resolve; }),
    });
    expect(host.textContent).toContain("Loading organization model access…");
    expect(host.textContent).not.toContain("No organization connection is available");
    expect(host.querySelector("[data-organization-model-picker]")).toBeNull();
    resolveOptions(options);
    await Promise.resolve();
    expect(host.textContent).toContain("Loading organization model access…");
    expect(host.querySelector("[data-organization-model-picker]")).toBeNull();
    resolveSelection(null);
    await vi.waitFor(() => expect(host.querySelector("[data-organization-model-picker]")).not.toBeNull());
    expect(host.querySelector<HTMLSelectElement>('[aria-label="organization connection"]')!.value).toBe("connection");
    expect(host.querySelector<HTMLSelectElement>('[aria-label="organization model"]')!.value).toBe("model-b");
    const use = Array.from(host.querySelectorAll("button")).find((button) => button.textContent?.trim() === "Use")!;
    use.click();
    expect(api.selectProjectOrganizationModel).not.toHaveBeenCalled();
    expect(host.textContent).toContain("confirm that Office broker may receive model input and output");
    expect(onError).not.toHaveBeenCalled();
});

it("distinguishes a successful empty response from an unavailable service", async () => {
    const { host, onError } = mount({ projectOrganizationModelOptions: async () => ({ ...options, options: [] }) });
    await vi.waitFor(() => expect(host.textContent).toContain("No organization connection is available to this project."));
    expect(host.textContent).not.toContain("unavailable");
    expect(onError).not.toHaveBeenCalled();
});
