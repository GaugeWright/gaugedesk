import { describe, expect, it } from "vitest";
import {
    clearProjectOrganizationModelSelection,
    parseProjectOrganizationModelOptions,
    parseProjectOrganizationModelSelection,
    projectOrganizationModelOptions,
    projectOrganizationModelSelection,
    selectProjectOrganizationModel,
} from "./project-organization-models";

const reply = () => ({
    v: 2,
    binding: { authority: "authority:model", organization: "organization:acme", environment: "test" },
    actor: "authority:member",
    project: { authority: "authority:home", id: "project:one" },
    home: "home:one",
    resource_basis: `organization-model-eligibility:v2:${"a".repeat(64)}`,
    options: [{
        connection: "connection:shared",
        name: "Acme models",
        provider: "openai",
        models: ["gpt-5", "gpt-5-mini"],
        organization_default: "gpt-5",
        private_broker: {
            authority: "authority:model-broker",
            name: "GaugeWright model broker",
            operator: "GaugeWright",
        },
    }],
});

const selectionReply = () => ({
    selection: {
        binding: reply().binding,
        project: reply().project,
        home: "home:one",
        connection: "connection:shared",
        model: "gpt-5",
        provider: "openai",
        private_broker: reply().options[0].private_broker,
        resource_basis: reply().resource_basis,
        selected_by: "authority:member",
    },
});

describe("project organization model selection", () => {
    it("reads, writes, and clears only the project Home reference", async () => {
        const calls: unknown[][] = [];
        const json = async (...args: unknown[]) => {
            calls.push(args);
            return args[0] === "DELETE" ? { selection: null } : selectionReply();
        };
        expect((await projectOrganizationModelSelection(json, "project:one"))?.model).toBe("gpt-5");
        const selected = await selectProjectOrganizationModel(json, "project:one", {
            binding: {
                authority: "authority:model",
                organization: "organization:acme",
                environment: "test",
            },
            connection: "connection:shared",
            model: "gpt-5",
            privateBroker: "authority:model-broker",
            admitPrivatePlaintext: true,
        });
        expect(selected.connection).toBe("connection:shared");
        await clearProjectOrganizationModelSelection(json, "project:one");
        expect(calls).toEqual([
            ["GET", "/projects/project%3Aone/organization-model-selection"],
            ["PUT", "/projects/project%3Aone/organization-model-selection", {
                binding: {
                    authority: "authority:model",
                    organization: "organization:acme",
                    environment: "test",
                },
                connection: "connection:shared",
                model: "gpt-5",
                private_broker: "authority:model-broker",
                admit_private_plaintext: true,
            }],
            ["DELETE", "/projects/project%3Aone/organization-model-selection"],
        ]);
    });

    it("rejects unknown fields, another project, and an incompatible basis", () => {
        const unknown = selectionReply() as ReturnType<typeof selectionReply> & { secret?: string };
        unknown.secret = "no";
        expect(() => parseProjectOrganizationModelSelection(unknown, "project:one")).toThrow(/malformed/);
        const other = selectionReply();
        other.selection.project.id = "project:other";
        expect(() => parseProjectOrganizationModelSelection(other, "project:one")).toThrow(/different project/);
        const old = selectionReply();
        old.selection.resource_basis = "old";
        expect(() => parseProjectOrganizationModelSelection(old, "project:one")).toThrow(/incompatible/);
    });
});

describe("project organization model options", () => {
    it("calls the path-bound route and maps the closed wire model", async () => {
        const calls: unknown[][] = [];
        const result = await projectOrganizationModelOptions(async (...args) => {
            calls.push(args);
            return reply();
        }, "project:one");
        expect(calls).toEqual([["GET", "/projects/project%3Aone/organization-model-options"]]);
        expect(result.options).toEqual([{
            connection: "connection:shared",
            name: "Acme models",
            provider: "openai",
            models: ["gpt-5", "gpt-5-mini"],
            organizationDefault: "gpt-5",
            privateBroker: {
                authority: "authority:model-broker",
                name: "GaugeWright model broker",
                operator: "GaugeWright",
            },
        }]);
        expect(result.project.id).toBe("project:one");
    });

    it("rejects another project, unknown disclosure fields, duplicate choices, and bad defaults", () => {
        const wrong = reply();
        wrong.project.id = "project:other";
        expect(() => parseProjectOrganizationModelOptions(wrong, "project:one")).toThrow(/different project/);

        const disclosure = reply() as ReturnType<typeof reply> & { secret?: string };
        disclosure.secret = "must-not-pass";
        expect(() => parseProjectOrganizationModelOptions(disclosure, "project:one")).toThrow(/malformed/);

        const duplicate = reply();
        duplicate.options.push({ ...duplicate.options[0] });
        expect(() => parseProjectOrganizationModelOptions(duplicate, "project:one")).toThrow(/repeat a connection/);

        const unavailableDefault = reply();
        unavailableDefault.options[0].organization_default = "other-model";
        expect(() => parseProjectOrganizationModelOptions(unavailableDefault, "project:one")).toThrow(/default is unavailable/);
    });
});
