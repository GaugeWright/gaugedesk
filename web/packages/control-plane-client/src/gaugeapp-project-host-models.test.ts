import { describe, expect, it } from "vitest";
import { parseProjectHostsModel } from "./gaugeapp-project-host-models";
import { parseProjectHostsPage } from "./gaugeapp-page-models";
import { emptyProjectHosts, managedProjectHosts } from "./gaugeapp-project-host-models.fixture";

const set = (root: unknown, path: (string | number)[], value: unknown) => {
    let target = root as Record<string | number, unknown>;
    for (const key of path.slice(0, -1)) target = target[key] as Record<string | number, unknown>;
    target[path[path.length - 1]] = value;
};

describe("Project Hosts read model", () => {
    it("preserves empty, local, registered, and managed inventory", () => {
        expect(parseProjectHostsModel(emptyProjectHosts)).toEqual(emptyProjectHosts);
        expect(parseProjectHostsModel(managedProjectHosts)).toEqual(managedProjectHosts);
        for (const kind of ["local", "registered"] as const) {
            const host = { id: "one", home_id: "home:one", name: "Workstation", kind, endpoint: "", lifecycle: "active", state: "live", repair_hint: null, projects: [{ id: "p1", name: "Research" }] };
            expect(parseProjectHostsModel({ ...emptyProjectHosts, homes: [host] }).homes).toEqual([host]);
        }
    });
    it("refuses each missing required populated field", () => {
        const visit = (value: unknown, path: (string | number)[] = []) => {
            if (!value || typeof value !== "object") return;
            for (const [key, child] of Object.entries(value)) {
                const part = Array.isArray(value) ? Number(key) : key;
                if (!Array.isArray(value)) {
                    const broken = structuredClone(managedProjectHosts);
                    let parent: unknown = broken;
                    for (const segment of path) parent = (parent as Record<string | number, unknown>)[segment];
                    delete (parent as Record<string | number, unknown>)[part];
                    expect(() => parseProjectHostsModel(broken), [...path, part].join(".")).toThrow(/incompatible/);
                }
                visit(child, [...path, part]);
            }
        };
        visit(managedProjectHosts);
    });
    it("never turns unavailable telemetry into zero usage or a fabricated count", () => {
        const model = structuredClone(managedProjectHosts);
        set(model, ["homes", 0, "execution", "freshness"], "unavailable");
        expect(() => parseProjectHostsModel(model)).toThrow(/execution/);
        set(model, ["homes", 0, "execution", "usage"], null);
        set(model, ["homes", 0, "execution", "queue"], null);
        set(model, ["homes", 0, "execution", "compute", "active_attempts"], null);
        expect(parseProjectHostsModel(model).homes[0].projects).toBeNull();
    });
    it("checks exact policy scope, service availability, unique identities and safe counters", () => {
        const page = { app: "administration", scope: { kind: "tenant", id: "tenant-a" }, id: "project-hosts", read_model: "ProjectHostsPageV1", version: 1, resource_basis: "basis", freshness: "registry-live", model: managedProjectHosts };
        expect(parseProjectHostsPage(page).model).toEqual(managedProjectHosts);
        expect(() => parseProjectHostsPage({ ...page, scope: { kind: "tenant", id: "tenant-b" } })).toThrow(/tenant_id/);
        expect(() => parseProjectHostsModel({ ...emptyProjectHosts, managed_enrollment: { ...emptyProjectHosts.managed_enrollment, region: null } })).toThrow(/managed_enrollment/);
        expect(() => parseProjectHostsModel({ ...managedProjectHosts, homes: [...managedProjectHosts.homes, ...managedProjectHosts.homes] })).toThrow(/homes/);
        const bad = structuredClone(managedProjectHosts);
        set(bad, ["homes", 0, "managed_policy", "max_attempt_nanos_usd"], Number.MAX_SAFE_INTEGER + 1);
        expect(() => parseProjectHostsModel(bad)).toThrow(/max_attempt/);
        const read = parseProjectHostsModel({ ...emptyProjectHosts, raw_credentials: "must-not-propagate" });
        expect(JSON.stringify(read)).not.toContain("must-not-propagate");
    });
});
