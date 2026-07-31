import { describe, expect, it } from "vitest";
import {
    EnvironmentViewError,
    manifestDocumentForPath,
    parseEnvironmentManifest,
    parseEnvironmentView,
    resolveDocumentPath,
} from "./environment-view";

describe("Environment document Views", () => {
    it("parses stable manifest bindings without deriving type from a suffix", () => {
        const manifest = parseEnvironmentManifest({
            version: 1,
            documents: [{
                id: "administration.machines",
                path: "machines.json",
                schema: "gw://schemas/machines/v1",
                view: "views/machines.mdx",
                help: "help/machines.md",
            }],
        });
        expect(manifestDocumentForPath(manifest, "machines.json")?.id).toBe("administration.machines");
        expect(manifestDocumentForPath(manifest, "machines.admin.json")).toBeUndefined();
    });

    it("rejects duplicate, unsafe, and incomplete manifest entries", () => {
        expect(() => parseEnvironmentManifest({ version: 1, documents: [
            { id: "a", path: "a.json", schema: "a" },
            { id: "a", path: "b.json", schema: "b" },
        ] })).toThrow(EnvironmentViewError);
        expect(() => parseEnvironmentManifest({ version: 1, documents: [
            { id: "a", path: "../a.json", schema: "a" },
        ] })).toThrow(EnvironmentViewError);
        expect(() => parseEnvironmentManifest({ version: 1, documents: [
            { id: "a", path: "a.json" },
        ] })).toThrow(EnvironmentViewError);
    });

    it("parses only literal allowlisted constrained MDX", () => {
        const nodes = parseEnvironmentView(
            "# Machines\n<Grid columns=\"2\"><Metric label=\"Live\" value=\"live\" /></Grid>",
            new Set(["Grid", "Metric"]),
        );
        expect(nodes).toHaveLength(2);
        expect(nodes[1]).toMatchObject({ kind: "element", name: "Grid" });
        expect(() => parseEnvironmentView("import X from 'x'\n<X />", new Set(["X"]))).toThrow();
        expect(() => parseEnvironmentView("<script>bad</script>", new Set())).toThrow();
        expect(() => parseEnvironmentView("<Metric value={secret} />", new Set(["Metric"]))).toThrow();
        expect(() => parseEnvironmentView("<Unknown />", new Set(["Metric"]))).toThrow();
    });

    it("resolves declarative data paths without evaluating expressions", () => {
        const value = { machines: [{ status: "live" }] };
        expect(resolveDocumentPath(value, "machines.0.status")).toBe("live");
        expect(resolveDocumentPath(value, "machines.constructor")).toBeUndefined();
    });
});
