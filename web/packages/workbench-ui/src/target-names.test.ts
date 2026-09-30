import { describe, expect, it } from "vitest";
import { storedTargetPath, targetNameForRoot, targetRenames, type TargetName } from "./target-names";

const targets: TargetName[] = [
    { root: "targets/t-abc", name: "website" },
    { root: "targets/t-def", name: "web site docs" },
];

describe("target names (DR-0248)", () => {
    it("maps a path the agent wrote to the stored partition", () => {
        expect(storedTargetPath("website/src/main.rs", targets)).toBe("targets/t-abc/src/main.rs");
        expect(storedTargetPath("website", targets)).toBe("targets/t-abc");
        expect(storedTargetPath("web site docs/a.md", targets)).toBe("targets/t-def/a.md");
        // A prefix that is not a whole folder name is not a target.
        expect(storedTargetPath("websites/a", targets)).toBe("websites/a");
        expect(storedTargetPath("targets/t-abc/x", targets)).toBe("targets/t-abc/x");
    });

    it("names a partition, and never shows the encoded id", () => {
        expect(targetNameForRoot("t-abc", targets)).toBe("website");
        expect(targetNameForRoot("t-zzz", targets)).toBeNull();
    });

    it("reads each rename from the diff of a target's name file", () => {
        const diff = [
            "diff --git a/.gaugedesk-names/t-abc b/.gaugedesk-names/t-abc",
            "--- a/.gaugedesk-names/t-abc",
            "+++ b/.gaugedesk-names/t-abc",
            "@@ -1 +1 @@",
            "-Acme site files",
            "+website",
            "diff --git a/targets/t-abc/index.html b/targets/t-abc/index.html",
            "--- a/targets/t-abc/index.html",
            "+++ b/targets/t-abc/index.html",
            "@@ -1 +1 @@",
            "-old",
            "+new",
            "diff --git a/.gaugedesk-names/t-def b/.gaugedesk-names/t-def",
            "--- /dev/null",
            "+++ b/.gaugedesk-names/t-def",
            "@@ -0,0 +1 @@",
            "+docs",
        ].join("\n");
        expect(targetRenames(diff)).toEqual([
            { root: "targets/t-abc", from: "Acme site files", to: "website" },
            { root: "targets/t-def", from: "", to: "docs" },
        ]);
    });
});
