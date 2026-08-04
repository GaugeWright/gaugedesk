import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

const implementationUrl = new URL("./elements.tsx", import.meta.url);
const editableThemeUrl = new URL("../public/embed.css", import.meta.url);

describe("editable embed theme", () => {
    it("publishes every public component default without minification or drift", async () => {
        const [implementation, editableTheme] = await Promise.all([
            readFile(implementationUrl, "utf8"),
            readFile(editableThemeUrl, "utf8"),
        ]);
        const publicAliases = new Map(
            [...implementation.matchAll(
                /^\s+(--[\w-]+):\s+var\((--gw-[\w-]+),/gmu,
            )].map((match) => [match[1], match[2]]),
        );
        const publicDefaults = [...implementation.matchAll(
            /^\s+[\w-]+:\s+var\((--gw-[\w-]+),\s+(.+)\)(?:\s*!important)?;$/gmu,
        )]
            .map((match) => ({
                property: match[1],
                value: match[2].replace(
                    /var\((--[\w-]+)\)/gu,
                    (_reference: string, property: string) =>
                        `var(${publicAliases.get(property) ?? property})`,
                ),
            }))
            .filter(({ value }) => !value.includes("${defaultMinHeight}"));

        expect(publicDefaults.length).toBeGreaterThan(20);
        for (const { property, value } of publicDefaults) {
            expect(editableTheme).toContain(`${property}: ${value};`);
        }

        expect(editableTheme).toContain("GaugeDesk Embeddable Panels — optional editable theme");
        expect(editableTheme).toContain("gw-chat {\n  --gw-panel-min-height: 520px;");
        expect(editableTheme).toContain("gw-viewer {\n  --gw-panel-min-height: 320px;");
        expect(editableTheme).toContain("gw-files,\ngw-chats {\n  --gw-panel-min-height: 280px;");
        expect(editableTheme.split("\n").length).toBeGreaterThan(70);
    });
});
