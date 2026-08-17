import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

// @ts-expect-error — a plain .mjs tool, deliberately not part of the TS project.
import { renderEmbedTheme, parseChain } from "../../../scripts/render-embed-theme.mjs";

const editableThemeUrl = new URL("../public/embed.css", import.meta.url);
const tokensUrl = new URL("../../workbench-ui/src/brand-tokens.css", import.meta.url);
const bridgeUrl = new URL("./elements.tsx", import.meta.url);

describe("editable embed theme", () => {
    it("is exactly what the panel defaults render to", async () => {
        // The renderer is the single implementation of "these agree". The check
        // this replaced re-derived the relationship with its own regex, so it
        // could — and did — pass while both sides carried a superseded palette:
        // they were consistent with each other and with nothing else.
        const published = await readFile(editableThemeUrl, "utf8");
        expect(published).toBe(renderEmbedTheme());
    });

    it("publishes resolved values, never a var() chain a customer cannot read", async () => {
        const published = await readFile(editableThemeUrl, "utf8");
        expect(published).not.toContain("--gw-default-");
        // One var() is legitimate: --gw-panel-border is defined in terms of the
        // customer's own --gw-edge, which is the behaviour they want.
        const references = [...published.matchAll(/var\((--[\w-]+)/gu)].map((match) => match[1]);
        expect(references).toEqual(["--gw-edge"]);
    });

    it("carries no brand value the vendored tokens do not own", async () => {
        const [published, tokens] = await Promise.all([
            readFile(editableThemeUrl, "utf8"),
            readFile(tokensUrl, "utf8"),
        ]);
        const owned = new Set(
            [...tokens.matchAll(/:\s*(#[0-9a-fA-F]{3,8})\s*;/gu)].map((m) => m[1].toLowerCase()),
        );
        const gwSession = published.slice(published.indexOf("gw-session {"));
        for (const [, hex] of gwSession.matchAll(/(#[0-9a-fA-F]{3,8})\b/gu)) {
            expect(owned, `${hex} is published but is not a vendored brand token`).toContain(
                hex.toLowerCase(),
            );
        }
    });

    it("keeps the renamed tokens working for a customer on an older copy", async () => {
        const bridge = await readFile(bridgeUrl, "utf8");
        // A customer who vendored embed.css before the rename set these names.
        // Dropping one silently reverts their panel to the default colour.
        for (const legacy of [
            "--gw-brand-navy",
            "--gw-accent-contrast",
            "--gw-bad",
            "--gw-font",
            "--gw-serif",
            "--gw-prose",
            "--gw-mono",
        ]) {
            expect(bridge, `${legacy} must stay accepted`).toContain(`var(${legacy},`);
        }
    });

    it("keeps the prose a person wrote", async () => {
        const published = await readFile(editableThemeUrl, "utf8");
        expect(published).toContain("GaugeDesk Embeddable Panels — optional editable theme");
        expect(published).toContain(
            "gw-chat {\n  --gw-panel-height: min(640px, 85vh);\n  --gw-panel-min-height: 520px;",
        );
        expect(published).toContain(
            "gw-viewer {\n  --gw-panel-height: auto;\n  --gw-panel-min-height: 320px;",
        );
        expect(published).toContain(
            "gw-files,\ngw-chats {\n  --gw-panel-height: auto;\n  --gw-panel-min-height: 280px;",
        );
    });
});

describe("the var() chain reader", () => {
    it("takes the whole fallback when it has commas of its own", () => {
        // The shadow token defaults to a value containing rgb(…); splitting on
        // the last comma takes the wrong half.
        expect(parseChain("var(--gw-panel-shadow, 0 14px 36px rgb(0 0 0 / 22%))")).toEqual({
            names: ["--gw-panel-shadow"],
            literal: "0 14px 36px rgb(0 0 0 / 22%)",
        });
    });

    it("walks a chain of renamed tokens down to the vendored default", () => {
        expect(parseChain("var(--gw-danger, var(--gw-bad, var(--gw-default-danger)))")).toEqual({
            names: ["--gw-danger", "--gw-bad", "--gw-default-danger"],
            literal: null,
        });
    });

    it("reads a font stack as one literal", () => {
        expect(parseChain('var(--gw-x, "A", B, serif)')).toEqual({
            names: ["--gw-x"],
            literal: '"A", B, serif',
        });
    });
});
