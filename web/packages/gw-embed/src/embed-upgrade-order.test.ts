import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

const elementsUrl = new URL("./elements.tsx", import.meta.url);

// The custom elements are DOM-bound and are exercised for real by
// gaugewright-cloud's public composition, which asserts the page raises no
// errors. This is the cheap local guard for the one property that composition
// caught: registration order.
describe("embed element registration order", () => {
    it("defines every panel before <gw-session>", async () => {
        const source = await readFile(elementsUrl, "utf8");
        const body = source.slice(source.indexOf("export function registerEmbedElements()"));
        const defined = [...body.matchAll(/customElements\.define\("([\w-]+)"/gu)]
            .map((match) => match[1]);

        expect(defined).toContain("gw-session");
        // Defining an element upgrades what the parser already built, and an
        // upgrade runs attributeChangedCallback synchronously. Registering the
        // session first therefore ran its `host` callback against children that
        // were still plain HTMLElements, and `panel.resetBinding()` threw on the
        // ordinary embed markup.
        expect(defined.at(-1)).toBe("gw-session");
        expect(defined.slice(0, -1).sort()).toEqual([
            "gw-chat",
            "gw-chats",
            "gw-files",
            "gw-viewer",
        ]);
    });
});
