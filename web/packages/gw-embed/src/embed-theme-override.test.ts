import { describe, expect, it } from "vitest";

import { readFileSync } from "node:fs";

const bridge = readFileSync(new URL("./elements.tsx", import.meta.url), "utf8");
const hostBlock = bridge.slice(bridge.indexOf(":host {"), bridge.indexOf("\n}", bridge.indexOf(":host {")));

/// Resolve one `var()` chain the way a browser would, given what the page set.
///
/// The reason this is worth simulating rather than trusting: the whole design
/// turns on a shadow root being able to carry a *default* without declaring the
/// public token. If `:host` declared `--gw-bg` outright it would beat the value
/// a host page inherits in, and every customer's theme would silently stop
/// working — a regression no colour comparison would catch, because the panel
/// would look perfectly correct until someone tried to change it.
function resolve(chain: string, set: Record<string, string>): string {
    const match = /^var\((--[\w-]+)(?:,\s*([\s\S]+))?\)$/u.exec(chain.trim());
    if (!match) return chain.trim();
    const [, name, fallback] = match;
    if (set[name] !== undefined) return set[name];
    if (fallback === undefined) return "";
    return resolve(fallback, set);
}

function chainFor(internal: string): string {
    const found = new RegExp(`^\\s*${internal}:\\s*(var\\([\\s\\S]*?\\));$`, "mu").exec(hostBlock);
    if (!found) throw new Error(`the bridge does not declare ${internal}`);
    return found[1];
}

// What brand-tokens.css actually puts on :host. Read rather than restated —
// writing the values here would make this file the very thing it is testing the
// absence of, and it would need editing every time the palette is tuned.
const tokens = readFileSync(new URL("../../workbench-ui/src/brand-tokens.css", import.meta.url), "utf8");
const VENDORED: Record<string, string> = Object.fromEntries(
    [...tokens.matchAll(/^\s*(--gw-default-[\w-]+):\s*([^;]+);/gmu)].map((m) => [m[1], m[2].trim()]),
);

describe("host page theming", () => {
    it("falls back to the company palette when the page sets nothing", () => {
        expect(resolve(chainFor("--bg"), VENDORED)).toBe(VENDORED["--gw-default-bg"]);
        expect(resolve(chainFor("--panel"), VENDORED)).toBe(VENDORED["--gw-default-panel"]);
        // Not a placeholder: a chain that resolved to nothing would also satisfy
        // an equality against an undefined lookup.
        expect(VENDORED["--gw-default-bg"]).toMatch(/^#[0-9a-f]{6}$/u);
    });

    it("lets a host page override a token", () => {
        expect(resolve(chainFor("--bg"), { ...VENDORED, "--gw-bg": "#ffeedd" })).toBe("#ffeedd");
    });

    it("still honours a legacy name a customer set before the rename", () => {
        expect(resolve(chainFor("--bad"), { ...VENDORED, "--gw-bad": "#c0ffee" })).toBe("#c0ffee");
    });

    it("prefers the current name when a page sets both", () => {
        const set = { ...VENDORED, "--gw-bad": "#c0ffee", "--gw-danger": "#decaf0" };
        expect(resolve(chainFor("--bad"), set)).toBe("#decaf0");
    });

    it("resolves the three-deep font chain in the documented order", () => {
        const chain = chainFor("--font-chrome");
        expect(resolve(chain, VENDORED)).toBe(VENDORED["--gw-default-font-chrome"]);
        expect(resolve(chain, { ...VENDORED, "--gw-serif": "Old" })).toBe("Old");
        expect(resolve(chain, { ...VENDORED, "--gw-serif": "Old", "--gw-font": "Mid" })).toBe("Mid");
        expect(
            resolve(chain, { ...VENDORED, "--gw-serif": "Old", "--gw-font": "Mid", "--gw-font-chrome": "New" }),
        ).toBe("New");
    });

    it("keeps an independently customized legacy serif on the serif alias", () => {
        // Both former names are present in a vendored embed.css, so a customer
        // may have changed only --gw-serif. The chrome alias prefers --gw-font;
        // the serif alias must not, or their serif silently disappears.
        const chain = chainFor("--serif");
        const both = { ...VENDORED, "--gw-serif": "Old", "--gw-font": "Mid" };
        expect(resolve(chain, both)).toBe("Old");
        expect(resolve(chainFor("--font-chrome"), both)).toBe("Mid");
        expect(resolve(chain, { ...both, "--gw-font-chrome": "New" })).toBe("New");
        expect(resolve(chain, VENDORED)).toBe(VENDORED["--gw-default-font-chrome"]);
        expect(resolve(chain, { ...VENDORED, "--gw-font": "Mid" })).toBe("Mid");
    });

    it("declares no public --gw- token on :host, which would shadow a host page's", () => {
        // A declaration like `--gw-bg: …;` here would win over the inherited
        // value and make the panel untunable. Only internal aliases may be
        // declared; the public names appear solely inside var().
        const declared = [...hostBlock.matchAll(/^\s*(--[\w-]+):/gmu)].map((match) => match[1]);
        expect(declared.filter((name) => name.startsWith("--gw-"))).toEqual([]);
        expect(declared.length).toBeGreaterThan(15);
    });
});
