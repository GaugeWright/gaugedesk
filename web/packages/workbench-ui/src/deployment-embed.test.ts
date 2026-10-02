import { describe, expect, it } from "vitest";
import { deploymentEmbedHtml } from "./deployment-embed";

describe("a deployment's embed code", () => {
    it("loads the embed script and places each granted panel, as first publishing does", () => {
        expect(deploymentEmbedHtml("https://panels.example/d/survey", ["gw-files", "gw-chat"])).toBe(
            `<script type="module" src="https://embed.gaugewright.com/embed.js"></script>\n`
            + `<gw-session host="https://panels.example/d/survey" panels="chat,files">\n`
            + `  <gw-chat></gw-chat>\n  <gw-files></gw-files>\n`
            + `</gw-session>`,
        );
    });
});
