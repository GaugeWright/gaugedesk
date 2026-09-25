import { describe, expect, it } from "vitest";
import hljs from "highlight.js/lib/core";
import whipplescript from "./whipplescript-grammar";

hljs.registerLanguage("whipplescript", whipplescript);
const token = (role: string, value: string) => `<span class="hljs-${role}">${value}</span>`;

describe("WhippleScript highlighting", () => {
    it("colours declarations and safely escapes values", () => {
        const source = `workflow Triage
class Done { note string }
rule begin
  when started
=> { complete result { note "<safe>" } }
`;
        const html = hljs.highlight(source, { language: "whipplescript" }).value;
        expect(html).toContain(token("keyword", "workflow"));
        expect(html).toContain(token("title", "Triage"));
        expect(html).toContain(token("type", "string"));
        expect(html).toContain(token("string", "&quot;&lt;safe&gt;&quot;"));
        expect(html).toContain('hljs-operator');
        expect(html).not.toContain("<safe>");
    });

    it("keeps keywords inside comments, strings and longer identifiers plain", () => {
        const source = `# rule inside a comment
description """\nworkflow InsideString\n"""
rule-when ready
// complete in a comment
`;
        const html = hljs.highlight(source, { language: "whipplescript" }).value;
        expect(html).toContain(token("comment", "# rule inside a comment"));
        expect(html).toContain(token("string", "&quot;&quot;&quot;\nworkflow InsideString\n&quot;&quot;&quot;"));
        expect(html).not.toContain(`${token("keyword", "rule")}-when`);
        expect(html).toContain(token("comment", "// complete in a comment"));
    });

    it("colours the managed workflow constructs GaugeDesk opens", () => {
        const source = `@service
file store quarantine { root "./quarantine" allow read ["**"] }
tracker review
rule ingest
  when started
=> { read text from quarantine at "item.json" as raw }
`;
        const html = hljs.highlight(source, { language: "whipplescript" }).value;
        expect(html).toContain(token("meta", "@service"));
        expect(html).toContain(token("keyword", "store"));
        expect(html).toContain(token("title", "quarantine"));
        expect(html).toContain(token("keyword", "tracker"));
        expect(html).toContain(token("keyword", "read"));
    });
});
