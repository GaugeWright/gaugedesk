/** WhippleScript's presentation grammar. The compiler remains the authority on
 * validity; this recognizes only enough source shape to colour a file safely. */
import type { LanguageFn } from "highlight.js";

const declarations = [
    "workflow", "class", "enum", "rule", "view", "pattern", "agent",
    "action", "harness", "signal", "gauge", "campaign", "mark",
    "region", "source", "test", "coerce", "assert", "measure",
    "store", "tracker",
];

const keywords = [
    "include", "use", "apply", "input", "output", "failure", "table",
    "when", "then", "given", "as", "is", "using", "with", "at",
    "every", "record", "emit", "complete", "fail", "case", "otherwise",
    "invoke", "await", "run", "return", "if", "where", "expect",
    "file", "read", "from", "after", "succeeds", "has", "ready",
    "claim", "done", "finish", "issue", "into", "endorsed", "allow",
];

const declaration = new RegExp(`\\b(?:${declarations.join("|")})(?![\\w-])`);

const whipplescript: LanguageFn = (hljs) => ({
    name: "WhippleScript",
    aliases: ["whip"],
    // Hyphens are part of WhippleScript identifiers, so a word such as
    // `when-ready` must not be coloured as the `when` keyword.
    keywords: {
        $pattern: String.raw`[A-Za-z_][\w-]*`,
        keyword: [...declarations, ...keywords],
        type: ["string", "int", "float", "bool"],
        literal: ["true", "false", "null"],
    },
    contains: [
        hljs.HASH_COMMENT_MODE,
        hljs.COMMENT(/\/\//, /$/),
        { scope: "meta", match: /@[A-Za-z_][\w-]*/ },
        { scope: "string", begin: /"""/, end: /"""/ },
        { scope: "string", begin: /"/, end: /"/, contains: [hljs.BACKSLASH_ESCAPE] },
        {
            match: [declaration, /\s+/, /[A-Za-z_][\w-]*/],
            scope: { 1: "keyword", 3: "title" },
        },
        { scope: "number", match: /\b\d+(?:\.\d+)?\b/ },
        { scope: "operator", match: /=>|->|==|!=|<=|>=|&&|\|\||[+*/<>=!]/ },
    ],
});

export default whipplescript;
