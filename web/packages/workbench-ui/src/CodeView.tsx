/**
 * Syntax highlighting for the View tab.
 *
 * This is the one place in the viewer where shipping a library is the right
 * call rather than the lazy one. Highlighting has no platform equivalent to
 * lean on — no engine will colour a `.rs` file for us — and reading code
 * without it is the difference between a document and a wall.
 *
 * Cost is controlled two ways. The grammars are registered explicitly instead
 * of taking highlight.js's default bundle, which carries nearly two hundred
 * languages for the handful a worktree actually holds; and the whole module is
 * reached through `lazy()`, so nothing here is fetched until someone opens a
 * file we have a language for.
 *
 * Highlighting is presentation only. It never changes a byte, and the Edit tab
 * still shows the file exactly as it is on disk.
 */

import { createMemo } from "solid-js";
import hljs from "highlight.js/lib/core";

import bash from "highlight.js/lib/languages/bash";
import c from "highlight.js/lib/languages/c";
import cpp from "highlight.js/lib/languages/cpp";
import csharp from "highlight.js/lib/languages/csharp";
import css from "highlight.js/lib/languages/css";
import d from "highlight.js/lib/languages/d";
import dart from "highlight.js/lib/languages/dart";
import diff from "highlight.js/lib/languages/diff";
import dockerfile from "highlight.js/lib/languages/dockerfile";
import elixir from "highlight.js/lib/languages/elixir";
import go from "highlight.js/lib/languages/go";
import graphql from "highlight.js/lib/languages/graphql";
import groovy from "highlight.js/lib/languages/groovy";
import haskell from "highlight.js/lib/languages/haskell";
import ini from "highlight.js/lib/languages/ini";
import java from "highlight.js/lib/languages/java";
import javascript from "highlight.js/lib/languages/javascript";
import json from "highlight.js/lib/languages/json";
import kotlin from "highlight.js/lib/languages/kotlin";
import less from "highlight.js/lib/languages/less";
import lua from "highlight.js/lib/languages/lua";
import makefile from "highlight.js/lib/languages/makefile";
import objectivec from "highlight.js/lib/languages/objectivec";
import perl from "highlight.js/lib/languages/perl";
import php from "highlight.js/lib/languages/php";
import powershell from "highlight.js/lib/languages/powershell";
import python from "highlight.js/lib/languages/python";
import r from "highlight.js/lib/languages/r";
import ruby from "highlight.js/lib/languages/ruby";
import rust from "highlight.js/lib/languages/rust";
import scala from "highlight.js/lib/languages/scala";
import scss from "highlight.js/lib/languages/scss";
import sql from "highlight.js/lib/languages/sql";
import swift from "highlight.js/lib/languages/swift";
import typescript from "highlight.js/lib/languages/typescript";
import xml from "highlight.js/lib/languages/xml";
import yaml from "highlight.js/lib/languages/yaml";

/** Every grammar `syntaxLanguageFor` can name. A language missing here would
 *  leave its files plain rather than break them, which is why that map and
 *  this one are allowed to be edited independently. */
const GRAMMARS: Readonly<Record<string, Parameters<typeof hljs.registerLanguage>[1]>> = {
    bash, c, cpp, csharp, css, d, dart, diff, dockerfile, elixir, go, graphql,
    groovy, haskell, ini, java, javascript, json, kotlin, less, lua, makefile,
    objectivec, perl, php, powershell, python, r, ruby, rust, scala, scss, sql,
    swift, typescript, xml, yaml,
};

for (const [name, grammar] of Object.entries(GRAMMARS)) hljs.registerLanguage(name, grammar);

/** Past this, highlighting costs more than it returns. A generated bundle or a
 *  vendored blob can run to megabytes, and the highlighter walks the whole
 *  string synchronously — the pane would stall on a file nobody reads line by
 *  line anyway. Such a file still renders, just plainly. */
const MAX_HIGHLIGHTED_CHARACTERS = 400_000;

export function CodeView(props: { readonly text: string; readonly language: string }) {
    const html = createMemo(() => {
        if (props.text.length > MAX_HIGHLIGHTED_CHARACTERS) return null;
        if (!hljs.getLanguage(props.language)) return null;
        try {
            return hljs.highlight(props.text, {
                language: props.language,
                ignoreIllegals: true,
            }).value;
        } catch {
            // A grammar that throws on a file is a highlighting failure, not a
            // reading failure: fall back to the text rather than to an error.
            return null;
        }
    });
    return (
        <pre class="filebody" data-file-view data-file-language={props.language}>
            {/* innerHTML is safe by construction: highlight.js escapes the
                source it is given and emits only its own `<span>` markup. */}
            <code class="hljs" innerHTML={html() ?? undefined}>
                {html() === null ? props.text : undefined}
            </code>
        </pre>
    );
}
