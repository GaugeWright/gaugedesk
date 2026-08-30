/** The carried TokenWright Environment bundle, as a view registry (ADR 0107).
 *
 * TokenWright owns these files; this repository carries a digest-pinned copy
 * because the box serves state and never markup. `contracts/tokenwright-environment-pin.json`
 * and `scripts/check-tokenwright-environment.mjs` are what stop the copy drifting.
 *
 * Nothing here is TokenWright-specific machinery. It is the data an add-on
 * system would supply: a manifest, some Views, some Help, and a validator per
 * schema id. The renderer that consumes it is the same one Administration uses.
 */

import {
    parseEnvironmentManifest,
    type EnvironmentManifest,
} from "./environment-view";
import type { EnvironmentViewRegistry } from "./EnvironmentDocumentView";

import manifestSource from "./tokenwright-files/manifest.json?raw";
import commandsSource from "./tokenwright-files/commands.json?raw";
import inferenceSchema from "./tokenwright-files/schemas/inference.v1.json?raw";
import postureSchema from "./tokenwright-files/schemas/posture.v1.json?raw";
import accessSchema from "./tokenwright-files/schemas/access.v1.json?raw";
import viewInference from "./tokenwright-files/views/inference.mdx?raw";
import viewPosture from "./tokenwright-files/views/posture.mdx?raw";
import viewAccess from "./tokenwright-files/views/access.mdx?raw";
import helpInference from "./tokenwright-files/help/inference.md?raw";
import helpPosture from "./tokenwright-files/help/posture.md?raw";
import helpAccess from "./tokenwright-files/help/access.md?raw";

export const TOKENWRIGHT_MANIFEST: EnvironmentManifest =
    parseEnvironmentManifest(JSON.parse(manifestSource));

export const TOKENWRIGHT_VIEW_SOURCES: Readonly<Record<string, string>> = {
    "views/inference.mdx": viewInference,
    "views/posture.mdx": viewPosture,
    "views/access.mdx": viewAccess,
};

export const TOKENWRIGHT_HELP_SOURCES: Readonly<Record<string, string>> = {
    "help/inference.md": helpInference,
    "help/posture.md": helpPosture,
    "help/access.md": helpAccess,
};

/** What the box advertises it can be told to do.
 *
 * Referencing a command here grants nothing: the session grant is authoritative
 * and a command absent from it renders as an inert "Unavailable in this
 * session" control. This is carried so the panel can label a control before the
 * grant arrives, not so it can decide anything. */
export interface TokenWrightCommandDeclaration {
    readonly id: string;
    readonly label: string;
    readonly effect: string;
    readonly idempotent: boolean;
    readonly refuses_when: string;
}

export const TOKENWRIGHT_COMMANDS: readonly TokenWrightCommandDeclaration[] =
    (JSON.parse(commandsSource) as { readonly commands: readonly TokenWrightCommandDeclaration[] }).commands;

const SCHEMA_SOURCES: readonly string[] = [inferenceSchema, postureSchema, accessSchema];

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** A validator per schema id, derived from the pinned schema's own `required`
 * list rather than written out again beside it.
 *
 * The weaker alternative — accept any object for every known id — cannot tell a
 * document from the box it was written for apart from one that is missing half
 * its blocks. That matters more here than elsewhere: a TokenWright box is
 * hardware someone else administers, and the design's stated fallback for a
 * document this GaugeDesk does not understand is a readable generic JSON
 * rendering. A View drawn confidently over a document it does not describe,
 * with "Unknown" where the fields should be, is the outcome that fallback
 * exists to prevent, and only a validator that actually looks will reach it. */
function validatorFor(source: string): readonly [string, (value: unknown) => boolean] {
    const schema = JSON.parse(source) as {
        readonly $id: string;
        readonly required?: readonly string[];
    };
    const required = schema.required ?? [];
    return [schema.$id, (value: unknown) => isRecord(value) && required.every((key) => key in value)];
}

export const TOKENWRIGHT_SCHEMAS: EnvironmentViewRegistry["schemas"] =
    Object.fromEntries(SCHEMA_SOURCES.map(validatorFor));

/** The registry a panel hands the shared renderer.
 *
 * `commands` is supplied by the caller from the *session grant*, never from
 * `TOKENWRIGHT_COMMANDS` — the manifest and this bundle describe presentation,
 * and authority comes only from authenticated discovery. */
export function tokenwrightViewRegistry(
    commands: EnvironmentViewRegistry["commands"],
): EnvironmentViewRegistry {
    return {
        manifest: TOKENWRIGHT_MANIFEST,
        views: TOKENWRIGHT_VIEW_SOURCES,
        schemas: TOKENWRIGHT_SCHEMAS,
        commands,
    };
}
