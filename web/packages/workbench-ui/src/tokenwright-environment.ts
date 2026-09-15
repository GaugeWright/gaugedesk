/**
 * Pinned TokenWright metadata used by GaugeDesk's purpose-built controls.
 *
 * TokenWright owns the document schemas and command declarations. GaugeDesk
 * carries only those protocol facts; it does not carry or interpret the old
 * Environment manifest, MDX Views, or Help-as-files presentation bundle.
 * Authority still comes exclusively from the current TokenWright session.
 */

import commandsSource from "./tokenwright-files/commands.json?raw";
import inferenceSchema from "./tokenwright-files/schemas/inference.v1.json?raw";
import postureSchema from "./tokenwright-files/schemas/posture.v1.json?raw";
import accessSchema from "./tokenwright-files/schemas/access.v1.json?raw";

export interface TokenWrightCommandDeclaration {
    readonly id: string;
    readonly label: string;
    readonly effect: string;
    readonly idempotent: boolean;
    readonly refuses_when: string;
}

export interface TokenWrightDocumentDeclaration {
    readonly id: string;
    readonly schema: string;
}

export type TokenWrightDocumentValidator = (value: unknown) => boolean;

export const TOKENWRIGHT_COMMANDS: readonly TokenWrightCommandDeclaration[] =
    (JSON.parse(commandsSource) as { readonly commands: readonly TokenWrightCommandDeclaration[] }).commands;

const SCHEMA_SOURCES: readonly string[] = [inferenceSchema, postureSchema, accessSchema];

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

function schemaEntry(source: string): readonly [TokenWrightDocumentDeclaration, TokenWrightDocumentValidator] {
    const schema = JSON.parse(source) as {
        readonly $id: string;
        readonly required?: readonly string[];
    };
    const segments = schema.$id?.replace(/\/$/u, "").split("/") ?? [];
    const document = segments.at(-2);
    if (!schema.$id || !document) throw new Error("TokenWright schema has no document identity.");
    const required = schema.required ?? [];
    return [
        { id: `tokenwright.${document}`, schema: schema.$id },
        (value: unknown) => isRecord(value) && required.every((key) => key in value),
    ];
}

const SCHEMA_ENTRIES = SCHEMA_SOURCES.map(schemaEntry);

/** The exact documents for which GaugeDesk has native controls. */
export const TOKENWRIGHT_DOCUMENTS: readonly TokenWrightDocumentDeclaration[] =
    SCHEMA_ENTRIES.map(([document]) => document);

/** Closed validators for the server documents consumed by those controls. */
export const TOKENWRIGHT_SCHEMAS: Readonly<Record<string, TokenWrightDocumentValidator>> =
    Object.fromEntries(SCHEMA_ENTRIES.map(([document, validate]) => [document.schema, validate]));
