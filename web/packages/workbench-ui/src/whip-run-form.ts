/**
 * The Run form's value model (WHIP-3's Run control): a starting value for each
 * declared input type, and the one question the form answers before sending —
 * whether what the person typed is a value of that type. The launch validates
 * again; this only keeps an obviously wrong run from being sent.
 */
import type { WorkflowInputType } from "@gaugewright/control-plane-client";

/** A field's draft: what the person has typed, before it is a value. */
export type Draft =
    | { kind: "text"; text: string }
    | { kind: "bool"; value: boolean }
    | { kind: "choice"; value: string }
    | { kind: "fixed"; value: string }
    | { kind: "optional"; set: boolean; inner: Draft }
    | { kind: "object"; fields: Record<string, Draft> }
    | { kind: "person"; authority: string };

/** An input that names a person: an object whose only field is a string
 *  `authority`. The form offers a person rather than a field to type into. */
export function isPersonType(type: WorkflowInputType): boolean {
    return type.kind === "object"
        && type.fields.length === 1
        && type.fields[0].name === "authority"
        && type.fields[0].type.kind === "string";
}

/** A starting value for `type`. A person input starts as `me`, when known. */
export function initialDraft(type: WorkflowInputType, me?: string): Draft {
    if (isPersonType(type)) return { kind: "person", authority: me ?? "" };
    switch (type.kind) {
        case "bool": return { kind: "bool", value: false };
        case "enum": return { kind: "choice", value: type.variants[0] ?? "" };
        case "literal": return { kind: "fixed", value: type.value };
        case "optional": return { kind: "optional", set: false, inner: initialDraft(type.of, me) };
        case "object":
            return { kind: "object", fields: Object.fromEntries(type.fields.map((f) => [f.name, initialDraft(f.type)])) };
        default: return { kind: "text", text: "" };
    }
}

export type Parsed = { ok: true; value: unknown } | { ok: false; error: string };

/** Turn a draft into a value of `type`, or say which field is wrong. */
export function parseDraft(type: WorkflowInputType, draft: Draft, label: string): Parsed {
    if (draft.kind === "person") {
        if (!isPersonType(type)) return bad(label);
        return draft.authority.trim()
            ? { ok: true, value: { authority: draft.authority.trim() } }
            : { ok: false, error: `choose who ${label} is` };
    }
    switch (type.kind) {
        case "string":
            return draft.kind === "text" ? { ok: true, value: draft.text } : bad(label);
        case "int": {
            if (draft.kind !== "text") return bad(label);
            const text = draft.text.trim();
            return /^-?\d+$/.test(text) ? { ok: true, value: Number(text) } : { ok: false, error: `${label} must be a whole number` };
        }
        case "float": {
            if (draft.kind !== "text") return bad(label);
            const value = Number(draft.text.trim());
            return draft.text.trim() !== "" && Number.isFinite(value) ? { ok: true, value } : { ok: false, error: `${label} must be a number` };
        }
        case "bool":
            return draft.kind === "bool" ? { ok: true, value: draft.value } : bad(label);
        case "enum":
            return draft.kind === "choice" && type.variants.includes(draft.value) ? { ok: true, value: draft.value } : { ok: false, error: `choose a ${label}` };
        case "literal":
            return { ok: true, value: type.value };
        case "optional":
            if (draft.kind !== "optional") return bad(label);
            return draft.set ? parseDraft(type.of, draft.inner, label) : { ok: true, value: null };
        case "object": {
            if (draft.kind !== "object") return bad(label);
            const value: Record<string, unknown> = {};
            for (const field of type.fields) {
                const parsed = parseDraft(field.type, draft.fields[field.name] ?? initialDraft(field.type), `${label}.${field.name}`);
                if (!parsed.ok) return parsed;
                value[field.name] = parsed.value;
            }
            return { ok: true, value };
        }
        case "json": {
            if (draft.kind !== "text") return bad(label);
            try {
                return { ok: true, value: JSON.parse(draft.text) };
            } catch {
                return { ok: false, error: `${label} must be JSON` };
            }
        }
    }
}

function bad(label: string): Parsed {
    return { ok: false, error: `${label} has the wrong shape` };
}
