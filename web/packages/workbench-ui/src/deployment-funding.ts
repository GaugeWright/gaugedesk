/**
 * Who pays for a public deployment's turns (ADR 0085 §1/§6, `FUND-1`).
 *
 * Two mutually exclusive sources, and the exclusivity is the whole point:
 *
 * - **managed** — GaugeWright's metered Cloudflare AI Gateway. No provider key
 *   belongs to the deployment; the owner is billed from measured usage plus
 *   margin. `credential_ref` is **empty**, and its emptiness is what the edge and
 *   the runtime read as "managed" — see `resolveAdmittedProvider`.
 * - **byok** — the owner's own provider credential, which their provider bills
 *   directly. `funding_ref` equals `credential_ref`.
 *
 * Naming both is refused rather than reconciled. The ambiguity is about who
 * pays, and resolving it quietly downstream is how a turn gets billed to the
 * wrong party.
 *
 * Pure functions, kept out of the panel so the rules survive a UI rewrite.
 */

export type FundingMode = "managed" | "byok";

export interface FundingDraft {
    readonly mode: FundingMode;
    /** The managed plan reference this Home is entitled to, "" when none. */
    readonly managedPlanRef: string;
    /** The selected owner credential, "" when none. */
    readonly credentialRef: string;
    readonly credentialClass: string;
}

export interface FundingFields {
    readonly funding_ref: string;
    readonly credential_ref: string;
    readonly credential_class: string;
}

/** A managed plan reference, as GaugeDesk's `managed_inference::funding_ref`
 *  mints it and the edge's `isManagedFunding` recognises it. Duplicated across
 *  three languages now; `managed_inference::cross_language_prefix` is the test
 *  that catches drift. */
export const MANAGED_PLAN_PREFIX = "gaugedesk:managed-plan:v1:";

export function isManagedPlanRef(reference: string): boolean {
    return reference.startsWith(MANAGED_PLAN_PREFIX);
}

/** Select a runtime-discovered entitlement only while it is actually usable. */
export function managedPlanRefFromBilling(billing: {
    readonly plan: { readonly status: string } | null;
    readonly funding_ref: string | null;
}): string {
    return billing.plan?.status === "active" && billing.funding_ref
        && isManagedPlanRef(billing.funding_ref)
        ? billing.funding_ref
        : "";
}

/** The funding fields to publish, or null when the draft is not yet publishable. */
export function fundingFieldsFrom(draft: FundingDraft): FundingFields | null {
    if (draft.mode === "managed") {
        if (!isManagedPlanRef(draft.managedPlanRef)) return null;
        return {
            funding_ref: draft.managedPlanRef,
            // Empty by design, not by omission: this is the signal.
            credential_ref: "",
            credential_class: draft.credentialClass,
        };
    }
    const credential = draft.credentialRef.trim();
    if (!credential || isManagedPlanRef(credential)) return null;
    return {
        // BYOK funding *is* the credential — the edge refuses any other pairing.
        funding_ref: credential,
        credential_ref: credential,
        credential_class: draft.credentialClass,
    };
}

/** Why this deployment cannot publish yet, in the owner's terms. "" when it can. */
export function fundingBlockerFor(draft: FundingDraft): string {
    if (draft.mode === "managed") {
        if (!isManagedPlanRef(draft.managedPlanRef)) {
            return "This Home has no managed plan, so metered billing is unavailable. "
                + "Choose your own provider key instead.";
        }
        return "";
    }
    if (!draft.credentialRef.trim()) {
        return "Choose or add a provider key, or switch to metered billing.";
    }
    if (isManagedPlanRef(draft.credentialRef)) {
        return "That is a billing plan, not a provider key.";
    }
    if (!draft.credentialClass.trim()) {
        return "The provider key has no class, so admission cannot match it to the release.";
    }
    return "";
}
