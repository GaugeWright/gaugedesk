import type { HubSessionStatus } from "@gaugewright/control-plane-client";
import type { MenuIdentity } from "@gaugewright/workbench-ui";

/** A Home admission is never a replacement for the composition's account authority. */
export function accountMenuIdentity(
    admitted: MenuIdentity | null | undefined,
    hasAccountAuthority: boolean,
    native: Pick<HubSessionStatus, "linked" | "expired" | "label" | "person"> | null | undefined,
    homeActor: string | null,
    localAccount = false,
): MenuIdentity | null {
    if (localAccount) return { name: "Local account" };
    if (admitted && !admitted.pending) return admitted;
    // The desktop's own sign-in carries a label (normally the email) from the
    // moment it opens; it names the account until the hosted profile does.
    // A record sealed before labels existed reports its account id as its
    // label, and an id is not a name.
    const nativeLabel = native?.linked === true && !native.expired && native.label !== native.person
        ? native.label
        : null;
    const person = nativeLabel ?? (hasAccountAuthority ? null : homeActor);
    if (!person) return admitted ?? null;
    const at = person.indexOf("@");
    return at > 0 ? { name: person.slice(0, at), email: person } : { name: person };
}
