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
    if (admitted) return admitted;
    const nativePerson = native?.linked === true && !native.expired ? native.label ?? native.person : null;
    const person = nativePerson ?? (hasAccountAuthority ? null : homeActor);
    if (!person) return null;
    const at = person.indexOf("@");
    return at > 0 ? { name: person.slice(0, at), email: person } : { name: person };
}
