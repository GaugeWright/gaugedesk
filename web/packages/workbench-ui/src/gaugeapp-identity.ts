import type { GaugeAppPageModel, GaugeAppSession } from "@gaugewright/control-plane-client";
import type { MenuIdentity } from "./AccountMenu";

function record(value: unknown): Record<string, unknown> | null {
    return value !== null && typeof value === "object" && !Array.isArray(value)
        ? value as Record<string, unknown>
        : null;
}

function text(value: unknown): string | undefined {
    return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

/** The account authority names the person. A Home login is neither required
 * nor a fallback when a GaugeApp composition supplies account identity. */
export function gaugeAppMenuIdentity(
    session: GaugeAppSession | undefined,
    page: GaugeAppPageModel | undefined,
): MenuIdentity | null {
    if (!session || session.app !== "account-settings" || session.scope.kind !== "person"
        || session.scope.id !== session.actor) return null;
    const model = page?.app === session.app && page.scope.kind === "person" && page.scope.id === session.actor
        && page.id === "account" && page.read_model === "AccountSettingsPageV1" && page.version === 1 ? record(page.model) : null;
    const profile = record(model?.profile);
    // A resource may retain its previous value while another account loads.
    // Never borrow that account's name or verified address for the new actor.
    if (profile?.account_id !== session.actor) return { name: session.actor };
    const contacts = Array.isArray(model?.verified_contacts) ? model.verified_contacts : [];
    const email = contacts.map((contact) => text(record(contact)?.email)).find(Boolean);
    const name = text(profile.display_name) ?? email?.split("@")[0] ?? session.actor;
    return { name, ...(email ? { email } : {}) };
}
