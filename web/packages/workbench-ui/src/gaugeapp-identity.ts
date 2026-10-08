import type { AccountSettingsSummary, GaugeAppPageModel, GaugeAppSession } from "@gaugewright/control-plane-client";
import type { MenuIdentity } from "./AccountMenu";

function record(value: unknown): Record<string, unknown> | null {
    return value !== null && typeof value === "object" && !Array.isArray(value)
        ? value as Record<string, unknown>
        : null;
}

function text(value: unknown): string | undefined {
    return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

/** Shown for a signed-in account that nothing has named yet. An account id
 * is not a name, and the account menu showed one until the profile arrived. */
export const UNNAMED_ACCOUNT = "Signed in";

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
    if (profile?.account_id !== session.actor) return { name: UNNAMED_ACCOUNT, pending: true };
    const contacts = Array.isArray(model?.verified_contacts) ? model.verified_contacts : [];
    const email = contacts.map((contact) => text(record(contact)?.email)).find(Boolean);
    const name = text(profile.display_name) ?? email?.split("@")[0] ?? UNNAMED_ACCOUNT;
    // Already validated as a re-encoded image URI by the page parser; checked
    // again here because this reads the model as a record, not as that type.
    const avatar = imageDataUri(profile.avatar);
    return { name, ...(email ? { email } : {}), ...(avatar ? { avatar } : {}) };
}

function imageDataUri(value: unknown): string | undefined {
    return typeof value === "string" && /^data:image\/(?:png|jpeg);base64,/.test(value) ? value : undefined;
}

/** The same identity, from the account summary the workbench reads on every
 * page load before Account Settings is admitted (WS-916), so the menu shows
 * the person's name and photo without admission and does not change once
 * admission arrives. Like the Account page, it never names the person by their
 * account id. */
export function summaryMenuIdentity(summary: AccountSettingsSummary | undefined): MenuIdentity | null {
    if (!summary) return null;
    const email = text(summary.profile.email);
    const name = text(summary.profile.display_name) ?? email?.split("@")[0] ?? UNNAMED_ACCOUNT;
    const avatar = imageDataUri(summary.profile.avatar);
    return { name, ...(email ? { email } : {}), ...(avatar ? { avatar } : {}) };
}
