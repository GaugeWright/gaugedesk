/**
 * The `/account/*` seam (ACCT-1, ADR 0053): everything the operator's own settings
 * surface reads and writes, as one interface a composition implements.
 *
 * It lives apart from the surfaces that consume it so that a composition can satisfy
 * the contract without importing a component, and so that what the account genuinely
 * supports can be read in one screen — the pre-split panel stated it above 800 lines
 * of markup.
 *
 * A linked credential's token is write-only: you link a provider, but the token is
 * never read back (sealed server-side, SEC-4).
 */
import type {
    AccountDevice,
    AccountFacility,
    AccountInvitation,
    AccountSignInMethod,
    AccountTenant,
    CodexLoginStart,
    CodexStatus,
    XaiGrokLoginStart,
    XaiGrokStatus,
    HubSessionStatus,
    LinkedProvider,
    ManagedInferenceBilling,
    ManagedInferencePlan,
} from "@gaugewright/control-plane-client";

export interface AccountPanelApi {
    accountSignInMethod(): Promise<AccountSignInMethod>;
    /** One record per provider: the store keys a credential by provider name, so there
     *  is no second key for the same provider and no name to tell two apart. */
    accountCredentials(): Promise<LinkedProvider[]>;
    accountDevices(): Promise<AccountDevice[]>;
    accountInvitations(): Promise<AccountInvitation[]>;
    acceptAccountInvitation(tenantId: string): Promise<AccountTenant>;
    codexStatus(): Promise<CodexStatus>;
    codexLoginStart(): Promise<CodexLoginStart>;
    codexLoginCancel(): Promise<void>;
    xaiGrokStatus(): Promise<XaiGrokStatus>;
    xaiGrokLoginStart(): Promise<XaiGrokLoginStart>;
    xaiGrokLoginCancel(): Promise<void>;
    accountLinkCredential(provider: string, token: string, baseUrl?: string): Promise<void>;
    accountUnlinkCredential(provider: string): Promise<void>;
    accountManagedInference(): Promise<ManagedInferenceBilling>;
    accountSetManagedInference(plan: ManagedInferencePlan): Promise<void>;
    accountRevokeDevice(id: string): Promise<void>;
    accountSettings(): Promise<Record<string, string>>;
    accountSetSetting(key: string, value: string): Promise<void>;
    accountFacilities(): Promise<AccountFacility[]>;
    accountAttachFacility(input: {
        id: string;
        kind?: string;
        displayName?: string;
    }): Promise<AccountFacility>;
    accountDetachFacility(id: string): Promise<void>;
    accountPublishLibrarySync(): Promise<void>;
    accountPullLibrarySync(): Promise<{ found: boolean; merged: number }>;
    /** Desktop → Hub account sign-in (ADR 0123, LOGIN-4). Optional: only the
     * co-resident desktop control plane custodies a Hub session; compositions
     * without these methods simply do not render the account-session section. */
    hubSessionStatus?(): Promise<HubSessionStatus>;
    /** `webReturn` (ADR 0140): the Hub will 302 back to this browser origin with
     * `#code=…`, so the caller navigates the current tab instead of opening a
     * new one. Absent/false on the desktop deep-link path. */
    hubSessionStart?(): Promise<{ url: string; webReturn?: boolean }>;
    /** Deliver the one-time return code by hand (LOGIN-7): the fallback for a
     * machine whose OS never routes `gaugewright://` back — the person pastes
     * the return link (or its code) into the panel instead. Same redemption as
     * the deep-linked path; the control plane holds the verifier either way. */
    hubSessionCallback?(code: string): Promise<HubSessionStatus>;
    hubSessionSignOut?(): Promise<void>;
}
