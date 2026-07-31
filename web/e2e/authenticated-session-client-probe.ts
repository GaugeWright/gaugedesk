import {
    accountCredentials,
    accountDevices,
    accountLinkCredential,
    accountDeleteHomeRoute,
    accountDetachFacility,
    accountFacilities,
    accountHomeRoutes,
    accountHomes,
    accountInvitations,
    accountManagedInference,
    accountPublishHomeRoute,
    accountRevokeDevice,
    accountRegisterHome,
    accountSelectHome,
    accountSetSetting,
    accountSettings,
    accountSignInMethod,
    accountTenants,
    accountUnlinkCredential,
    accountUnregisterHome,
    accountAttachFacility,
    browserRouteJson,
    codexStatus,
    createOrganization,
    defaultModel,
    endSession,
    exchangeMobileAccountHandoff,
    onboardingStatus,
    refreshHostedAccountSession,
    refreshMobileAccountToken,
} from "@gaugewright/control-plane-client";
import type {
    HomeId,
    ProjectId,
} from "@gaugewright/control-plane-client";

/** Read the authenticated account method through the exact production client. */
export async function readAccountSession(base: string) {
    return accountSignInMethod(browserRouteJson(base));
}

/** Read the signed-in account bootstrap through the exact production clients
 * used by the Account surface and project-to-Home router. */
export async function readAccountBootstrap(base: string) {
    const json = browserRouteJson(base);
    return {
        tenants: await accountTenants(json),
        homes: await accountHomes(json),
        homeRoutes: await accountHomeRoutes(json),
        facilities: await accountFacilities(json),
        invitations: await accountInvitations(json),
        devices: await accountDevices(json),
        settings: await accountSettings(json),
        credentials: await accountCredentials(json),
        managedInference: await accountManagedInference(json),
        codex: await codexStatus(json),
        onboarding: await onboardingStatus(json),
        defaultModel: await defaultModel(json),
    };
}

/** Mutate and read back a disposable person-owned account lifecycle through
 * exact production clients. Cleanup uses those same clients and leaves only
 * the deliberately durable organization and setting records. */
export async function mutateAccountBootstrap(base: string) {
    const json = browserRouteJson(base);
    const tenant = await createOrganization(json, "Wiring Organization");
    await accountSetSetting(json, "wiring.account-bootstrap", "verified");
    const settings = await accountSettings(json);

    const facilityId = "wiring-facility";
    const facility = await accountAttachFacility(json, {
        id: facilityId,
        kind: "library_sync",
        displayName: "Wiring facility",
    });
    const facilitiesAfterAttach = await accountFacilities(json);
    await accountDetachFacility(json, facilityId);
    const facilitiesAfterDetach = await accountFacilities(json);

    const homeId = "home:wiring-account-bootstrap" as HomeId;
    const projectId = "project:wiring-account-bootstrap" as ProjectId;
    const endpoint = "http://localhost:65534";
    await accountRegisterHome(json, {
        id: homeId,
        kind: "registered",
        endpoint,
    });
    await accountSelectHome(json, homeId);
    const homesAfterSelect = await accountHomes(json);
    await accountPublishHomeRoute(json, {
        project: projectId,
        homeId,
        endpoint,
    });
    const routesAfterPublish = await accountHomeRoutes(json);
    await accountDeleteHomeRoute(json, projectId);
    const routesAfterDelete = await accountHomeRoutes(json);
    await accountUnregisterHome(json, homeId);
    const homesAfterDelete = await accountHomes(json);

    return {
        tenant,
        setting: settings["wiring.account-bootstrap"],
        facility,
        facilityAttached: facilitiesAfterAttach.some((entry) =>
            entry.id === facilityId && entry.status === "active"),
        facilityDetached: facilitiesAfterDetach.every((entry) =>
            entry.id !== facilityId || entry.status !== "active"),
        homeSelected: homesAfterSelect.selectedHome === homeId,
        routePublished: routesAfterPublish.some((entry) =>
            entry.project === projectId && entry.homeId === homeId),
        routeDeleted: routesAfterDelete.every((entry) => entry.project !== projectId),
        homeDeleted: homesAfterDelete.homes.every((entry) => entry.id !== homeId),
    };
}

/** Link, project, and unlink a disposable credential through the exact
 * production clients without returning the credential plaintext. */
export async function mutateAccountCredential(base: string) {
    const json = browserRouteJson(base);
    const provider = "wiring-provider";
    await accountLinkCredential(json, provider, "wiring-credential-token");
    const afterLink = await accountCredentials(json);
    await accountUnlinkCredential(json, provider);
    const afterUnlink = await accountCredentials(json);
    return {
        linked: afterLink.some((entry) =>
            entry.provider === provider && entry.linked),
        unlinked: afterUnlink.every((entry) => entry.provider !== provider),
    };
}

/** Revoke a disposable registry fixture through the exact production client,
 * then read the durable revoked fact through the shipped Account projection. */
export async function mutateAccountDeviceRevocation(base: string) {
    const json = browserRouteJson(base);
    const id = "wiring-account-device";
    await json("POST", "/account/devices", {
        id,
        label: "Wiring account device",
        subkey_pubkey: "wiring-public-subkey",
    });
    const afterRegister = await accountDevices(json);
    await accountRevokeDevice(json, id);
    const afterRevoke = await accountDevices(json);
    return {
        registered: afterRegister.some((entry) =>
            entry.id === id && entry.status === "active"),
        revoked: afterRevoke.some((entry) =>
            entry.id === id && entry.status === "revoked"),
    };
}

/** Exercise the production hosted-cookie refresh owner. */
export async function refreshAccountSession(base: string) {
    return refreshHostedAccountSession(base);
}

/** Exercise the production logout owner, including its idempotency key. */
export async function logoutAccountSession(base: string) {
    await endSession(base);
}

/** Cross the exact production native handoff client while retaining a
 * serializable denial result for the generated browser campaign. */
export async function exchangeMobileAccountHandoffResult(
    base: string,
    code: string,
    verifier: string,
) {
    try {
        return {
            ok: true,
            token: await exchangeMobileAccountHandoff(base, code, verifier),
            error: null,
        };
    } catch (error) {
        return {
            ok: false,
            token: null,
            error: error instanceof Error ? error.message : String(error),
        };
    }
}

/** Cross the exact production native refresh client with a serializable
 * authority result so invalid bearer properties do not bypass the client. */
export async function refreshMobileAccountTokenResult(
    base: string,
    token: string,
) {
    try {
        return {
            ok: true,
            token: await refreshMobileAccountToken(base, token),
            error: null,
        };
    } catch (error) {
        return {
            ok: false,
            token: null,
            error: error instanceof Error ? error.message : String(error),
        };
    }
}
