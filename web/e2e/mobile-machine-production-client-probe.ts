import { WorkbenchControlPlane } from "../apps/workbench-web/src/workbench-control-plane";

/** Owner-side native Machine lifecycle through the exact shipped client. The
 * native app owns claim/proof/session use; this companion owns invitation,
 * approval, controller projection, and revocation on the same real Machine. */
export function createMachineOwnerClient(base: string) {
    const client = new WorkbenchControlPlane(base);
    return {
        mintInvitation: (endpoint: string) =>
            client.mintMachineControllerInvitation(endpoint),
        listRequests: () => client.listMachineControllerRequests(),
        approve: (requestId: string) => client.approveMachineController(requestId),
        listControllers: () => client.listMachineControllers(),
        revoke: (controllerId: string) => client.revokeMachineController(controllerId),
    };
}
