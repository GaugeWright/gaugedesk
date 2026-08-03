import { createBdd } from "playwright-bdd";
import {
    installAuthenticatedTransportProof,
    type AuthenticatedTransportProof,
} from "../authenticated-transport-proof";
import { installTransportFidelityGuards } from "../fidelity-guard";

const { Before, After } = createBdd();
const authenticatedProofs = new WeakMap<object, AuthenticatedTransportProof>();

Before(
    {
        name: "prohibit application-route interception",
        tags: "@transport or @authenticated or @staging or @production",
    },
    async ({ page, $tags }) => {
        installTransportFidelityGuards(page, $tags);
    },
);

Before(
    {
        name: "observe authenticated transport",
        tags: "@authenticated",
    },
    async ({ page, request }) => {
        authenticatedProofs.set(page, installAuthenticatedTransportProof(page, request));
    },
);

After(
    {
        name: "require successful authenticated transport",
        tags: "@authenticated",
    },
    async ({ page }) => {
        const proof = authenticatedProofs.get(page);
        if (!proof) throw new Error("@authenticated scenario did not install its transport proof");
        try {
            await proof.assertSuccessfulCredentialedRequest();
        } finally {
            proof.restore();
            authenticatedProofs.delete(page);
        }
    },
);
