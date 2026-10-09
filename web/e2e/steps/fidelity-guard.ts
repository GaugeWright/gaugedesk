import { createBdd } from "playwright-bdd";
import {
    installTransportProof,
    type TransportProof,
} from "../authenticated-transport-proof";
import { installStandardFixtureGuards } from "../fidelity-guard";

const { Before, After } = createBdd();
const transportProofs = new WeakMap<object, TransportProof>();

Before(
    {
        name: "isolate Stripe then prohibit application-route interception",
    },
    async ({ page, $tags }) => {
        await installStandardFixtureGuards(page, $tags);
    },
);

Before(
    {
        name: "observe application transport",
        tags: "@transport or @staging or @production",
    },
    async ({ page, request }) => {
        transportProofs.set(page, installTransportProof(page, request));
    },
);

After(
    {
        name: "require declared application transport",
        tags: "@transport or @staging or @production",
    },
    async ({ page, $tags }) => {
        const proof = transportProofs.get(page);
        if (!proof) throw new Error("real-transport scenario did not install its proof");
        try {
            await proof.assertSuccessfulApplicationRequest();
            if ($tags.includes("@authenticated")) {
                await proof.assertSuccessfulCredentialedRequest();
            }
        } finally {
            proof.restore();
            transportProofs.delete(page);
        }
    },
);
