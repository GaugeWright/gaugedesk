import { createBdd } from "playwright-bdd";
import { installTransportFidelityGuards } from "../fidelity-guard";

const { Before } = createBdd();

Before(
    {
        name: "prohibit application-route interception",
        tags: "@transport or @authenticated or @staging or @production",
    },
    async ({ page, $tags }) => {
        installTransportFidelityGuards(page, $tags);
    },
);
