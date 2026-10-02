import { createComponent } from "solid-js";
import { render } from "solid-js/web";
import { afterEach, expect, it, vi } from "vitest";
import type { QuarantineIndex } from "@gaugewright/control-plane-client";
import { ProjectInbox, type ProjectInboxApi } from "./ProjectInbox";

let dispose: (() => void) | undefined;
afterEach(() => { dispose?.(); document.body.replaceChildren(); });

// The top bar's inbound count opens this Inbox, so a verdict must tell it to
// re-read, or the count outlives the item it counted.
it("says when a verdict reached the gate", async () => {
    const host = document.createElement("div");
    document.body.append(host);
    const index = {
        project: "proj-a",
        pending: 1,
        items: [{
            item_id: "visitor-ana:1", source_id: "visitor-ana", schema_ref: "survey.v1",
            byte_len: 43, arrived_at_unix_ms: 1, status: "Pending", workspace_path: null,
        }],
    } as unknown as QuarantineIndex;
    const api: ProjectInboxApi = {
        listQuarantine: async () => index,
        readQuarantinedItem: async () => "{}",
        reviewQuarantinedItem: vi.fn(async () => ({ workspacePath: "inbound/visitor-ana-1.json" })),
    };
    const onReviewed = vi.fn();
    dispose = render(() => createComponent(ProjectInbox, {
        api, project: "proj-a", projectName: "Survey", onClose: vi.fn(), onReviewed,
    }), host);
    await vi.waitFor(() => expect(host.querySelector(".quarantine-row")).not.toBeNull());
    (host.querySelector(".quarantine-row") as HTMLButtonElement).click();
    await vi.waitFor(() => expect(host.querySelector(".quarantine-actions .primary")).not.toBeNull());
    (host.querySelector(".quarantine-actions .primary") as HTMLButtonElement).click();
    await vi.waitFor(() => expect(onReviewed).toHaveBeenCalledOnce());
    expect(api.reviewQuarantinedItem).toHaveBeenCalledWith("proj-a", "visitor-ana:1", "keep");
});
