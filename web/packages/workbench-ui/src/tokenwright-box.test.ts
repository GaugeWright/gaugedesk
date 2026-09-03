import { describe, expect, it, vi } from "vitest";
import type { ManagementEnvironmentSession } from "@gaugewright/control-plane-client";
import { setTokenWrightDesired, tokenwrightCommandsFrom } from "./tokenwright-box";

function fakeJson(response: unknown) {
    const calls: [string, string, unknown?, unknown?][] = [];
    const json = vi.fn(async (method: string, path: string, body?: unknown, options?: unknown) => {
        calls.push([method, path, body, options]);
        return response;
    });
    return { json: json as never, calls };
}

const session: ManagementEnvironmentSession = {
    id: "sess_1",
    environment: "tokenwright",
    scope: { kind: "tenant", id: "tenant-a" },
    actor: "paired-home",
    capabilities: ["RunTurn", "AdministerBox"],
    documents: [
        {
            id: "tokenwright.inference", path: "inference.json",
            schema: "gw://schemas/tokenwright/inference/v1",
            revision: "rev-1", freshness: "live", readable: true, editable: true,
            commands: ["tokenwright.engine.restart", "tokenwright.models.prune"],
        },
        {
            id: "tokenwright.posture", path: "posture.json",
            schema: "gw://schemas/tokenwright/posture/v1",
            revision: "rev-2", freshness: "live", readable: false, editable: false,
            commands: [],
        },
    ],
    commands: [
        { id: "tokenwright.engine.restart", capability: "AdministerBox", review: "immediate" },
        { id: "tokenwright.models.prune", capability: "AdministerBox", review: "immediate" },
    ],
};

const receipt = (status: string) => ({
    receipt: {
        id: "rcpt_1", session_id: "sess_1", environment: "tokenwright",
        scope: session.scope, document_id: "tokenwright.inference",
        command_id: "tokenwright.engine.restart", base_revision: "rev-1", status,
    },
});

function bind(route: ReturnType<typeof fakeJson>, revision: string | undefined = "rev-1", keys?: string[]) {
    let index = 0;
    return tokenwrightCommandsFrom({
        json: route.json,
        session,
        revisionOf: () => revision,
        newIdempotencyKey: keys ? () => keys[index++]! : () => `key-${index++}`,
    });
}

describe("binding a TokenWright session to runnable controls", () => {
    it("offers exactly the commands the grant carries", () => {
        const commands = bind(fakeJson(receipt("applied")));
        expect(Object.keys(commands).sort()).toEqual([
            "tokenwright.engine.restart", "tokenwright.models.prune",
        ]);
    });

    it("offers nothing for a document whose grant carries no commands", () => {
        const readOnly: ManagementEnvironmentSession = {
            ...session,
            documents: session.documents.map((d) => ({ ...d, commands: [] })),
        };
        const commands = tokenwrightCommandsFrom({
            json: fakeJson(receipt("applied")).json, session: readOnly,
            revisionOf: () => "rev-1",
        });
        // The renderer draws these as "Unavailable in this session" rather than
        // as a button that fails when pressed.
        expect(Object.keys(commands)).toEqual([]);
    });

    it("never offers a command the box advertises but the grant withholds", () => {
        // `tokenwright.unpair` is in the carried bundle. Authority comes from
        // the grant, so it must not appear here.
        const commands = bind(fakeJson(receipt("applied")));
        expect(commands["tokenwright.unpair"]).toBeUndefined();
    });

    it("labels a granted control from the carried declarations", () => {
        const commands = bind(fakeJson(receipt("applied")));
        expect(commands["tokenwright.engine.restart"]?.label).toBe("Restart engine");
    });

    it("submits with no payload at all", async () => {
        const route = fakeJson(receipt("applied"));
        await bind(route)["tokenwright.engine.restart"]!.run();
        const body = route.calls[0]?.[2] as Record<string, unknown>;
        expect(body.payload).toEqual({});
        expect(route.calls[0]?.[1]).toBe("/environments/tokenwright/commands");
    });

    it("reads the base revision at press time, not when the binding was built", async () => {
        // A revision captured at build time is stale the moment anything else
        // changes the document, and the box would answer `conflict` to a press
        // the operator has no reason to think is stale.
        const route = fakeJson(receipt("applied"));
        let current = "rev-1";
        const commands = tokenwrightCommandsFrom({
            json: route.json, session, revisionOf: () => current,
            newIdempotencyKey: () => "key",
        });
        current = "rev-9";
        await commands["tokenwright.engine.restart"]!.run();
        expect((route.calls[0]?.[2] as Record<string, unknown>).base_revision).toBe("rev-9");
    });

    it("refuses to press when no revision is known yet", async () => {
        // Built inline rather than through `bind`: passing `undefined` to a
        // parameter with a default gets the default, so the helper could not
        // express "no revision" at all.
        const route = fakeJson(receipt("applied"));
        const commands = tokenwrightCommandsFrom({
            json: route.json, session, revisionOf: () => undefined,
            newIdempotencyKey: () => "key",
        });
        await expect(commands["tokenwright.engine.restart"]!.run())
            .rejects.toThrow(/re-read the document/u);
        expect(route.calls).toHaveLength(0);
    });

    it("uses a fresh idempotency key per press", async () => {
        // Reusing one across presses would make the second press return the
        // first receipt and do nothing, which reads as a dead button.
        const route = fakeJson(receipt("applied"));
        const commands = bind(route, "rev-1", ["key-a", "key-b"]);
        await commands["tokenwright.engine.restart"]!.run();
        await commands["tokenwright.engine.restart"]!.run();
        const keys = route.calls.map((call) => (call[3] as { idempotencyKey: string }).idempotencyKey);
        expect(keys).toEqual(["key-a", "key-b"]);
    });

    it("surfaces a conflict as something the operator can act on", async () => {
        const route = fakeJson(receipt("conflict"));
        await expect(bind(route)["tokenwright.engine.restart"]!.run())
            .rejects.toThrow(/changed while you were looking at it/u);
    });

    it("surfaces a refusal rather than reporting success", async () => {
        const route = fakeJson(receipt("rejected"));
        await expect(bind(route)["tokenwright.engine.restart"]!.run())
            .rejects.toThrow(/refused/u);
    });

    it("reports an applied receipt to the caller", async () => {
        const route = fakeJson(receipt("applied"));
        const seen: string[] = [];
        const commands = tokenwrightCommandsFrom({
            json: route.json, session, revisionOf: () => "rev-1",
            onReceipt: (value) => seen.push(value.status),
            newIdempotencyKey: () => "key",
        });
        await commands["tokenwright.models.prune"]!.run();
        expect(seen).toEqual(["applied"]);
    });
});

describe("selecting a model, which is a literal edit", () => {
    const content = {
        desired: { model: null, models: ["qwen3-coder-30b"], autostart: true, direct_access: false },
        engine: { name: "FreeToken", status: "running" },
    };

    it("sends ONLY the editable block, never a projected field", async () => {
        // The bug this replaces: the whole document went back with `desired`
        // swapped, which echoed live projections — relay and direct status,
        // and every key's `last_used_at` — straight back at the box. The box
        // compares what the client SENT against what it now holds, so any
        // projection that moved in the window between read and write turned a
        // perfectly ordinary edit into a 422. `last_used_at` is stamped at
        // whole-second granularity, so it fired when an edit happened to
        // straddle a second boundary and passed otherwise.
        //
        // Sending only `desired` makes that race structurally impossible
        // rather than rare, which is why this asserts on the ABSENCE of the
        // other keys and not merely on `desired` being right.
        const route = fakeJson({ receipt: { id: "rcpt_2", status: "applied" } });
        await setTokenWrightDesired(route.json, {
            session, documentId: "tokenwright.inference", baseRevision: "rev-1",
            desired: { ...content.desired, model: "qwen3-coder-30b" },
        }, "key-1");
        const body = route.calls[0]?.[2] as { content: Record<string, unknown> };
        expect(route.calls[0]?.[1]).toBe("/environments/tokenwright/changes");
        expect(Object.keys(body.content)).toEqual(["desired"]);
        expect((body.content.desired as Record<string, unknown>).model).toBe("qwen3-coder-30b");
    });

    it("is refused when the grant does not mark the document editable", async () => {
        const readOnly: ManagementEnvironmentSession = {
            ...session,
            documents: session.documents.map((d) => ({ ...d, editable: false })),
        };
        const route = fakeJson({ receipt: {} });
        await expect(setTokenWrightDesired(route.json, {
            session: readOnly, documentId: "tokenwright.inference", baseRevision: "rev-1",
            desired: content.desired,
        })).rejects.toThrow(/not editable/u);
        expect(route.calls).toHaveLength(0);
    });
});
