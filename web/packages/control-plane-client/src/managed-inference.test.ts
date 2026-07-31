import { describe, expect, it } from "vitest";
import {
    accountManagedInference,
    accountSetManagedInference,
} from "./control-plane-account";

function recorder(reply: unknown = {}) {
    const calls: { method: string; path: string; body?: unknown }[] = [];
    const json = async (method: string, path: string, body?: unknown) => {
        calls.push({ method, path, body });
        return reply;
    };
    return { json, calls };
}

describe("managed inference account client (LLM-3)", () => {
    it("reads the plan and usage projection", async () => {
        const reply = {
            plan: { plan: "managed", status: "active", included_tokens: 100 },
            funding_ref: "gaugedesk:managed-plan:v1:6163636f756e74:6d616e61676564",
            usage: { runs: 1, total_tokens: 12, overage_tokens: 0 },
        };
        const { json, calls } = recorder(reply);
        expect(await accountManagedInference(json)).toEqual(reply);
        expect(calls[0]).toEqual({
            method: "GET",
            path: "/account/managed-inference",
            body: undefined,
        });
    });

    it("writes only operational plan state, never a provider secret", async () => {
        const { json, calls } = recorder();
        const plan = { plan: "managed", status: "suspended" as const, included_tokens: 100 };
        await accountSetManagedInference(json, plan);
        expect(calls[0]).toEqual({
            method: "POST",
            path: "/account/managed-inference",
            body: plan,
        });
    });
});
