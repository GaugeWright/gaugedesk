import { describe, expect, it, vi } from "vitest";

import {
    connectTokenWrightBox,
    type ConnectDependencies,
    type OpenedBoxTransport,
    type TokenWrightConnectState,
} from "./tokenwright-connect";

const PIN = `sha256:${"ab".repeat(32)}`;
const ROUTE = "F8E0l3whZo41YL6B8yzSJAQdF8E0l3whZo41YL6B8yw";
/** Produced by the box's own `tokenwright.invite.encode`. */
const INVITE =
    "tw1_eyJ2IjoxLCJyIjoid3NzOi8vcmVsYXkuZXhhbXBsZTo0NDMvciIsImMiOiJBQkNELUVGR0gtSktNTi1QUVJTLVRWV1giLCJmIjoic2hhMjU2OmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWIifQ";

function claimAnswer(overrides: Record<string, unknown> = {}) {
    return {
        paired: {
            home: "home_a", paired_at: "2026-09-01T20:00:00Z",
            fingerprint: PIN, route: ROUTE, ...overrides,
        },
        key: { id: "key_c30f", name: "paired-home", secret: "s3cret" },
    };
}

function deps(overrides: Partial<ConnectDependencies> = {}): ConnectDependencies & {
    states: TokenWrightConnectState[];
    saved: unknown[];
} {
    const states: TokenWrightConnectState[] = [];
    const saved: unknown[] = [];
    const transport: OpenedBoxTransport = {
        json: async () => claimAnswer(),
        presentedFingerprint: PIN,
    };
    return {
        states,
        saved,
        homeId: "home_a",
        homeKey: "home-root",
        open: async () => transport,
        save: async (connection) => { saved.push(connection); },
        onState: (state) => states.push(state),
        ...overrides,
    };
}

describe("adding a box", () => {
    it("ends connected and stores what reaches the box again", async () => {
        const dependencies = deps();
        const state = await connectTokenWrightBox(INVITE, dependencies);
        expect(state.phase).toBe("connected");
        expect(state.connection?.route).toBe(ROUTE);
        expect(dependencies.saved).toEqual([state.connection]);
    });

    it("stores before it reports success", async () => {
        // A claim that succeeded and was not persisted has spent the code and
        // lost the box. If "connected" could ever be shown before the save
        // resolved, an operator would close the window on a box they no longer
        // have a route to.
        const order: string[] = [];
        const dependencies = deps({
            save: async () => {
                order.push("save-start");
                await new Promise((resolve) => setTimeout(resolve, 5));
                order.push("save-done");
            },
            onState: (state) => order.push(`state:${state.phase}`),
        });
        await connectTokenWrightBox(INVITE, dependencies);
        expect(order.indexOf("save-done")).toBeLessThan(order.indexOf("state:connected"));
    });

    it("walks the phases in an order a panel can paint", async () => {
        const dependencies = deps();
        await connectTokenWrightBox(INVITE, dependencies);
        expect(dependencies.states.map((state) => state.phase)).toEqual([
            "reading", "dialling", "claiming", "storing", "connected",
        ]);
        // A spinner with no words is indistinguishable from a hang.
        expect(dependencies.states.every((state) => state.message.length > 0)).toBe(true);
    });

    it("shows the box being trusted before anything is dialled", async () => {
        const dependencies = deps();
        await connectTokenWrightBox(INVITE, dependencies);
        const dialling = dependencies.states.find((state) => state.phase === "dialling");
        expect(dialling?.invite?.relayEndpoint).toBe("wss://relay.example:443/r");
        expect(dialling?.invite?.fingerprint).toBe(PIN);
    });

    it("closes the tunnel whichever way the journey ends", async () => {
        // A tunnel whose owner has gone leaves a leg spliced against the relay,
        // and every later attempt to reach that box waits for a splice that
        // cannot happen.
        for (const json of [
            async () => claimAnswer(),
            async () => { throw new Error("refused"); },
        ]) {
            const close = vi.fn();
            await connectTokenWrightBox(INVITE, deps({
                open: async () => ({ json, presentedFingerprint: PIN, close }),
            }));
            expect(close).toHaveBeenCalledOnce();
        }
    });
});

describe("failing in a way the operator can act on", () => {
    it("rejects a bad paste before dialling anything", async () => {
        // "Cannot connect" would send someone to look at their network when the
        // real answer is that they copied one line short.
        const open = vi.fn();
        const state = await connectTokenWrightBox("not-a-pairing-string", deps({ open }));
        expect(state.phase).toBe("failed");
        expect(open).not.toHaveBeenCalled();
        expect(state.retryable).toBe(true);
    });

    it("offers a retry for a paste, because pasting again is the fix", async () => {
        const state = await connectTokenWrightBox(INVITE.slice(0, 30), deps());
        expect(state.retryable).toBe(true);
    });

    it("refuses to offer a retry once the code is spent", async () => {
        // Pasting the same string produces the same refusal. A retry button
        // here hides the fact that a new code must come from the box.
        const state = await connectTokenWrightBox(INVITE, deps({
            open: async () => ({
                json: async () => { throw new Error("already_paired"); },
                presentedFingerprint: PIN,
            }),
        }));
        expect(state.phase).toBe("failed");
        expect(state.retryable).toBe(false);
        expect(state.message).toMatch(/unpair it on the box/);
    });

    it("says both things that look identical from here when the dial fails", async () => {
        const state = await connectTokenWrightBox(INVITE, deps({
            open: async () => { throw new Error("timed out"); },
        }));
        expect(state.message).toMatch(/switched off/);
        expect(state.message).toMatch(/relay may be unreachable/);
        expect(state.retryable).toBe(true);
    });

    it("does not call a failed claim a failure with nothing done", async () => {
        // The code is spent, the box is claimed, and its only route did not
        // reach disk. "Failed" would suggest nothing happened.
        const state = await connectTokenWrightBox(INVITE, deps({
            save: async () => { throw new Error("disk full"); },
        }));
        expect(state.phase).toBe("failed");
        expect(state.message).toMatch(/was claimed/);
        expect(state.message).toMatch(/cannot be recovered/);
        // The route is still handed to the panel, because it is the only copy
        // left anywhere.
        expect(state.connection?.route).toBe(ROUTE);
        expect(state.retryable).toBe(false);
    });

    it("refuses a box whose certificate disagrees with what it reports", async () => {
        const state = await connectTokenWrightBox(INVITE, deps({
            open: async () => ({
                json: async () => claimAnswer(),
                presentedFingerprint: `sha256:${"cd".repeat(32)}`,
            }),
        }));
        expect(state.phase).toBe("failed");
        expect(state.message).toMatch(/certificate does not match/);
    });

    it("never stores anything when the claim was refused", async () => {
        const dependencies = deps({
            open: async () => ({
                json: async () => { throw new Error("bad_proof"); },
                presentedFingerprint: PIN,
            }),
        });
        await connectTokenWrightBox(INVITE, dependencies);
        expect(dependencies.saved).toEqual([]);
    });
});
