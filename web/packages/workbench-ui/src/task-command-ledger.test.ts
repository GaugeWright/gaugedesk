import { createRoot } from "solid-js";
import { describe, expect, it } from "vitest";
import { createTaskCommandLedger } from "./session-composer-controller";
import { withPendingTasks, empty } from "./transcript";

const scope = { home: {}, chat: "chat-one", authority: { home_id: "home-one", actor_id: "alice" } };
const accepted = { type: "user", text: "same text", client_request_id: "command-one", chat_id: "chat-one", home_id: "home-one", actor_id: "alice" };
describe("addressed task-command correlation", () => {
    it("keeps uncertainty and same-text legacy snapshots non-standing until the exact Home answers", () => createRoot((dispose) => {
        const ledger = createTaskCommandLedger();
        ledger.begin(scope, "command-one", "same text", 0);
        ledger.uncertain(scope, "command-one");
        ledger.observe(scope, { type: "user", text: "same text" });
        ledger.observe(scope, { status: 200 });
        ledger.observe(scope, { status: 403 });
        ledger.observe(scope, { command_status: "applied" });
        ledger.observe(scope, { command_status: "rejected" });
        expect(ledger.pending()).toHaveLength(1);
        expect(ledger.pending()[0]?.uncertain).toBe(true);
        expect(withPendingTasks(empty, ledger.pending()).lines).toEqual([
            { seq: 0, tier: "operational", kind: "user", text: "same text" },
        ]);
        ledger.observe(scope, accepted);
        expect(ledger.pending()).toEqual([]);
        dispose();
    }));
    it("refuses another Home, chat, ID or inherited ancestor as reconciliation", () => createRoot((dispose) => {
        const ledger = createTaskCommandLedger();
        ledger.begin(scope, "command-one", "same text", 0);
        ledger.observe({ home: {}, chat: "chat-one" }, accepted);
        ledger.observe({ ...scope, project: "other-project" }, accepted);
        ledger.observe(scope, { ...accepted, chat_id: "chat-two" });
        ledger.observe(scope, { ...accepted, client_request_id: "command-two" });
        ledger.observe(scope, { ...accepted, actor_id: "bob" });
        ledger.observe(scope, { ...accepted, home_id: "home-two" });
        ledger.observe(scope, { type: "user", text: "same text", client_request_id: "command-one", chat_id: "chat-one" });
        ledger.observe(scope, { ...accepted, origin: "ancestor-chat" });
        ledger.observe(scope, { correlation: { ...accepted, outcome: "expired" } });
        expect(ledger.pending()).toHaveLength(1);
        ledger.observe(scope, accepted);
        expect(ledger.pending()).toEqual([]);
        dispose();
    }));
    it("retires only the matching attempt on explicit refusal or terminal and keeps concurrent work", () => createRoot((dispose) => {
        const ledger = createTaskCommandLedger();
        ledger.begin(scope, "command-one", "one", 0);
        ledger.begin(scope, "command-two", "two", 0);
        const other = { home: scope.home, chat: "chat-two" };
        ledger.begin(other, "command-one", "other chat", 0);
        ledger.observe(scope, { correlation: { client_request_id: "command-one", chat_id: scope.chat, home_id: "home-one", actor_id: "alice", outcome: "refused" } });
        expect(ledger.pending().map((command) => [command.scope.chat, command.id])).toEqual([
            ["chat-one", "command-two"], ["chat-two", "command-one"],
        ]);
        ledger.observe(scope, { type: "taskcorrelation", client_request_id: "command-two", chat_id: scope.chat, home_id: "home-one", actor_id: "alice", outcome: "settled" });
        expect(ledger.pending().map((command) => command.scope.chat)).toEqual(["chat-two"]);
        dispose();
    }));
    it("records a replay once and does not mistake prior same-text messages for its effect", () => createRoot((dispose) => {
        const ledger = createTaskCommandLedger();
        ledger.begin(scope, "command-one", "same text", 1);
        ledger.begin(scope, "command-one", "same text", 1);
        expect(ledger.pending()).toHaveLength(1);
        const old = { lines: [{ seq: 0, tier: "admitted" as const, kind: "user", text: "same text" }], openText: null };
        expect(withPendingTasks(old, ledger.pending()).lines.map((line) => line.tier)).toEqual(["admitted", "operational"]);
        ledger.observe(scope, { ...accepted, client_request_id: "earlier-command" });
        expect(ledger.pending()).toHaveLength(1);
        ledger.observe(scope, accepted);
        expect(withPendingTasks(old, ledger.pending()).lines).toEqual(old.lines);
        dispose();
    }));
});
