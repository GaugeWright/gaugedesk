import { afterEach, describe, expect, it, vi } from "vitest";

import type { EngagementId, StreamEvent } from "@gaugewright/control-plane-client";
import { EdgeSessionApi } from "./edge-session";
import type { LatencyObservation } from "./latency";

class FakeWebSocket {
    static readonly CONNECTING = 0;
    static readonly OPEN = 1;
    static readonly CLOSED = 3;
    readonly sent: string[] = [];
    readyState = FakeWebSocket.CONNECTING;
    private readonly listeners = new Map<string, ((event: { data?: string }) => void)[]>();

    constructor(readonly url: string) {}

    addEventListener(
        type: string,
        listener: (event: { data?: string }) => void,
        _options?: unknown,
    ) {
        const listeners = this.listeners.get(type) ?? [];
        listeners.push(listener);
        this.listeners.set(type, listeners);
    }

    emit(type: string, event: { data?: string } = {}) {
        if (type === "open") this.readyState = FakeWebSocket.OPEN;
        for (const listener of this.listeners.get(type) ?? []) listener(event);
    }

    send(value: string) {
        this.sent.push(value);
    }

    close() {
        this.readyState = FakeWebSocket.CLOSED;
        this.emit("close");
    }
}

afterEach(() => {
    vi.unstubAllGlobals();
});

describe("EdgeSessionApi", () => {
    it("starts fresh sessions anonymously while keeping history commands authenticated", async () => {
        vi.stubGlobal("fetch", vi.fn());
        const controls = {
            open: vi.fn(async () => undefined),
            create: vi.fn(async () => undefined),
            erase: vi.fn(async () => undefined),
        };
        const authenticated = new EdgeSessionApi(
            "https://panels.gaugewright.com/d/theory-a",
            "sess_0123456789abcdef0123456789abcdef" as EngagementId,
            "resume-capability",
            "connection-capability",
            Date.now() + 15 * 60 * 1000,
            "audience-assertion",
            false,
            undefined,
            controls,
        );
        expect(authenticated.embedAudience).toBe(true);
        await authenticated.embedOpenChat(
            "sess_11111111111111111111111111111111",
        );
        await authenticated.embedNewChat();
        await authenticated.embedEraseChat(
            "sess_22222222222222222222222222222222",
        );
        expect(controls.open).toHaveBeenCalledWith(
            "sess_11111111111111111111111111111111",
        );
        expect(controls.create).toHaveBeenCalledOnce();
        expect(controls.erase).toHaveBeenCalledWith(
            "sess_22222222222222222222222222222222",
        );
        authenticated.dispose();

        const anonymousControls = {
            create: vi.fn(async () => undefined),
        };
        const anonymous = new EdgeSessionApi(
            "https://panels.gaugewright.com/d/theory-a",
            "sess_0123456789abcdef0123456789abcdef" as EngagementId,
            "resume-capability",
            "connection-capability",
            Date.now() + 15 * 60 * 1000,
            null,
            false,
            undefined,
            anonymousControls,
        );
        expect(anonymous.embedAudience).toBe(false);
        await anonymous.embedNewChat();
        expect(anonymousControls.create).toHaveBeenCalledOnce();
        await expect(anonymous.embedOpenChat(
            "sess_11111111111111111111111111111111",
        )).rejects.toThrow(
            "authenticated audience is required",
        );
        anonymous.dispose();
    });

    it("hydrates and sends turns over one cursor-resumable WebSocket", async () => {
        const fetchMock = vi.fn();
        const sockets: FakeWebSocket[] = [];
        const latency: LatencyObservation[] = [];
        vi.stubGlobal("fetch", fetchMock);
        fetchMock
            .mockResolvedValueOnce(
                new Response(
                    JSON.stringify({
                        session_id: "sess_0123456789abcdef0123456789abcdef",
                        release_id: `sha256:${"a".repeat(64)}`,
                        cursor: 0,
                        transcript: [{ type: "assistant", text: "ready" }],
                        files: [{ path: "answer.md" }],
                    }),
                ),
            )
            .mockResolvedValueOnce(
                new Response(
                    JSON.stringify({
                        session_id: "sess_0123456789abcdef0123456789abcdef",
                        release_id: `sha256:${"a".repeat(64)}`,
                        cursor: 8,
                        transcript: [
                            { type: "assistant", text: "ready" },
                            { type: "user", text: "hello" },
                            { type: "assistant", text: "hi" },
                        ],
                        files: [{ path: "answer.md" }, { path: "new.md" }],
                    }),
                ),
            );
        vi.stubGlobal(
            "WebSocket",
            class extends FakeWebSocket {
                constructor(url: string) {
                    super(url);
                    sockets.push(this);
                }
            },
        );

        const api = new EdgeSessionApi(
            "https://panels.gaugewright.com/d/theory-a",
            "sess_0123456789abcdef0123456789abcdef" as EngagementId,
            "resume-capability",
            "connection-capability",
            Date.now() + 15 * 60 * 1000,
            null,
            false,
            (observation) => latency.push(observation),
        );
        const transcript = api.getTranscript("ignored" as EngagementId);
        await vi.waitFor(() => expect(sockets).toHaveLength(1));
        sockets[0]!.emit("open");
        sockets[0]!.emit("message", {
            data: JSON.stringify({
                type: "session_ready",
                sequence: 0,
                snapshot: {
                    session_id: "sess_0123456789abcdef0123456789abcdef",
                    release_id: `sha256:${"a".repeat(64)}`,
                    cursor: 0,
                    transcript: [{ type: "assistant", text: "ready" }],
                    files: [{ path: "answer.md" }],
                },
            }),
        });
        expect(await transcript).toEqual([
            { type: "assistant", text: "ready" },
        ]);

        const deltas: StreamEvent[] = [];
        api.subscribe("ignored" as EngagementId, (event) => deltas.push(event));
        const turn = api.runEmbedTurn("ignored" as EngagementId, "hello", [
            { mimeType: "image/png", data: "aGVsbG8=" },
        ]);
        await vi.waitFor(() => expect(sockets[0]!.sent).toHaveLength(1));
        const sent = JSON.parse(sockets[0]!.sent[0]!) as {
            request_id: string;
            type: string;
            text: string;
            images: { media_type: string; data_base64: string }[];
        };
        expect(sent).toMatchObject({
            type: "send_message",
            text: "hello",
            images: [{ media_type: "image/png", data_base64: "aGVsbG8=" }],
        });
        sockets[0]!.emit("message", {
            data: JSON.stringify({
                type: "message_accepted",
                sequence: 1,
                request_id: sent.request_id,
                role: "user",
                text: "hello",
            }),
        });
        sockets[0]!.emit("message", {
            data: JSON.stringify({
                type: "text_delta",
                sequence: 2,
                request_id: sent.request_id,
                delta: "hi",
            }),
        });
        sockets[0]!.emit("message", {
            data: JSON.stringify({
                type: "latency",
                source: "session",
                span: "runtime",
                phase: "direct_provider_headers",
                request_id: sent.request_id,
                elapsed_ms: 12.5,
            }),
        });
        api.recordFirstTextRendered();
        sockets[0]!.emit("message", {
            data: JSON.stringify({
                type: "tool_call",
                sequence: 3,
                request_id: sent.request_id,
                call_id: "call-1",
                tool: "read",
                arguments: { path: "answer.md" },
            }),
        });
        sockets[0]!.emit("message", {
            data: JSON.stringify({
                type: "tool_result",
                sequence: 4,
                request_id: sent.request_id,
                call_id: "call-1",
                ok: true,
                result: "contents",
            }),
        });
        sockets[0]!.emit("message", {
            data: JSON.stringify({
                type: "workspace_snapshot",
                sequence: 5,
                request_id: sent.request_id,
                files: [{ path: "answer.md" }, { path: "new.md" }],
            }),
        });
        sockets[0]!.emit("message", {
            data: JSON.stringify({
                type: "usage",
                sequence: 6,
                request_id: sent.request_id,
                usage: {
                    usage_ref: "usage:turn-1",
                    input_tokens: 100,
                    cached_input_tokens: 60,
                    output_tokens: 10,
                },
            }),
        });
        const stop = api.stopTurn();
        await vi.waitFor(() => expect(sockets[0]!.sent).toHaveLength(2));
        expect(JSON.parse(sockets[0]!.sent[1]!)).toEqual({
            type: "stop",
            request_id: sent.request_id,
            after: 6,
        });
        sockets[0]!.emit("message", {
            data: JSON.stringify({
                type: "turn_stopped",
                sequence: 7,
                request_id: sent.request_id,
                command_id: `public:sess_0123456789abcdef0123456789abcdef:${sent.request_id}`,
            }),
        });
        await expect(stop).resolves.toBeUndefined();
        await expect(turn).resolves.toEqual({ outcome: "interrupted" });
        sockets[0]!.emit("message", {
            data: JSON.stringify({
                type: "text_delta",
                sequence: 8,
                request_id: sent.request_id,
                delta: "must be ignored",
            }),
        });
        sockets[0]!.emit("message", {
            data: JSON.stringify({
                type: "turn_terminal",
                sequence: 9,
                request_id: sent.request_id,
                status: 200,
                body: { outcome: "completed" },
            }),
        });
        expect(deltas).toEqual([
            { type: "text", delta: "hi" },
            {
                type: "tool",
                tool: "read",
                mediated: true,
                call_id: "call-1",
                target: "answer.md",
                args: JSON.stringify({ path: "answer.md" }),
            },
            {
                type: "toolresult",
                call_id: "call-1",
                ok: true,
                result: "contents",
            },
        ]);
        expect(await api.getTranscript("ignored" as EngagementId)).toEqual([
            { type: "assistant", text: "ready" },
            { type: "user", text: "hello" },
        ]);
        expect(await api.getTree("ignored" as EngagementId)).toEqual([
            { path: "answer.md", isDir: false },
            { path: "new.md", isDir: false },
        ]);
        expect(api.getUsage()).toEqual({
            usage_ref: "usage:turn-1",
            input_tokens: 100,
            cached_input_tokens: 60,
            output_tokens: 10,
        });
        expect(latency.map(({ phase }) => phase)).toEqual([
            "socket_connect_start",
            "session_ready_received",
            "prompt_submitted",
            "command_sent",
            "first_event_received",
            "first_text_received",
            "direct_provider_headers",
            "first_text_rendered",
            "terminal_received",
        ]);
        expect(latency.at(-3)).toEqual({
            source: "session",
            span: "runtime",
            phase: "direct_provider_headers",
            request_id: sent.request_id,
            elapsed_ms: 12.5,
        });
        expect(
            latency.every(
                (observation) =>
                    !("text" in observation) &&
                    !("body" in observation) &&
                    !("capability" in observation),
            ),
        ).toBe(true);
        expect(fetchMock).toHaveBeenCalledTimes(2);
        expect(
            fetchMock.mock.calls.map(([url]) => new URL(String(url)).pathname),
        ).toEqual([
            "/d/theory-a/sessions/sess_0123456789abcdef0123456789abcdef/state",
            "/d/theory-a/sessions/sess_0123456789abcdef0123456789abcdef/state",
        ]);
        api.dispose();
    });

    it("retries an interrupted turn with the same request id after reconnect", async () => {
        vi.useFakeTimers();
        const sockets: FakeWebSocket[] = [];
        vi.stubGlobal("fetch", vi.fn());
        vi.stubGlobal(
            "WebSocket",
            class extends FakeWebSocket {
                constructor(url: string) {
                    super(url);
                    sockets.push(this);
                }
            },
        );
        const api = new EdgeSessionApi(
            "https://panels.gaugewright.com/d/theory-a",
            "sess_0123456789abcdef0123456789abcdef" as EngagementId,
            "resume-capability",
            "connection-capability",
            Date.now() + 15 * 60 * 1000,
            null,
            false,
        );
        const ready = api.ready();
        sockets[0]!.emit("open");
        sockets[0]!.emit("message", {
            data: JSON.stringify({
                type: "session_ready",
                snapshot: { cursor: 0, transcript: [], files: [] },
            }),
        });
        await ready;

        const turn = api.runEmbedTurn("ignored" as EngagementId, "recover me");
        await vi.waitFor(() => expect(sockets[0]!.sent).toHaveLength(1));
        const first = JSON.parse(sockets[0]!.sent[0]!) as {
            request_id: string;
            text: string;
        };
        sockets[0]!.emit("message", {
            data: JSON.stringify({
                type: "text_delta",
                sequence: 1,
                request_id: first.request_id,
                delta: "partial",
            }),
        });
        sockets[0]!.close();
        await vi.advanceTimersByTimeAsync(100);
        expect(sockets).toHaveLength(2);
        expect(sockets[1]!.url).toContain("after=1");
        sockets[1]!.emit("open");
        sockets[1]!.emit("message", {
            data: JSON.stringify({
                type: "session_ready",
                snapshot: { cursor: 1, transcript: [], files: [] },
            }),
        });
        expect(sockets[1]!.sent).toHaveLength(1);
        const retried = JSON.parse(sockets[1]!.sent[0]!) as {
            request_id: string;
            text: string;
            after: number;
        };
        expect(retried).toEqual({
            type: "send_message",
            request_id: first.request_id,
            text: "recover me",
            after: 1,
        });
        sockets[1]!.emit("message", {
            data: JSON.stringify({
                type: "turn_terminal",
                sequence: 2,
                request_id: first.request_id,
                status: 200,
                body: { outcome: "completed" },
            }),
        });
        await expect(turn).resolves.toEqual({ outcome: "completed" });
        api.dispose();
        vi.useRealTimers();
    });

    it("repairs a cursor gap from the last contiguous event", async () => {
        vi.useFakeTimers();
        const sockets: FakeWebSocket[] = [];
        vi.stubGlobal("fetch", vi.fn());
        vi.stubGlobal(
            "WebSocket",
            class extends FakeWebSocket {
                constructor(url: string) {
                    super(url);
                    sockets.push(this);
                }
            },
        );
        const api = new EdgeSessionApi(
            "https://panels.gaugewright.com/d/theory-a",
            "sess_0123456789abcdef0123456789abcdef" as EngagementId,
            "resume-capability",
            "connection-capability",
            Date.now() + 15 * 60 * 1000,
            null,
            false,
        );
        const ready = api.ready();
        sockets[0]!.emit("open");
        sockets[0]!.emit("message", {
            data: JSON.stringify({
                type: "session_ready",
                snapshot: { cursor: 0, transcript: [], files: [] },
            }),
        });
        await ready;
        const events: StreamEvent[] = [];
        api.subscribe("ignored" as EngagementId, (event) => events.push(event));

        sockets[0]!.emit("message", {
            data: JSON.stringify({
                type: "text_delta",
                sequence: 2,
                request_id: "turn-1",
                delta: "must not skip sequence one",
            }),
        });
        expect(sockets[0]!.readyState).toBe(FakeWebSocket.CLOSED);
        expect(events).toEqual([]);

        await vi.advanceTimersByTimeAsync(100);
        expect(sockets).toHaveLength(2);
        expect(sockets[1]!.url).not.toContain("after=");
        sockets[1]!.emit("open");
        sockets[1]!.emit("message", {
            data: JSON.stringify({
                type: "session_ready",
                snapshot: { cursor: 0, transcript: [], files: [] },
            }),
        });
        sockets[1]!.emit("message", {
            data: JSON.stringify({
                type: "text_delta",
                sequence: 1,
                request_id: "turn-1",
                delta: "replayed",
            }),
        });
        expect(events).toEqual([{ type: "text", delta: "replayed" }]);
        api.dispose();
        vi.useRealTimers();
    });
});
