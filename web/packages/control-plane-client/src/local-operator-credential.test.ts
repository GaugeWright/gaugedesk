import { afterEach, describe, expect, it, vi } from "vitest";
import { browserRouteRequest } from "./browser-route-json";
import {
    LOCAL_OPERATOR_HEADER,
    localOperatorCredentialFor,
    registerLocalOperatorCredential,
    resetLocalOperatorCredentialForTest,
} from "./local-operator-credential";

afterEach(() => {
    resetLocalOperatorCredentialForTest();
    vi.unstubAllGlobals();
});

function capturedHeaders() {
    const calls: Headers[] = [];
    vi.stubGlobal("fetch", vi.fn(async (_url: string, init: RequestInit) => {
        calls.push(new Headers(init.headers));
        return new Response("{}", { status: 200 });
    }));
    return calls;
}

describe("the desktop window's local operator credential", () => {
    it("goes only to the registered local control plane", async () => {
        registerLocalOperatorCredential("http://127.0.0.1:7878", Promise.resolve("s3cret"));
        expect(await localOperatorCredentialFor("http://127.0.0.1:7878/workspace")).toBe("s3cret");
        expect(await localOperatorCredentialFor("http://127.0.0.1:7878/account/hub-session/home/h/x")).toBe("s3cret");
        // A different port, host or scheme is a different origin.
        expect(await localOperatorCredentialFor("http://127.0.0.1:7911/workspace")).toBeNull();
        expect(await localOperatorCredentialFor("http://localhost:7878/workspace")).toBeNull();
        expect(await localOperatorCredentialFor("https://home.example.com/workspace")).toBeNull();
    });

    it("is sent by no one until the window registers it", async () => {
        expect(await localOperatorCredentialFor("http://127.0.0.1:7878/workspace")).toBeNull();
    });

    it("sends nothing when the shell issued none or refused", async () => {
        registerLocalOperatorCredential("http://127.0.0.1:7878", Promise.resolve(null));
        expect(await localOperatorCredentialFor("http://127.0.0.1:7878/workspace")).toBeNull();
        registerLocalOperatorCredential("http://127.0.0.1:7878", Promise.reject(new Error("no command")));
        expect(await localOperatorCredentialFor("http://127.0.0.1:7878/workspace")).toBeNull();
    });

    it("rides every request the shared builder makes to that origin, and none elsewhere", async () => {
        const calls = capturedHeaders();
        registerLocalOperatorCredential("http://127.0.0.1:7878", Promise.resolve("s3cret"));
        await browserRouteRequest("http://127.0.0.1:7878")("/workspace");
        await browserRouteRequest("http://127.0.0.1:7878/")("/chats", { method: "POST" });
        await browserRouteRequest("https://home.example.com")("/workspace");
        expect(calls.map((headers) => headers.get(LOCAL_OPERATOR_HEADER))).toEqual(["s3cret", "s3cret", null]);
    });

    it("waits for the shell's answer, so a request made at startup still carries it", async () => {
        const calls = capturedHeaders();
        let answer!: (secret: string) => void;
        registerLocalOperatorCredential("http://127.0.0.1:7878", new Promise((resolve) => { answer = resolve; }));
        const pending = browserRouteRequest("http://127.0.0.1:7878")("/workspace");
        answer("late");
        await pending;
        expect(calls[0].get(LOCAL_OPERATOR_HEADER)).toBe("late");
    });
});
