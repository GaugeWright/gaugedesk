import { describe, expect, it } from "vitest";
import { captureHomeDiscovery, isHomeAuthenticationFailure } from "./home-bootstrap";

describe("hosted Home bootstrap failure", () => {
    it("recognizes an expired or absent Hub session", () => {
        expect(
            isHomeAuthenticationFailure(
                new Error("GET /account/homes: 401 authenticate to access your account"),
            ),
        ).toBe(true);
    });

    it("keeps availability failures distinct from authentication", () => {
        expect(isHomeAuthenticationFailure(new Error("GET /account/homes: 503 unavailable"))).toBe(
            false,
        );
        expect(isHomeAuthenticationFailure(null)).toBe(false);
    });

    it("resolves an authentication rejection into renderable UI state", async () => {
        await expect(
            captureHomeDiscovery(async () => {
                throw new Error("GET /account/homes: 401 authenticate to access your account");
            }),
        ).resolves.toEqual({
            kind: "failure",
            authentication: true,
            message: "GET /account/homes: 401 authenticate to access your account",
        });
    });

    it("passes a successful Home result through unchanged", async () => {
        const result = { kind: "connected" as const, homeId: "home:cloud:test" };
        await expect(captureHomeDiscovery(async () => result)).resolves.toBe(result);
    });
});
