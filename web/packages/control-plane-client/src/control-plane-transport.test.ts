import { describe, expect, it } from "vitest";
import {
    isSecureControlPlaneEndpoint,
    resolveControlPlaneBase,
    SOLO_CONTROL_PLANE,
} from "./control-plane-transport";

const store = (v: string | null): Pick<Storage, "getItem"> => ({ getItem: () => v });

describe("resolveControlPlaneBase - solo vs enterprise control plane (DEPLOY-5)", () => {
    it("defaults to the co-resident solo control plane with no query or storage", () => {
        expect(resolveControlPlaneBase("", store(null))).toBe(SOLO_CONTROL_PLANE);
        expect(resolveControlPlaneBase("?foo=1", store(null))).toBe(SOLO_CONTROL_PLANE);
    });

    it("uses a persisted enterprise org control-plane endpoint when set", () => {
        expect(resolveControlPlaneBase("", store("https://cp.acme.example"))).toBe(
            "https://cp.acme.example",
        );
    });

    it("lets an explicit cp query override win over the persisted endpoint", () => {
        expect(resolveControlPlaneBase("?cp=http://localhost:9999", store("https://cp.acme.example"))).toBe(
            "http://localhost:9999",
        );
    });

    it("tolerates null storage when no enterprise endpoint is available", () => {
        expect(resolveControlPlaneBase("", null)).toBe(SOLO_CONTROL_PLANE);
        expect(resolveControlPlaneBase("?cp=https://x", null)).toBe("https://x");
    });
});

describe("isSecureControlPlaneEndpoint - channel encryption (ENTSEC-3)", () => {
    it("accepts https and loopback, and refuses non-loopback plaintext", () => {
        expect(isSecureControlPlaneEndpoint("https://cp.acme.example")).toBe(true);
        expect(isSecureControlPlaneEndpoint("http://127.0.0.1:7878")).toBe(true);
        expect(isSecureControlPlaneEndpoint("http://localhost:7879")).toBe(true);
        expect(isSecureControlPlaneEndpoint("http://cp.acme.example")).toBe(false);
        expect(isSecureControlPlaneEndpoint("not a url")).toBe(false);
    });

    it("resolveControlPlaneBase ignores an insecure endpoint and fails safe to solo", () => {
        expect(resolveControlPlaneBase("?cp=http://evil.example", store(null))).toBe(SOLO_CONTROL_PLANE);
        expect(resolveControlPlaneBase("", store("http://evil.example"))).toBe(SOLO_CONTROL_PLANE);
        expect(resolveControlPlaneBase("", store("https://cp.acme.example"))).toBe("https://cp.acme.example");
    });
});
