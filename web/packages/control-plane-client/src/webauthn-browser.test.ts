import { describe, expect, it } from "vitest";
import { registrationResponseJSON } from "./webauthn-browser";

describe("account passkey registration wire", () => {
    it("places the attestation fields where the server's RegistrationResponse reads them", () => {
        const credential = {
            id: "browser-id",
            rawId: Uint8Array.of(1, 2).buffer,
            type: "public-key",
            authenticatorAttachment: "cross-platform",
            response: {
                attestationObject: Uint8Array.of(3, 4).buffer,
                clientDataJSON: Uint8Array.of(5, 6).buffer,
                getTransports: () => ["hybrid"],
            },
            getClientExtensionResults: () => ({}),
        } as unknown as PublicKeyCredential;

        expect(registrationResponseJSON(credential)).toEqual({
            id: "AQI",
            transports: ["hybrid"],
            attestationObject: "AwQ",
            clientDataJSON: "BQY",
        });
    });
});
