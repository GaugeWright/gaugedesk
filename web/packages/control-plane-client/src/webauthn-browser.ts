/** Browser WebAuthn wire conversion shared by account entry, fresh
 * authorization, and Account Settings. The server owns every challenge and
 * verifies every response; these helpers only translate WebAuthn's binary
 * browser values to and from its base64url JSON contract. */

const record = (value: unknown): Record<string, unknown> => {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
        throw new Error("WebAuthn response is malformed.");
    }
    return value as Record<string, unknown>;
};

const text = (value: unknown): string => {
    if (typeof value !== "string" || !value) throw new Error("WebAuthn response is malformed.");
    return value;
};

const values = (value: unknown): readonly unknown[] => value == null
    ? []
    : Array.isArray(value)
        ? value
        : (() => { throw new Error("WebAuthn response is malformed."); })();

function decodeBase64Url(value: string): ArrayBuffer {
    const base64 = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
    try {
        const bytes = Uint8Array.from(atob(base64), (character) => character.charCodeAt(0));
        return bytes.buffer;
    } catch {
        throw new Error("WebAuthn response is malformed.");
    }
}

function encodeBase64Url(value: ArrayBuffer): string {
    const bytes = new Uint8Array(value);
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function publicKeyCreationOptions(value: unknown): PublicKeyCredentialCreationOptions {
    const envelope = record(value);
    const raw = envelope.publicKey == null ? envelope : record(envelope.publicKey);
    const user = record(raw.user);
    const excludeCredentials = values(raw.excludeCredentials).map((item) => {
        const descriptor = record(item);
        return { ...descriptor, id: decodeBase64Url(text(descriptor.id)) } as PublicKeyCredentialDescriptor;
    });
    return {
        ...raw,
        challenge: decodeBase64Url(text(raw.challenge)),
        user: { ...user, id: decodeBase64Url(text(user.id)) } as PublicKeyCredentialUserEntity,
        excludeCredentials,
    } as PublicKeyCredentialCreationOptions;
}

export function registrationCredentialJSON(credential: PublicKeyCredential): Record<string, unknown> {
    const response = credential.response as AuthenticatorAttestationResponse;
    return {
        id: credential.id,
        rawId: encodeBase64Url(credential.rawId),
        type: credential.type,
        authenticatorAttachment: credential.authenticatorAttachment,
        response: {
            attestationObject: encodeBase64Url(response.attestationObject),
            clientDataJSON: encodeBase64Url(response.clientDataJSON),
            transports: typeof response.getTransports === "function" ? response.getTransports() : [],
        },
        clientExtensionResults: credential.getClientExtensionResults(),
    };
}

export function publicKeyRequestOptions(value: unknown): PublicKeyCredentialRequestOptions {
    const envelope = record(value);
    const raw = envelope.publicKey == null ? envelope : record(envelope.publicKey);
    const allowCredentials = values(raw.allowCredentials).map((item) => {
        const descriptor = record(item);
        return { ...descriptor, id: decodeBase64Url(text(descriptor.id)) } as PublicKeyCredentialDescriptor;
    });
    return {
        ...raw,
        challenge: decodeBase64Url(text(raw.challenge)),
        allowCredentials,
    } as PublicKeyCredentialRequestOptions;
}

export function authenticationCredentialJSON(credential: PublicKeyCredential): Record<string, unknown> {
    const response = credential.response as AuthenticatorAssertionResponse;
    return {
        id: credential.id,
        rawId: encodeBase64Url(credential.rawId),
        type: credential.type,
        authenticatorAttachment: credential.authenticatorAttachment,
        response: {
            authenticatorData: encodeBase64Url(response.authenticatorData),
            clientDataJSON: encodeBase64Url(response.clientDataJSON),
            signature: encodeBase64Url(response.signature),
            userHandle: response.userHandle ? encodeBase64Url(response.userHandle) : null,
        },
        clientExtensionResults: credential.getClientExtensionResults(),
    };
}
