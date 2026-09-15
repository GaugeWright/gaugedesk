/**
 * The passkey door: how a person obtains a hosted account.
 *
 * Consumer OIDC resolves an existing subject link before minting a session
 * (ADR 0146) and cannot create an account, so on a fresh deployment this is
 * the only way in. Both tests that need an account share this rather than
 * each growing its own ceremony.
 *
 * Every request is an ordinary `fetch` from the page under test, so the
 * browser applies the real origin, cookie and CORS rules. The WebAuthn step
 * is Chromium's own implementation driven by a CDP virtual authenticator, so
 * the credential is really created and really verified.
 */

/** Attach a CTAP2 platform authenticator. Returns a disposer. */
export async function attachVirtualAuthenticator(context, page) {
    const cdp = await context.newCDPSession(page);
    await cdp.send("WebAuthn.enable");
    const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
        options: {
            protocol: "ctap2",
            transport: "internal",
            hasResidentKey: true,
            hasUserVerification: true,
            isUserVerified: true,
            automaticPresenceSimulation: true,
        },
    });
    return async () => {
        await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId });
    };
}

/** Begin the verified-email proof. Returns the challenge id. */
export async function beginEmailProof(page, apiOrigin, email) {
    const result = await page.evaluate(async ([api, address]) => {
        const response = await fetch(`${api}/auth/account/email/start`, {
            method: "POST",
            credentials: "include",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ email: address }),
        });
        return { status: response.status, body: await response.json().catch(() => null) };
    }, [apiOrigin, email]);
    if (result.status !== 202 || typeof result.body?.challenge_id !== "string") {
        throw new Error(`email proof did not start: ${JSON.stringify(result)}`);
    }
    return result.body.challenge_id;
}

/**
 * Complete the proof and create the first passkey, returning the account id.
 *
 * The server sets its session as an HttpOnly cookie; nothing here reads a
 * bearer, because there isn't one to read.
 */
export async function completePasskeyAccount(page, apiOrigin, { challengeId, code, displayName }) {
    const result = await page.evaluate(async ([api, challenge, verification, name]) => {
        const b64urlToBytes = (value) => {
            const padded = value.replace(/-/g, "+").replace(/_/g, "/");
            const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
            return Uint8Array.from(binary, (character) => character.charCodeAt(0));
        };
        const bytesToB64url = (buffer) =>
            btoa(String.fromCharCode(...new Uint8Array(buffer)))
                .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
        const post = async (path, body) => {
            const response = await fetch(`${api}${path}`, {
                method: "POST",
                credentials: "include",
                headers: { "content-type": "application/json" },
                body: JSON.stringify(body),
            });
            const parsed = await response.json().catch(() => null);
            if (!response.ok) {
                throw new Error(`${path} returned ${response.status}: ${JSON.stringify(parsed)}`);
            }
            return parsed;
        };

        const verified = await post("/auth/account/email/complete", {
            challenge_id: challenge,
            code: verification,
        });
        const started = await post("/auth/account/passkey/register/start", {
            email_verification: verified.email_verification,
            display_name: name,
        });
        // The server sends base64url; the platform API wants ArrayBuffers.
        const options = started.public_key?.publicKey ?? started.public_key;
        const credential = await navigator.credentials.create({
            publicKey: {
                ...options,
                challenge: b64urlToBytes(options.challenge),
                user: { ...options.user, id: b64urlToBytes(options.user.id) },
                excludeCredentials: (options.excludeCredentials ?? []).map((descriptor) => ({
                    ...descriptor,
                    id: b64urlToBytes(descriptor.id),
                })),
            },
        });
        if (!credential || credential.type !== "public-key") {
            throw new Error("the authenticator created no credential");
        }
        const finished = await post("/auth/account/passkey/register/finish", {
            ceremony_id: started.ceremony_id,
            label: "Passkey",
            credential: {
                id: bytesToB64url(credential.rawId),
                transports: credential.response.getTransports?.() ?? [],
                attestationObject: bytesToB64url(credential.response.attestationObject),
                clientDataJSON: bytesToB64url(credential.response.clientDataJSON),
            },
        });
        return finished.account_id;
    }, [apiOrigin, challengeId, code, displayName]);
    if (typeof result !== "string" || !result) {
        throw new Error(`passkey account was not created: ${JSON.stringify(result)}`);
    }
    return result;
}
