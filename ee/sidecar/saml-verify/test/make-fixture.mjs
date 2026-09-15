// Test helper: mint a signed SAML Response (an IdP simulator) so the verify sidecar
// can be exercised end-to-end without a live IdP. Signs the Assertion with xml-crypto
// (the same dsig engine node-saml verifies with), per the standard SAML recipe.

import { SignedXml } from "xml-crypto";

/** A signed, base64-encoded SAML Response with the given subject + attributes. */
export function makeSignedResponse({ subject, audience, attributes, certPem, keyPem, requestId, recipient = "http://localhost/saml/acs", issuer = "https://idp.example.com/metadata" }) {
    const assertionId = "_assertion-fixture-1";
    // Fixed, long-lived window so a *committed* fixture never expires (test fixtures
    // assert signature/audience, not clock — verify.test.mjs always sits inside it).
    const future = "2099-12-31T23:59:59.000Z";
    const past = "2020-01-01T00:00:00.000Z";

    const attrXml = Object.entries(attributes || {})
        .map(
            ([name, values]) =>
                `<saml:Attribute Name="${name}">` +
                values
                    .map((v) => `<saml:AttributeValue>${v}</saml:AttributeValue>`)
                    .join("") +
                `</saml:Attribute>`,
        )
        .join("");

    const assertion =
        `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ` +
        `Version="2.0" ID="${assertionId}" IssueInstant="${past}">` +
        `<saml:Issuer>${issuer}</saml:Issuer>` +
        `<saml:Subject><saml:NameID>${subject}</saml:NameID>` +
        `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
        `<saml:SubjectConfirmationData NotOnOrAfter="${future}" Recipient="${recipient}"${requestId ? ` InResponseTo="${requestId}"` : ""}/>` +
        `</saml:SubjectConfirmation></saml:Subject>` +
        `<saml:Conditions NotBefore="${past}" NotOnOrAfter="${future}">` +
        `<saml:AudienceRestriction><saml:Audience>${audience}</saml:Audience></saml:AudienceRestriction>` +
        `</saml:Conditions>` +
        `<saml:AttributeStatement>${attrXml}</saml:AttributeStatement>` +
        `</saml:Assertion>`;

    const sig = new SignedXml({ privateKey: keyPem, publicCert: certPem });
    sig.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    sig.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
    sig.addReference({
        xpath: `//*[local-name(.)='Assertion']`,
        transforms: [
            "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
            "http://www.w3.org/2001/10/xml-exc-c14n#",
        ],
        digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
        uri: assertionId,
    });
    sig.computeSignature(assertion, {
        location: {
            reference: `//*[local-name(.)='Assertion']/*[local-name(.)='Issuer']`,
            action: "after",
        },
    });
    const signedAssertion = sig.getSignedXml();

    const response =
        `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
        `xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ` +
        `ID="_response-fixture-1" IssueInstant="${past}"${requestId ? ` InResponseTo="${requestId}"` : ""}>` +
        `<saml:Issuer>${issuer}</saml:Issuer>` +
        `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
        signedAssertion +
        `</samlp:Response>`;

    return Buffer.from(response, "utf8").toString("base64");
}
