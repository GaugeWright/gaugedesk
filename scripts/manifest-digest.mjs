// The canonical digest of a product-route manifest.
//
// This repository owns `contracts/product-routes.json`, so it owns what that
// file's digest *is*. The digest is not a hash of the bytes: a manifest
// rewritten with different key order or different whitespace is the same
// contract, and two artifacts built from it must agree that it is. Canonical
// JSON — object keys sorted, arrays left in order, no formatting — is what
// makes that true.
//
// It has one owning source because it is a cross-repository artifact. The
// hosted surfaces stamp this digest into `gaugewright-release.json` and a
// deployment gate compares them; a second implementation that sorted
// differently would make two correct artifacts look like skew, which is
// precisely the failure the digest exists to detect.

import { createHash } from "node:crypto";

/** Key-sorted, order-preserving projection of a parsed JSON value. */
export function canonical(value) {
    if (Array.isArray(value)) return value.map(canonical);
    if (value && typeof value === "object") {
        return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
    }
    return value;
}

/** The sha256 of a parsed manifest in canonical form. */
export function digest(value) {
    return createHash("sha256").update(JSON.stringify(canonical(value))).digest("hex");
}

/** The sha256 of a manifest still in its serialized form. */
export function manifestDigest(body) {
    return digest(JSON.parse(body));
}
