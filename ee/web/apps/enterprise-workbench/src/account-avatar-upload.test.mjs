import assert from "node:assert/strict";
import test from "node:test";
import { AVATAR_UPLOAD_MAX_BYTES, avatarFileProblem, avatarInitials, centreSquare } from "./account-avatar-upload.ts";

test("only the admitted image types under the ceiling are sent", () => {
    assert.equal(avatarFileProblem({ size: 10, type: "image/jpeg" }), null);
    assert.equal(avatarFileProblem({ size: 10, type: "image/webp" }), null);
    // A browser that cannot name the type leaves the decision to the decoder.
    assert.equal(avatarFileProblem({ size: 10, type: "" }), null);
    assert.match(avatarFileProblem({ size: 10, type: "image/svg+xml" }), /PNG, JPEG, WebP or GIF/);
    assert.match(avatarFileProblem({ size: 10, type: "application/pdf" }), /PNG, JPEG, WebP or GIF/);
    assert.match(avatarFileProblem({ size: AVATAR_UPLOAD_MAX_BYTES + 1, type: "image/png" }), /5 MB/);
});

test("the crop is the centred square of the source", () => {
    assert.deepEqual(centreSquare(600, 300), { x: 150, y: 0, side: 300 });
    assert.deepEqual(centreSquare(300, 500), { x: 0, y: 100, side: 300 });
    assert.deepEqual(centreSquare(64, 64), { x: 0, y: 0, side: 64 });
});

test("initials come from the name, or from an address's local part", () => {
    assert.equal(avatarInitials("Ada Lovelace"), "AL");
    assert.equal(avatarInitials("ada"), "A");
    assert.equal(avatarInitials("jamie.o-neil@example.com"), "JO");
    assert.equal(avatarInitials("  Grace   Brewster Hopper "), "GB");
    assert.equal(avatarInitials(""), "?");
});
