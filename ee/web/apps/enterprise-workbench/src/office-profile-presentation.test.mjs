import assert from "node:assert/strict";
import test from "node:test";
import { officeProfilePresentation, OFFICE_PROFILE_COMMAND } from "./office-profile-presentation.ts";

const available = { state: "available", this_home: "home:front-office" };

test("enrollment names the Project Host and waits for an explicit acknowledgement", () => {
    const before = officeProfilePresentation(available, [OFFICE_PROFILE_COMMAND], false);
    assert.equal(before.host, "home:front-office");
    assert.equal(before.offerEnrollment, true);
    assert.equal(before.enrollPayload, null, "nothing is submitted before the acknowledgement");
    assert.match(before.detail, /permanent/);
    assert.doesNotMatch(before.detail, /hosted routes/, "enrollment does not yet close the hosted data routes (WS-426)");
    const after = officeProfilePresentation(available, [OFFICE_PROFILE_COMMAND], true);
    assert.deepEqual(after.enrollPayload, { home_id: "home:front-office" });
});

test("a person without the command is told who can enroll and is offered nothing", () => {
    const view = officeProfilePresentation(available, ["organization-policy.set"], true);
    assert.equal(view.offerEnrollment, false);
    assert.equal(view.enrollPayload, null);
    assert.match(view.detail, /administrator/);
});

test("an enrolled organization is shown as permanent and never offered enrollment again", () => {
    const view = officeProfilePresentation(
        { state: "enrolled", home_id: "home:front-office", this_home: "home:front-office", bound_here: true, enrolled_by: "authority:admin", enrolled_at_ms: 1 },
        [OFFICE_PROFILE_COMMAND],
        true,
    );
    assert.equal(view.status, "Enrolled");
    assert.equal(view.offerEnrollment, false);
    assert.equal(view.enrollPayload, null);
    assert.match(view.detail, /no way to leave/);
});

test("a binding to another Project Host warns that this Home serves no office staff", () => {
    const view = officeProfilePresentation(
        { state: "enrolled", home_id: "home:front-office", this_home: "home:restored-copy", bound_here: false, enrolled_by: "authority:admin", enrolled_at_ms: 1 },
        [OFFICE_PROFILE_COMMAND],
        true,
    );
    assert.equal(view.tone, "warn");
    assert.equal(view.host, "home:front-office");
    assert.match(view.detail, /another Project Host/);
});

test("an unavailable profile shows the server's reason and no action", () => {
    const view = officeProfilePresentation(
        { state: "unavailable", this_home: "home:hosted", reason: "a hosted Home cannot hold the office-controlled profile" },
        [OFFICE_PROFILE_COMMAND],
        true,
    );
    assert.equal(view.offerEnrollment, false);
    assert.match(view.detail, /hosted Home/);
});
