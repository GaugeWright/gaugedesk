import assert from "node:assert/strict";
import test from "node:test";
import {
    applyAppearancePreference,
    resetAppearancePreference,
} from "./appearance-preference.ts";

function root() {
    return { dataset: {} };
}

test("appearance applies only the closed server preference to the Desk root", () => {
    const element = root();
    const preference = {
        version: 1,
        interface_scale: "large",
        contrast: "high",
        motion: "reduced",
    };
    applyAppearancePreference(preference, element);
    assert.deepEqual(element.dataset, {
        gwInterfaceScale: "large",
        gwContrast: "high",
        gwMotion: "reduced",
    });
});

test("appearance reset removes the previous account's choices", () => {
    const element = root();
    applyAppearancePreference({ version: 1, interface_scale: "large", contrast: "high", motion: "reduced" }, element);
    resetAppearancePreference(element);
    assert.deepEqual(element.dataset, {
        gwInterfaceScale: "standard",
        gwContrast: "standard",
        gwMotion: "system",
    });
});
