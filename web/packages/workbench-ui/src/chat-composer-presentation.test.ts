import { describe, expect, it } from "vitest";
import { immediateDestinationPresentation } from "./ChatComposer";

describe("immediate composer language", () => {
    it("reserves steering language for a host that can interrupt", () => {
        expect(immediateDestinationPresentation(true, false, false)).toEqual({
            label: "Steer",
            detail: "Run it now",
        });
        expect(immediateDestinationPresentation(true, true, true)).toEqual({
            label: "Steer",
            detail: "Run it now, interrupting the turn in flight",
        });
    });

    it("presents a non-steering management message as Send", () => {
        expect(immediateDestinationPresentation(false, false, false)).toEqual({
            label: "Send",
            detail: "Send it now",
        });
        expect(immediateDestinationPresentation(false, true, false)).toEqual({
            label: "Send",
            detail: "Wait for the current turn to finish",
        });
        expect(immediateDestinationPresentation(false, true, true)).toEqual({
            label: "Send",
            detail: "Add it to the queue",
        });
    });
});
