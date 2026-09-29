import { describe, expect, it } from "vitest";
import { openingPressGuard } from "./ContextMenu";

// WebKit on macOS reports a Control-click as `contextmenu` followed by a primary
// `click` from the same press. That click opened the nav chat the menu was on,
// moved the cursor to the composer, and dismissed the menu as it opened.

function harness() {
    const target = new EventTarget();
    const guard = openingPressGuard(target);
    const reached: string[] = [];
    // Registered after the guard, standing in for the row's delegated handler and
    // the menu's outside-click dismissal.
    target.addEventListener("click", () => reached.push("click"));
    // A click's `detail` counts the presses behind it; one from the keyboard or a
    // script has none. (`CustomEvent` carries a `detail` where Node has no MouseEvent.)
    const dispatchClick = (detail: number) => {
        const event = new CustomEvent("click", { cancelable: true, detail });
        target.dispatchEvent(event);
        return event;
    };
    const click = () => dispatchClick(1);
    const keyboardClick = () => dispatchClick(0);
    const press = () => target.dispatchEvent(new Event("pointerdown"));
    const key = () => target.dispatchEvent(new Event("keydown"));
    return { guard, reached, click, keyboardClick, press, key };
}

describe("openingPressGuard", () => {
    it("swallows the click that finishes the press that opened the menu", () => {
        const { guard, reached, click } = harness();
        guard.arm();
        expect(click().defaultPrevented).toBe(true);
        expect(reached).toEqual([]);
    });

    it("lets clicks through while no menu has opened", () => {
        const { reached, click, press } = harness();
        press();
        expect(click().defaultPrevented).toBe(false);
        expect(reached).toEqual(["click"]);
    });

    it("swallows one click, not the next", () => {
        const { guard, reached, click } = harness();
        guard.arm();
        click();
        click();
        expect(reached).toEqual(["click"]);
    });

    it("lets a new press's click through, as when the opening press sent none", () => {
        const { guard, reached, click, press } = harness();
        guard.arm();
        press();
        click();
        expect(reached).toEqual(["click"]);
    });

    it("lets a keyboard-activated click through", () => {
        const { guard, reached, keyboardClick } = harness();
        guard.arm();
        expect(keyboardClick().defaultPrevented).toBe(false);
        expect(reached).toEqual(["click"]);
    });

    it("still swallows the opening press's click when a key lands before it", () => {
        const { guard, reached, click, key } = harness();
        guard.arm();
        key();
        click();
        expect(reached).toEqual([]);
    });

    it("stops listening once disposed", () => {
        const { guard, reached, click } = harness();
        guard.arm();
        guard.dispose();
        click();
        expect(reached).toEqual(["click"]);
    });
});
