// The notice above the navigator when the selected Home did not answer and desk
// opened on the projects shared with the person instead (WS-1036).
import { createComponent } from "solid-js";
import { render } from "solid-js/web";
import { afterEach, expect, it, vi } from "vitest";
import { SilentHomeNotice } from "./SilentHomeNotice";

let dispose: (() => void) | undefined;
afterEach(() => {
    dispose?.();
    dispose = undefined;
    document.body.replaceChildren();
});

it("says which Home is silent, and offers trying it again or using another of the account's Homes", () => {
    const host = document.createElement("div");
    document.body.append(host);
    const onRetry = vi.fn();
    const onSelect = vi.fn();
    dispose = render(() => createComponent(SilentHomeNotice, {
        home: "home:local-user" as never,
        homes: [
            { id: "home:local-user" as never, kind: "registered", endpoint: "" },
            { id: "home:cloud" as never, kind: "cloud", endpoint: "https://cloud.example" },
        ],
        busy: false,
        onRetry,
        onSelect,
    }), host);
    const notice = host.querySelector<HTMLElement>("[data-silent-home]");
    expect(notice?.getAttribute("role")).toBe("status");
    // Named as the person knows it: every desktop's id is home:local-user.
    expect(notice?.textContent).toContain("Your desktop Home isn’t responding");
    expect(notice?.textContent).not.toContain("home:local-user");
    host.querySelector<HTMLButtonElement>("[data-silent-home-retry]")!.click();
    expect(onRetry).toHaveBeenCalledOnce();
    // Only the account's other Homes are offered.
    const choices = [...host.querySelectorAll<HTMLButtonElement>("[data-home-choice]")];
    expect(choices.map((choice) => choice.dataset.homeChoice)).toEqual(["home:cloud"]);
    expect(choices[0]!.textContent).toBe("Use cloud.example");
    choices[0]!.click();
    expect(onSelect).toHaveBeenCalledWith("home:cloud");
});

it("names a silent Home with an address by its host", () => {
    const host = document.createElement("div");
    document.body.append(host);
    dispose = render(() => createComponent(SilentHomeNotice, {
        home: "home:office" as never,
        homes: [{ id: "home:office" as never, kind: "registered", endpoint: "https://office.example:8443" }],
        busy: false,
        onRetry: () => undefined,
        onSelect: () => undefined,
    }), host);
    expect(host.textContent).toContain("Your Home at office.example isn’t responding");
    expect(host.querySelector("[data-home-choice]")).toBeNull();
});
