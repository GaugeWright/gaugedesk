// The composer's model picker when a shared project's chat has nothing to run
// on: it says why instead of opening on an empty list (DR-0476 §2).
import { createComponent } from "solid-js";
import { render } from "solid-js/web";
import { afterEach, expect, it } from "vitest";
import { ComposerModelBar } from "./ComposerModelBar";

let dispose: (() => void) | undefined;
afterEach(() => {
    dispose?.();
    dispose = undefined;
    document.body.replaceChildren();
});

function mount(props: Partial<Parameters<typeof ComposerModelBar>[0]>) {
    const host = document.createElement("div");
    document.body.append(host);
    dispose = render(() => createComponent(ComposerModelBar, {
        options: [],
        value: "",
        onPick: () => undefined,
        onAddModel: () => undefined,
        ...props,
    }), host);
    host.querySelector<HTMLButtonElement>("[data-model-picker]")!.click();
    return host;
}

it("says the owner linked no key to a shared project, and offers no way to add one", () => {
    const reason = "The owner hasn't linked a model key to this project.";
    const host = mount({ unavailable: reason });
    const button = host.querySelector<HTMLButtonElement>("[data-model-picker]")!;
    expect(button.textContent).toContain("No model");
    expect(button.title).toBe(reason);
    expect(host.querySelector("[data-model-unavailable]")?.textContent?.trim()).toBe(reason);
    expect(host.querySelector("[data-add-model]")).toBeNull();
});

it("offers to add a model where the person can, as before", () => {
    const host = mount({});
    expect(host.querySelector("[data-model-picker]")!.textContent).toContain("Select model");
    expect(host.querySelector("[data-model-unavailable]")).toBeNull();
    expect(host.querySelector("[data-add-model]")).not.toBeNull();
});

it("lists the models there are, and says nothing about a key", () => {
    const host = mount({
        options: [{ id: "owner-model", provider: "openai-generic", label: "owner-model", thinking: ["off"] }],
        unavailable: undefined,
    });
    expect(host.querySelector('[data-model-option="openai-generic:owner-model"]')).not.toBeNull();
    expect(host.querySelector("[data-model-unavailable]")).toBeNull();
});
