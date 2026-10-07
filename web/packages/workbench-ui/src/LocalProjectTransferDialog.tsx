/**
 * Move signed-out work to the signed-in account (DR-0328 §7).
 *
 * Work done on this computer without signing in belongs to its local account.
 * It reaches an account only by this explicit act, so the dialog names the
 * account and every project before anything moves, and moves only the ones
 * left ticked. Personal is never offered: the server never lists it.
 */

import { createSignal, For, Show, type JSX } from "solid-js";

export interface LocalProjectTransferOffer {
    /** How the receiving account is named to the person. */
    readonly account: string;
    readonly projects: readonly { readonly id: string; readonly name: string }[];
}

export function localProjectTransferLabel(account: string): string {
    return `Move signed-out projects to ${account}`;
}

export function LocalProjectTransferDialog(props: {
    offer: LocalProjectTransferOffer;
    onMove: (projects: readonly string[]) => Promise<void>;
    onClose: () => void;
}): JSX.Element {
    const [chosen, setChosen] = createSignal<ReadonlySet<string>>(
        new Set(props.offer.projects.map((project) => project.id)),
    );
    const [moving, setMoving] = createSignal(false);
    const [error, setError] = createSignal("");
    const count = () => props.offer.projects.filter((project) => chosen().has(project.id)).length;
    const toggle = (id: string, on: boolean) => {
        const next = new Set(chosen());
        if (on) next.add(id);
        else next.delete(id);
        setChosen(next);
        setError("");
    };
    const close = () => {
        if (!moving()) props.onClose();
    };
    const move = async (event: SubmitEvent) => {
        event.preventDefault();
        if (moving() || count() === 0) return;
        setMoving(true);
        setError("");
        try {
            // In the order the person saw them, and only those still ticked.
            await props.onMove(props.offer.projects
                .filter((project) => chosen().has(project.id))
                .map((project) => project.id));
            props.onClose();
        } catch (failure) {
            setError(failure instanceof Error ? failure.message : "The projects could not be moved. Try again.");
        } finally {
            setMoving(false);
        }
    };
    return (
        <div class="modal-overlay" data-local-project-transfer onClick={close}>
            <form
                class="modal create-agent-dialog local-project-transfer"
                role="dialog"
                aria-modal="true"
                aria-labelledby="local-project-transfer-title"
                onClick={(event) => event.stopPropagation()}
                onKeyDown={(event) => event.key === "Escape" && close()}
                onSubmit={(event) => void move(event)}
            >
                <div class="modal-head">
                    <div>
                        <span class="create-agent-eyebrow">This computer</span>
                        <h3 id="local-project-transfer-title">{localProjectTransferLabel(props.offer.account)}</h3>
                    </div>
                    <button type="button" class="create-agent-close" aria-label="Close" disabled={moving()} onClick={close}>×</button>
                </div>
                <p class="create-agent-intro">
                    These projects were made on this computer without signing in.
                    Moving them makes <strong data-local-project-transfer-account>{props.offer.account}</strong> their
                    owner, with their chats, and signed-out use here no longer reaches them.
                    The signed-out Personal project stays where it is.
                </p>
                <fieldset class="local-project-transfer-list" disabled={moving()}>
                    <legend>Projects to move</legend>
                    <For each={props.offer.projects}>
                        {(project) => (
                            <label data-local-project={project.id}>
                                <input
                                    type="checkbox"
                                    checked={chosen().has(project.id)}
                                    onChange={(event) => toggle(project.id, event.currentTarget.checked)}
                                />
                                <span>{project.name}</span>
                            </label>
                        )}
                    </For>
                </fieldset>
                <Show when={error()}><p class="create-agent-error" role="alert">{error()}</p></Show>
                <div class="create-agent-actions">
                    <button type="button" disabled={moving()} onClick={close}>Cancel</button>
                    <button type="submit" class="create-agent-submit" data-local-project-transfer-confirm disabled={moving() || count() === 0}>
                        {moving()
                            ? "Moving…"
                            : `Move ${count()} ${count() === 1 ? "project" : "projects"} to ${props.offer.account}`}
                    </button>
                </div>
            </form>
        </div>
    );
}
