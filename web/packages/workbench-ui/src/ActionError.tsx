/**
 * The failure of an action the reader just took, shown where they took it.
 *
 * A failure written only to a status line that is not on screen reads as a
 * button that did nothing. This renders nothing until there is a failure, says
 * what failed in the action's own words, and stays until it is dismissed or
 * replaced by the next failure. Routine success is never shown here.
 */

import { Show, type JSX } from "solid-js";

export function ActionError(props: {
    /** The failure to show; empty renders nothing. */
    readonly message: string;
    readonly onDismiss: () => void;
    /** Which surface this notice belongs to, for tests and styling. */
    readonly where?: string;
}): JSX.Element {
    return (
        <Show when={props.message}>
            <div class="action-error" role="alert" data-action-error={props.where ?? ""}>
                <span>{props.message}</span>
                <button type="button" aria-label="Dismiss" title="Dismiss" onClick={() => props.onDismiss()}>✕</button>
            </div>
        </Show>
    );
}
