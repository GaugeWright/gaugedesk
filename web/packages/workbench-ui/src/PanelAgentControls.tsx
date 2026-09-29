/**
 * The controls the Panel-agent surfaces share (PANEL-12).
 *
 * `Option` is every yes/no and every one-of-few choice: the box or dot first,
 * where the eye and the pointer land, then the name, then a quiet line saying
 * what it does. One row, not a card.
 */

import { Show, type JSX } from "solid-js";
import "./panel-agent.css";

export function Option(props: {
    type: "checkbox" | "radio";
    name?: string;
    checked: boolean;
    disabled?: boolean;
    title?: string;
    onChange: (checked: boolean) => void;
    label: JSX.Element;
    detail?: JSX.Element;
}): JSX.Element {
    return <label class="pa-option" classList={{ disabled: !!props.disabled }} title={props.title}>
        <input type={props.type} name={props.name} checked={props.checked} disabled={props.disabled}
            onChange={(event) => props.onChange(event.currentTarget.checked)} />
        <span><strong>{props.label}</strong><Show when={props.detail}><small>{props.detail}</small></Show></span>
    </label>;
}
