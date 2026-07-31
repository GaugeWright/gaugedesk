import type { JSX } from "solid-js";

export type PanelCollapseDirection = "left" | "right";

/** One geometry for every desktop panel collapse control. */
export function PanelCollapseIcon(props: {
    readonly direction: PanelCollapseDirection;
}): JSX.Element {
    const points = () => props.direction === "left" ? "8 2 4 6 8 10" : "4 2 8 6 4 10";
    return (
        <svg
            class="panel-collapse-icon"
            data-direction={props.direction}
            viewBox="0 0 12 12"
            aria-hidden="true"
        >
            <polyline points={points()} />
        </svg>
    );
}
