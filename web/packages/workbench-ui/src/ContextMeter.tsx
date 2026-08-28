/**
 * The composer's **context-window meter**: how much of the model's window this
 * chat is currently carrying.
 *
 * It sits at the far end of the rail as a bare ring. A gauge is read as a
 * fraction — mostly empty, half gone, nearly full — and that is the whole reason
 * to glance at it; the digits were a second, slower way of saying the same thing
 * in a rail that is trying to be quiet. The exact counts live in the tooltip,
 * where you go when the glance is not enough.
 *
 * Quiet until it isn't: muted through the ordinary range, warn past 75%, bad past
 * 90%, where the next long turn is what starts dropping history.
 */
import { type JSX } from "solid-js";

export interface ContextUsage {
    /** Tokens the next turn would carry (prompt + transcript + attachments). */
    readonly used: number;
    /** The pinned model's context window. */
    readonly limit: number;
}

const CIRCUMFERENCE = 2 * Math.PI * 5;

export function ContextMeter(props: {
    readonly usage: ContextUsage;
    readonly onCompact?: () => void;
    readonly compactDisabled?: boolean;
}): JSX.Element {
    const fraction = () =>
        props.usage.limit > 0 ? Math.min(1, Math.max(0, props.usage.used / props.usage.limit)) : 0;
    const percent = () => Math.round(fraction() * 100);
    const tone = () => (percent() >= 90 ? "bad" : percent() >= 75 ? "warn" : "ok");
    const ring = () => (
        <span
            class="context-meter"
            data-context-meter
            data-tone={tone()}
            title={`Context: ${format(props.usage.used)} of ${format(props.usage.limit)} tokens used (${percent()}%)`}
        >
            <svg class="context-ring" viewBox="0 0 12 12" aria-hidden="true">
                <circle cx="6" cy="6" r="5" class="context-ring-track" />
                {/* Starts at 12 o'clock and fills clockwise: the dash carries the
                    used arc, the gap the rest. */}
                <circle
                    cx="6"
                    cy="6"
                    r="5"
                    class="context-ring-fill"
                    stroke-dasharray={`${(fraction() * CIRCUMFERENCE).toFixed(2)} ${CIRCUMFERENCE.toFixed(2)}`}
                    transform="rotate(-90 6 6)"
                />
            </svg>
        </span>
    );
    return props.onCompact ? (
        <button
            type="button"
            class="context-compact"
            data-context-compact
            disabled={props.compactDisabled}
            aria-label="Compact context now"
            title={props.compactDisabled
                ? "Context can be compacted while the agent is running"
                : "Compact context now using the runtime's selected compactor"}
            onClick={props.onCompact}
        >
            {ring()}
        </button>
    ) : ring();
}

function format(tokens: number): string {
    if (tokens >= 1_000_000) return `${(tokens / 1_000_000).toFixed(1)}M`;
    if (tokens >= 1_000) return `${Math.round(tokens / 1_000)}k`;
    return String(tokens);
}
