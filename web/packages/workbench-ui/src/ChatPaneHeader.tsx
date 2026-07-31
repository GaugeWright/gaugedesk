/** Canonical desktop chat-pane header shared by every workbench Environment. */
import { Show, type JSX } from "solid-js";
import { PanelCollapseIcon } from "./PanelCollapseIcon";
export type ChatPaneStatusTone = "ready" | "working" | "review" | "conflict" | "error";

export interface ChatPaneHeaderProps {
    /** The shell supplies the persistent CHAT label; this is only a selected-chat title. */
    readonly title?: string;
    readonly lineage?: string;
    readonly lineageKind?: string;
    readonly targetLabel?: string;
    readonly targetTitle?: string;
    readonly statusLabel?: string;
    readonly statusTone?: ChatPaneStatusTone;
    readonly statusPhase?: string;
    readonly statusTitle?: string;
    readonly mobile: boolean;
    readonly actions?: JSX.Element;
    readonly onCollapse: () => void;
}

export function ChatPaneHeader(props: ChatPaneHeaderProps): JSX.Element {
    return (
        <h2 class="chat-heading">
            <Show when={!props.mobile}>
                <button
                    class="panel-collapse left"
                    data-collapse="run"
                    type="button"
                    title="Hide Chat"
                    aria-label="Hide Chat"
                    onClick={props.onCollapse}
                >
                    <PanelCollapseIcon direction="left" />
                </button>
            </Show>
            <Show when={props.title}>
                <span class="chat-title" data-chat-title>{props.title}</span>
            </Show>
            <Show when={props.lineage}>
                <span
                    class="chat-lineage"
                    data-chat-lineage
                    data-kind={props.lineageKind}
                    title={`what this chat is working on: ${props.lineage}`}
                >
                    {props.lineage}
                </span>
            </Show>
            <Show when={props.targetLabel}>
                <span class="chat-target-status" data-chat-target title={props.targetTitle}>
                    {props.targetLabel}
                </span>
            </Show>
            <Show when={props.statusLabel}>
                <span
                    class="status-badge"
                    data-testid="run-phase"
                    data-status={props.statusTone ?? "ready"}
                    data-run-phase={props.statusPhase}
                    title={props.statusTitle}
                >
                    <Show when={props.statusTone === "working"}><span class="status-dot" /></Show>
                    {props.statusLabel}
                </span>
            </Show>
            {props.actions}
        </h2>
    );
}
