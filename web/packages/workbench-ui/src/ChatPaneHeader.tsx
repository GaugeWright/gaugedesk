/** The chat lane's branch and kind, between its menu and collapse control. */
import { Show, type JSX } from "solid-js";
import { PanelCollapseIcon } from "./PanelCollapseIcon";

export interface ChatPaneHeaderProps {
    readonly menu?: JSX.Element;
    readonly branch?: string;
    readonly kind?: "work" | "edit" | "management";
    /** The run state remains available to assistive technology and the browser lane. */
    readonly statusLabel?: string;
    readonly statusPhase?: string;
    readonly mobile: boolean;
    readonly onCollapse: () => void;
}

export function ChatPaneHeader(props: ChatPaneHeaderProps): JSX.Element {
    const kindLabel = () => props.kind === "edit" ? "Edit chat"
        : props.kind === "management" ? "Management chat" : "Work chat";
    return (
        <div class="chat-toolbar">
            {props.menu}
            <Show when={props.branch && props.kind}>
                <span class="chat-identity" data-chat-branch={props.branch} data-chat-kind={props.kind}
                    title={`${props.branch} · ${kindLabel()}`}>
                    <span class="chat-identity-branch">{props.branch}</span>
                    <span class="chat-identity-divider" aria-hidden="true">·</span>
                    <span class="chat-identity-kind">{kindLabel()}</span>
                </span>
            </Show>
            <Show when={props.statusLabel}>
                <span
                    class="chat-status-assistive"
                    role="status"
                    data-testid="run-phase"
                    data-run-phase={props.statusPhase}
                >
                    {props.statusLabel}
                </span>
            </Show>
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
        </div>
    );
}
