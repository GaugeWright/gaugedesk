import { createSignal, For, Show, type JSX } from "solid-js";
import type { ArchetypeNode, ProjectNode } from "@gaugewright/control-plane-client";

export function PanelAgentPreview(props: {
    agent: ArchetypeNode;
    project?: ProjectNode;
    onClose: () => void;
}): JSX.Element {
    const profile = () => props.agent.panelProfile;
    const [activePanel, setActivePanel] = createSignal(profile()?.panels.default_component ?? "gw-chat");
    const [draft, setDraft] = createSignal("");
    const [messages, setMessages] = createSignal<Array<{ from: "visitor" | "agent"; text: string }>>([]);
    const [outputs, setOutputs] = createSignal<string[]>([]);

    function send() {
        const text = draft().trim();
        if (!text) return;
        setMessages((current) => [...current, { from: "visitor", text }, {
            from: "agent",
            text: "Preview response — the public runtime will execute this Panel-agent version with the frozen provider and abilities.",
        }]);
        setOutputs((current) => [...current, `preview-${current.length + 1}.json`]);
        setDraft("");
    }

    return <div class="modal-overlay" role="presentation" onClick={(event) => {
        if (event.target === event.currentTarget) props.onClose();
    }}><section class="modal embed-monitor" role="dialog" aria-modal="true" aria-label={`Preview ${props.agent.name}`}>
        <header class="modal-head"><div><strong>{props.agent.name} · Preview</strong>
            <div class="muted">Disposable public session · {props.project ? `${props.project.name} configuration` : "Library draft"}</div></div>
            <button type="button" class="icon-button" aria-label="Close" onClick={props.onClose}>×</button></header>
        <div class="settings-hint warn">Preview output is isolated. It does not enter a project Inbox or create a Personal chat.</div>
        <Show when={profile()} fallback={<p class="error">This Panel agent has no public profile.</p>}>
            {(contract) => <>
                <div class="deployment-actions" role="tablist" aria-label="Published panels">
                    <For each={contract().panels.components}>{(panel) => <button type="button"
                        classList={{ active: activePanel() === panel }} onClick={() => setActivePanel(panel)}>
                        {panel.replace(/^gw-/, "")}
                    </button>}</For>
                </div>
                <div class="deployment-preview">
                    <Show when={activePanel() === "gw-chat"} fallback={<div class="status" style={{ padding: "24px" }}>
                        {activePanel().replace(/^gw-/, "")} panel mounted from the frozen profile.
                    </div>}>
                        <div style={{ padding: "12px", overflow: "auto", height: "calc(100% - 54px)" }}>
                            <For each={messages()} fallback={<p class="muted">Start a visitor session to exercise the declared public contract.</p>}>
                                {(message) => <p class="member-row"><strong>{message.from === "visitor" ? "Visitor" : props.agent.name}</strong><span>{message.text}</span></p>}
                            </For>
                        </div>
                        <div class="deployment-actions" style={{ padding: "8px", "border-top": "1px solid var(--edge)" }}>
                            <input class="settings-input" style={{ flex: "1" }} value={draft()} placeholder="Visitor message…"
                                onInput={(event) => setDraft(event.currentTarget.value)} onKeyDown={(event) => event.key === "Enter" && send()} />
                            <button type="button" class="primary" onClick={send}>Send</button>
                        </div>
                    </Show>
                </div>
                <section class="admin-section"><h3>Contract under test</h3><div class="member-list">
                    <div class="member-row"><span>Abilities</span><span class="member-id">{contract().public_abilities.join(", ") || "Chat only"}</span></div>
                    <div class="member-row"><span>Inputs</span><span class="member-id">{contract().audience_inputs.join(", ")}</span></div>
                    <div class="member-row"><span>Provider</span><span class="member-id">{contract().provider.provider} · {contract().provider.model}</span></div>
                    <div class="member-row"><span>Preview output</span><span class="member-id">{outputs().length ? outputs().join(", ") : "None"}</span></div>
                </div></section>
            </>}
        </Show>
    </section></div>;
}
