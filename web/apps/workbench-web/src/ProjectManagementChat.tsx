import { createMemo, createResource, createSignal, onCleanup, Show, type JSX } from "solid-js";
import { engagementId, type ProjectId } from "@gaugewright/control-plane-client";
import { ChatPanel, ChatPaneHeader, localTurnActivity, type Session, type Transcript } from "@gaugewright/workbench-ui";
import type { ProjectManagementSession, WorkbenchControlPlane } from "./workbench-control-plane";

interface Props {
    readonly api: WorkbenchControlPlane;
    readonly project: ProjectId;
    readonly name: string;
    readonly mobile: boolean;
    readonly onCollapse: () => void;
    readonly onChanged: () => void | Promise<void>;
}

export function ProjectManagementChat(props: Props): JSX.Element {
    const [session, { refetch: refetchSession }] = createResource(() => props.project,
        (project) => props.api.openProjectManagement(project));
    const [messages, { refetch: refetchMessages }] = createResource(
        () => session() ? { project: props.project, session: session()! } : undefined,
        ({ project, session }) => props.api.projectManagementMessages(project, session),
    );
    const [busy, setBusy] = createSignal(false);
    const [error, setError] = createSignal("");
    const [confirmClear, setConfirmClear] = createSignal(false);
    onCleanup(() => {
        const admitted = session();
        if (admitted && busy()) void props.api.stopProjectManagement(props.project, admitted).catch(() => undefined);
    });
    const transcript = createMemo<Transcript>(() => ({
        openText: null,
        lines: (messages() ?? []).map((message) => ({
            seq: message.sequence, tier: "admitted" as const,
            kind: message.role, text: message.text,
        })),
    }));
    const current = (admitted: ProjectManagementSession, project: ProjectId) =>
        session()?.id === admitted.id && props.project === project;
    const send = async (text: string, _images: readonly unknown[] = [], composedId?: string) => {
        const admitted = session();
        const project = props.project;
        if (!admitted) throw new Error("Project settings are not ready");
        setError("");
        setBusy(true);
        try {
            await props.api.sendProjectManagementMessage(project, admitted, text, composedId ?? crypto.randomUUID());
            if (!current(admitted, project)) return;
            await refetchMessages();
            await refetchSession();
            await props.onChanged();
        } catch (reason) {
            if (current(admitted, project)) setError(reason instanceof Error ? reason.message : String(reason));
            throw reason;
        } finally {
            if (current(admitted, project)) setBusy(false);
        }
    };
    const stop = async () => {
        const admitted = session();
        if (admitted) await props.api.stopProjectManagement(props.project, admitted);
    };
    const chatSession = createMemo<Session | undefined>(() => {
        const admitted = session();
        if (!admitted) return undefined;
        const project = props.project;
        return {
            api: { getTree: async () => [], getFile: async () => "", putFile: async () => undefined },
            engagementId: () => engagementId(admitted.id),
            project: () => project,
            worktreeRev: () => admitted.update_cursor,
            selectedFile: () => null,
            selectFile: () => undefined,
            diff: () => "",
            mergePhase: () => null,
            mergeConflicted: () => false,
            chatKind: () => "work",
            methodName: () => "Project settings",
            transcript,
            busy,
            turnActivity: localTurnActivity(busy, transcript),
            composerCapabilities: () => ({ queue: false, steer: false, stop: true, hold: false, fork: false, attachments: [] }),
            canCommand: () => current(admitted, project),
            merge: () => undefined,
            onContentSaved: () => undefined,
            send: send as Session["send"],
            appliesComposedIdOnce: true,
            stop,
        };
    });
    return <div class="project-management-chat">
        <Show when={chatSession()} fallback={<div class="project-management-chat-loading" role="status">
            {session.error ? <><p>Project settings chat is unavailable: {String(session.error)}</p><button type="button" onClick={() => void refetchSession()}>Retry</button></> : "Opening project settings…"}
        </div>}>
            {(active) => <>
                <ChatPaneHeader branch={props.name} kind="management" statusLabel={busy() ? "Working" : "Ready"}
                    mobile={props.mobile} onCollapse={props.onCollapse}
                    menu={<button type="button" class="project-management-chat-menu" title="Clear project settings conversation"
                        aria-label="Clear project settings conversation" onClick={() => setConfirmClear(true)}>⋯</button>} />
                <Show when={confirmClear()}><div class="project-management-chat-confirm" role="alert">
                    <span>Clear this conversation?</span>
                    <button type="button" onClick={() => setConfirmClear(false)}>Cancel</button>
                    <button type="button" class="danger" disabled={busy()} onClick={() => {
                        const admitted = session();
                        if (!admitted) return;
                        void props.api.eraseProjectManagement(props.project, admitted)
                            .then(() => refetchMessages())
                            .then(() => { setConfirmClear(false); setError(""); })
                            .catch((reason) => setError(reason instanceof Error ? reason.message : String(reason)));
                    }}>Clear</button>
                </div></Show>
                <Show when={messages.error}><p class="project-management-chat-error" role="alert">Could not load this conversation. <button type="button" onClick={() => void refetchMessages()}>Retry</button></p></Show>
                <Show when={error()}>{(reason) => <p class="project-management-chat-error" role="alert">{reason()}</p>}</Show>
                <ChatPanel session={active()} bare agentName="Project settings"
                    notice="Ask about this project's settings or request a change."
                    composerPlaceholder="ask about this project…" />
            </>}
        </Show>
    </div>;
}
