import { createMemo, createResource, createSignal, onCleanup, Show, type Accessor, type JSX } from "solid-js";
import { engagementId } from "@gaugewright/control-plane-client";
import { ChatPanel, ChatPaneHeader, Icon, localTurnActivity, type Session, type Transcript } from "@gaugewright/workbench-ui";
import type { ManagementSession, ManagementTarget, WorkbenchControlPlane } from "./workbench-control-plane";

/** How the chat names its GaugeApp. It carries no notice or placeholder: an
 *  empty settings chat is an empty composer (DR-0308). */
export interface ManagementChatCopy {
    /** "Project settings" — the agent's name and the loading/error subject. */
    readonly label: string;
}

export const MANAGEMENT_CHAT_COPY: Record<ManagementTarget["app"], ManagementChatCopy> = {
    "project-settings": { label: "Project settings" },
    "agent-settings": { label: "Agent settings" },
    "panel-settings": { label: "Panel settings" },
};

interface SettingsProps {
    readonly api: WorkbenchControlPlane;
    readonly target: ManagementTarget;
    /** The managed thing's name, shown in the chat header. */
    readonly name: string;
    readonly mobile: boolean;
    readonly onCollapse: () => void;
    readonly onChanged: () => void | Promise<void>;
}

/** An admitted controller owns its transport, streaming transcript and command
 * lifetimes. Sharing the chat surface must not admit a second session or move
 * that controller's scope onto the settings Home transport. */
interface OwnedProps {
    readonly ownedSession: Accessor<Session | undefined>;
    readonly label: string;
    readonly name: string;
    readonly kind: "management" | "settings";
    readonly mobile: boolean;
    readonly onCollapse: () => void;
    readonly composerPlaceholder: string;
    readonly fallback: JSX.Element;
    readonly menu: JSX.Element;
    readonly beforeComposer: JSX.Element;
    readonly afterComposer: JSX.Element;
}

/** The bounded management conversation of any GaugeApp the Home serves. */
export function ManagementChat(props: SettingsProps | OwnedProps): JSX.Element {
    return "ownedSession" in props
        ? <ManagementChatPresentation {...props} />
        : <SettingsManagementChat {...props} />;
}

function ManagementChatPresentation(props: OwnedProps): JSX.Element {
    return <Show when={props.ownedSession()} fallback={props.fallback}>
        {(active) => <>
            <ChatPaneHeader branch={props.name} kind={props.kind}
                statusLabel={active().busy() ? "Working" : "Ready"}
                mobile={props.mobile} onCollapse={props.onCollapse} menu={props.menu} />
            {props.beforeComposer}
            <ChatPanel session={active()} bare agentName={props.label}
                composerPlaceholder={props.composerPlaceholder} />
            {props.afterComposer}
        </>}
    </Show>;
}

function SettingsManagementChat(props: SettingsProps): JSX.Element {
    const copy = () => MANAGEMENT_CHAT_COPY[props.target.app];
    const [session, { refetch: refetchSession }] = createResource(() => props.target,
        (target) => props.api.openManagement(target));
    const [messages, { refetch: refetchMessages }] = createResource(
        () => session() ? { target: props.target, session: session()! } : undefined,
        ({ target, session }) => props.api.managementMessages(target, session),
    );
    const [busy, setBusy] = createSignal(false);
    const [error, setError] = createSignal("");
    const [confirmClear, setConfirmClear] = createSignal(false);
    onCleanup(() => {
        const admitted = session();
        if (admitted && busy()) void props.api.stopManagement(props.target, admitted).catch(() => undefined);
    });
    const transcript = createMemo<Transcript>(() => ({
        openText: null,
        lines: (messages() ?? []).map((message) => ({
            seq: message.sequence, tier: "admitted" as const,
            kind: message.role, text: message.text,
        })),
    }));
    const current = (admitted: ManagementSession, target: ManagementTarget) =>
        session()?.id === admitted.id && props.target.app === target.app && props.target.id === target.id;
    const send = async (text: string, _images: readonly unknown[] = [], composedId?: string) => {
        const admitted = session();
        const target = props.target;
        if (!admitted) throw new Error(`${copy().label} are not ready`);
        setError("");
        setBusy(true);
        try {
            await props.api.sendManagementMessage(target, admitted, text, composedId ?? crypto.randomUUID());
            if (!current(admitted, target)) return;
            await refetchMessages();
            await refetchSession();
            await props.onChanged();
        } catch (reason) {
            if (current(admitted, target)) setError(reason instanceof Error ? reason.message : String(reason));
            throw reason;
        } finally {
            if (current(admitted, target)) setBusy(false);
        }
    };
    const stop = async () => {
        const admitted = session();
        if (admitted) await props.api.stopManagement(props.target, admitted);
    };
    const chatSession = createMemo<Session | undefined>(() => {
        const admitted = session();
        if (!admitted) return undefined;
        const target = props.target;
        return {
            api: { getTree: async () => [], getFile: async () => "", putFile: async () => undefined },
            engagementId: () => engagementId(admitted.id),
            project: () => target.app === "project-settings" ? target.id
                : target.app === "panel-settings" ? target.project : null,
            worktreeRev: () => admitted.update_cursor,
            selectedFile: () => null,
            selectFile: () => undefined,
            diff: () => "",
            mergePhase: () => null,
            mergeConflicted: () => false,
            chatKind: () => "work",
            methodName: () => copy().label,
            transcript,
            busy,
            turnActivity: localTurnActivity(busy, transcript),
            composerCapabilities: () => ({ queue: false, steer: false, stop: true, hold: false, fork: false, attachments: [] }),
            canCommand: () => current(admitted, target),
            merge: () => undefined,
            onContentSaved: () => undefined,
            send: send as Session["send"],
            appliesComposedIdOnce: true,
            stop,
        };
    });
    const clearLabel = () => `Clear ${copy().label.toLowerCase()} conversation`;
    return <div class="management-chat" data-management-chat={props.target.app}>
        <ManagementChatPresentation ownedSession={chatSession} label={copy().label}
            name={props.name} kind="settings" mobile={props.mobile} onCollapse={props.onCollapse}
            composerPlaceholder=""
            fallback={<div class="management-chat-loading" role="status">
                {session.error
                    ? <><p>{copy().label} chat is unavailable: {String(session.error)}</p><button type="button" onClick={() => void refetchSession()}>Retry</button></>
                    : `Opening ${copy().label.toLowerCase()}…`}
            </div>}
            menu={<div class="chat-options-anchor"><button type="button" class="chat-options-trigger"
                classList={{ active: confirmClear() }} title={clearLabel()} aria-label={clearLabel()}
                onClick={() => setConfirmClear(true)}><Icon name="menu" /></button></div>}
            beforeComposer={<>
                <Show when={confirmClear()}><div class="management-chat-confirm" role="alert">
                    <span>Clear this conversation?</span>
                    <button type="button" onClick={() => setConfirmClear(false)}>Cancel</button>
                    <button type="button" class="danger" disabled={busy()} onClick={() => {
                        const admitted = session();
                        if (!admitted) return;
                        void props.api.eraseManagement(props.target, admitted)
                            .then(() => refetchMessages())
                            .then(() => { setConfirmClear(false); setError(""); })
                            .catch((reason) => setError(reason instanceof Error ? reason.message : String(reason)));
                    }}>Clear</button>
                </div></Show>
                <Show when={messages.error}><p class="management-chat-error" role="alert">Could not load this conversation. <button type="button" onClick={() => void refetchMessages()}>Retry</button></p></Show>
                <Show when={error()}>{(reason) => <p class="management-chat-error" role="alert">{reason()}</p>}</Show>
            </>}
            afterComposer={null}
        />
    </div>;
}
