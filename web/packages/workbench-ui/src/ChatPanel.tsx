/**
 * The one shared chat panel (ADR 0076). Environments choose this panel through
 * their manifest; they do not implement another transcript/composer pair.
 *
 * A placement may supply a richer composer (desktop queue, steering, model and
 * attachment controls). Remote/audience environments use the panel's default
 * Session-backed composer. The panel shell and transcript are shared either way.
 */
import {createSignal, Show, type JSX} from "solid-js";
import { ChatComposer } from "./ChatComposer";
import { AudienceChats } from "./AudienceChats";
import {
    createSessionComposerController,
    type SessionComposerController,
} from "./session-composer-controller";
import { type FilterPrefs } from "./transcript-filter";
import { type TranscriptLine } from "./transcript";
import { TranscriptView } from "./TranscriptView";
import { type Session, useSession } from "./session-context";

export interface ChatPanelProps {
    /** Explicit leaf for hosts that mount without an ambient provider. */
    readonly session?: Session;
    /** Optional pre-bound controller for owner Environments and quick-start. */
    readonly composerController?: SessionComposerController;
    readonly composerInputRef?: (element: HTMLTextAreaElement) => void;
    readonly composerPlaceholder?: string;
    /** Live working/stop row rendered after the shared transcript. */
    readonly transcriptTail?: JSX.Element;
    readonly prefs?: FilterPrefs;
    readonly onResolveCredential?: () => void;
    readonly pendingSend?: string;
    /** Audience presentation carries deployment-controlled attribution. */
    readonly audience?: boolean;
    /** Host-authored first assistant line; presentation-only, never runtime truth. */
    readonly openingMessage?: string;
    /** Human-readable assistant name used in transcript labels and the composer. */
    readonly agentName?: string;
    /** Desktop already owns the panel container; preserve direct flex children. */
    readonly bare?: boolean;
}

export function SessionComposer(props: {
    session?: Session;
    audience: boolean;
    agentName?: string;
    placeholder?: string;
    controller?: SessionComposerController;
    inputRef?: (element: HTMLTextAreaElement) => void;
    quickStart?: boolean;
}): JSX.Element {
    if (!props.session && !props.controller) {
        throw new Error("SessionComposer requires a Session or a bound controller");
    }
    const session = props.session;
    const controller = props.controller ?? createSessionComposerController({
        scope: () => String(session!.engagementId() ?? "session"),
        busy: session!.busy,
        capabilities: session!.composerCapabilities,
        send: (text, images, options) => session!.send(text, images, options),
        stop: session!.stop,
        runtime: session!.composerRuntime,
    });
    const hasAttachments = () => controller.capabilities().attachments.length > 0;
    const hasQueue = () => controller.capabilities().queue;
    const canSteer = () => controller.capabilities().steer;
    return (
        <ChatComposer
            draft={controller.draft()}
            placeholder={props.placeholder ?? (props.agentName?.trim() ? `Ask ${props.agentName.trim()}…` : "task the agent…")}
            queue={hasQueue() ? controller.queue() : []}
            attachments={controller.attachments()}
            busy={controller.busy()}
            gated={controller.gated()}
            reviewNext={controller.reviewNext()}
            canSubmit={controller.canSubmit()}
            error={controller.error()}
            attaching={controller.attaching()}
            audience={props.audience}
            quickStart={props.quickStart}
            modelToolbar={controller.modelToolbar?.()}
            onDraft={controller.setDraft}
            onSubmit={controller.submit}
            onSteer={canSteer() ? controller.steer : undefined}
            onStop={controller.capabilities().stop ? controller.stop : undefined}
            onToggleGate={controller.capabilities().stage ? controller.toggleGate : undefined}
            onToggleReview={controller.toggleReview}
            onAttachInput={hasAttachments() ? (event) => {
                const input = event.currentTarget;
                const files = Array.from(input.files ?? []);
                input.value = "";
                void controller.attachFiles(files);
            } : undefined}
            onPasteFiles={hasAttachments() ? controller.attachFiles : undefined}
            onRemoveAttachment={controller.removeAttachment}
            onReorderQueue={hasQueue() ? controller.reorderQueue : undefined}
            onEditQueue={hasQueue() ? controller.editQueued : undefined}
            onRemoveQueue={hasQueue() ? controller.removeQueued : undefined}
            onSendNow={hasQueue() ? controller.sendNowQueued : undefined}
            inputRef={props.inputRef}
        />
    );
}

function NewSessionButton(props: { session: Session }): JSX.Element {
    const [starting, setStarting] = createSignal(false);
    const [failed, setFailed] = createSignal(false);
    const start = async () => {
        if (starting() || props.session.busy?.()) return;
        setFailed(false);
        setStarting(true);
        try {
            await props.session.api.embedNewChat?.();
        } catch {
            setFailed(true);
        } finally {
            setStarting(false);
        }
    };
    return (
        <Show when={props.session.api.embedNewChat}>
            <button
                type="button"
                class="embed-new-session"
                data-new-embed-session
                disabled={starting() || props.session.busy?.() === true}
                onClick={() => void start()}
            >
                {starting() ? "Starting…" : "New session"}
            </button>
            <Show when={failed()}>
                <span class="embed-new-session-error" role="status">
                    Could not start a new session.
                </span>
            </Show>
        </Show>
    );
}

export function ChatPanel(props: ChatPanelProps): JSX.Element {
    // Solid has no hook-order restriction; short-circuiting lets direct-handle
    // hosts pass a leaf while normal panel mounts consume SessionProvider.
    const ambient = props.session ? undefined : useSession();
    const session = () => props.session ?? ambient!;
    const lines = (): readonly TranscriptLine[] => {
        const opening = props.openingMessage?.trim();
        const transcript = session().transcript().lines;
        if (!opening) return transcript;
        return [
            {
                seq: -1,
                tier: "operational",
                kind: "assistant",
                text: opening,
            },
            ...transcript,
        ];
    };
    const body = () => (
        <>
            <Show when={props.audience === true}>
                <div class="embed-chat-toolbar" data-embed-chat-toolbar>
                    <AudienceChats session={session()} />
                    <NewSessionButton session={session()} />
                </div>
            </Show>
            <div
                class="transcript"
                data-embed-transcript={props.audience ? "" : undefined}
                data-pending-send={props.pendingSend}
            >
                <TranscriptView
                    lines={lines()}
                    agentName={props.agentName}
                    onOpen={session().selectFile}
                    prefs={props.prefs}
                    onResolveCredential={props.onResolveCredential}
                    onFork={session().forkAt}
                />
                {props.transcriptTail}
            </div>
            <SessionComposer
                session={session()}
                audience={props.audience === true}
                agentName={props.agentName}
                placeholder={props.composerPlaceholder}
                controller={props.composerController}
                inputRef={props.composerInputRef}
            />
        </>
    );
    return props.bare ? body() : (
        <div
            class="embed-chat"
            data-chat-panel
            data-embed-chat={props.audience ? "" : undefined}
        >
            {body()}
        </div>
    );
}
