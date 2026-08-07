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
import {
    type Session,
    type TurnActivity as Activity,
    type TurnObservation,
    useSession,
} from "./session-context";
import { liveToolVerb } from "./tool-verb";

/** One label per live-turn state, keyed by the shared vocabulary so a state
 *  added to `TURN_ACTIVITIES` cannot compile without a phrase to show for it.
 *
 *  `streaming_output` is intentionally blank: the answer text arriving in the
 *  transcript is itself the indicator, and a status line under it would only
 *  narrate what the reader is already watching. */
const ACTIVITY_LABEL: Record<Activity, (name: string, observation: TurnObservation) => string> = {
    idle: () => "",
    awaiting_model: (name) => `${name} is thinking`,
    streaming_output: () => "",
    // The tool's name is the reason this state earns a line at all: a ten-second
    // pause reads completely differently as "running a command".
    running_tool: (name, observation) =>
        observation.tool ? `${name} is ${liveToolVerb(observation.tool)}` : `${name} is using a tool`,
    compacting: (name) => `${name} is making room for more context`,
    retrying: (name) => `${name} is retrying`,
    settling: (name) => `${name} is finishing up`,
    stopping: (name) => `Stopping ${name}`,
};

function TurnActivity(props: { session: Session; agentName?: string }): JSX.Element {
    const observation = () => props.session.turnActivity();
    const label = () =>
        ACTIVITY_LABEL[observation().state](props.agentName?.trim() || "Agent", observation());
    return (
        <Show when={label() !== ""}>
            <div
                class="turn-activity"
                data-turn-activity={observation().state}
                data-turn-tool={observation().tool}
                role="status"
                aria-live="polite"
            >
                <span>{label()}</span>
                <span class="turn-activity-dots" aria-hidden="true"><i /><i /><i /></span>
            </div>
        </Show>
    );
}

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
        canCommand: session!.canCommand,
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
            blocked={controller.blocked()}
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
                <TurnActivity session={session()} agentName={props.agentName} />
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
