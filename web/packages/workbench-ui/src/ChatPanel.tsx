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
import {
    buildOutgoing,
    classifyAttachment,
    fileToBase64,
    type Attachment,
} from "./attachments";
import { AudienceChats } from "./AudienceChats";
import { type FilterPrefs } from "./transcript-filter";
import { type TranscriptLine } from "./transcript";
import { TranscriptView } from "./TranscriptView";
import { type Session, useSession } from "./session-context";

export interface ChatPanelProps {
    /** Explicit leaf for hosts that mount without an ambient provider. */
    readonly session?: Session;
    /** Desktop supplies its owner-grade queue/steer/model composer here. */
    readonly composer?: JSX.Element;
    /** Live working/stop row rendered after the shared transcript. */
    readonly transcriptTail?: JSX.Element;
    readonly prefs?: FilterPrefs;
    readonly onResolveCredential?: () => void;
    readonly pendingSend?: string;
    /** Audience presentation carries deployment-controlled attribution. */
    readonly audience?: boolean;
    /** Host-authored first assistant line; presentation-only, never runtime truth. */
    readonly openingMessage?: string;
    /** Desktop already owns the panel container; preserve direct flex children. */
    readonly bare?: boolean;
}

function SessionComposer(props: { session: Session; audience: boolean }): JSX.Element {
    const [draft, setDraft] = createSignal("");
    const [attachments, setAttachments] = createSignal<Attachment[]>([]);
    // WhippleScript 0.3.1 (DR-0050) removed `ask_human`: no turn parks waiting
    // for a person, so the composer has one mode. An agent that needs something
    // sends on a channel or files a task; the reply is an ordinary message.
    const submit = () => {
        const outgoing = buildOutgoing(draft(), attachments());
        if (!outgoing.message.trim()) return;
        if (props.session.busy?.()) return;
        setDraft("");
        setAttachments([]);
        props.session.send(outgoing.message, outgoing.images);
    };
    const pasteImages = async (files: readonly File[]) => {
        const images: Attachment[] = [];
        for (const file of files) {
            if (classifyAttachment(file) !== "image") continue;
            images.push({
                kind: "image",
                name: file.name || "pasted image",
                mimeType: file.type,
                data: await fileToBase64(file),
            });
        }
        if (images.length > 0) setAttachments((current) => [...current, ...images]);
    };
    return (
        <>
            <ChatComposer
                    draft={draft()}
                    placeholder="task the agent…"
                    attachments={attachments()}
                    busy={props.session.busy?.() ?? false}
                    canSubmit={draft().trim().length > 0 || attachments().length > 0}
                    audience={props.audience}
                    onDraft={setDraft}
                    onSubmit={() => submit()}
                    onPasteFiles={pasteImages}
                    onRemoveAttachment={(index) =>
                        setAttachments((current) => current.filter((_, at) => at !== index))
                    }
                    onStop={
                        props.session.stop
                            ? () => {
                                  void props.session.stop!();
                              }
                            : undefined
                    }
                />
        </>
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
                    onOpen={session().selectFile}
                    prefs={props.prefs}
                    onResolveCredential={props.onResolveCredential}
                    onFork={session().forkAt}
                />
                {props.transcriptTail}
            </div>
            {props.composer ?? (
                <SessionComposer session={session()} audience={props.audience === true} />
            )}
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
