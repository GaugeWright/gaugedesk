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
import { type FilterPrefs } from "./transcript-filter";
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
    /** Desktop already owns the panel container; preserve direct flex children. */
    readonly bare?: boolean;
}

function SessionComposer(props: { session: Session; audience: boolean }): JSX.Element {
    const [draft, setDraft] = createSignal("");
    // WhippleScript 0.3.1 (DR-0050) removed `ask_human`: no turn parks waiting
    // for a person, so the composer has one mode. An agent that needs something
    // sends on a channel or files a task; the reply is an ordinary message.
    const submit = () => {
        const text = draft().trim();
        if (!text) return;
        if (props.session.busy?.()) return;
        setDraft("");
        props.session.send(text);
    };
    return (
        <>
            <ChatComposer
                    draft={draft()}
                    placeholder="task the agent…"
                    busy={props.session.busy?.() ?? false}
                    canSubmit={draft().trim().length > 0}
                    audience={props.audience}
                    onDraft={setDraft}
                    onSubmit={() => submit()}
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

export function ChatPanel(props: ChatPanelProps): JSX.Element {
    // Solid has no hook-order restriction; short-circuiting lets direct-handle
    // hosts pass a leaf while normal panel mounts consume SessionProvider.
    const ambient = props.session ? undefined : useSession();
    const session = () => props.session ?? ambient!;
    const body = () => (
        <>
            <Show when={props.audience === true}>
                <AudienceChats session={session()} />
            </Show>
            <div
                class="transcript"
                data-embed-transcript={props.audience ? "" : undefined}
                data-pending-send={props.pendingSend}
            >
                <TranscriptView
                    lines={session().transcript().lines}
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
