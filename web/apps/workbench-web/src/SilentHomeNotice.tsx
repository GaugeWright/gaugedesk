import { For, Show } from "solid-js";
import type { AccountHome, HomeId } from "@gaugewright/control-plane-client";

/** A Home as a person knows it. An account Home record carries no name, and
 * its id says nothing — every desktop's is `home:local-user` (WS-1024) — so a
 * Home with an address is named by its host, and one reached only through its
 * relay is the person's desktop. */
export function homeDescription(home: AccountHome | undefined): string {
    if (home?.endpoint) {
        try {
            return new URL(home.endpoint).hostname;
        } catch {
            return "your Home";
        }
    }
    if (!home) return "your Home";
    return home.kind === "cloud" ? "your cloud Home" : "your desktop Home";
}

/** The Home that did not answer, as the notice's first words name it. */
function silentSubject(home: AccountHome | undefined): string {
    if (home?.endpoint) return `Your Home at ${homeDescription(home)}`;
    const described = homeDescription(home);
    return described.charAt(0).toUpperCase() + described.slice(1);
}

/**
 * Above the navigator when the account's selected Home did not answer and desk
 * opened on the projects shared with the person instead (WS-1036). It says so
 * plainly, and offers what the Home gate would have: trying that Home again,
 * or using another of the account's Homes. Without it, the person's own
 * projects would be missing with nothing to say why.
 */
export function SilentHomeNotice(props: {
    readonly home: HomeId;
    readonly homes: readonly AccountHome[];
    readonly busy: boolean;
    readonly onRetry: () => void;
    readonly onSelect: (home: HomeId) => void;
}) {
    const silent = () => props.homes.find((home) => home.id === props.home);
    const others = () => props.homes.filter((home) => home.id !== props.home);
    return (
        <div class="homegate-notice silent-home-notice" role="status" data-silent-home={props.home}>
            <span>
                {silentSubject(silent())} isn’t responding, so your own projects aren’t listed.
                Projects shared with you are below.
            </span>
            <button type="button" class="homegate-link" data-silent-home-retry disabled={props.busy}
                onClick={() => props.onRetry()}>
                {props.busy ? "Checking…" : "Try again"}
            </button>
            <Show when={others().length > 0}>
                <For each={others()}>
                    {(other) => (
                        <button type="button" class="homegate-link" data-home-choice={other.id}
                            disabled={props.busy} onClick={() => props.onSelect(other.id)}>
                            Use {homeDescription(other)}
                        </button>
                    )}
                </For>
            </Show>
        </div>
    );
}
