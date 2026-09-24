/**
 * Running a `.whip` file from the chat it is open in (WHIP-3).
 *
 * A Run button sits in the file's header. A workflow with no inputs runs on
 * one click; one with inputs asks for them in a small popover, a person input
 * as a choice of person starting with you. Beside the button, the latest run's
 * status; its history is the file's Runs tab.
 *
 * What runs is the file as kept on its target's Main, never this chat's unkept
 * edits: the Home launches only a revision in Main's history, and the form
 * describes that same revision. The Home steps a run once launched.
 */
import { createSignal, For, Match, onCleanup, onMount, Show, Switch, type JSX } from "solid-js";
import type { ChatWhipDescription, ChatWhipRunView, ProjectWorkflowLaunchResult, RosterPerson, WorkflowInputType } from "@gaugewright/control-plane-client";
import { initialDraft, parseDraft, type Draft } from "./whip-run-form";
import { instanceViewFromV0 } from "./whip-view";
import { WhipInstancesView } from "./WhipViews";

export interface WhipRunApi {
    describe(): Promise<ChatWhipDescription>;
    stop?(run: ChatWhipRunView, key: string): Promise<void>;
    run(run: { path: string; cut: string; inputs: Record<string, unknown>; requestId: string }): Promise<ProjectWorkflowLaunchResult>;
    roster?(): Promise<RosterPerson[]>;
}

// Bumped whenever this client starts a run, so every view of runs — the
// viewer's header and Runs tab, the Files panel's dots — reads them again.
const [runsLaunched, setRunsLaunched] = createSignal(0);
export { runsLaunched };

/** A run's state in plain words, and the tone its dot is drawn in. */
export function runStatus(state: ChatWhipRunView["state"]): { label: string; tone: "active" | "wait" | "ok" | "bad" | "quiet" } {
    switch (state) {
        case "running": return { label: "Running", tone: "active" };
        case "waiting": return { label: "Waiting on a task", tone: "wait" };
        case "completed": return { label: "Finished", tone: "ok" };
        case "failed": return { label: "Failed", tone: "bad" };
        case "cancelled": return { label: "Stopped", tone: "quiet" };
        default: return { label: "Status unknown", tone: "quiet" };
    }
}

/** When a run started, briefly; the runtime's own text when it is not a date. */
export function startedLabel(startedAt: string | null): string {
    if (!startedAt) return "";
    const numeric = /^\d+$/.test(startedAt) ? Number(startedAt) : NaN;
    const date = Number.isFinite(numeric) ? new Date(numeric < 1e12 ? numeric * 1000 : numeric) : new Date(startedAt);
    if (Number.isNaN(date.getTime())) return startedAt;
    const today = new Date().toDateString() === date.toDateString();
    return today
        ? date.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })
        : date.toLocaleString([], { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
}

export function RunDot(props: { state: ChatWhipRunView["state"] }): JSX.Element {
    return <span class="run-dot" data-run-tone={runStatus(props.state).tone} title={runStatus(props.state).label} aria-hidden="true" />;
}

function Field(props: { label: string; type: WorkflowInputType; draft: Draft; onChange: (draft: Draft) => void; people?: RosterPerson[]; me?: string }): JSX.Element {
    const draft = () => props.draft;
    return (
        <Switch fallback={
            <label>{props.label}
                <input type="text" value={draft().kind === "text" ? (draft() as { text: string }).text : ""}
                    onInput={(e) => props.onChange({ kind: "text", text: e.currentTarget.value })} />
            </label>
        }>
            <Match when={draft().kind === "person"}>
                <label>{props.label}
                    <select value={(draft() as { authority: string }).authority}
                        onChange={(e) => props.onChange({ kind: "person", authority: e.currentTarget.value })}>
                        <option value="">Choose a person…</option>
                        <For each={props.people ?? []}>{(person) => (
                            <option value={person.authority}>{person.authority === props.me ? `You (${person.display})` : person.display}</option>
                        )}</For>
                        <Show when={props.me && !(props.people ?? []).some((p) => p.authority === props.me)}>
                            <option value={props.me!}>You</option>
                        </Show>
                    </select>
                </label>
            </Match>
            <Match when={props.type.kind === "int" || props.type.kind === "float"}>
                <label>{props.label}
                    <input type="text" inputMode={props.type.kind === "int" ? "numeric" : "decimal"}
                        value={draft().kind === "text" ? (draft() as { text: string }).text : ""}
                        onInput={(e) => props.onChange({ kind: "text", text: e.currentTarget.value })} />
                </label>
            </Match>
            <Match when={props.type.kind === "bool"}>
                <label class="whip-run-inline">
                    <input type="checkbox" checked={draft().kind === "bool" && (draft() as { value: boolean }).value}
                        onChange={(e) => props.onChange({ kind: "bool", value: e.currentTarget.checked })} /> {props.label}
                </label>
            </Match>
            <Match when={props.type.kind === "enum" && props.type}>
                {(type) => (
                    <label>{props.label}
                        <select value={draft().kind === "choice" ? (draft() as { value: string }).value : ""}
                            onChange={(e) => props.onChange({ kind: "choice", value: e.currentTarget.value })}>
                            <For each={(type() as { variants: string[] }).variants}>{(v) => <option value={v}>{v}</option>}</For>
                        </select>
                    </label>
                )}
            </Match>
            <Match when={props.type.kind === "literal" && props.type}>
                {(type) => <p class="muted">{props.label}: always “{(type() as { value: string }).value}”</p>}
            </Match>
            <Match when={props.type.kind === "optional" && props.type}>
                {(type) => {
                    const current = () => draft() as Extract<Draft, { kind: "optional" }>;
                    return (
                        <div class="whip-run-optional">
                            <label class="whip-run-inline">
                                <input type="checkbox" checked={current().set}
                                    onChange={(e) => props.onChange({ ...current(), set: e.currentTarget.checked })} /> Set {props.label}
                            </label>
                            <Show when={current().set}>
                                <Field label={props.label} type={(type() as { of: WorkflowInputType }).of} draft={current().inner} people={props.people} me={props.me}
                                    onChange={(inner) => props.onChange({ ...current(), inner })} />
                            </Show>
                        </div>
                    );
                }}
            </Match>
            <Match when={props.type.kind === "object" && props.type}>
                {(type) => {
                    const current = () => draft() as Extract<Draft, { kind: "object" }>;
                    const shape = () => type() as Extract<WorkflowInputType, { kind: "object" }>;
                    return (
                        <fieldset class="whip-run-object">
                            <legend>{props.label}{shape().name ? ` (${shape().name})` : ""}</legend>
                            <For each={shape().fields}>{(field) => (
                                <Field label={field.name} type={field.type} draft={current().fields[field.name] ?? initialDraft(field.type, props.me)} people={props.people} me={props.me}
                                    onChange={(next) => props.onChange({ kind: "object", fields: { ...current().fields, [field.name]: next } })} />
                            )}</For>
                        </fieldset>
                    );
                }}
            </Match>
            <Match when={props.type.kind === "json"}>
                <label>{props.label} <span class="muted">(JSON)</span>
                    <textarea value={draft().kind === "text" ? (draft() as { text: string }).text : ""}
                        onInput={(e) => props.onChange({ kind: "text", text: e.currentTarget.value })} />
                </label>
            </Match>
        </Switch>
    );
}

function newRequestId(): string {
    return typeof crypto !== "undefined" && "randomUUID" in crypto ? crypto.randomUUID() : `run-${Date.now()}-${Math.random()}`;
}

function who(run: ChatWhipRunView, people: RosterPerson[] | undefined): string {
    if (run.byYou) return "you";
    return people?.find((person) => person.authority === run.launchedBy)?.display ?? run.launchedBy;
}

/**
 * The file header's Run button, and the latest run's status beside it.
 * `runs` is this file's runs, newest first; `onLaunched` asks for them again.
 */
export function WhipRunControl(props: {
    api: WhipRunApi;
    runs: ChatWhipRunView[];
    me?: string;
    onLaunched: () => void;
    onOpenRuns: () => void;
}): JSX.Element {
    const [open, setOpen] = createSignal<null | "form" | "status">(null);
    const [description, setDescription] = createSignal<ChatWhipDescription | null>(null);
    const [people, setPeople] = createSignal<RosterPerson[] | undefined>();
    const [drafts, setDrafts] = createSignal<Record<string, Draft>>({});
    const [message, setMessage] = createSignal<string | null>(null);
    const [busy, setBusy] = createSignal(false);
    // One request key per intended run, kept across a retry so a lost reply
    // cannot start a second run; a run that started takes a new key.
    let requestId = newRequestId();
    let root: HTMLSpanElement | undefined;
    const latest = () => props.runs[0];
    const me = () => description()?.actor ?? props.me;
    const draftFor = (name: string, type: WorkflowInputType) => drafts()[name] ?? initialDraft(type, me());

    const close = (event: MouseEvent) => {
        if (open() && root && !root.contains(event.target as Node)) setOpen(null);
    };
    onMount(() => document.addEventListener("mousedown", close));
    onCleanup(() => document.removeEventListener("mousedown", close));

    const launch = async (current: ChatWhipDescription) => {
        const inputs: Record<string, unknown> = {};
        for (const input of current.inputs) {
            const parsed = parseDraft(input.type, draftFor(input.name, input.type), input.name);
            if (!parsed.ok) {
                setMessage(parsed.error);
                setOpen("form");
                return;
            }
            inputs[input.name] = parsed.value;
        }
        setBusy(true);
        setMessage(null);
        try {
            await props.api.run({ path: current.path, cut: current.cut, inputs, requestId });
            requestId = newRequestId();
            setDrafts({});
            setOpen(null);
            setRunsLaunched((n) => n + 1);
            props.onLaunched();
        } catch {
            setMessage("It didn’t start. Run again retries the same request, so it can’t start twice.");
            setOpen("form");
        } finally {
            setBusy(false);
        }
    };

    // One key per intended stop, kept across a retry of the same stop.
    let stopKey = newRequestId();
    const stop = async (run: ChatWhipRunView) => {
        setBusy(true);
        setMessage(null);
        try {
            await props.api.stop!(run, stopKey);
            stopKey = newRequestId();
            setOpen(null);
            setRunsLaunched((n) => n + 1);
            props.onLaunched();
        } catch {
            setMessage("It didn’t stop. Stop again retries the same request.");
        } finally {
            setBusy(false);
        }
    };

    const start = async () => {
        if (open() === "form") return setOpen(null);
        setBusy(true);
        setMessage(null);
        try {
            const current = await props.api.describe();
            setDescription(current);
            if (current.inputs.length === 0) {
                setBusy(false);
                return void launch(current);
            }
            if (props.api.roster && !people()) setPeople(await props.api.roster().catch(() => []));
            setOpen("form");
        } catch {
            setDescription(null);
            setMessage("This can’t run: it has to be a kept .whip file that compiles, in a project you can run it in.");
            setOpen("form");
        } finally {
            setBusy(false);
        }
    };

    return (
        <span class="whip-run-control" ref={root} data-whip-run>
            <Show when={latest()}>
                {(run) => (
                    <button type="button" class="run-pill" data-run-status={run().state}
                        onClick={() => setOpen(open() === "status" ? null : "status")}>
                        <RunDot state={run().state} />{runStatus(run().state).label}
                    </button>
                )}
            </Show>
            <button type="button" class="run-button" disabled={busy()} onClick={() => void start()}
                title="Run the kept version of this workflow" aria-label="Run">
                <span aria-hidden="true">▶</span><Show when={!latest()}> Run</Show>
            </button>
            <Show when={open() === "form"}>
                <div class="whip-run-pop" role="dialog" aria-label="Run workflow">
                    <Show when={description()} fallback={<p class="muted" role="status">{message()}</p>}>
                        {(current) => (
                            <form class="whip-run" onSubmit={(event) => { event.preventDefault(); void launch(current()); }}>
                                <strong>Run {current().workflow}</strong>
                                <For each={current().inputs}>{(input) => (
                                    <Field label={input.name} type={input.type} draft={draftFor(input.name, input.type)}
                                        people={people()} me={me()}
                                        onChange={(next) => { setMessage(null); setDrafts({ ...drafts(), [input.name]: next }); }} />
                                )}</For>
                                <p class="muted">Runs the kept version. Anything it assigns shows up in the task bar.</p>
                                <Show when={message()}>{(text) => <p class="whip-run-error" role="alert">{text()}</p>}</Show>
                                <div class="whip-run-actions">
                                    <button type="button" onClick={() => setOpen(null)}>Cancel</button>
                                    <button type="submit" class="primary" disabled={busy()}>Run</button>
                                </div>
                            </form>
                        )}
                    </Show>
                </div>
            </Show>
            <Show when={open() === "status" && latest()}>
                {(run) => (
                    <div class="whip-run-pop" role="dialog" aria-label="Latest run">
                        <p><RunDot state={run().state} /> <strong>{runStatus(run().state).label}</strong></p>
                        <p class="muted">
                            Started {startedLabel(run().startedAt)} by {who(run(), people())}.
                        </p>
                        <Show when={message()}>{(text) => <p class="whip-run-error" role="alert">{text()}</p>}</Show>
                        <div class="whip-run-actions">
                            <Show when={run().canStop && props.api.stop}>
                                <button type="button" disabled={busy()} onClick={() => void stop(run())}>Stop</button>
                            </Show>
                            <button type="button" onClick={() => { setOpen(null); props.onOpenRuns(); }}>All runs</button>
                            <button type="button" class="primary" onClick={() => { setOpen(null); void start(); }}>Run again</button>
                        </div>
                    </div>
                )}
            </Show>
        </span>
    );
}

/** The runs of a file launched from its folder, newest first; each opens to
 *  its firings, drawn exactly as any program's instances are. */
export function WhipRunsView(props: { runs: ChatWhipRunView[] | undefined; error?: boolean; emptyText?: string }): JSX.Element {
    const [openRun, setOpenRun] = createSignal<string | null>(null);
    const keyOf = (run: ChatWhipRunView) => `${run.launchedBy}\u0000${run.requestId}`;
    return (
        <div class="whip-runs" data-whip-runs>
            <Switch>
                <Match when={props.error}>
                    <p class="muted" role="status">This file’s runs can’t be read right now.</p>
                </Match>
                <Match when={!props.runs}>
                    <p class="muted">Reading runs…</p>
                </Match>
                <Match when={props.runs!.length === 0}>
                    <p class="muted">{props.emptyText ?? "No runs yet. Use Run above to start one."}</p>
                </Match>
                <Match when={props.runs}>
                    {(runs) => (
                        <ol>
                            <For each={runs()}>{(run) => (
                                <li data-run-status={run.state}>
                                    <button type="button" class="whip-runs-row" aria-expanded={openRun() === keyOf(run)}
                                        disabled={!run.view}
                                        onClick={() => setOpenRun(openRun() === keyOf(run) ? null : keyOf(run))}>
                                        <RunDot state={run.state} />
                                        <span class="whip-runs-state">{runStatus(run.state).label}</span>
                                        <span class="muted">{startedLabel(run.startedAt)}</span>
                                        <span class="muted">{who(run, undefined)}</span>
                                    </button>
                                    <Show when={openRun() === keyOf(run) && run.view}>
                                        {(view) => <WhipInstancesView instances={[instanceViewFromV0(view())]} />}
                                    </Show>
                                </li>
                            )}</For>
                        </ol>
                    )}
                </Match>
            </Switch>
        </div>
    );
}
