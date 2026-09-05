/**
 * **Operating a TokenWright box.** The whole surface: which boxes this account
 * holds, and for the selected one — its engine, the model it runs, the models
 * it holds, its hardware, its security posture, and who may reach it.
 *
 *   ┌──────────┬──────────────────────────────────────────────────┐
 *   │ Boxes    │ key_1c93   ● running  FreeToken 0.3.2  relay ●   │
 *   │ ● 1c93   │ ─ Inference ── Posture ⚠1 ── Access ─            │
 *   │   90ad   │ ┌ Engine ─────────┐ ┌ Model ──────────────────┐  │
 *   │          │ │ ● running  3h   │ │ tinyllama  q4_k_m  2048 │  │
 *   │ + add    │ │ [Stop][Restart] │ │ Requested [▾] [Apply]   │  │
 *   └──────────┴──────────────────────────────────────────────────┘
 *
 * A purpose-built panel rather than the generic document renderer, on purpose:
 * the constrained View shows every field the same way, and a page an operator
 * actually works in needs a status to be a chip, a size to be a bar, a control
 * to appear only when it can succeed. ADR 0161 says as much of the generic
 * shape — "useful pages still needed special components".
 *
 * What is unchanged from the generic path is everything that matters for
 * trust: state comes from the box's documents, every control goes through the
 * box's admission path with a base revision and an idempotency key, and every
 * call goes to the Home, which holds the box's sealed credential. This page
 * never sees a route or a key.
 */

import { createEffect, createMemo, createResource, createSignal, For, onCleanup, Show, type JSX } from "solid-js";
import {
    boxRouteJson,
    claimBox,
    forgetBox,
    listBoxes,
    openManagementEnvironment,
    readManagementDocument,
    type ManagementEnvironmentReceipt,
    type ManagementEnvironmentSession,
    type RouteJson,
    type StoredBox,
} from "@gaugewright/control-plane-client";
import { setTokenWrightDesired, tokenwrightCommandsFrom, type TokenWrightCommandBinding } from "./tokenwright-box";
import type { EnvironmentViewCommand } from "./EnvironmentDocumentView";
import {
    ago,
    engineChangePending,
    engineControls,
    engineLabel,
    engineTone,
    isServedEngine,
    KNOWN_ENGINES,
    mib,
    modelApplyPending,
    modelStateTone,
    orphanedMib,
    percent,
    severityTone,
    undeclaredOnDisk,
    type AccessDocument,
    type InferenceDocument,
    type PostureDocument,
    type Tone,
} from "./tokenwright-panel";

export interface TokenWrightBoxPanelProps {
    /** The Home's transport. Every request goes through it. */
    readonly json: RouteJson;
    /** How often to re-read the open box's documents. */
    readonly pollMs?: number;
}

type Tab = "inference" | "posture" | "access";

interface Opened {
    readonly route: RouteJson;
    readonly session: ManagementEnvironmentSession;
    readonly inference: { content: InferenceDocument; revision: string };
    readonly posture: { content: PostureDocument; revision: string };
    readonly access: { content: AccessDocument; revision: string };
}

interface Toast {
    readonly id: number;
    readonly tone: Tone["tone"];
    readonly text: string;
}

async function openBox(home: RouteJson, box: StoredBox): Promise<Opened> {
    const route = boxRouteJson(home, box.fingerprint);
    const session = await openManagementEnvironment(route, "tokenwright");
    const read = async <T,>(id: string) => {
        const document = await readManagementDocument(route, session, id);
        return { content: document.content as T, revision: document.revision };
    };
    // Sequential on purpose. Each request the Home carries is its own relay
    // leg, and a route holds one client leg at a time — three reads in flight
    // together are three legs racing for one splice, and the relay refuses the
    // losers with "roles are not complementary". Found by doing it the other
    // way: the panel sat on "opening…" with 502s in the console.
    const inference = await read<InferenceDocument>("tokenwright.inference");
    const posture = await read<PostureDocument>("tokenwright.posture");
    const access = await read<AccessDocument>("tokenwright.access");
    return { route, session, inference, posture, access };
}

// --- small pieces ----------------------------------------------------------

function Chip(props: { readonly tone: Tone["tone"]; readonly children: JSX.Element }): JSX.Element {
    return <span class="twb-chip" data-tone={props.tone}>{props.children}</span>;
}

function Stat(props: { readonly label: string; readonly children: JSX.Element; readonly mono?: boolean }): JSX.Element {
    return (
        <div class="twb-stat">
            <div class="twb-stat-label">{props.label}</div>
            <div class="twb-stat-value" classList={{ "twb-mono": props.mono }}>{props.children}</div>
        </div>
    );
}

function Bar(props: { readonly used: number; readonly total: number; readonly tone?: Tone["tone"] }): JSX.Element {
    const pct = () => percent(props.used, props.total);
    return (
        <div class="twb-bar" role="meter" aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct()}>
            <div class="twb-bar-fill" data-tone={props.tone ?? "info"} style={{ width: `${pct()}%` }} />
        </div>
    );
}

function Card(props: { readonly title: string; readonly actions?: JSX.Element; readonly children: JSX.Element; readonly wide?: boolean }): JSX.Element {
    return (
        <section class="twb-card" classList={{ "twb-card-wide": props.wide }}>
            <header class="twb-card-head">
                <h3>{props.title}</h3>
                <div class="twb-card-actions">{props.actions}</div>
            </header>
            {props.children}
        </section>
    );
}

// --- the panel ----------------------------------------------------------------

export function TokenWrightBoxPanel(props: TokenWrightBoxPanelProps): JSX.Element {
    const [generation, setGeneration] = createSignal(0);
    const [selected, setSelected] = createSignal<string | null>(null);
    const [tab, setTab] = createSignal<Tab>("inference");
    const [toasts, setToasts] = createSignal<Toast[]>([]);
    const [busy, setBusy] = createSignal<string | null>(null);
    const [adding, setAdding] = createSignal(false);
    const [pairing, setPairing] = createSignal("");
    const [addError, setAddError] = createSignal<string | null>(null);

    let nextToast = 1;
    function toast(tone: Tone["tone"], text: string): void {
        const id = nextToast++;
        setToasts((held) => [...held, { id, tone, text }]);
        setTimeout(() => setToasts((held) => held.filter((t) => t.id !== id)), 7000);
    }

    const [boxes, { refetch: refetchBoxes }] = createResource(
        generation,
        async () => await listBoxes(props.json),
        { initialValue: [] as readonly StoredBox[] },
    );

    // Pick the first box once the list arrives, so the page is never a blank
    // right pane next to a populated left one.
    createEffect(() => {
        const held = boxes();
        if (!selected() && held.length > 0) setSelected(held[0]!.fingerprint);
        if (selected() && !held.some((b) => b.fingerprint === selected())) setSelected(held[0]?.fingerprint ?? null);
    });

    const selectedBox = createMemo(() => boxes().find((b) => b.fingerprint === selected()) ?? null);

    const [tick, setTick] = createSignal(0);
    // The source is a *string*, and it is built from `selected()` rather than
    // from the box object. A tuple is a new value every time the source
    // function re-runs, and the source re-runs whenever the boxes list is
    // refetched — so the resource fired five times in a row on load, five
    // session dials raced for one relay leg, and the panel sat on "opening…".
    const [opened, { refetch }] = createResource(
        () => (selected() ? `${selected()}#${tick()}` : null),
        async (key) => {
            const fingerprint = key.split("#")[0]!;
            const box = boxes().find((b) => b.fingerprint === fingerprint)
                ?? { fingerprint, relayEndpoint: "", pairedAt: "", homeId: "", keyId: "", sealed: true };
            return await openBox(props.json, box);
        },
    );

    // One open in flight at a time: a poll that fired while the previous read
    // was still crossing the relay would race it for the same leg.
    const interval = setInterval(() => {
        if (selectedBox() && !busy() && !opened.loading) setTick((t) => t + 1);
    }, props.pollMs ?? 4000);
    onCleanup(() => clearInterval(interval));

    const reread = () => { if (!opened.loading) { setTick((t) => t + 1); void refetch(); } };

    /** The last good read, or nothing. Never throws — the raw accessor does
     *  when the resource errored, which would turn a failed poll into a blank
     *  page rather than a stale one with an error banner. */
    const live = createMemo<Opened | undefined>(() => {
        try { return opened.latest; } catch { return undefined; }
    });
    const openError = () => (opened.error as Error | undefined);

    const binding = (): TokenWrightCommandBinding | null => {
        const held = live();
        if (!held) return null;
        return {
            json: held.route,
            session: held.session,
            revisionOf: (id) => ({
                "tokenwright.inference": held.inference.revision,
                "tokenwright.posture": held.posture.revision,
                "tokenwright.access": held.access.revision,
            })[id],
            onReceipt: (receipt: ManagementEnvironmentReceipt) => {
                const tone = receipt.status === "applied" ? "ok" : receipt.status === "conflict" ? "warn" : "bad";
                const label = LABEL[receipt.command_id ?? ""] ?? receipt.command_id ?? "command";
                toast(tone, `${label} — ${receipt.status}`);
            },
        };
    };

    const commands = createMemo<Readonly<Record<string, EnvironmentViewCommand>>>(() => {
        const b = binding();
        return b ? tokenwrightCommandsFrom(b) : {};
    });

    async function run(id: string): Promise<void> {
        const command = commands()[id];
        if (!command || busy()) return;
        setBusy(id);
        try {
            await command.run();
        } catch (error) {
            // The receipt already produced a toast for a rejection; this is for
            // the transport failing before there was one.
            if (!(error instanceof Error && /refused this|changed while/.test(error.message))) {
                toast("bad", error instanceof Error ? error.message : String(error));
            }
        } finally {
            setBusy(null);
            reread();
        }
    }

    /** Write one field of `desired` and reconcile. The whole document goes back
     *  with only that field changed, which is the box's own edit contract. */
    async function patchDesired(patch: Record<string, unknown>, said: string, slot: string): Promise<void> {
        const held = live();
        if (!held || busy()) return;
        setBusy(slot);
        try {
            const receipt = await setTokenWrightDesired(held.route, {
                session: held.session,
                documentId: "tokenwright.inference",
                baseRevision: held.inference.revision,
                // Only the editable block goes back — the box refuses a body
                // that alters a projected field, and several projections here
                // move on their own, so echoing the whole document opted into a
                // race (gaugedesk #… / TokenWright #1).
                desired: { ...held.inference.content.desired, ...patch },
            });
            toast(receipt.status === "applied" ? "ok" : "bad", `${said} — ${receipt.status}`);
        } catch (error) {
            toast("bad", error instanceof Error ? error.message : String(error));
        } finally {
            setBusy(null);
            reread();
        }
    }

    const requestModel = (model: string | null) =>
        patchDesired({ model }, `Requested ${model ?? "no model"}`, "desired.model");

    // Changing the engine restarts the engine unit into the new one; the box
    // holds one at a time. It does not touch the supervisor, the pairing, or the
    // trail — swapping an engine is not a box-level event.
    const requestEngine = (engine: string) =>
        patchDesired({ engine }, `Requested ${engineLabel(engine)}`, "desired.engine");

    async function add(event: Event): Promise<void> {
        event.preventDefault();
        if (busy() || !pairing().trim()) return;
        setBusy("claim");
        setAddError(null);
        try {
            const added = await claimBox(props.json, pairing());
            setPairing("");
            setAdding(false);
            toast("ok", `Paired ${added.keyId || added.fingerprint.slice(7, 19)}`);
            setGeneration((g) => g + 1);
            void refetchBoxes();
            setSelected(added.fingerprint);
        } catch (error) {
            setAddError(error instanceof Error ? error.message : String(error));
        } finally {
            setBusy(null);
        }
    }

    async function forget(box: StoredBox): Promise<void> {
        if (!confirm(`Forget ${box.keyId}? This removes the only way to reach it; the box stays paired and must be unpaired in person to be claimed again.`)) return;
        await forgetBox(props.json, box.fingerprint);
        setGeneration((g) => g + 1);
        void refetchBoxes();
    }

    const CommandButton = (p: { readonly id: string; readonly danger?: boolean; readonly primary?: boolean; readonly confirm?: string }): JSX.Element => (
        <Show when={commands()[p.id]}>
            <button
                type="button"
                class="twb-btn"
                classList={{ "twb-btn-danger": p.danger, "twb-btn-primary": p.primary }}
                disabled={busy() !== null}
                onClick={() => { if (!p.confirm || confirm(p.confirm)) void run(p.id); }}
            >
                {busy() === p.id ? "…" : LABEL[p.id] ?? p.id}
            </button>
        </Show>
    );

    return (
        <div class="twb">
            {/* ---- boxes ---- */}
            <nav class="twb-nav" aria-label="Boxes">
                <div class="twb-nav-head">
                    <span>Boxes</span>
                    <button type="button" class="twb-btn twb-btn-small" onClick={() => { setAdding((a) => !a); setAddError(null); }}>
                        {adding() ? "Cancel" : "+ Add"}
                    </button>
                </div>
                <Show when={adding()}>
                    <form class="twb-add" onSubmit={add}>
                        <input
                            class="twb-input twb-mono"
                            type="password"
                            autocomplete="off"
                            placeholder="tw1_… pairing string"
                            value={pairing()}
                            onInput={(e) => setPairing(e.currentTarget.value)}
                            disabled={busy() === "claim"}
                        />
                        <button type="submit" class="twb-btn twb-btn-primary twb-btn-small" disabled={busy() === "claim" || !pairing().trim()}>
                            {busy() === "claim" ? "Pairing…" : "Pair"}
                        </button>
                        <Show when={addError()}>{(e) => <div class="twb-error">{e()}</div>}</Show>
                    </form>
                </Show>
                <ul class="twb-nav-list">
                    <For each={boxes()} fallback={<li class="twb-nav-empty">No boxes paired yet.</li>}>
                        {(box) => (
                            <li>
                                <button
                                    type="button"
                                    class="twb-nav-item"
                                    classList={{ "twb-nav-item-active": selected() === box.fingerprint }}
                                    onClick={() => { setSelected(box.fingerprint); setTab("inference"); }}
                                >
                                    <span class="twb-dot" data-tone={box.sealed ? "ok" : "bad"} />
                                    <span class="twb-mono">{box.keyId || box.fingerprint.slice(7, 19)}</span>
                                    <span class="twb-nav-sub">{box.relayEndpoint.replace(/^wss?:\/\//, "")}</span>
                                </button>
                            </li>
                        )}
                    </For>
                </ul>
            </nav>

            {/* ---- the selected box ---- */}
            <main class="twb-main">
                <Show when={selectedBox()} fallback={<div class="twb-empty">Pair a box to operate it.</div>}>
                    {(box) => (
                        <>
                            <header class="twb-head">
                                <div class="twb-head-title">
                                    <span class="twb-mono twb-head-id">{box().keyId || box().fingerprint.slice(7, 19)}</span>
                                    <Show when={live()} fallback={<Chip tone={openError() ? "bad" : "muted"}>{openError() ? "unreachable" : "opening…"}</Chip>}>
                                        {(held) => (
                                            <>
                                                <Chip tone={engineTone(held().inference.content.engine.status).tone}>
                                                    {engineTone(held().inference.content.engine.status).label}
                                                </Chip>
                                                <span class="twb-head-meta">
                                                    {held().inference.content.engine.name}
                                                    <Show when={held().inference.content.engine.version}> {held().inference.content.engine.version}</Show>
                                                </span>
                                                <span class="twb-head-meta">
                                                    relay <Chip tone={held().access.content.relay.status === "parked" ? "ok" : "warn"}>{held().access.content.relay.status}</Chip>
                                                </span>
                                                <Show when={openError()}><Chip tone="warn">stale</Chip></Show>
                                            </>
                                        )}
                                    </Show>
                                </div>
                                <div class="twb-head-actions">
                                    <button type="button" class="twb-btn twb-btn-small" onClick={reread} disabled={opened.loading}>Refresh</button>
                                    <button type="button" class="twb-btn twb-btn-small twb-btn-quiet" onClick={() => void forget(box())}>Forget</button>
                                </div>
                            </header>

                            <div class="twb-tabs" role="tablist">
                                <For each={[["inference", "Inference"], ["posture", "Posture"], ["access", "Access"]] as const}>
                                    {([id, label]) => (
                                        <button
                                            type="button"
                                            role="tab"
                                            class="twb-tab"
                                            aria-selected={tab() === id}
                                            onClick={() => setTab(id)}
                                        >
                                            {label}
                                            <Show when={id === "posture" && live()?.posture.content.summary.critical}>
                                                <span class="twb-badge" data-tone="bad">{live()!.posture.content.summary.critical}</span>
                                            </Show>
                                            <Show when={id === "posture" && !live()?.posture.content.summary.critical && live()?.posture.content.summary.warning}>
                                                <span class="twb-badge" data-tone="warn">{live()!.posture.content.summary.warning}</span>
                                            </Show>
                                        </button>
                                    )}
                                </For>
                            </div>

                            <Show when={openError()}>
                                {(e) => <div class="twb-error twb-error-block">Could not reach the box: {e().message}</div>}
                            </Show>

                            <Show when={live()}>
                                {(held) => (
                                    <div class="twb-body">
                                        <Show when={tab() === "inference"}>
                                            <InferenceTab
                                                doc={held().inference.content}
                                                busy={busy()}
                                                run={run}
                                                requestModel={requestModel}
                                                requestEngine={requestEngine}
                                                CommandButton={CommandButton}
                                            />
                                        </Show>
                                        <Show when={tab() === "posture"}>
                                            <PostureTab doc={held().posture.content} CommandButton={CommandButton} />
                                        </Show>
                                        <Show when={tab() === "access"}>
                                            <AccessTab doc={held().access.content} CommandButton={CommandButton} />
                                        </Show>
                                    </div>
                                )}
                            </Show>
                        </>
                    )}
                </Show>
            </main>

            <div class="twb-toasts" aria-live="polite">
                <For each={toasts()}>
                    {(t) => <div class="twb-toast" data-tone={t.tone}>{t.text}</div>}
                </For>
            </div>
        </div>
    );
}

// --- tabs -------------------------------------------------------------------

type ButtonComponent = (p: { readonly id: string; readonly danger?: boolean; readonly primary?: boolean; readonly confirm?: string }) => JSX.Element;

function InferenceTab(props: {
    readonly doc: InferenceDocument;
    readonly busy: string | null;
    readonly run: (id: string) => Promise<void>;
    readonly requestModel: (model: string | null) => Promise<void>;
    readonly requestEngine: (engine: string) => Promise<void>;
    readonly CommandButton: ButtonComponent;
}): JSX.Element {
    const d = () => props.doc;
    const B = props.CommandButton;
    const vram = () => d().hardware.vram_total_mib > 0;
    const diskUsed = () => d().storage.disk_total_mib - d().storage.disk_free_mib;
    const missing = () => undeclaredOnDisk(d());
    const orphaned = () => orphanedMib(d());
    // Served-ness is a property of what is *running*, not what is requested: it
    // decides which controls make sense against the engine actually there.
    const served = () => isServedEngine(d().engine.name);
    const engineSwitching = () => engineChangePending(d().desired.engine, d().engine.name);
    // Interrupting in-flight work is universal — applying a model restarts the
    // engine on every backend — but a served engine also reloads its weights
    // onto the GPU, which is minutes, so the warning says both.
    const applyWarning = () =>
        served()
            ? `Applying restarts ${engineLabel(d().engine.name)} and reloads the model onto the GPU — this interrupts any running request and can take minutes. Continue?`
            : "Applying restarts the engine and interrupts any running request. Continue?";

    return (
        <div class="twb-grid">
            <Card
                title="Engine"
                actions={<>
                    <For each={engineControls(d().engine.status)}>{(id) => <B id={id} primary={id === "tokenwright.engine.start"} />}</For>
                    <B id="tokenwright.engine.update" />
                </>}
            >
                <div class="twb-stats">
                    <Stat label="Status"><Chip tone={engineTone(d().engine.status).tone}>{engineTone(d().engine.status).label}</Chip></Stat>
                    <Stat label="Engine">{engineLabel(d().engine.name) || "—"} <span class="twb-muted">{served() ? "· served" : d().engine.name ? "· embedded" : ""}</span></Stat>
                    <Stat label="Version" mono>{d().engine.version || "—"}</Stat>
                    <Stat label="Uptime">{d().engine.uptime ?? "—"}</Stat>
                    <Stat label="Restarts">{d().engine.restarts}</Stat>
                    <Stat label="Autostart">{d().desired.autostart ? "on" : "off"}</Stat>
                </div>
                <div class="twb-row">
                    <label class="twb-label" for="twb-engine">Run engine</label>
                    <select
                        id="twb-engine"
                        class="twb-select twb-mono"
                        disabled={props.busy !== null}
                        onChange={(e) => {
                            if (confirm(`Switch this box to ${engineLabel(e.currentTarget.value)}? The engine restarts; a box runs one at a time.`)) {
                                void props.requestEngine(e.currentTarget.value);
                            } else {
                                e.currentTarget.value = d().desired.engine;
                            }
                        }}
                    >
                        <For each={KNOWN_ENGINES}>
                            {(id) => <option value={id} selected={d().desired.engine === id}>{engineLabel(id)}</option>}
                        </For>
                    </select>
                    <Show when={engineSwitching()}>
                        <span class="twb-warn-text">requested {engineLabel(d().desired.engine)}, not yet running — restart to apply</span>
                    </Show>
                </div>
                <Show when={d().engine.last_error}>
                    {(e) => <div class="twb-error">{e()}</div>}
                </Show>
            </Card>

            <Card
                title="Model"
                actions={<>
                    <Show when={modelApplyPending(d())}><B id="tokenwright.model.reconcile" primary confirm={applyWarning()} /></Show>
                    {/* A served engine holds exactly the model it was started
                        with and cannot run without one, so "unload" is not a
                        thing it can do — the same reason Stop hides when the
                        engine is already stopped. */}
                    <Show when={d().model.id && !served()}><B id="tokenwright.model.unload" /></Show>
                </>}
            >
                <Show when={d().model.id} fallback={<div class="twb-muted twb-pad">No model loaded.</div>}>
                    <div class="twb-stats">
                        <Stat label="Loaded" mono>{d().model.id}</Stat>
                        <Stat label="Quantization" mono>{d().model.quantization ?? "—"}</Stat>
                        <Stat label="Context">{d().model.context_length?.toLocaleString() ?? "—"}</Stat>
                        <Stat label="Weights">{mib(d().model.size_mib)}</Stat>
                        <Stat label="Loaded"><span title={d().model.loaded_at ?? ""}>{ago(d().model.loaded_at)}</span></Stat>
                    </div>
                    <Show when={served()}>
                        <div class="twb-note">{engineLabel(d().engine.name)} reports the model id only — quantization, context, and size are its own to know, and the box does not read into them.</div>
                    </Show>
                </Show>
                <div class="twb-row">
                    <label class="twb-label" for="twb-requested">Requested</label>
                    <select
                        id="twb-requested"
                        class="twb-select twb-mono"
                        disabled={props.busy !== null}
                        onChange={(e) => void props.requestModel(e.currentTarget.value || null)}
                    >
                        <option value="" selected={d().desired.model === null}>— none —</option>
                        <For each={d().desired.models}>
                            {(id) => <option value={id} selected={d().desired.model === id}>{id}</option>}
                        </For>
                    </select>
                    <Show when={modelApplyPending(d())}>
                        <span class="twb-muted">not yet applied</span>
                    </Show>
                </div>
            </Card>

            <Card title="Throughput">
                <div class="twb-stats">
                    <Stat label="Tokens / s"><span class="twb-big">{d().throughput.tokens_per_second.toFixed(1)}</span></Stat>
                    <Stat label="Active">{d().throughput.active_requests} / {d().throughput.max_concurrent}</Stat>
                    <Stat label="Requests">{d().throughput.requests_total.toLocaleString()}</Stat>
                    <Stat label="Rejected (overload)">{d().throughput.rejected_overload_total.toLocaleString()}</Stat>
                </div>
                <Bar used={d().throughput.active_requests} total={d().throughput.max_concurrent} tone={d().throughput.active_requests >= d().throughput.max_concurrent ? "warn" : "info"} />
            </Card>

            {/* Only a served engine has a scheduler of its own to report. The
                card is absent for FreeToken and while the engine is down —
                `serving` is null in both cases — rather than shown empty. */}
            <Show when={d().serving}>
                {(s) => (
                    <Card title="Serving">
                        <div class="twb-stats">
                            <Stat label="Running">{s().running ?? "—"}</Stat>
                            <Stat label="Queued">
                                <span classList={{ "twb-warn-text": (s().queued ?? 0) > 0 }}>{s().queued ?? "—"}</span>
                            </Stat>
                            <Stat label="KV cache">{s().kv_cache_used_pct === null ? "—" : `${s().kv_cache_used_pct!.toFixed(0)}%`}</Stat>
                        </div>
                        <Show when={s().kv_cache_used_pct !== null}>
                            <div class="twb-meter">
                                <span>KV-cache pool</span>
                                <Bar used={s().kv_cache_used_pct ?? 0} total={100}
                                    tone={(s().kv_cache_used_pct ?? 0) > 90 ? "warn" : "info"} />
                            </div>
                        </Show>
                        <Show when={Object.keys(s().native).length > 0}>
                            <div class="twb-stats twb-native">
                                <For each={Object.entries(s().native)}>
                                    {([label, value]) => <Stat label={label}>{value.toLocaleString()}</Stat>}
                                </For>
                            </div>
                        </Show>
                    </Card>
                )}
            </Show>

            <Card title="Hardware">
                <div class="twb-stats">
                    <Stat label="GPU">{d().hardware.gpu === "unknown" ? <span class="twb-muted">none detected</span> : d().hardware.gpu}</Stat>
                    <Stat label="Driver" mono>{d().hardware.driver === "unknown" ? "—" : d().hardware.driver}</Stat>
                    <Stat label="CUDA" mono>{d().hardware.cuda === "unknown" ? "—" : d().hardware.cuda}</Stat>
                    <Stat label="System RAM">{mib(d().hardware.ram_total_mib)}</Stat>
                </div>
                <Show when={vram()}>
                    <div class="twb-meter">
                        <span>VRAM {mib(d().hardware.vram_used_mib)} of {mib(d().hardware.vram_total_mib)}</span>
                        <Bar used={d().hardware.vram_used_mib} total={d().hardware.vram_total_mib} tone={percent(d().hardware.vram_used_mib, d().hardware.vram_total_mib) > 90 ? "warn" : "info"} />
                    </div>
                </Show>
            </Card>

            <Card
                title="Models on disk"
                wide
                actions={<>
                    <Show when={missing().length > 0}><B id="tokenwright.models.reconcile" primary /></Show>
                    <Show when={orphaned() > 0}><B id="tokenwright.models.prune" /></Show>
                </>}
            >
                <table class="twb-table">
                    <thead><tr><th>Model</th><th>Quant</th><th class="twb-num">Size</th><th>State</th><th>Digest</th></tr></thead>
                    <tbody>
                        <For each={d().models} fallback={<tr><td colspan="5" class="twb-muted">Nothing on disk.</td></tr>}>
                            {(m) => (
                                <tr>
                                    <td class="twb-mono">{m.id}</td>
                                    <td class="twb-mono">{m.quantization}</td>
                                    <td class="twb-num">{mib(m.size_mib)}</td>
                                    <td><Chip tone={modelStateTone(m.state).tone}>{modelStateTone(m.state).label}</Chip></td>
                                    <td>{m.digest_verified === null ? "…" : m.digest_verified ? "verified" : <span class="twb-bad">mismatch</span>}</td>
                                </tr>
                            )}
                        </For>
                        <For each={missing()}>
                            {(id) => (
                                <tr class="twb-row-ghost">
                                    <td class="twb-mono">{id}</td><td>—</td><td class="twb-num">—</td>
                                    <td><Chip tone="muted">declared, not fetched</Chip></td><td>—</td>
                                </tr>
                            )}
                        </For>
                    </tbody>
                </table>
                <div class="twb-meter">
                    <span>Disk {mib(diskUsed())} used of {mib(d().storage.disk_total_mib)}<Show when={orphaned() > 0}> · {mib(orphaned())} reclaimable</Show></span>
                    <Bar used={diskUsed()} total={d().storage.disk_total_mib} tone={percent(diskUsed(), d().storage.disk_total_mib) > 90 ? "warn" : "info"} />
                </div>
            </Card>

            <Show when={d().events.length > 0}>
                <Card title="Recent events" wide>
                    <ul class="twb-events">
                        <For each={[...d().events].slice(-8).reverse()}>
                            {(e) => (
                                <li>
                                    <span class="twb-dot" data-tone={e.level === "error" ? "bad" : e.level === "warn" ? "warn" : "muted"} />
                                    <span class="twb-muted twb-mono" title={e.at}>{ago(e.at)}</span>
                                    <span>{e.message}</span>
                                </li>
                            )}
                        </For>
                    </ul>
                </Card>
            </Show>
        </div>
    );
}

function PostureTab(props: { readonly doc: PostureDocument; readonly CommandButton: ButtonComponent }): JSX.Element {
    const d = () => props.doc;
    const B = props.CommandButton;
    return (
        <div class="twb-grid">
            <Card
                title="Findings"
                wide
                actions={<>
                    <span class="twb-muted">checked {ago(d().checked_at)}</span>
                    <B id="tokenwright.posture.rescan" />
                </>}
            >
                <div class="twb-summary">
                    <Chip tone="bad">{d().summary.critical} critical</Chip>
                    <Chip tone="warn">{d().summary.warning} warning</Chip>
                    <Chip tone="info">{d().summary.advisory} advisory</Chip>
                    <Chip tone="ok">{d().summary.checks_passed} passed</Chip>
                </div>
                <ul class="twb-findings">
                    <For each={d().findings} fallback={<li class="twb-muted">Nothing to report.</li>}>
                        {(f) => (
                            <li class="twb-finding" data-tone={severityTone(f.severity).tone}>
                                <div class="twb-finding-head">
                                    <Chip tone={severityTone(f.severity).tone}>{f.severity}</Chip>
                                    <strong>{f.title}</strong>
                                    <span class="twb-muted twb-mono">{f.id}</span>
                                </div>
                                <div class="twb-finding-fix">{f.remediation}</div>
                            </li>
                        )}
                    </For>
                </ul>
            </Card>

            <Card
                title="Network"
                actions={<>
                    <Show when={!d().network.wireguard.enabled}><B id="tokenwright.wireguard.enable" /></Show>
                    <Show when={d().network.wireguard.enabled}><B id="tokenwright.wireguard.disable" /></Show>
                </>}
            >
                <div class="twb-stats">
                    <Stat label="Firewall"><Chip tone={d().network.firewall.active ? "ok" : "bad"}>{d().network.firewall.active ? "active" : "inactive"}</Chip> <span class="twb-muted">{d().network.firewall.backend}</span></Stat>
                    <Stat label="Inbound default">{d().network.firewall.default_incoming}</Stat>
                    <Stat label="Public listeners">{d().network.listeners.length}</Stat>
                    <Stat label="Direct access (WireGuard)"><Chip tone={d().network.wireguard.enabled ? "ok" : "muted"}>{d().network.wireguard.enabled ? "enabled" : "off"}</Chip></Stat>
                    <Show when={d().network.wireguard.enabled}>
                        <Stat label="Peers">{d().network.wireguard.peers}</Stat>
                        <Stat label="Port" mono>{d().network.wireguard.listen_port ?? "—"}</Stat>
                    </Show>
                </div>
            </Card>

            <Card title="Audit trail">
                <div class="twb-stats">
                    <Stat label="Entries">{d().audit.entries.toLocaleString()}</Stat>
                    <Stat label="Chain"><Chip tone={d().audit.chain_verified ? "ok" : "bad"}>{d().audit.chain_verified ? "verified" : "broken"}</Chip></Stat>
                    <Stat label="Anchored">{d().audit.anchored_count} of {d().audit.entries}</Stat>
                    <Stat label="Last anchor"><span title={d().audit.last_anchored_at ?? ""}>{ago(d().audit.last_anchored_at)}</span></Stat>
                </div>
            </Card>

            <Card title="Services" wide>
                <table class="twb-table">
                    <thead><tr><th>Unit</th><th>State</th><th>User</th><th>Hardening</th></tr></thead>
                    <tbody>
                        <For each={d().services}>
                            {(s) => (
                                <tr>
                                    <td class="twb-mono">{s.unit}</td>
                                    <td><Chip tone={s.state === "active" ? "ok" : s.state === "failed" ? "bad" : "muted"}>{s.state}</Chip></td>
                                    <td class="twb-mono">{s.user}</td>
                                    <td class="twb-muted">
                                        {[s.no_new_privileges && "no-new-privs", s.protect_system !== "no" && `protect=${s.protect_system}`, s.network_restricted && "network-restricted"].filter(Boolean).join(" · ") || "—"}
                                    </td>
                                </tr>
                            )}
                        </For>
                    </tbody>
                </table>
            </Card>
        </div>
    );
}

function AccessTab(props: { readonly doc: AccessDocument; readonly CommandButton: ButtonComponent }): JSX.Element {
    const d = () => props.doc;
    const B = props.CommandButton;
    return (
        <div class="twb-grid">
            <Card title="Pairing" actions={<B id="tokenwright.unpair" danger />}>
                <div class="twb-stats">
                    <Stat label="Home" mono>{d().pairing.home}</Stat>
                    <Stat label="Paired"><span title={d().pairing.paired_at}>{ago(d().pairing.paired_at)}</span></Stat>
                    <Stat label="Certificate" mono><span title={d().pairing.fingerprint}>{d().pairing.fingerprint.slice(7, 23)}…</span></Stat>
                </div>
            </Card>

            <Card title="Reachability">
                <div class="twb-stats">
                    <Stat label="Relay"><Chip tone={d().relay.status === "parked" ? "ok" : "warn"}>{d().relay.status}</Chip></Stat>
                    <Stat label="Endpoint" mono>{d().relay.endpoint ?? "—"}</Stat>
                    <Stat label="Last connected"><span title={d().relay.last_connected_at ?? ""}>{ago(d().relay.last_connected_at)}</span></Stat>
                    <Stat label="Direct access"><Chip tone={d().direct.enabled ? "ok" : "muted"}>{d().direct.enabled ? "enabled" : "off"}</Chip></Stat>
                    <Show when={d().direct.base_url}><Stat label="Base URL" mono>{d().direct.base_url}</Stat></Show>
                </div>
            </Card>

            <Show when={d().reveal}>
                {(r) => (
                    <Card title="New key — shown once" wide actions={<B id="tokenwright.key.acknowledge" primary />}>
                        <div class="twb-reveal">
                            <span class="twb-mono">{r().key}</span>
                            <code class="twb-secret">{r().secret}</code>
                        </div>
                        <div class="twb-muted">Copy it now. Acknowledging clears it from the box permanently.</div>
                    </Card>
                )}
            </Show>

            <Card title="Keys" wide>
                <table class="twb-table">
                    <thead><tr><th>Name</th><th>Prefix</th><th>State</th><th>Created</th><th>Last used</th></tr></thead>
                    <tbody>
                        <For each={d().keys}>
                            {(k) => (
                                <tr>
                                    <td>{k.name} <span class="twb-muted twb-mono">{k.id}</span></td>
                                    <td class="twb-mono">{k.prefix}…</td>
                                    <td><Chip tone={k.state === "active" ? "ok" : "muted"}>{k.state}</Chip></td>
                                    <td><span title={k.created_at}>{ago(k.created_at)}</span></td>
                                    <td><span title={k.last_used_at ?? ""}>{ago(k.last_used_at)}</span></td>
                                </tr>
                            )}
                        </For>
                    </tbody>
                </table>
            </Card>
        </div>
    );
}

const LABEL: Record<string, string> = {
    "tokenwright.engine.start": "Start",
    "tokenwright.engine.stop": "Stop",
    "tokenwright.engine.restart": "Restart",
    "tokenwright.engine.update": "Update engine",
    "tokenwright.model.reconcile": "Apply",
    "tokenwright.model.unload": "Unload",
    "tokenwright.models.reconcile": "Fetch declared",
    "tokenwright.models.prune": "Free orphaned",
    "tokenwright.posture.rescan": "Re-check",
    "tokenwright.wireguard.enable": "Enable direct access",
    "tokenwright.wireguard.disable": "Disable direct access",
    "tokenwright.key.acknowledge": "I have saved it",
    "tokenwright.unpair": "Unpair box",
};
