import { createMemo, createSignal, For, Match, Show, Switch, type JSX } from "solid-js";

export type DeploymentAudience = "anonymous" | "managed" | "oidc";
export type DeploymentFunding = "managed" | "byok";
export type DeploymentPanelKind = "chat" | "viewer" | "files" | "history";

export interface DeploymentStudioSelection {
    readonly projectName: string;
    readonly archetypeName: string;
    readonly version: number;
    readonly abilities: readonly string[];
}

export interface DeploymentStudioProps {
    readonly selection: DeploymentStudioSelection;
    readonly onClose?: () => void;
}

type StepId = "agent" | "audience" | "experience" | "limits" | "review";

const STEPS: readonly { id: StepId; label: string; hint: string }[] = [
    { id: "agent", label: "Agent", hint: "What will run" },
    { id: "audience", label: "Audience", hint: "Who can open it" },
    { id: "experience", label: "Experience", hint: "What visitors see" },
    { id: "limits", label: "Limits", hint: "Cost and retention" },
    { id: "review", label: "Review", hint: "Confirm and publish" },
];

function deploymentSlug(value: string): string {
    return value.toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "") || "agent";
}

function panelLabel(panel: DeploymentPanelKind): string {
    return { chat: "Chat", viewer: "Answer viewer", files: "Downloads", history: "Past chats" }[panel];
}

function ChoiceCard(props: {
    readonly selected: boolean;
    readonly title: string;
    readonly detail: string;
    readonly meta?: string;
    readonly onSelect: () => void;
}): JSX.Element {
    return (
        <button
            type="button"
            class="deployment-choice"
            classList={{ selected: props.selected }}
            aria-pressed={props.selected}
            onClick={props.onSelect}
        >
            <span class="deployment-choice-mark" aria-hidden="true">{props.selected ? "●" : "○"}</span>
            <span class="deployment-choice-copy">
                <strong>{props.title}</strong>
                <span>{props.detail}</span>
                <Show when={props.meta}><small>{props.meta}</small></Show>
            </span>
        </button>
    );
}

function SettingRow(props: {
    readonly label: string;
    readonly value: string;
    readonly note?: string;
}): JSX.Element {
    return (
        <div class="deployment-review-row">
            <span>
                <strong>{props.label}</strong>
                <Show when={props.note}><small>{props.note}</small></Show>
            </span>
            <span>{props.value}</span>
        </div>
    );
}

export function DeploymentStudio(props: DeploymentStudioProps): JSX.Element {
    const [step, setStep] = createSignal<StepId>("agent");
    const [published, setPublished] = createSignal(false);
    const [view, setView] = createSignal<"configure" | "operate">("configure");
    const [deploymentId, setDeploymentId] = createSignal(deploymentSlug(props.selection.archetypeName));
    const [origin, setOrigin] = createSignal("https://example.com");
    const [audience, setAudience] = createSignal<DeploymentAudience>("anonymous");
    const [oidcIssuer, setOidcIssuer] = createSignal("https://login.example.com");
    const [panels, setPanels] = createSignal<DeploymentPanelKind[]>(["chat", "viewer"]);
    const [agentName, setAgentName] = createSignal(props.selection.archetypeName);
    const [openingMessage, setOpeningMessage] = createSignal(
        "Hi — tell me what you’re working on and I’ll help you find the next step.",
    );
    const [funding, setFunding] = createSignal<DeploymentFunding>("managed");
    const [spendLimit, setSpendLimit] = createSignal(25);
    const [turnLimit, setTurnLimit] = createSignal(20);
    const [retentionDays, setRetentionDays] = createSignal(30);
    const [collect, setCollect] = createSignal(false);
    const [acknowledged, setAcknowledged] = createSignal(false);
    const [previewMessage, setPreviewMessage] = createSignal("");
    const [previewSent, setPreviewSent] = createSignal(false);
    const [copied, setCopied] = createSignal(false);
    const [paused, setPaused] = createSignal(false);

    const currentIndex = createMemo(() => STEPS.findIndex((candidate) => candidate.id === step()));
    const selectedPanels = createMemo(() => panels().map(panelLabel).join(", "));
    const deploymentUrl = createMemo(() => `https://panels.gaugewright.com/d/${deploymentId()}`);
    const embedCode = createMemo(() => [
        `<script src="https://embed.gaugewright.com/embed.js"></script>`,
        `<gw-session host="${deploymentUrl()}">`,
        ...panels().map((panel) => `  <gw-${panel === "history" ? "chats" : panel}></gw-${panel === "history" ? "chats" : panel}>`),
        `</gw-session>`,
    ].join("\n"));

    const togglePanel = (panel: DeploymentPanelKind) => {
        if (panel === "chat") return;
        setPanels((current) => current.includes(panel)
            ? current.filter((candidate) => candidate !== panel)
            : [...current, panel]);
    };

    const goNext = () => {
        const next = STEPS[currentIndex() + 1];
        if (next) setStep(next.id);
    };

    const goBack = () => {
        const previous = STEPS[currentIndex() - 1];
        if (previous) setStep(previous.id);
    };

    const publish = () => {
        if (!acknowledged()) return;
        setPublished(true);
        setView("operate");
    };

    const copyCode = async () => {
        await navigator.clipboard?.writeText(embedCode());
        setCopied(true);
        window.setTimeout(() => setCopied(false), 1400);
    };

    const sendPreview = (event: SubmitEvent) => {
        event.preventDefault();
        if (!previewMessage().trim()) return;
        setPreviewSent(true);
        setPreviewMessage("");
    };

    return (
        <div class="deployment-studio" data-deployment-studio>
            <header class="deployment-studio-head">
                <div>
                    <div class="deployment-breadcrumb">{props.selection.projectName} / {props.selection.archetypeName}</div>
                    <h1>{published() ? deploymentId() : `Deploy ${props.selection.archetypeName}`}</h1>
                </div>
                <div class="deployment-head-actions">
                    <span class="badge" classList={{ released: published() }}>
                        {published() ? (paused() ? "paused" : "live") : "draft"}
                    </span>
                    <Show when={props.onClose}>
                        <button type="button" class="icon-button" aria-label="Close deployment studio" onClick={props.onClose}>×</button>
                    </Show>
                </div>
            </header>

            <Show when={published()}>
                <nav class="deployment-view-tabs" aria-label="Deployment view">
                    <button type="button" classList={{ active: view() === "configure" }} onClick={() => setView("configure")}>Configure</button>
                    <button type="button" classList={{ active: view() === "operate" }} onClick={() => setView("operate")}>Operate</button>
                </nav>
            </Show>

            <Show when={view() === "configure"} fallback={
                <div class="deployment-operate">
                    <main class="deployment-operate-main">
                        <section class="deployment-live-callout">
                            <span class="deployment-live-dot" classList={{ paused: paused() }} />
                            <div>
                                <strong>{paused() ? "This deployment is paused" : "Your panel is live"}</strong>
                                <span>{paused() ? "Existing records are retained. New visitor sessions are blocked." : `New visitors receive version ${props.selection.version}.`}</span>
                            </div>
                            <button type="button" onClick={() => setPaused(!paused())}>{paused() ? "Resume" : "Pause"}</button>
                        </section>

                        <section class="deployment-operate-grid">
                            <article class="deployment-metric"><span>Sessions</span><strong>184</strong><small>31 this week</small></article>
                            <article class="deployment-metric"><span>Settled turns</span><strong>612</strong><small>3.3 per session</small></article>
                            <article class="deployment-metric"><span>Spend</span><strong>$8.42</strong><small>of ${spendLimit().toFixed(2)} limit</small></article>
                            <article class="deployment-metric"><span>Collected</span><strong>{collect() ? "12" : "Off"}</strong><small>{collect() ? "sealed results waiting" : "no visitor output leaves sessions"}</small></article>
                        </section>

                        <section class="deployment-operate-section">
                            <div class="deployment-section-head"><div><h2>Add it to your site</h2><p>This code stays the same when you publish an update.</p></div><button type="button" onClick={() => void copyCode()}>{copied() ? "Copied" : "Copy code"}</button></div>
                            <pre class="embed-snippet">{embedCode()}</pre>
                        </section>

                        <section class="deployment-operate-section">
                            <div class="deployment-section-head"><div><h2>Recent activity</h2><p>Operational facts only; visitor content is not shown here.</p></div><button type="button">Refresh</button></div>
                            <div class="deployment-activity-row"><span class="deployment-activity-state live" /><span><strong>Anonymous visitor</strong><small>8 turns · version {props.selection.version}</small></span><time>2 min ago</time></div>
                            <div class="deployment-activity-row"><span class="deployment-activity-state" /><span><strong>Anonymous visitor</strong><small>3 turns · version {props.selection.version}</small></span><time>18 min ago</time></div>
                            <div class="deployment-activity-row"><span class="deployment-activity-state" /><span><strong>Anonymous visitor</strong><small>Result collected · sealed</small></span><time>1 hr ago</time></div>
                        </section>
                    </main>
                    <aside class="deployment-operate-side">
                        <h2>Deployment</h2>
                        <SettingRow label="Active release" value={`Version ${props.selection.version}`} />
                        <SettingRow label="Website" value={origin().replace(/^https?:\/\//, "")} />
                        <SettingRow label="Audience" value={audience() === "anonymous" ? "Anyone" : audience() === "managed" ? "Managed sign-in" : "Your identity provider"} />
                        <SettingRow label="Panels" value={selectedPanels()} />
                        <SettingRow label="Funding" value={funding() === "managed" ? "Metered" : "Your OpenAI key"} />
                        <button type="button" class="deployment-secondary-wide" onClick={() => { setView("configure"); setStep("agent"); }}>Edit configuration</button>
                        <button type="button" class="deployment-danger-wide">Revoke deployment</button>
                    </aside>
                </div>
            }>
                <div class="deployment-configure">
                    <nav class="deployment-step-rail" aria-label="Deployment setup">
                        <For each={STEPS}>{(candidate, index) => (
                            <button
                                type="button"
                                classList={{ active: step() === candidate.id, complete: index() < currentIndex() }}
                                aria-current={step() === candidate.id ? "step" : undefined}
                                onClick={() => setStep(candidate.id)}
                            >
                                <span class="deployment-step-number">{index() < currentIndex() ? "✓" : index() + 1}</span>
                                <span><strong>{candidate.label}</strong><small>{candidate.hint}</small></span>
                            </button>
                        )}</For>
                    </nav>

                    <main class="deployment-step-body">
                        <Switch>
                            <Match when={step() === "agent"}>
                                <div class="deployment-step-copy"><span class="deployment-kicker">Step 1 of 5</span><h2>Start with the release you tested</h2><p>A deployment freezes this exact version. Publishing another version later will not change visitors until you choose to update.</p></div>
                                <section class="deployment-release-card">
                                    <div class="deployment-release-icon" aria-hidden="true">{props.selection.archetypeName.slice(0, 1)}</div>
                                    <div><strong>{props.selection.archetypeName}</strong><span>{props.selection.projectName} · Version {props.selection.version}</span></div>
                                    <span class="badge released">ready</span>
                                </section>
                                <fieldset class="deployment-fieldset-clean">
                                    <legend>Frozen abilities</legend>
                                    <div class="deployment-chip-row"><For each={props.selection.abilities}>{(ability) => <span class="deployment-chip">{ability}</span>}</For></div>
                                    <p>These are part of the release. Deployment can narrow what visitors see, but cannot give the agent new abilities.</p>
                                </fieldset>
                                <label class="settings-field"><span class="settings-label">Deployment name</span><input class="settings-input" value={deploymentId()} onInput={(event) => setDeploymentId(deploymentSlug(event.currentTarget.value))} /><small>Used in the permanent panel URL. You will not need to change it for updates.</small></label>
                            </Match>

                            <Match when={step() === "audience"}>
                                <div class="deployment-step-copy"><span class="deployment-kicker">Step 2 of 5</span><h2>Choose who can start a session</h2><p>The website origin and audience policy are checked before a visitor can create a session or cause model spend.</p></div>
                                <label class="settings-field"><span class="settings-label">Website origin</span><input class="settings-input" type="url" value={origin()} onInput={(event) => setOrigin(event.currentTarget.value)} placeholder="https://www.example.com" /><small>Only pages on this exact origin can load the panel.</small></label>
                                <div class="deployment-choice-list">
                                    <ChoiceCard selected={audience() === "anonymous"} title="Anyone on the site" detail="No sign-in. Each visitor receives an isolated session." meta="Best for public guides and lead capture" onSelect={() => setAudience("anonymous")} />
                                    <ChoiceCard selected={audience() === "managed"} title="Require a visitor sign-in" detail="GaugeWright handles email and social sign-in for this deployment." meta="Visitors can return to their past chats" onSelect={() => setAudience("managed")} />
                                    <ChoiceCard selected={audience() === "oidc"} title="Use your identity provider" detail="Your site’s OIDC provider identifies each visitor." meta="For an existing customer or member portal" onSelect={() => setAudience("oidc")} />
                                </div>
                                <Show when={audience() === "oidc"}><label class="settings-field deployment-nested-field"><span class="settings-label">OIDC issuer</span><input class="settings-input" value={oidcIssuer()} onInput={(event) => setOidcIssuer(event.currentTarget.value)} /></label></Show>
                            </Match>

                            <Match when={step() === "experience"}>
                                <div class="deployment-step-copy"><span class="deployment-kicker">Step 3 of 5</span><h2>Compose the visitor experience</h2><p>Panels are a disclosure boundary, not agent permissions. A panel that is not selected cannot render on the customer site.</p></div>
                                <fieldset class="deployment-fieldset-clean"><legend>Panels</legend><div class="deployment-panel-options">
                                    <label class="selected required"><input type="checkbox" checked disabled /><span><strong>Chat</strong><small>Conversation and responses</small></span><em>Required</em></label>
                                    <For each={(["viewer", "files", "history"] as DeploymentPanelKind[])}>{(panel) => <label classList={{ selected: panels().includes(panel) }}><input type="checkbox" checked={panels().includes(panel)} onChange={() => togglePanel(panel)} /><span><strong>{panelLabel(panel)}</strong><small>{panel === "viewer" ? "Structured answers and previews" : panel === "files" ? "Approved visitor downloads" : "Authenticated visitors only"}</small></span></label>}</For>
                                </div></fieldset>
                                <div class="deployment-two-columns"><label class="settings-field"><span class="settings-label">Assistant name</span><input class="settings-input" value={agentName()} onInput={(event) => setAgentName(event.currentTarget.value)} /></label><label class="settings-field"><span class="settings-label">Opening message</span><textarea class="settings-input deployment-textarea" value={openingMessage()} onInput={(event) => setOpeningMessage(event.currentTarget.value)} /></label></div>
                            </Match>

                            <Match when={step() === "limits"}>
                                <div class="deployment-step-copy"><span class="deployment-kicker">Step 4 of 5</span><h2>Set the operating boundary</h2><p>Visitors never choose or supply funding. If the selected source or a limit is unavailable, the deployment fails closed.</p></div>
                                <h3 class="deployment-subhead">Who pays</h3>
                                <div class="deployment-choice-list horizontal"><ChoiceCard selected={funding() === "managed"} title="Metered by GaugeWright" detail="Usage appears on your GaugeWright bill." onSelect={() => setFunding("managed")} /><ChoiceCard selected={funding() === "byok"} title="Your OpenAI key" detail="Your provider account pays directly." onSelect={() => setFunding("byok")} /></div>
                                <Show when={funding() === "byok"}><div class="deployment-notice"><strong>Production key</strong><span>OpenAI · added 3 days ago · public deployment use allowed</span><button type="button">Choose another</button></div></Show>
                                <div class="deployment-limit-grid"><label class="settings-field"><span class="settings-label">Total spend limit</span><div class="deployment-input-prefix"><span>$</span><input class="settings-input" type="number" min="1" value={spendLimit()} onInput={(event) => setSpendLimit(event.currentTarget.valueAsNumber)} /></div><small>Pause new turns when this deployment reaches the limit.</small></label><label class="settings-field"><span class="settings-label">Turns per visitor</span><input class="settings-input" type="number" min="1" value={turnLimit()} onInput={(event) => setTurnLimit(event.currentTarget.valueAsNumber)} /><small>Applies before model spend.</small></label><label class="settings-field"><span class="settings-label">Resume for</span><select class="settings-input" value={retentionDays()} onChange={(event) => setRetentionDays(Number(event.currentTarget.value))}><option value="1">1 day</option><option value="7">7 days</option><option value="30">30 days</option></select><small>This is a resumption window, not a collection deadline.</small></label></div>
                                <label class="deployment-collection-toggle"><input type="checkbox" checked={collect()} onChange={(event) => setCollect(event.currentTarget.checked)} /><span><strong>Collect approved visitor results</strong><small>Seal declared output to this project’s recipient keyring and drain it into quarantine.</small></span></label>
                            </Match>

                            <Match when={step() === "review"}>
                                <div class="deployment-step-copy"><span class="deployment-kicker">Step 5 of 5</span><h2>Review what will become public</h2><p>Publishing creates an immutable signed release and activates it for new visitor sessions.</p></div>
                                <section class="deployment-review-list">
                                    <SettingRow label="Release" note={props.selection.projectName} value={`${props.selection.archetypeName} · v${props.selection.version}`} />
                                    <SettingRow label="Website" note="Exact origin" value={origin()} />
                                    <SettingRow label="Audience" value={audience() === "anonymous" ? "Anyone on the site" : audience() === "managed" ? "Managed visitor sign-in" : "Your OIDC provider"} />
                                    <SettingRow label="Panels" value={selectedPanels()} />
                                    <SettingRow label="Funding" value={funding() === "managed" ? "Metered by GaugeWright" : "Production OpenAI key"} />
                                    <SettingRow label="Limits" value={`$${spendLimit()} total · ${turnLimit()} turns per visitor`} />
                                    <SettingRow label="Retention" value={`${retentionDays()} days`} />
                                    <SettingRow label="Collection" value={collect() ? "Sealed to project recipient" : "Nothing collected"} />
                                </section>
                                <label class="deployment-acknowledgement"><input type="checkbox" checked={acknowledged()} onChange={(event) => setAcknowledged(event.currentTarget.checked)} /><span><strong>I understand where visitor data goes</strong><small>The selected model provider receives prompts and admitted context in plaintext. This is not confidential inference.</small></span></label>
                            </Match>
                        </Switch>

                        <footer class="deployment-step-actions">
                            <button type="button" class="link-button" disabled={currentIndex() === 0} onClick={goBack}>Back</button>
                            <span>Changes are saved in this draft</span>
                            <Show when={step() === "review"} fallback={<button type="button" onClick={goNext}>Continue</button>}>
                                <button type="button" disabled={!acknowledged()} onClick={publish}>Publish panel</button>
                            </Show>
                        </footer>
                    </main>

                    <aside class="deployment-preview-pane">
                        <div class="deployment-preview-head"><div><span>Visitor preview</span><small>{origin().replace(/^https?:\/\//, "") || "Your website"}</small></div><span class="deployment-preview-status">Allowed origin</span></div>
                        <div class="deployment-browser-frame">
                            <div class="deployment-browser-bar"><i /><i /><i /><span>{origin().replace(/^https?:\/\//, "") || "example.com"}</span></div>
                            <div class="deployment-site-placeholder"><span>YOUR SITE</span><i /><i class="short" /></div>
                            <div class="deployment-panel-preview">
                                <header><div class="deployment-agent-avatar">{agentName().slice(0, 1) || "A"}</div><div><strong>{agentName() || "Your assistant"}</strong><span>{audience() === "anonymous" ? "New private session" : "Signed in"}</span></div><button type="button" aria-label="Panel menu">•••</button></header>
                                <div class="deployment-panel-tabs"><For each={panels()}>{(panel) => <span classList={{ active: panel === "chat" }}>{panelLabel(panel)}</span>}</For></div>
                                <div class="deployment-chat-preview"><div class="deployment-preview-message assistant">{openingMessage() || "Add an opening message."}</div><Show when={previewSent()}><div class="deployment-preview-message visitor">Can you help me get started?</div><div class="deployment-preview-message assistant muted">This preview does not call a model.</div></Show></div>
                                <form class="deployment-preview-composer" onSubmit={sendPreview}><input value={previewMessage()} onInput={(event) => setPreviewMessage(event.currentTarget.value)} placeholder={`Message ${agentName() || "this assistant"}`} /><button type="submit" aria-label="Send preview message">↑</button></form>
                                <footer>Powered by GaugeDesk</footer>
                            </div>
                        </div>
                        <p class="deployment-preview-note">Interactive preview · no model calls or visitor records</p>
                    </aside>
                </div>
            </Show>
        </div>
    );
}
