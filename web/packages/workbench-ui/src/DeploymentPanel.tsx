import { createEffect, createSignal, For, onCleanup, onMount, Show, type JSX } from "solid-js";
import type {
    AgentAbility,
    CollectionRecipient,
    EngagementId,
    ManagedInferenceBilling,
    PlacementId,
    ProvisionPublicCredentialInput,
    PublicCredentialMetadata,
    PublicDeploymentInput,
    PublicDeploymentInspection,
    PublicDeploymentOutcome,
} from "@gaugewright/control-plane-client";
import { startDeploymentMonitor } from "./deployment-monitor";
import { collectionBlockerFor, collectionInputFrom, retentionSeconds } from "./deployment-collection";
import {
    fundingBlockerFor,
    fundingFieldsFrom,
    isManagedPlanRef,
    managedPlanRefFromBilling,
    type FundingMode,
} from "./deployment-funding";

export interface DeploymentPanelApi {
    getPlacementAbilities(id: PlacementId): Promise<AgentAbility[]>;
    publishDeployment(input: PublicDeploymentInput): Promise<PublicDeploymentOutcome>;
    inspectDeployment(edge: string, deployment: string): Promise<PublicDeploymentInspection>;
    controlDeployment(
        edge: string,
        deployment: string,
        command: "pause" | "resume" | "revoke",
        expectedRevision: number,
    ): Promise<PublicDeploymentInspection["deployment"]>;
    erasePublicSession(edge: string, deployment: string, session: string): Promise<void>;
    listPublicCredentials(edge: string): Promise<PublicCredentialMetadata[]>;
    provisionPublicCredential(input: ProvisionPublicCredentialInput): Promise<PublicCredentialMetadata>;
    revokePublicCredential(edge: string, credentialRef: string): Promise<void>;
    /** Discover the signed-in owner's admitted funding source at runtime. */
    accountManagedInference?(): Promise<ManagedInferenceBilling>;
    /** The collection surfaces (ADR 0109 §5–§7). Optional so an environment that
     *  cannot collect still renders the rest of the panel rather than crashing on
     *  a missing method. */
    listCollectionRecipients?(): Promise<CollectionRecipient[]>;
    ensureCollectionRecipient?(recipientId: string): Promise<CollectionRecipient>;
    drainCollections?(input: {
        deployment_id: string;
        edge_origin: string;
        project_id: string;
        recipient_id: string;
        schema_ref: string;
        admission_scope: string;
    }): Promise<{ landed: readonly string[]; refused: readonly unknown[] }>;
    /** Start the installed project gate for one newly landed item. */
    screenQuarantinedItem?(
        project: string,
        item: string,
        chat: EngagementId,
    ): Promise<{ workspacePath: string | null; parked: boolean }>;
}

export interface DeploymentSelection {
    /** The project a drain lands in — its quarantine, never its workspace. */
    readonly projectId: string;
    readonly projectName: string;
    readonly placementId: PlacementId;
    readonly archetypeName: string;
    /** An existing chat on the deployed placement that owns gate execution and
     * receives approved material. Absent means publishing is available but a
     * collection cannot yet be drained. */
    readonly reviewChatId?: EngagementId;
}

const allPanels = ["gw-chat", "gw-viewer", "gw-files", "gw-chats"] as const;

function slug(value: string): string {
    return value
        .toLowerCase()
        .replace(/[^a-z0-9_-]+/g, "-")
        .replace(/^-+|-+$/g, "")
        .slice(0, 64) || "agent";
}

export function DeploymentPanel(props: {
    api: DeploymentPanelApi;
    selection: DeploymentSelection;
    defaultEdgeOrigin: string;
    defaultFundingRef: string;
    defaultCredentialRef: string;
    onClose: () => void;
}): JSX.Element {
    const [deploymentId, setDeploymentId] = createSignal(slug(props.selection.archetypeName));
    const [edgeOrigin, setEdgeOrigin] = createSignal(props.defaultEdgeOrigin);
    const [allowedOrigin, setAllowedOrigin] = createSignal(
        typeof window === "undefined" ? "https://example.com" : window.location.origin,
    );
    const [panels, setPanels] = createSignal<PublicDeploymentInput["panel_ceiling"]>(allPanels);
    const [maxSpend, setMaxSpend] = createSignal(1_000);
    const [visitorTurns, setVisitorTurns] = createSignal(20);
    const [maxSessions, setMaxSessions] = createSignal(100);
    const [model, setModel] = createSignal("gpt-5-mini");
    // Starts empty. It used to default to the managed pseudo-credential, which
    // is exactly the coupling ADR 0085 §1 separates: a BYOK selection must be a
    // deliberate act, because it decides who gets billed.
    const [credentialRef, setCredentialRef] = createSignal("");
    // Which of ADR 0085 §1's two sources pays for this deployment's turns.
    // Defaults to the metered plan when this Home has one: it is the path that
    // needs no provider key from the owner at all.
    const [managedPlanRef, setManagedPlanRef] = createSignal(
        isManagedPlanRef(props.defaultFundingRef) ? props.defaultFundingRef : "",
    );
    const [fundingMode, setFundingMode] = createSignal<FundingMode>(
        managedPlanRef() ? "managed" : "byok",
    );
    const [credentialClass, setCredentialClass] = createSignal("managed-openai");
    const [credentials, setCredentials] = createSignal<PublicCredentialMetadata[]>([]);
    const [credentialLabel, setCredentialLabel] = createSignal("");
    const [providerKey, setProviderKey] = createSignal("");
    const [credentialBusy, setCredentialBusy] = createSignal(false);
    const [credentialError, setCredentialError] = createSignal("");
    const [whiteLabel, setWhiteLabel] = createSignal(false);
    // Retention: how long a visitor may resume, within the release's ceiling
    // (ADR 0109). A resumption window, not a collection deadline — the copy says
    // so, because conflating the two is how an owner sets a short window
    // expecting it to bound how long their data sits somewhere.
    const [idleTtlHours, setIdleTtlHours] = createSignal(24);
    const [absoluteTtlDays, setAbsoluteTtlDays] = createSignal(30);
    // Collection. Off unless the owner turns it on and names a recipient: there
    // is no ambient fallback, so a deployment that selects nothing collects
    // nothing rather than sealing to something the release did not authorize.
    const [collecting, setCollecting] = createSignal(false);
    const [exportablePaths, setExportablePaths] = createSignal("responses.json");
    const [transcriptEligible, setTranscriptEligible] = createSignal(false);
    const [schemaRef, setSchemaRef] = createSignal("survey.v1");
    const [recipientClass, setRecipientClass] = createSignal("collection:tenant");
    const [maxArtifactKb, setMaxArtifactKb] = createSignal(1_000);
    const [recipients, setRecipients] = createSignal<CollectionRecipient[]>([]);
    const [recipientId, setRecipientId] = createSignal("");
    const [recipientBusy, setRecipientBusy] = createSignal(false);
    const [collectionError, setCollectionError] = createSignal("");
    const [drainBusy, setDrainBusy] = createSignal(false);
    const [drainResult, setDrainResult] = createSignal("");

    /** The selected keyring, or null when this deployment collects nothing. */
    const selectedRecipient = () =>
        recipients().find((person) => person.recipient_id === recipientId()) ?? null;

    const draft = () => ({
        collecting: collecting(),
        paths: exportablePaths(),
        transcript: transcriptEligible(),
        schemaRef: schemaRef(),
        recipientClass: recipientClass(),
        maxArtifactKb: maxArtifactKb(),
        recipient: selectedRecipient(),
    });
    const collectionInput = () => collectionInputFrom(draft());
    const collectionBlocker = () => collectionBlockerFor(draft());

    const fundingDraft = () => ({
        mode: fundingMode(),
        managedPlanRef: managedPlanRef(),
        credentialRef: credentialRef(),
        credentialClass: credentialClass(),
    });
    const fundingFields = () => fundingFieldsFrom(fundingDraft());
    const fundingBlocker = () => fundingBlockerFor(fundingDraft());

    async function loadRecipients() {
        if (!props.api.listCollectionRecipients) return;
        try {
            const found = await props.api.listCollectionRecipients();
            setRecipients(found);
            if (!recipientId() && found.length > 0) setRecipientId(found[0].recipient_id);
        } catch (reason) {
            setCollectionError(String(reason));
        }
    }

    async function mintRecipient(id: string) {
        const wanted = id.trim();
        if (!wanted || !props.api.ensureCollectionRecipient) return;
        setRecipientBusy(true);
        setCollectionError("");
        try {
            // Load-or-create: naming an existing keyring selects it rather than
            // minting a second one, because artifacts sealed to the first would
            // otherwise never open again.
            const recipient = await props.api.ensureCollectionRecipient(wanted);
            setRecipients((current) => [
                ...current.filter((person) => person.recipient_id !== recipient.recipient_id),
                recipient,
            ].sort((a, b) => a.recipient_id.localeCompare(b.recipient_id)));
            setRecipientId(recipient.recipient_id);
        } catch (reason) {
            setCollectionError(String(reason));
        } finally {
            setRecipientBusy(false);
        }
    }

    async function drain() {
        const published = outcome();
        const recipient = selectedRecipient();
        const reviewChat = props.selection.reviewChatId;
        if (!published || !recipient || !props.api.drainCollections || !reviewChat
            || !props.api.screenQuarantinedItem) return;
        setDrainBusy(true);
        setDrainResult("");
        try {
            const result = await props.api.drainCollections({
                deployment_id: published.deployment_id,
                edge_origin: published.edge_origin,
                project_id: props.selection.projectId,
                recipient_id: recipient.recipient_id,
                schema_ref: schemaRef().trim(),
                // The scope a session sealed its wraps under, which the edge sets
                // to the deployment id when it bootstraps one. Passed explicitly
                // rather than defaulted in the client: it is opaque to us, and a
                // wrong one fails to open an artifact rather than opening
                // something else, so the coupling belongs where it is visible.
                admission_scope: published.deployment_id,
            });
            // Deliberately says "quarantine", not "your workspace". This surface
            // ends at the boundary (ADR 0110): nothing an agent can read has
            // happened yet, and telling an owner otherwise would misdescribe the
            // one protection the whole path exists for.
            const landed = result.landed.length;
            const refused = result.refused.length;
            const screened = await Promise.allSettled(result.landed.map((item) =>
                props.api.screenQuarantinedItem!(
                    props.selection.projectId,
                    item,
                    reviewChat,
                )));
            const screenFailures = screened.filter((entry) => entry.status === "rejected").length;
            setDrainResult(
                landed === 0 && refused === 0
                    ? "Nothing was waiting."
                    : `${landed} item(s) into quarantine; the project's gate started.`
                        + (screenFailures > 0
                            ? ` ${screenFailures} gate start(s) failed; the items remain quarantined.`
                            : "")
                        + (refused > 0 ? ` ${refused} refused and left with the deployment.` : ""),
            );
        } catch (reason) {
            setDrainResult(String(reason));
        } finally {
            setDrainBusy(false);
        }
    }

    onMount(() => void loadRecipients());
    const [busy, setBusy] = createSignal(false);
    const [error, setError] = createSignal("");
    const [outcome, setOutcome] = createSignal<PublicDeploymentOutcome | null>(null);
    const [inspection, setInspection] = createSignal<PublicDeploymentInspection | null>(null);
    const [lastInspectedAt, setLastInspectedAt] = createSignal<number | null>(null);
    const [monitorError, setMonitorError] = createSignal("");
    const [armed, setArmed] = createSignal("");
    const [abilities, setAbilities] = createSignal<AgentAbility[] | null>(null);
    const [abilitiesError, setAbilitiesError] = createSignal("");
    let preview: HTMLDivElement | undefined;

    const edge = () => edgeOrigin().trim().replace(/\/+$/, "");
    // Only the owner's real credentials. A synthetic "GaugeWright managed" entry
    // used to sit here, from when managed funding still needed a credential
    // reference — under ADR 0085 §1 it has none, and offering a fake one invited
    // publishing a plan and a credential together.
    const availableCredentials = () => credentials();

    const loadCredentials = async () => {
        setCredentialBusy(true);
        setCredentialError("");
        try {
            setCredentials(await props.api.listPublicCredentials(edge()));
        } catch (reason) {
            setCredentialError(String(reason));
        } finally {
            setCredentialBusy(false);
        }
    };

    onMount(() => {
        void loadCredentials();
        if (props.api.accountManagedInference) {
            void props.api.accountManagedInference().then((billing) => {
                const discovered = managedPlanRefFromBilling(billing);
                if (!discovered) return;
                setManagedPlanRef(discovered);
                if (!credentialRef()) setFundingMode("managed");
            }).catch((reason) => setCredentialError(`Managed plan discovery failed: ${String(reason)}`));
        }
        void props.api.getPlacementAbilities(props.selection.placementId)
            .then(setAbilities)
            .catch((reason) => setAbilitiesError(String(reason)));
    });

    const chooseCredential = (reference: string) => {
        const credential = availableCredentials().find(
            (candidate) => candidate.credential_ref === reference,
        );
        setCredentialRef(reference);
        // Funding is no longer derived from the credential: the mode decides who
        // pays, and `fundingFieldsFrom` builds the pairing. Deriving it here is
        // what allowed a plan and a credential to both be set.
        setCredentialClass(credential ? credential.credential_class : "managed-openai");
    };

    const provisionCredential = async () => {
        setCredentialBusy(true);
        setCredentialError("");
        try {
            const credential = await props.api.provisionPublicCredential({
                edge_origin: edge(),
                provider: "openai",
                credential_class: "managed-openai",
                api_key: providerKey(),
                label: credentialLabel().trim(),
            });
            setProviderKey("");
            setCredentialLabel("");
            setCredentials((current) => [...current, credential]);
            chooseCredential(credential.credential_ref);
        } catch (reason) {
            setCredentialError(String(reason));
        } finally {
            setCredentialBusy(false);
        }
    };

    const revokeCredential = async () => {
        const reference = credentialRef();
        if (!reference.startsWith("credential:public:")) return;
        setCredentialBusy(true);
        setCredentialError("");
        try {
            await props.api.revokePublicCredential(edge(), reference);
            setCredentials((current) => current.filter(
                (credential) => credential.credential_ref !== reference,
            ));
            // Revoking the selected key leaves no funding rather than silently
            // falling back to another source.
            chooseCredential("");
        } catch (reason) {
            setCredentialError(String(reason));
        } finally {
            setCredentialBusy(false);
        }
    };

    createEffect(() => {
        const published = outcome();
        if (!preview) return;
        preview.replaceChildren();
        if (!published) return;
        const session = document.createElement("gw-session");
        session.setAttribute("host", published.deployment_url);
        session.setAttribute("panels", panels().map((panel) => panel.replace("gw-", "")).join(","));
        for (const panel of panels()) session.append(document.createElement(panel));
        preview.append(session);
    });

    createEffect(() => {
        if (!inspection()) return;
        const stop = startDeploymentMonitor(
            () => props.api.inspectDeployment(
                    edgeOrigin().trim().replace(/\/+$/, ""),
                    deploymentId().trim(),
                ),
            (next, at) => {
                setInspection(next);
                setLastInspectedAt(at);
                setMonitorError("");
            },
            (reason) => {
                setMonitorError(String(reason));
            },
            window,
        );
        onCleanup(stop);
    });

    const togglePanel = (panel: typeof allPanels[number], checked: boolean) => {
        setPanels((current) => checked
            ? [...new Set([...current, panel])]
            : current.filter((value) => value !== panel));
    };

    const publish = async (event: SubmitEvent) => {
        event.preventDefault();
        setBusy(true);
        setError("");
        try {
            const funding = fundingFields();
            if (!funding) {
                // Refuse locally rather than send a pairing the edge will reject:
                // the owner gets the reason in their own terms instead of a 422.
                setError(fundingBlocker() || "This deployment has no usable funding source.");
                return;
            }
            const published = await props.api.publishDeployment({
                placement_id: props.selection.placementId,
                deployment_id: deploymentId().trim(),
                edge_origin: edgeOrigin().trim().replace(/\/+$/, ""),
                allowed_origins: [allowedOrigin().trim().replace(/\/+$/, "")],
                panel_ceiling: panels(),
                max_spend_cents: maxSpend(),
                reserve_cents_per_turn: 5,
                per_visitor_turn_limit: visitorTurns(),
                max_concurrent_sessions: maxSessions(),
                // One source of truth for who pays; `fundingFields` refuses to
                // produce a pairing the edge would reject, so a bad combination
                // cannot reach the wire (ADR 0085 §1, `FUND-1`).
                ...funding,
                model: model().trim(),
                white_label: whiteLabel(),
                retention_idle_ttl_seconds: retentionSeconds(idleTtlHours(), absoluteTtlDays()).idle,
                retention_absolute_ttl_seconds:
                    retentionSeconds(idleTtlHours(), absoluteTtlDays()).absolute,
                collection: collectionInput(),
            });
            setOutcome(published);
            const nextInspection = await props.api.inspectDeployment(
                published.edge_origin,
                published.deployment_id,
            );
            setInspection(nextInspection);
            setLastInspectedAt(Date.now());
            setMonitorError("");
        } catch (reason) {
            setError(String(reason));
        } finally {
            setBusy(false);
        }
    };

    const refresh = async () => {
        setBusy(true);
        setError("");
        try {
            const nextInspection = await props.api.inspectDeployment(
                edgeOrigin().trim().replace(/\/+$/, ""),
                deploymentId().trim(),
            );
            setInspection(nextInspection);
            setLastInspectedAt(Date.now());
            setMonitorError("");
        } catch (reason) {
            setError(String(reason));
        } finally {
            setBusy(false);
        }
    };

    const control = async (command: "pause" | "resume" | "revoke") => {
        const current = inspection();
        if (!current) return;
        if (command === "revoke" && armed() !== "revoke") {
            setArmed("revoke");
            return;
        }
        setBusy(true);
        setError("");
        try {
            await props.api.controlDeployment(
                edgeOrigin().trim().replace(/\/+$/, ""),
                deploymentId().trim(),
                command,
                current.deployment.activation_revision,
            );
            setArmed("");
            await refresh();
        } catch (reason) {
            setError(String(reason));
            setBusy(false);
        }
    };

    const eraseSession = async (session: string) => {
        if (armed() !== session) {
            setArmed(session);
            return;
        }
        setBusy(true);
        setError("");
        try {
            await props.api.erasePublicSession(
                edgeOrigin().trim().replace(/\/+$/, ""),
                deploymentId().trim(),
                session,
            );
            setArmed("");
            await refresh();
        } catch (reason) {
            setError(String(reason));
            setBusy(false);
        }
    };

    const copy = async () => {
        const html = outcome()?.embed_html;
        if (html) await navigator.clipboard?.writeText(html);
    };

    return (
        <div class="modal-overlay" data-deployment-panel onClick={() => props.onClose()}>
            <div
                class="modal embed-monitor"
                role="dialog"
                aria-label={`Deploy ${props.selection.archetypeName}`}
                onClick={(event) => event.stopPropagation()}
                onKeyDown={(event) => event.key === "Escape" && props.onClose()}
            >
                <div class="modal-head">
                    <h3>Deploy {props.selection.archetypeName}</h3>
                    <button type="button" onClick={() => props.onClose()}>×</button>
                </div>
                <p class="muted">
                    Publish the tested agent from {props.selection.projectName}. Publishing the
                    same deployment id updates it in place.
                </p>
                <form class="settings-form" onSubmit={publish}>
                    <fieldset class="settings-field">
                        <legend class="settings-label">Agent abilities</legend>
                        <Show when={abilities()} fallback={
                            <span class="muted">
                                {abilitiesError() || "Loading frozen release abilities…"}
                            </span>
                        }>
                            {(frozen) => (
                                <span>
                                    {frozen().length === 0
                                        ? "Chat only"
                                        : frozen().join(" · ")}
                                </span>
                            )}
                        </Show>
                        <p class="muted">
                            Frozen by the selected archetype release. Change abilities in
                            Archetype Settings and publish a new release to alter them.
                        </p>
                    </fieldset>
                    <label class="settings-field">
                        <span class="settings-label">Deployment id</span>
                        <input class="settings-input" value={deploymentId()}
                            onInput={(event) => setDeploymentId(event.currentTarget.value)} required />
                    </label>
                    <label class="settings-field">
                        <span class="settings-label">Website origin</span>
                        <input class="settings-input" value={allowedOrigin()}
                            onInput={(event) => setAllowedOrigin(event.currentTarget.value)}
                            placeholder="https://example.com" required />
                    </label>
                    <label class="settings-field">
                        <span class="settings-label">Edge origin</span>
                        <input class="settings-input" value={edgeOrigin()}
                            onInput={(event) => setEdgeOrigin(event.currentTarget.value)} required />
                    </label>
                    <fieldset class="settings-field">
                        <legend class="settings-label">Panels</legend>
                        <For each={allPanels}>{(panel) => (
                            <label class="settings-checkbox">
                                <input type="checkbox" checked={panels().includes(panel)}
                                    onChange={(event) => togglePanel(panel, event.currentTarget.checked)} />
                                {panel}
                            </label>
                        )}</For>
                    </fieldset>
                    <div class="deployment-field-grid">
                        <label class="settings-field">
                            <span class="settings-label">Total budget (cents)</span>
                            <input class="settings-input" type="number" min="1" value={maxSpend()}
                                onInput={(event) => setMaxSpend(event.currentTarget.valueAsNumber)} />
                        </label>
                        <label class="settings-field">
                            <span class="settings-label">Turns per visitor</span>
                            <input class="settings-input" type="number" min="1" value={visitorTurns()}
                                onInput={(event) => setVisitorTurns(event.currentTarget.valueAsNumber)} />
                        </label>
                        <label class="settings-field">
                            <span class="settings-label">Concurrent sessions</span>
                            <input class="settings-input" type="number" min="1" value={maxSessions()}
                                onInput={(event) => setMaxSessions(event.currentTarget.valueAsNumber)} />
                        </label>
                        <label class="settings-field">
                            <span class="settings-label">Model</span>
                            <input class="settings-input" value={model()}
                                onInput={(event) => setModel(event.currentTarget.value)} required />
                        </label>
                        <label class="settings-field">
                            <span class="settings-label">Who pays for visitors' turns</span>
                            {/* Two mutually exclusive sources (ADR 0085 §1). The
                                control is the *mode*, not a reference: picking a
                                reference directly is how a plan and a credential
                                could both end up set, and that ambiguity is about
                                who pays. */}
                            <select class="settings-input" value={fundingMode()}
                                onChange={(event) =>
                                    setFundingMode(event.currentTarget.value as FundingMode)}
                                required>
                                <option value="managed"
                                    disabled={!isManagedPlanRef(managedPlanRef())}>
                                    Metered — billed to you at cost plus margin
                                </option>
                                <option value="byok">
                                    Your own provider key — your provider bills you
                                </option>
                            </select>
                            <span class="settings-hint">
                                <Show
                                    when={fundingMode() === "managed"}
                                    fallback={<>Your key funds every visitor's turn on this panel. Visitors never supply or inherit a credential.</>}
                                >
                                    Turns run on GaugeWright's metered gateway. You are billed
                                    from measured usage — no provider key of yours is involved,
                                    and visitors never fund anything.
                                </Show>
                            </span>
                        </label>
                        <Show when={fundingMode() === "byok"}>
                        <label class="settings-field">
                            <span class="settings-label">Provider credential</span>
                            <select class="settings-input" value={credentialRef()}
                                onChange={(event) => chooseCredential(event.currentTarget.value)}
                                required>
                                <option value="" disabled>Select a credential</option>
                                <For each={availableCredentials()}>{(credential) => (
                                    <option value={credential.credential_ref}>
                                        {credential.label || "Owner credential"} · {credential.provider}
                                    </option>
                                )}</For>
                            </select>
                        </label>
                        </Show>
                    </div>
                    <label class="settings-checkbox">
                        <input type="checkbox" checked={whiteLabel()}
                            onChange={(event) => setWhiteLabel(event.currentTarget.checked)} />
                        Hide GaugeWright attribution
                    </label>
                    <p class="muted">
                        The deployment receives only a credential reference. Provider secrets
                        remain in the edge host and are injected only at provider egress. BYOK
                        funding charges the provider account behind the selected key.
                    </p>
                    <fieldset class="settings-field">
                        <legend class="settings-label">Bring your own OpenAI key</legend>
                        <div class="deployment-field-grid">
                            <label class="settings-field">
                                <span class="settings-label">Label</span>
                                <input class="settings-input" value={credentialLabel()}
                                    onInput={(event) => setCredentialLabel(event.currentTarget.value)}
                                    placeholder="Production key" />
                            </label>
                            <label class="settings-field">
                                <span class="settings-label">API key</span>
                                <input class="settings-input" type="password" value={providerKey()}
                                    autocomplete="off"
                                    onInput={(event) => setProviderKey(event.currentTarget.value)}
                                    placeholder="sk-…" />
                            </label>
                        </div>
                        <div class="deployment-actions">
                            <button type="button" disabled={credentialBusy()}
                                onClick={() => void provisionCredential()}>
                                Add key
                            </button>
                            <button type="button" disabled={credentialBusy()}
                                onClick={() => void loadCredentials()}>Refresh keys</button>
                            <button type="button" class="danger"
                                disabled={credentialBusy()
                                    || !credentialRef().startsWith("credential:public:")}
                                onClick={() => void revokeCredential()}>Revoke selected key</button>
                        </div>
                        <Show when={credentialError()}>
                            <p class="error">{credentialError()}</p>
                        </Show>
                    </fieldset>
                    <fieldset class="deployment-fieldset">
                        <legend class="settings-label">Retention</legend>
                        {/* A resumption window, not a collection deadline. Saying so
                            here is the point: an owner who reads this as "how long
                            you keep my visitors' answers" would set it short and be
                            wrong about what they bought. Collection latency is
                            independent, and the drain below is what ends custody. */}
                        <p class="settings-hint">
                            How long a visitor may come back to their session. This is a
                            resumption window, not a deadline on collected material — draining
                            is what ends the deployment's custody. The release sets a ceiling and
                            the edge refuses anything above it.
                        </p>
                        <div class="deployment-field-grid">
                            <label class="settings-field">
                                <span class="settings-label">Idle (hours)</span>
                                <input class="settings-input" type="number" min="1" value={idleTtlHours()}
                                    onInput={(event) =>
                                        setIdleTtlHours(Number(event.currentTarget.value) || 1)} />
                            </label>
                            <label class="settings-field">
                                <span class="settings-label">Absolute (days)</span>
                                <input class="settings-input" type="number" min="1" value={absoluteTtlDays()}
                                    onInput={(event) =>
                                        setAbsoluteTtlDays(Number(event.currentTarget.value) || 1)} />
                            </label>
                        </div>
                    </fieldset>
                    <fieldset class="deployment-fieldset">
                        <legend class="settings-label">Collection</legend>
                        <label class="settings-checkbox">
                            <input type="checkbox" checked={collecting()}
                                onChange={(event) => setCollecting(event.currentTarget.checked)} />
                            <span>Collect what visitors produce</span>
                        </label>
                        <Show when={collecting()}>
                            <p class="settings-hint">
                                Only the paths named here can leave a session, and only sealed to
                                the keyring you choose. Nothing is sealed to an ambient default: a
                                deployment with no recipient collects nothing.
                            </p>
                            <div class="deployment-field-grid">
                                <label class="settings-field">
                                    <span class="settings-label">Exportable paths</span>
                                    <input class="settings-input" value={exportablePaths()}
                                        onInput={(event) => setExportablePaths(event.currentTarget.value)}
                                        placeholder="responses.json, notes/*" />
                                </label>
                                <label class="settings-field">
                                    <span class="settings-label">Schema</span>
                                    <input class="settings-input" value={schemaRef()}
                                        onInput={(event) => setSchemaRef(event.currentTarget.value)}
                                        placeholder="survey.v1" />
                                </label>
                                <label class="settings-field">
                                    <span class="settings-label">Recipient class</span>
                                    <input class="settings-input" value={recipientClass()}
                                        onInput={(event) => setRecipientClass(event.currentTarget.value)} />
                                </label>
                                <label class="settings-field">
                                    <span class="settings-label">Size bound (KB)</span>
                                    <input class="settings-input" type="number" min="1" value={maxArtifactKb()}
                                        onInput={(event) =>
                                            setMaxArtifactKb(Number(event.currentTarget.value) || 1)} />
                                </label>
                            </div>
                            {/* Independently declared, because a transcript is a
                                different disclosure from a workspace file: it carries
                                everything the visitor typed, not what they chose to
                                submit. */}
                            <label class="settings-checkbox">
                                <input type="checkbox" checked={transcriptEligible()}
                                    onChange={(event) =>
                                        setTranscriptEligible(event.currentTarget.checked)} />
                                <span>Include the conversation transcript</span>
                            </label>
                            <label class="settings-field">
                                <span class="settings-label">Recipient keyring</span>
                                <select class="settings-input" value={recipientId()}
                                    onChange={(event) => setRecipientId(event.currentTarget.value)}>
                                    <option value="">— none selected —</option>
                                    <For each={recipients()}>
                                        {(person) => (
                                            <option value={person.recipient_id}>
                                                {person.recipient_id}
                                            </option>
                                        )}
                                    </For>
                                </select>
                            </label>
                            {/* The private half never leaves this Home; it is what
                                opens a drained artifact. Showing the public half is
                                safe and makes the asymmetry visible rather than
                                something the owner has to take on faith. */}
                            <Show when={selectedRecipient()}>{(person) => (
                                <p class="settings-hint">
                                    Sealing to <code>{person().recipient_ref}</code>. Its public half
                                    is <code>{person().public_key_hex.slice(0, 16)}…</code>; the private
                                    half stays on this machine and is what opens what arrives.
                                </p>
                            )}</Show>
                            <div class="deployment-actions">
                                <input class="settings-input" value={recipientId()}
                                    onInput={(event) => setRecipientId(event.currentTarget.value)}
                                    placeholder="new-keyring-name" />
                                <button type="button" disabled={recipientBusy() || !recipientId().trim()}
                                    onClick={() => void mintRecipient(recipientId())}>
                                    {recipientBusy() ? "Working…" : "Use this keyring"}
                                </button>
                            </div>
                            <Show when={collectionBlocker()}>
                                <p class="settings-hint warn">{collectionBlocker()}</p>
                            </Show>
                            <Show when={collectionError()}>
                                <p class="error">{collectionError()}</p>
                            </Show>
                        </Show>
                    </fieldset>
                    <div class="deployment-actions">
                        <button type="submit" disabled={busy()
                            || panels().length === 0
                            || Boolean(fundingBlocker())
                            || Boolean(collectionBlocker())}>
                            {busy() ? "Working…" : outcome() ? "Publish update" : "Publish"}
                        </button>
                        <button type="button" disabled={busy()} onClick={() => void refresh()}>
                            Load deployment
                        </button>
                    </div>
                    <Show when={fundingBlocker()}>
                        <p class="settings-hint warn">{fundingBlocker()}</p>
                    </Show>
                    <Show when={error()}><p class="error">{error()}</p></Show>
                </form>
                <Show when={outcome()}>{(published) => (
                    <section class="admin-section" data-deployment-result>
                        <h4>Live deployment</h4>
                        <a href={published().deployment_url} target="_blank" rel="noreferrer">
                            {published().deployment_url}
                        </a>
                        <pre class="embed-snippet">{published().embed_html}</pre>
                        <button type="button" onClick={() => void copy()}>Copy embed HTML</button>
                        <h4>Preview</h4>
                        <div class="deployment-preview" ref={preview} />
                    </section>
                )}</Show>
                <Show when={inspection()}>{(current) => (
                    <section class="admin-section" data-deployment-monitor>
                        <div class="modal-head">
                            <h4>Operation</h4>
                            <span class="badge">{current().deployment.lifecycle}</span>
                        </div>
                        <p class="muted" aria-live="polite">
                            Monitoring every 10 seconds
                            <Show when={lastInspectedAt()}>
                                {(at) => <> · updated {new Date(at()).toLocaleTimeString()}</>}
                            </Show>
                        </p>
                        <Show when={monitorError()}>
                            <p class="error">Monitoring delayed: {monitorError()}</p>
                        </Show>
                        <ul class="member-list">
                            <li class="member-row"><span class="member-id">sessions</span>
                                <span>{current().deployment.sessions}</span></li>
                            <li class="member-row"><span class="member-id">settled turns</span>
                                <span>{current().deployment.settled_turns}</span></li>
                            <li class="member-row"><span class="member-id">spend</span>
                                <span>{current().deployment.spent_cents.toFixed(4)}¢</span></li>
                            <li class="member-row"><span class="member-id">reserved</span>
                                <span>{current().deployment.reserved_cents.toFixed(4)}¢</span></li>
                        </ul>
                        <div class="deployment-actions">
                            <Show when={current().deployment.lifecycle === "active"} fallback={
                                <button type="button"
                                    disabled={busy() || current().deployment.lifecycle === "revoked"}
                                    onClick={() => void control("resume")}>Resume</button>
                            }>
                                <button type="button" disabled={busy()}
                                    onClick={() => void control("pause")}>Pause</button>
                            </Show>
                            <button type="button" class="danger"
                                disabled={busy() || current().deployment.lifecycle === "revoked"}
                                onClick={() => void control("revoke")}>
                                {armed() === "revoke" ? "Confirm revoke" : "Revoke"}
                            </button>
                            <button type="button" disabled={busy()} onClick={() => void refresh()}>
                                Refresh
                            </button>
                        </div>
                        {/* Draining is where this surface ends (ADR 0110). The button
                            says "quarantine" and not "workspace" because that is what
                            happens: nothing an agent can read has occurred yet, and
                            describing it as delivery would misstate the one protection
                            the whole path exists for. */}
                        <Show when={props.api.drainCollections && selectedRecipient()}>
                            <h4>Collected material</h4>
                            <p class="settings-hint">
                                Draining moves what the deployment holds into
                                <strong> {props.selection.projectName}</strong>'s quarantine. No agent
                                can read it there; it reaches the workspace only through the
                                project's gate.
                            </p>
                            <Show when={props.selection.reviewChatId && props.api.screenQuarantinedItem}
                                fallback={<p class="settings-hint" data-drain-blocked>
                                    Start a chat on this placement before draining so the project's
                                    gate has an explicit review destination.
                                </p>}>
                            <div class="deployment-actions">
                                <button type="button" disabled={drainBusy() || busy()}
                                    onClick={() => void drain()}>
                                    {drainBusy() ? "Draining…" : "Drain into quarantine"}
                                </button>
                            </div>
                            </Show>
                            <Show when={drainResult()}>
                                <p class="settings-hint" data-drain-result>{drainResult()}</p>
                            </Show>
                        </Show>
                        <h4>Audience sessions</h4>
                        <ul class="member-list">
                            <For each={current().audience}
                                fallback={<li class="muted">No retained sessions.</li>}>
                                {(session) => (
                                    <li class="member-row">
                                        <span class="member-id">
                                            {session.session_id} · {session.principal_mode}
                                        </span>
                                        <span>{session.settled_turns} turns</span>
                                        <button type="button" class="danger" disabled={busy()}
                                            onClick={() => void eraseSession(session.session_id)}>
                                            {armed() === session.session_id
                                                ? "Confirm erase"
                                                : "Erase"}
                                        </button>
                                    </li>
                                )}
                            </For>
                        </ul>
                    </section>
                )}</Show>
            </div>
        </div>
    );
}
