/**
 * The per-project **Engagement** pane (`FED-7`) — the product surface for handing a
 * project's home to a client machine and co-owning it, opened **from a project** (its
 * id comes from context, never typed). It replaces the old global `FederationPanel`
 * modal's project half: no raw `offer`/`sync`/`commit`/`abort` controls, no typed
 * project id, no typed payload "handle".
 *
 * It renders projections — the [[handoff]] status, participants, and connected data —
 * and submits control-plane commands (`INV-5`): one **Hand off** action (relocate the
 * home to a paired peer; the two-phase commit runs underneath, invisible), per-owner
 * **revoke** (licensing, future-only), and **Connect a folder** (a native folder
 * picker; the data handle is derived under the hood, never shown). Device pairing and
 * incoming consent live in the global Devices modal (Settings ▸ Devices).
 */

import { createEffect, createResource, createSignal, For, Show, type JSX } from "solid-js";
import {
    describeFailure,
    type EngagementId,
    type ProjectId,
    type Workspace,
    type CreatedHomeInvitation,
    type PlacementDistributionStatus,
    type PlacementId,
} from "@gaugewright/control-plane-client";
import {
    type EngagementInvite,
    type FederationPeer,
    type HandoffStatus,
    type ConnectedData,
    type Participant,
    type PlacedRun,
    type QueuedRun,
    type RunResult,
} from "@gaugewright/control-plane-client";
import { qrSvg } from "./qr-code";

const isTauri = () => typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

/** A human label for where the project's home is, from the folded handoff status. */
function homeLabel(s: HandoffStatus | null | undefined): string {
    if (!s || s.phase === "draft") return "this device";
    if (s.phase === "committed") return s.home === "target" ? "the client's device" : "this device";
    if (s.phase === "offered" || s.phase === "log_synced") return "this device (handoff in flight)";
    return "this device";
}

export interface EngagementPaneApi {
    getWorkspace(): Promise<Workspace>;
    handoffStatus(project: ProjectId): Promise<HandoffStatus>;
    handoffParticipants(project: ProjectId): Promise<Participant[]>;
    handoffData(project: ProjectId): Promise<ConnectedData[]>;
    listPeers(): Promise<FederationPeer[]>;
    runQueue(): Promise<QueuedRun[]>;
    handoffRelocate(project: ProjectId, peer: string): Promise<HandoffStatus>;
    getPlacementDistribution(placement: PlacementId): Promise<PlacementDistributionStatus>;
    setPlacementDistribution(
        placement: PlacementId,
        input: {
            profile: "licensed" | "protected_commercial";
            recipient_authority?: string;
            lease_seconds?: number;
            max_runs?: number;
        },
    ): Promise<PlacementDistributionStatus>;
    revokePlacementDistribution(placement: PlacementId): Promise<PlacementDistributionStatus>;
    renewPlacementDistribution(placement: PlacementId): Promise<PlacementDistributionStatus>;
    getPlacementDistributionAudit(placement: PlacementId): Promise<{
        events: readonly { action: string; at: number; uses: number; detail: string }[];
    }>;
    invite(project: ProjectId, disposition?: "relocate" | "join"): Promise<EngagementInvite>;
    inviteStatus(inviteId: string): Promise<{ accepted: boolean; accepted_by: string | null; confirm_code: string }>;
    handoffAbort(project: ProjectId): Promise<HandoffStatus>;
    handoffRevoke(project: ProjectId, authority: string, owns: string): Promise<void>;
    placeRun(
        peer: string,
        project: ProjectId,
        archetype: string,
        dataHandle: string,
        prompt: string,
        targetChat?: string,
    ): Promise<PlacedRun>;
    runResult(correlation: string): Promise<RunResult>;
    admitRunOnce(correlation: string): Promise<void>;
    allowRuns(project: ProjectId, operator: string): Promise<void>;
    denyRun(correlation: string): Promise<void>;
    handoffConnectData(project: ProjectId, handle: string, label?: string): Promise<void>;
    createHomeInvitation(
        authority: string,
        project: ProjectId,
        role?: "member" | "viewer",
    ): Promise<CreatedHomeInvitation>;
}

export function EngagementPane(props: {
    api: EngagementPaneApi;
    project: ProjectId;
    projectName: string;
    onClose: () => void;
}): JSX.Element {
    const [status, setStatus] = createSignal("");
    const [peer, setPeer] = createSignal("");
    // A minted combined invite (FED-7 Slice 2): shown as a QR + link + confirm code
    // while waiting for the client to accept on a fresh device.
    const [invite, setInvite] = createSignal<EngagementInvite | null>(null);
    const [accepted, setAccepted] = createSignal(false);
    // The folder a non-Tauri (browser/e2e) host connects, since there is no native
    // picker there — an inline field stands in for the dialog.
    const [folder, setFolder] = createSignal("");
    const [showFolderField, setShowFolderField] = createSignal(false);
    const [personAuthority, setPersonAuthority] = createSignal("");
    const [personInvite, setPersonInvite] = createSignal<CreatedHomeInvitation | null>(null);

    const [handoff, { refetch: refetchHandoff }] = createResource(
        () => props.project,
        (p) => props.api.handoffStatus(p),
    );
    const [participants, { refetch: refetchParticipants }] = createResource(
        () => props.project,
        (p) => props.api.handoffParticipants(p),
    );
    const [connected, { refetch: refetchData }] = createResource(
        () => props.project,
        (p) => props.api.handoffData(p),
    );
    const [peers] = createResource(() => props.api.listPeers());
    const [workspace] = createResource(() => props.api.getWorkspace());
    const projectPlacements = () => workspace()?.projects
        .find((project) => project.id === props.project)?.placements ?? [];
    const [distributionPlacement, setDistributionPlacement] = createSignal("");
    const selectedDistributionPlacement = () =>
        distributionPlacement() || projectPlacements()[0]?.placementId || "";
    const [distribution, { refetch: refetchDistribution }] = createResource(
        selectedDistributionPlacement,
        (placement) => placement
            ? props.api.getPlacementDistribution(placement as PlacementId)
            : Promise.resolve(null),
    );
    const [protectedProfile, setProtectedProfile] = createSignal(false);
    const [recipientTenant, setRecipientTenant] = createSignal("");
    const [leaseDays, setLeaseDays] = createSignal("30");
    const [maxRuns, setMaxRuns] = createSignal("0");
    const [distributionAudit, setDistributionAudit] = createSignal("");
    createEffect(() => {
        const current = distribution();
        if (!current) return;
        setProtectedProfile(current.profile === "protected_commercial");
        setRecipientTenant(current.recipient_authority);
        setLeaseDays(String(Math.max(1, Math.round(current.lease_seconds / 86_400))));
        setMaxRuns(String(current.max_runs));
    });

    async function saveDistribution(): Promise<void> {
        const placement = selectedDistributionPlacement();
        if (!placement) return;
        try {
            const profile = protectedProfile() ? "protected_commercial" : "licensed";
            const saved = await props.api.setPlacementDistribution(placement as PlacementId, {
                profile,
                ...(profile === "protected_commercial" ? {
                    recipient_authority: recipientTenant().trim(),
                    lease_seconds: Math.max(1, Number.parseInt(leaseDays(), 10)) * 86_400,
                    max_runs: Math.max(0, Number.parseInt(maxRuns(), 10) || 0),
                } : {}),
            });
            setStatus(saved.profile === "licensed"
                ? "licensed distribution saved — ordinary cross-organization federation remains open"
                : "protected commercial distribution saved — the exact recipient will be bound when the Home moves");
            await refetchDistribution();
        } catch (error) {
            setStatus(describeFailure("save the Agent distribution profile", error));
        }
    }

    async function revokeDistribution(): Promise<void> {
        try {
            await props.api.revokePlacementDistribution(selectedDistributionPlacement() as PlacementId);
            setStatus("protected commercial lease revoked — future releases are refused");
            await refetchDistribution();
        } catch (error) {
            setStatus(describeFailure("revoke the protected commercial lease", error));
        }
    }

    async function renewDistribution(): Promise<void> {
        try {
            await props.api.renewPlacementDistribution(selectedDistributionPlacement() as PlacementId);
            setStatus("protected commercial lease renewed for the exact recipient and current Agent revision");
            await refetchDistribution();
        } catch (error) {
            setStatus(describeFailure("renew the protected commercial lease", error));
        }
    }

    async function readDistributionAudit(): Promise<void> {
        try {
            const audit = await props.api.getPlacementDistributionAudit(
                selectedDistributionPlacement() as PlacementId,
            );
            setDistributionAudit(audit.events
                .map((event) => `${event.action} · ${event.uses} use(s)`)
                .join("; "));
        } catch (error) {
            setStatus(describeFailure("read the protected commercial audit", error));
        }
    }
    // Co-drive (FED-7): the host's admission queue (pending operator runs for this
    // project), and the operator's place-a-run controls.
    const [queue, { refetch: refetchQueue }] = createResource(
        () => props.project,
        async (p) => (await props.api.runQueue()).filter((r) => r.project === p),
    );
    const [runArchetype, setRunArchetype] = createSignal("");
    const [runPrompt, setRunPrompt] = createSignal("");
    const [runTargetChat, setRunTargetChat] = createSignal("");

    const refetchAll = () => {
        void refetchHandoff();
        void refetchParticipants();
        void refetchData();
    };

    const phase = () => handoff()?.phase ?? "draft";
    const handedOff = () => phase() === "committed";
    const inFlight = () => phase() === "offered" || phase() === "log_synced";
    const pairedPeers = () => (peers() ?? []).filter((p: FederationPeer) => p.active);
    const hubChats = (): { id: EngagementId; title: string }[] => {
        const project = workspace()?.projects.find((item) => item.id === props.project);
        if (!project) return [];
        const members = new Set(
            project.placements.flatMap((placement) =>
                placement.workstreams.flatMap((workstream) => workstream.members),
            ),
        );
        return project.placements
            .flatMap((placement) => placement.chats)
            .filter((chat) => members.has(chat.id))
            .map((chat) => ({ id: chat.id, title: chat.title }));
    };

    const handOff = async () => {
        const target = peer() || pairedPeers()[0]?.authority;
        if (!target) {
            setStatus("pair a device first (in Paired devices)");
            return;
        }
        try {
            const s = await props.api.handoffRelocate(props.project, target);
            setStatus(
                s.phase === "committed"
                    ? `handed off to ${target} — home is now there`
                    : `invite sent to ${target} — waiting for them to accept`,
            );
            refetchAll();
        } catch (e) {
            setStatus(describeFailure("hand off", e));
        }
    };
    // Mint a combined invite for a *new* device (first contact, no prior pairing) and
    // poll until the client accepts — one link that pairs and hands off (ADR 0047).
    const inviteNewDevice = async (disposition: "relocate" | "join") => {
        try {
            const inv = await props.api.invite(props.project, disposition);
            setInvite(inv);
            setAccepted(false);
            setStatus(
                disposition === "join"
                    ? "operator invite ready — the project Home will stay here"
                    : "handoff invite ready — share the QR or link; waiting for the client to accept",
            );
            void pollInvite(inv);
        } catch (e) {
            setStatus(describeFailure("create the invite", e));
        }
    };
    const pollInvite = async (invitation: EngagementInvite) => {
        for (let i = 0; i < 60 && !accepted(); i++) {
            await new Promise((r) => setTimeout(r, 1000));
            try {
                const s = await props.api.inviteStatus(invitation.invite_id);
                if (s.accepted) {
                    setAccepted(true);
                    setStatus(`accepted by ${s.accepted_by ?? "a device"} · confirm code ${s.confirm_code}`);
                    if (invitation.disposition === "join") {
                        refetchAll();
                        return;
                    }
                    // Acceptance resolves the pairing invitation before the
                    // origin's receiver finishes the two-phase relocation. A
                    // single refetch here can observe `offered` and then freeze
                    // forever. Follow the durable handoff projection through
                    // commit, which is the state the pane actually promises.
                    for (let settle = 0; settle < 60; settle++) {
                        const handoff = await props.api.handoffStatus(props.project);
                        if (handoff.phase === "committed") {
                            await refetchHandoff();
                            void refetchParticipants();
                            void refetchData();
                            return;
                        }
                        await new Promise((r) => setTimeout(r, 500));
                    }
                    refetchAll();
                    return;
                }
            } catch {
                /* keep polling */
            }
        }
    };
    const copyInvite = async () => {
        const url = invite()?.invite_url;
        if (url) {
            try {
                await navigator.clipboard?.writeText(url);
                setStatus("invite link copied");
            } catch {
                /* selectable regardless */
            }
        }
    };
    const invitePerson = async () => {
        const authority = personAuthority().trim();
        if (!authority) {
            setStatus("enter the GaugeWright account authority to invite");
            return;
        }
        try {
            const created = await props.api.createHomeInvitation(authority, props.project);
            setPersonInvite(created);
            setStatus("project invitation ready — share this link with that account only");
        } catch (e) {
            setStatus(describeFailure("invite the person", e));
        }
    };
    const copyPersonInvite = async () => {
        const url = personInvite()?.url;
        if (!url) return;
        try {
            await navigator.clipboard?.writeText(url);
            setStatus("project invitation link copied");
        } catch {
            setStatus("select and copy the project invitation link");
        }
    };
    const cancel = async () => {
        try {
            await props.api.handoffAbort(props.project);
            setStatus("handoff cancelled — the project stays here");
            refetchAll();
        } catch (e) {
            setStatus(describeFailure("cancel the handoff", e));
        }
    };
    const revoke = async (authority: string, owns: string) => {
        try {
            await props.api.handoffRevoke(props.project, authority, owns);
            setStatus(`revoked ${authority}'s access to ${owns}`);
            refetchParticipants();
        } catch (e) {
            setStatus(describeFailure("revoke access", e));
        }
    };
    // Operator: place a run on the host (executes if allowed, else queues for admission).
    const placeRun = async () => {
        const target = peer() || pairedPeers()[0]?.authority;
        if (!target) {
            setStatus("no paired host to place a run on");
            return;
        }
        const targetChat = runTargetChat() || hubChats()[0]?.id;
        if (!targetChat) {
            setStatus("create or join a workstream chat before placing a federated run");
            return;
        }
        try {
            const r = await props.api.placeRun(
                target,
                props.project,
                runArchetype().trim() || "Agent",
                connected()?.[0]?.handle ?? "data",
                runPrompt().trim() || "go",
                targetChat,
            );
            setStatus(
                r.status === "admitted"
                    ? `run executed on the host (${r.observations_admitted ?? 0} observations)`
                    : r.status === "pending"
                      ? "run placed — waiting for the host to admit it"
                      : `run refused: ${r.reason ?? "?"}`,
            );
            setRunPrompt("");
            refetchQueue();
            // If it landed pending, poll for the host's "Allow once" delivery.
            if (r.status === "pending") void pollRunResult(r.correlation);
        } catch (e) {
            setStatus(describeFailure("place the run", e));
        }
    };
    const pollRunResult = async (correlation: string) => {
        for (let i = 0; i < 120; i++) {
            await new Promise((res) => setTimeout(res, 1000));
            try {
                const r = await props.api.runResult(correlation);
                if (r.status === "done") {
                    setStatus(`host ran it (${r.observations_admitted ?? 0} observations)`);
                    return;
                }
            } catch {
                /* keep polling */
            }
        }
    };
    // Host: admit a queued operator run — once, or as a standing per-project allow — or deny.
    const admitOnce = async (correlation: string) => {
        try {
            await props.api.admitRunOnce(correlation);
            setStatus("ran it once");
            refetchQueue();
        } catch (e) {
            setStatus(describeFailure("allow once", e));
        }
    };
    const allowProject = async (operator: string) => {
        try {
            await props.api.allowRuns(props.project, operator);
            setStatus(`allowed ${operator}'s runs on this project`);
            refetchQueue();
        } catch (e) {
            setStatus(describeFailure("allow runs", e));
        }
    };
    const denyRun = async (correlation: string) => {
        try {
            await props.api.denyRun(correlation);
            setStatus("run denied");
            refetchQueue();
        } catch (e) {
            setStatus(describeFailure("deny the run", e));
        }
    };
    const connectFolder = async () => {
        let path = folder().trim();
        if (isTauri()) {
            const { open } = await import("@tauri-apps/plugin-dialog");
            const picked = await open({
                directory: true,
                multiple: false,
                title: `Connect a folder to ${props.projectName}`,
            });
            if (typeof picked !== "string") return;
            path = picked;
        } else if (!showFolderField()) {
            // First click in a browser host reveals the stand-in field for the picker.
            setShowFolderField(true);
            return;
        }
        if (!path) return;
        try {
            // The handle is derived from the folder path; the user never sees it.
            const label = path.split("/").filter(Boolean).pop() ?? path;
            await props.api.handoffConnectData(props.project, path, label);
            setStatus(`connected ${label}`);
            setFolder("");
            setShowFolderField(false);
            refetchData();
        } catch (e) {
            setStatus(describeFailure("connect the folder", e));
        }
    };

    return (
        <div class="modal-overlay" data-engagement-modal onClick={() => props.onClose()}>
            <div
                class="modal engagement-pane"
                data-engagement-pane={props.project}
                onClick={(e) => e.stopPropagation()}
                onKeyDown={(e) => e.key === "Escape" && props.onClose()}
            >
                <div class="modal-head">
                    <h3>Engagement — {props.projectName}</h3>
                    <button type="button" onClick={() => props.onClose()}>close</button>
                </div>

                {/* Home + connectivity */}
                <p class="status" data-engagement-home>
                    Home: <strong>{homeLabel(handoff())}</strong>
                    {" · "}
                    <span data-engagement-phase>{phase()}</span>
                </p>

                <Show when={projectPlacements().length > 0}>
                    <section class="engagement-handoff" data-protected-profile>
                        <h4>Agent distribution</h4>
                        <p class="status">
                            Cross-organization Agents are <strong>licensed by default</strong>.
                            Protected commercial adds recipient-bound encryption, attribution,
                            leases, metering, and revocation. A skilled operator of the recipient
                            Home can still capture plaintext while it runs.
                        </p>
                        <select
                            class="fed-paste"
                            data-distribution-placement
                            value={selectedDistributionPlacement()}
                            onChange={(event) => setDistributionPlacement(event.currentTarget.value)}
                        >
                            <For each={projectPlacements()}>
                                {(placement) => (
                                    <option value={placement.placementId}>{placement.archetypeName}</option>
                                )}
                            </For>
                        </select>
                        <label class="status">
                            <input
                                type="checkbox"
                                checked={protectedProfile()}
                                onChange={(event) => setProtectedProfile(event.currentTarget.checked)}
                            />
                            Protect this placement commercially
                        </label>
                        <Show when={protectedProfile()}>
                            <input
                                class="fed-paste"
                                data-distribution-recipient
                                placeholder="Exact recipient tenant ID"
                                value={recipientTenant()}
                                onInput={(event) => setRecipientTenant(event.currentTarget.value)}
                            />
                            <input
                                class="fed-paste"
                                type="number"
                                min="1"
                                max="31"
                                aria-label="Lease days"
                                value={leaseDays()}
                                onInput={(event) => setLeaseDays(event.currentTarget.value)}
                            />
                            <input
                                class="fed-paste"
                                type="number"
                                min="0"
                                aria-label="Maximum runs; zero means metered without a ceiling"
                                value={maxRuns()}
                                onInput={(event) => setMaxRuns(event.currentTarget.value)}
                            />
                        </Show>
                        <button
                            type="button"
                            class="tree-action"
                            data-distribution-save
                            onClick={() => void saveDistribution()}
                        >
                            Save distribution
                        </button>
                        <p class="status" data-distribution-status>
                            Current: {distribution()?.state ?? "licensed"}
                            <Show when={distribution()?.license_id}>
                                {(license) => <> · lease {license()}</>}
                            </Show>
                        </p>
                        <Show when={distribution()?.license_id}>
                            <div class="pair-device-actions">
                                <button type="button" class="tree-action" onClick={() => void renewDistribution()}>
                                    Renew lease
                                </button>
                                <button type="button" class="tree-action" onClick={() => void readDistributionAudit()}>
                                    View audit
                                </button>
                                <button type="button" class="tree-action" onClick={() => void revokeDistribution()}>
                                    Revoke lease
                                </button>
                            </div>
                            <Show when={distributionAudit()}>
                                <p class="status" data-distribution-audit>{distributionAudit()}</p>
                            </Show>
                        </Show>
                    </section>
                </Show>

                {/* The single state-driven action — never the raw state machine. */}
                <Show
                    when={!handedOff()}
                    fallback={
                        <p class="status" data-engagement-status>
                            This project's home is on the client's device. You drive runs they admit.
                        </p>
                    }
                >
                    <Show
                        when={inFlight()}
                        fallback={
                            <div class="engagement-handoff">
                                <Show
                                    when={invite()}
                                    fallback={
                                        <div class="pair-device-actions">
                                            {/* First contact uses one protocol with an explicit
                                                relocate or non-relocating N-party disposition. */}
                                            <button
                                                type="button"
                                                class="tree-action"
                                                data-engagement-invite
                                                onClick={() => void inviteNewDevice("relocate")}
                                            >
                                                Move Home to a new device
                                            </button>
                                            <button
                                                type="button"
                                                class="tree-action"
                                                data-engagement-join
                                                onClick={() => void inviteNewDevice("join")}
                                            >
                                                Add an operator
                                            </button>
                                            {/* Already-paired device: hand off directly. */}
                                            <Show when={pairedPeers().length > 0}>
                                                <select
                                                    class="fed-paste"
                                                    data-engagement-peer
                                                    value={peer()}
                                                    onChange={(e) => setPeer(e.currentTarget.value)}
                                                >
                                                    <For each={pairedPeers()}>
                                                        {(p) => <option value={p.authority}>{p.authority}</option>}
                                                    </For>
                                                </select>
                                                <button
                                                    type="button"
                                                    class="tree-action"
                                                    data-engagement-handoff
                                                    onClick={() => void handOff()}
                                                >
                                                    Hand off to this device
                                                </button>
                                            </Show>
                                        </div>
                                    }
                                >
                                    {(inv) => (
                                        <div class="engagement-invite">
                                            <p class="status">Have the client scan this or open the link:</p>
                                            <div
                                                class="pd-qr"
                                                data-engagement-qr
                                                innerHTML={qrSvg(inv().invite_url)}
                                            />
                                            <code class="pair-ticket" data-engagement-invite-link>
                                                {inv().invite_url}
                                            </code>
                                            <p class="status">
                                                Confirm code: <strong>{inv().confirm_code}</strong> — verify the
                                                client reads this back.
                                            </p>
                                            <div class="pair-device-actions">
                                                <button
                                                    type="button"
                                                    class="tree-action"
                                                    data-engagement-invite-copy
                                                    onClick={() => void copyInvite()}
                                                >
                                                    copy link
                                                </button>
                                            </div>
                                            <Show when={accepted()}>
                                                <p class="status" data-engagement-accepted>
                                                    {inv().disposition === "join"
                                                        ? "✓ operator added — Home stays here"
                                                        : "✓ accepted — Home moving to the client"}
                                                </p>
                                            </Show>
                                        </div>
                                    )}
                                </Show>
                            </div>
                        }
                    >
                        <div class="engagement-handoff pair-device-actions">
                            <span class="status" data-engagement-status>
                                Invite sent — waiting for the client to accept.
                            </span>
                            <button type="button" class="tree-action" data-engagement-cancel onClick={() => void cancel()}>
                                cancel
                            </button>
                        </div>
                    </Show>
                </Show>

                {/* Ordinary free-account participation is separate from device pairing
                    and Home relocation. It grants this project on the current Home. */}
                <section class="engagement-person-invite" data-person-invite>
                    <p class="status" style={{ margin: "12px 0 4px" }}>
                        Invite a person to this project:
                    </p>
                    <Show
                        when={personInvite()}
                        fallback={<div class="pair-device-actions">
                            <input
                                class="fed-paste"
                                data-person-authority
                                value={personAuthority()}
                                placeholder="GaugeWright account authority"
                                onInput={(event) => setPersonAuthority(event.currentTarget.value)}
                            />
                            <button
                                type="button"
                                class="tree-action"
                                data-person-invite-create
                                onClick={() => void invitePerson()}
                            >
                                Create project invitation
                            </button>
                        </div>}
                    >
                        {(created) => <div class="engagement-invite">
                            <p class="status">
                                This link works only for the invited account and grants only this project.
                            </p>
                            <code class="pair-ticket" data-person-invite-link>{created().url}</code>
                            <button
                                type="button"
                                class="tree-action"
                                data-person-invite-copy
                                onClick={() => void copyPersonInvite()}
                            >
                                copy link
                            </button>
                        </div>}
                    </Show>
                </section>

                {/* Participants & ownership (revoke = licensing, not secrecy). */}
                <Show when={(participants() ?? []).length > 0}>
                    <p class="status" style={{ margin: "12px 0 4px" }}>People &amp; ownership:</p>
                    <ul class="fed-participants" data-engagement-participants>
                        <For each={participants() ?? []}>
                            {(p) => (
                                <li class="fed-participant" data-engagement-participant={p.authority}>
                                    <span class="fed-peer-name">{p.authority}</span>
                                    <span>{p.role} · owns {p.owns}</span>
                                    <Show when={!p.revoked} fallback={<span class="fed-peer-grant">revoked</span>}>
                                        <button
                                            type="button"
                                            class="tree-action"
                                            data-engagement-revoke={p.owns}
                                            onClick={() => void revoke(p.authority, p.owns)}
                                        >
                                            {p.owns === "data" ? "Stop sharing" : "Revoke access"}
                                        </button>
                                    </Show>
                                </li>
                            )}
                        </For>
                    </ul>
                </Show>

                {/* Connected data — a folder picker, never a handle. */}
                <p class="status" style={{ margin: "12px 0 4px" }}>Connected data:</p>
                <ul class="fed-data" data-engagement-data>
                    <For
                        each={connected() ?? []}
                        fallback={<li class="status">No folder connected yet.</li>}
                    >
                        {(d) => <li data-engagement-data-item={d.handle}>{d.label ?? d.handle}</li>}
                    </For>
                </ul>
                <Show when={showFolderField() && !isTauri()}>
                    <input
                        class="fed-paste"
                        data-engagement-folder
                        value={folder()}
                        placeholder="/path/to/folder"
                        onInput={(e) => setFolder(e.currentTarget.value)}
                    />
                </Show>
                <button
                    type="button"
                    class="tree-action"
                    data-engagement-connect-data
                    onClick={() => void connectFolder()}
                >
                    Connect a folder
                </button>

                {/* Co-drive: the host's admission queue + the operator's place-a-run. */}
                <p class="status" style={{ margin: "12px 0 4px" }}>Co-drive runs:</p>
                <Show when={(queue() ?? []).length > 0}>
                    <ul class="fed-incoming" data-engagement-run-queue>
                        <For each={queue() ?? []}>
                            {(r) => (
                                <li class="fed-incoming-item" data-engagement-run={r.correlation}>
                                    <span>
                                        <strong>{r.operator}</strong> wants to run{" "}
                                        <strong>{r.archetype}</strong> on <code>{r.data_handle}</code>
                                    </span>
                                    <button
                                        type="button"
                                        class="tree-action"
                                        data-engagement-run-once={r.correlation}
                                        onClick={() => void admitOnce(r.correlation)}
                                    >
                                        Allow once
                                    </button>
                                    <button
                                        type="button"
                                        class="tree-action"
                                        data-engagement-run-allow={r.operator}
                                        onClick={() => void allowProject(r.operator)}
                                    >
                                        Allow for project
                                    </button>
                                    <button
                                        type="button"
                                        class="tree-action"
                                        data-engagement-run-deny={r.correlation}
                                        onClick={() => void denyRun(r.correlation)}
                                    >
                                        Deny
                                    </button>
                                </li>
                            )}
                        </For>
                    </ul>
                </Show>
                <Show when={handedOff()}>
                    <div class="pair-device-actions">
                        <select
                            class="fed-paste"
                            data-engagement-run-target-chat
                            aria-label="Hub workstream chat"
                            value={runTargetChat()}
                            onChange={(e) => setRunTargetChat(e.currentTarget.value)}
                        >
                            <option value="">Choose a hub workstream chat</option>
                            <For each={hubChats()}>
                                {(chat) => <option value={chat.id}>{chat.title}</option>}
                            </For>
                        </select>
                        <input
                            class="fed-paste"
                            data-engagement-run-archetype
                            value={runArchetype()}
                            placeholder="Agent"
                            onInput={(e) => setRunArchetype(e.currentTarget.value)}
                        />
                        <input
                            class="fed-paste"
                            data-engagement-run-prompt
                            value={runPrompt()}
                            placeholder="what should it do?"
                            onInput={(e) => setRunPrompt(e.currentTarget.value)}
                        />
                        <button
                            type="button"
                            class="tree-action"
                            data-engagement-place-run
                            onClick={() => void placeRun()}
                        >
                            Place a run
                        </button>
                    </div>
                </Show>

                <Show when={status()}>
                    <p class="status" data-engagement-feedback>{status()}</p>
                </Show>
            </div>
        </div>
    );
}
