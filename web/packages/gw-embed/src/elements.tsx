/**
 * The embed custom elements (EMBED-2): `<gw-session>` + `<gw-chat>` / `<gw-viewer>`
 * / `<gw-files>`. They let a consultant drop the workbench's panels into their own
 * page in any stack (ADR 0051 §3) — the delivery side of the context-portable
 * panels EMBED-1 built.
 *
 * Architecture:
 *  - `<gw-session>` holds one EDGE-5 session client adapted to the shared workbench
 *    Session contract and exposed as the element's `.session` property. It is a
 *    logical provider (light DOM) — its panel children find it by DOM ancestry.
 *  - each panel element finds its Session (the ancestor `<gw-session>`'s `.session`,
 *    or its own `.session` set directly — the JS-handle escape hatch for detached
 *    layouts), attaches a **shadow root** for style isolation, adopts the workbench
 *    stylesheet, and renders the existing Solid panel against the Session.
 *
 * Solid context cannot cross separate render roots, so each panel re-provides the
 * shared Session into its own tree via {@link SessionProvider} — the panel code is
 * unchanged (`useSession()` works exactly as on the desktop).
 */
import { createResource, Show, type JSX } from "solid-js";
import { render } from "solid-js/web";
import { type ControlPlane, type EngagementId } from "@gaugewright/control-plane-client";
import { EdgeSessionApi } from "./edge-session";
import {
    LATENCY_EVENT,
    observeBrowserLatency,
    relayServerLatency,
    type LatencyObservation,
} from "./latency";
import { createRemoteSession } from "./remote-session";
import { ChatPanel } from "@gaugewright/workbench-ui/ChatPanel";
import { AudienceChats } from "@gaugewright/workbench-ui/AudienceChats";
import { ContentViewer } from "@gaugewright/workbench-ui/ContentViewer";
import {
    Environment,
    panelManifest,
    type PanelId,
} from "@gaugewright/workbench-ui/environment";
import { SessionProvider, type Session } from "@gaugewright/workbench-ui/session-context";
import { Workspace } from "@gaugewright/workbench-ui/Workspace";
import appCss from "@gaugewright/workbench-ui/styles.css?inline";

/**
 * The shadow-root theme bridge. The workbench palette is defined on `:root`
 * (`styles.css`), which does **not** apply inside a shadow tree — so we re-declare
 * the workbench's internal palette vars on `:host` (custom properties *do* inherit
 * across the shadow boundary), each sourced from a consultant-facing `--gw-*`
 * token with the workbench default as fallback. A consultant themes the embed by
 * setting any `--gw-*` on `<gw-session>` (or any ancestor); it cascades into every
 * panel's shadow root. Injected before `styles.css` so its `var(--bg)` etc. resolve.
 */
const embedThemeCss = (defaultMinHeight: string) => `
:host {
  /* Public theme tokens. Internal aliases are declared here so unrelated host
     variables with generic names such as --panel or --muted cannot leak in. */
  --gw-navy: var(--gw-brand-navy, #0e2d50);
  --bg: var(--gw-bg, #0f1115);
  --panel: var(--gw-panel, #161922);
  --edge: var(--gw-edge, #262b36);
  --ink: var(--gw-ink, #d8dee9);
  --muted: var(--gw-muted, #7d869c);
  --accent: var(--gw-accent, #6aa3ff);
  --accent-strong: var(--gw-accent-strong, #2a6fce);
  --accent-hover: var(--gw-accent-hover, #8ab8ff);
  --accent-contrast: var(--gw-accent-contrast, #08111e);
  --warn: var(--gw-warn, #e0a35a);
  --bad: var(--gw-bad, #e06a6a);
  --ui: var(--gw-font, "Manrope", ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif);
  --serif: var(--gw-serif, "STIX Two Text", "Iowan Old Style", Georgia, ui-serif, serif);
  --mono: var(--gw-mono, "CommitMono", "Commit Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace);
  --fs-label: var(--gw-font-size-label, 10px);
  --fs-small: var(--gw-font-size-small, 11px);
  --fs-ui: var(--gw-font-size-ui, 12px);
  --fs-body: var(--gw-font-size-body, 13px);
  --fs-title: var(--gw-font-size-title, 15px);

  /* Structural rules are deliberately protected at the shadow boundary. A
     host page customizes them through --gw-panel-* instead of accidentally
     breaking a panel through broad element or universal selectors. */
  display: block !important;
  box-sizing: border-box !important;
  width: var(--gw-panel-width, 100%) !important;
  max-width: 100% !important;
  height: var(--gw-panel-height, auto) !important;
  min-width: 0 !important;
  min-height: var(--gw-panel-min-height, ${defaultMinHeight}) !important;
  margin: 0 !important;
  padding: 0 !important;
  border: 0 !important;
  overflow: visible !important;
  background: transparent !important;
  color: var(--ink) !important;
  font-family: var(--ui) !important;
  font-size: var(--fs-body) !important;
  color-scheme: var(--gw-color-scheme, dark);
  isolation: isolate;
}
/* Powered-by attribution (EMBED-7): a quiet mark on every embedded panel. */
.gw-powered-by {
  display: block;
  flex: 0 0 auto;
  padding: 4px 8px;
  font-size: 10px;
  line-height: 1.4;
  text-align: right;
  color: var(--muted);
  text-decoration: none;
}
.gw-powered-by:hover { color: var(--accent); }
.gw-embed-panel {
  box-sizing: border-box;
  display: flex;
  flex-direction: column;
  height: 100%;
  /* Host pages commonly size a custom element with min-height rather than a
     definite height. Inherit that used contract into the shadow tree so the
     first panel can absorb its slack and keep its composer docked. */
  min-height: inherit;
  overflow: hidden;
  padding: var(--gw-panel-padding, 12px);
  border: var(--gw-panel-border, 1px solid var(--edge));
  border-radius: var(--gw-panel-radius, 12px);
  background: var(--bg);
  color: var(--ink);
  box-shadow: var(--gw-panel-shadow, 0 14px 36px rgb(0 0 0 / 22%));
}
.gw-embed-panel > :first-child {
  flex: 1 1 auto;
  min-height: 0;
}
`;

/** Fail-safe branding: the mark is visible while config loads or if the read fails, and is
 * suppressed only by an explicit deployment `white_label: true`. */
function PoweredBy(props: { session: Session }) {
    const [config] = createResource(() =>
        props.session.api.embedGetConfig?.() ?? Promise.resolve({ white_label: false }),
    );
    return (
        <Show when={config()?.white_label !== true}>
            <a
                class="gw-powered-by"
                part="attribution"
                data-embed-powered-by
                href="https://gaugewright.com"
                target="_blank"
                rel="noreferrer"
            >
                Powered by GaugeDesk
            </a>
        </Show>
    );
}

/** `<gw-session cp="…" engagement="…">`: builds + owns the scoped remote Session. */
export class GwSessionElement extends HTMLElement {
    /** The Session its panel children render against (also settable directly). */
    session?: Session;
    /** The first-class producer that binds identity, placement transport, and
     * the panel manifest (ADR 0076). */
    environment?: Environment;
    private _teardown?: () => void;
    private _base: string | null = null;
    private _audienceAssertion: string | null = null;
    private readonly _latencyObserver = (
        observation: LatencyObservation,
    ) => {
        this.dispatchEvent(
            new CustomEvent(LATENCY_EVENT, {
                bubbles: true,
                composed: true,
                detail: observation,
            }),
        );
    };

    private observeLatency(
        phase: Parameters<typeof observeBrowserLatency>[1],
        fields?: Parameters<typeof observeBrowserLatency>[2],
    ): void {
        observeBrowserLatency(this._latencyObserver, phase, fields);
    }

    connectedCallback() {
        // Custom elements are inline by default. Make the provider a useful
        // zero-config block without replacing an intentional grid/flex layout.
        if (getComputedStyle(this).display === "inline") this.style.display = "block";
        if (this.session || this._teardown) return; // already built, or injected via handle
        const host = this.getAttribute("host");
        if (host) void this.bootstrap(host);
    }

    /** Admit or resume one hosted visitor engagement during page load, then
     * bind all child panels to its one Session DO connection. */
    private async bootstrap(host: string) {
        const traceId = `boot_${crypto.randomUUID().replaceAll("-", "")}`;
        this.observeLatency("bootstrap_start", { trace_id: traceId });
        try {
            const base = /^https?:\/\//.test(host) ? host.replace(/\/$/, "") : `https://${host}`;
            this._base = base;
            const resumeStorageKey = `gaugewright:resume:${base}`;
            const claimStorageKey = `gaugewright:claim:${base}`;
            const audienceAssertion = this.getAttribute("token")?.trim() || null;
            this._audienceAssertion = audienceAssertion;
            let resumeCapability = localStorage.getItem(resumeStorageKey);
            const activate = (resume: string | null) =>
                fetch(`${base}/bootstrap`, {
                    method: "POST",
                    headers: { "content-type": "application/json" },
                    credentials: "omit",
                    body: JSON.stringify(
                        {
                            ...(resume ? { resume_capability: resume } : {}),
                            ...(audienceAssertion
                                ? { audience_assertion: audienceAssertion }
                                : {}),
                            ...(audienceAssertion && localStorage.getItem(claimStorageKey)
                                ? {
                                      claim_capability:
                                          localStorage.getItem(claimStorageKey),
                                  }
                                : {}),
                            trace_id: traceId,
                        },
                    ),
                });
            let res = await activate(resumeCapability);
            if (res.status === 410) {
                localStorage.removeItem(resumeStorageKey);
                resumeCapability = null;
                res = await activate(null);
            }
            this.observeLatency("bootstrap_response", { trace_id: traceId });
            if (!res.ok) return;
            await this.adoptBootstrap(
                base,
                audienceAssertion,
                await res.json(),
                claimStorageKey,
            );
        } catch {
            /* host unreachable → fail-closed (no session) */
        }
    }

    private async adoptBootstrap(
        base: string,
        audienceAssertion: string | null,
        value: unknown,
        claimStorageKey = `gaugewright:claim:${base}`,
    ): Promise<void> {
        const payload = value as {
            session_id?: string;
            panels?: string[];
            white_label?: boolean;
            resume_capability?: string;
            connection_capability?: string;
            connection_expires_at_unix_ms?: number;
            claim_capability?: string;
            latency?: unknown[];
        };
        for (const observation of payload.latency ?? []) {
            if (
                observation &&
                typeof observation === "object" &&
                !Array.isArray(observation)
            ) {
                relayServerLatency(
                    this._latencyObserver,
                    observation as Record<string, unknown>,
                );
            }
        }
        if (
            !payload.session_id ||
            !payload.resume_capability ||
            !payload.connection_capability ||
            !Number.isSafeInteger(payload.connection_expires_at_unix_ms)
        ) {
            throw new Error("hosted session bootstrap was incomplete");
        }
        localStorage.setItem(
            `gaugewright:resume:${base}`,
            payload.resume_capability,
        );
        if (payload.claim_capability) {
            localStorage.setItem(claimStorageKey, payload.claim_capability);
        } else if (audienceAssertion) {
            localStorage.removeItem(claimStorageKey);
        }
        const granted = (payload.panels ?? []).map(
            (panel) => panel.replace(/^gw-/, "") as PanelId,
        );
        const api = new EdgeSessionApi(
            base,
            payload.session_id as EngagementId,
            payload.resume_capability,
            payload.connection_capability,
            Number(payload.connection_expires_at_unix_ms),
            audienceAssertion,
            payload.white_label === true,
            this._latencyObserver,
            audienceAssertion
                ? {
                      open: (chat) =>
                          this.activateAudience({ requested_session_id: chat }),
                      create: () => this.activateAudience({ new_session: true }),
                      erase: (chat) => this.eraseAudienceChat(chat),
                  }
                : undefined,
        );
        await api.ready();
        if (!this.isConnected) {
            api.dispose();
            return;
        }
        this._teardown?.();
        this._teardown = undefined;
        this.session = undefined;
        this.environment = undefined;
        this.querySelectorAll<GwPanelElement>(
            "gw-chat, gw-viewer, gw-files, gw-chats",
        ).forEach((panel) => panel.resetBinding());
        this.bindSession(payload.session_id, granted, api);
    }

    private async activateAudience(
        selection: { requested_session_id: string } | { new_session: true },
    ): Promise<void> {
        const base = this._base;
        const audienceAssertion = this._audienceAssertion;
        if (!base || !audienceAssertion) {
            throw new Error("authenticated audience is required");
        }
        const traceId = `boot_${crypto.randomUUID().replaceAll("-", "")}`;
        this.observeLatency("bootstrap_start", { trace_id: traceId });
        const response = await fetch(`${base}/bootstrap`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            credentials: "omit",
            body: JSON.stringify({
                audience_assertion: audienceAssertion,
                ...selection,
                trace_id: traceId,
            }),
        });
        this.observeLatency("bootstrap_response", { trace_id: traceId });
        if (!response.ok) {
            throw new Error(`audience chat activation: ${response.status}`);
        }
        await this.adoptBootstrap(
            base,
            audienceAssertion,
            await response.json(),
        );
    }

    private async eraseAudienceChat(chat: string): Promise<void> {
        const base = this._base;
        const audienceAssertion = this._audienceAssertion;
        if (!base || !audienceAssertion) {
            throw new Error("authenticated audience is required");
        }
        const response = await fetch(
            `${base}/audience/sessions/${encodeURIComponent(chat)}`,
            {
                method: "DELETE",
                headers: { "content-type": "application/json" },
                credentials: "omit",
                body: JSON.stringify({
                    audience_assertion: audienceAssertion,
                }),
            },
        );
        if (!response.ok) throw new Error(`erase chat: ${response.status}`);
        if (this.session?.engagementId() !== chat) return;
        const list = await fetch(`${base}/audience/sessions`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            credentials: "omit",
            body: JSON.stringify({ audience_assertion: audienceAssertion }),
        });
        if (!list.ok) throw new Error(`my chats: ${list.status}`);
        const value = (await list.json()) as {
            sessions?: { session_id: string }[];
        };
        const next = value.sessions?.[0]?.session_id;
        await this.activateAudience(
            next ? { requested_session_id: next } : { new_session: true },
        );
    }

    /** Build the scoped edge session and bind the panel children. */
    private bindSession(
        engagement: string,
        panelCeiling: readonly PanelId[],
        api: EdgeSessionApi,
    ) {
        const token = this.getAttribute("token");
        const explicitPanels = this.getAttribute("panels");
        const childPanels = [...this.querySelectorAll("gw-chat, gw-viewer, gw-files, gw-chats")]
            .map((element) => element.tagName.toLowerCase().replace(/^gw-/, "") as PanelId);
        const requested = panelManifest(
            explicitPanels ?? (childPanels.length ? childPanels : ["chat"]),
        ).panels;
        const granted = requested.filter((panel) => panelCeiling.includes(panel));
        // A public deployment with no matching granted panel renders nothing. Do not construct a
        // broader Environment and rely on visual hiding: composition itself is the scope.
        if (granted.length === 0) return;
        const manifest = panelManifest(granted);
        this.environment = new Environment({
            identity: token
                ? {
                      kind: "authenticated",
                      subject: this.getAttribute("subject")?.trim() || "authenticated-audience",
                  }
                : { kind: "anonymous", subject: `anonymous:${engagement}` },
            controlPlane: api as unknown as ControlPlane,
            manifest,
            sessionFactory: (_controlPlane, engagementId) =>
                createRemoteSession({ api, engagementId }),
        });
        const binding = this.environment.openSession(engagement as EngagementId);
        this.session = binding.session;
        this._teardown = () => {
            binding.dispose();
            api.dispose();
        };
        // Nudge any panel children that connected before us (DOM normally connects
        // us first, but be order-independent).
        this.querySelectorAll<GwPanelElement>("gw-chat, gw-viewer, gw-files, gw-chats").forEach((p) => p.bind?.());
        this.observeLatency("panels_bound");
    }

    disconnectedCallback() {
        this._teardown?.();
        this._teardown = undefined;
        this.session = undefined;
        this.environment = undefined;
        this._base = null;
        this._audienceAssertion = null;
    }
}

/** Base for a panel element: find the Session, isolate in a shadow root, render. */
abstract class GwPanelElement extends HTMLElement {
    /** The JS-handle escape hatch: set this to mount detached from a `<gw-session>`. */
    session?: Session;
    private _disposeRender?: () => void;
    protected abstract readonly panelId: PanelId;
    protected readonly defaultMinHeight: string = "320px";

    /** The Solid view this element renders against the resolved Session. */
    protected abstract view(session: Session): JSX.Element;

    connectedCallback() {
        this.bind();
    }

    /** Resolve the Session (own handle → ancestor `<gw-session>`) and render once.
     *  A no-op if already rendered or no Session is reachable yet (the ancestor
     *  `<gw-session>` re-drives this once it is built). Public so a host can call it
     *  after setting `.session` directly. */
    bind() {
        if (this._disposeRender) return;
        const host = this.closest<GwSessionElement>("gw-session");
        if (!this.session && host?.environment && !host.environment.includes(this.panelId)) return;
        const session = this.session ?? host?.session;
        if (!session) return;
        const attributionOwner =
            !host ||
            host.querySelector("gw-chat, gw-viewer, gw-files, gw-chats") === this;
        const root = this.shadowRoot ?? this.attachShadow({ mode: "open" });
        // Theme bridge first (defines the palette on :host), then the workbench
        // stylesheet (consumes it via var(--bg)… — its own :root block is inert here).
        const theme = document.createElement("style");
        theme.textContent = embedThemeCss(this.defaultMinHeight);
        root.appendChild(theme);
        const style = document.createElement("style");
        style.textContent = appCss;
        root.appendChild(style);
        this._disposeRender = render(
            () => (
                <SessionProvider value={session}>
                    <div
                        class="gw-embed-panel"
                        part={`panel panel-${this.panelId}`}
                        data-gw-panel={this.panelId}
                    >
                        {this.view(session)}
                        <Show when={attributionOwner}>
                            <PoweredBy session={session} />
                        </Show>
                    </div>
                </SessionProvider>
            ),
            root,
        );
    }

    resetBinding() {
        this._disposeRender?.();
        this._disposeRender = undefined;
        this.session = undefined;
        this.shadowRoot?.replaceChildren();
    }

    disconnectedCallback() {
        this._disposeRender?.();
        this._disposeRender = undefined;
    }
}

export class GwChatElement extends GwPanelElement {
    protected readonly panelId = "chat" as const;
    protected override readonly defaultMinHeight = "520px";

    protected view(session: Session): JSX.Element {
        return <ChatPanel session={session} audience />;
    }
}

export class GwViewerElement extends GwPanelElement {
    protected readonly panelId = "viewer" as const;
    protected override readonly defaultMinHeight = "320px";

    protected view(): JSX.Element {
        return <ContentViewer />;
    }
}

export class GwFilesElement extends GwPanelElement {
    protected readonly panelId = "files" as const;
    protected override readonly defaultMinHeight = "280px";

    protected view(): JSX.Element {
        return <Workspace />;
    }
}

export class GwChatsElement extends GwPanelElement {
    protected readonly panelId = "chats" as const;
    protected override readonly defaultMinHeight = "280px";

    protected view(session: Session): JSX.Element {
        return <AudienceChats session={session} standalone />;
    }
}

/** Register the embed custom elements (idempotent). */
export function registerEmbedElements() {
    if (typeof customElements === "undefined" || customElements.get("gw-session")) return;
    customElements.define("gw-session", GwSessionElement);
    customElements.define("gw-chat", GwChatElement);
    customElements.define("gw-viewer", GwViewerElement);
    customElements.define("gw-files", GwFilesElement);
    customElements.define("gw-chats", GwChatsElement);
}
