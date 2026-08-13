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
// Also imported on its own for the Turnstile gate, which is a separate shadow
// tree in the light DOM: it inherits nothing from a panel's shadow root, so it
// needs its own copy of the token declarations rather than its own copy of the
// values. `styles.css` @imports the same file, so the panels already have it.
import brandTokensCss from "@gaugewright/workbench-ui/brand-tokens.css?inline";

/**
 * The shadow-root theme bridge. The workbench palette is defined on `:root`
 * (`styles.css`), which does **not** apply inside a shadow tree — so we re-declare
 * the workbench's internal palette vars on `:host` (custom properties *do* inherit
 * across the shadow boundary), each sourced from a consultant-facing `--gw-*`
 * token. A consultant themes the embed by setting any `--gw-*` on `<gw-session>`
 * (or any ancestor); it cascades into every panel's shadow root. Injected before
 * `styles.css` so its `var(--bg)` etc. resolve.
 *
 * **No value is written here.** The defaults come from `brand-tokens.css`, which
 * rides in with `styles.css` and declares `--gw-default-*` on `:host` as well as
 * `:root` (GaugeWright `DR-0077`). This block used to carry its own hexes, and
 * they were a fork: when the company eased the dark ramp off black, `:root` moved
 * and this did not, so every embedded panel spent the interval drawing a grey
 * ground inside a navy page. Reaching a default through `--gw-default-*` rather
 * than declaring the public `--gw-*` here is what keeps a host page able to
 * override it — a `:host` declaration would beat the inherited value outright.
 *
 * Three public names were reconciled with the company palette and three more
 * with the type families. The former names still work: a customer who vendored
 * an older `embed.css` and set `--gw-bad` keeps the colour they chose.
 */
const embedThemeCss = (defaultMinHeight: string) => `
:host {
  /* Public theme tokens. Internal aliases are declared here so unrelated host
     variables with generic names such as --panel or --muted cannot leak in.
     --navy is internal for the same reason it is not --gw-navy: that name is
     the public one, and a host page setting the documented token must not
     collide with the alias the stylesheet reads. */
  --navy: var(--gw-navy, var(--gw-brand-navy, var(--gw-default-navy)));
  --bg: var(--gw-bg, var(--gw-default-bg));
  --panel: var(--gw-panel, var(--gw-default-panel));
  --edge: var(--gw-edge, var(--gw-default-edge));
  --ink: var(--gw-ink, var(--gw-default-ink));
  --muted: var(--gw-muted, var(--gw-default-muted));
  --accent: var(--gw-accent, var(--gw-default-accent));
  --accent-strong: var(--gw-accent-strong, var(--gw-default-accent-strong));
  --accent-hover: var(--gw-accent-hover, var(--gw-default-accent-hover));
  --accent-contrast: var(--gw-on-accent, var(--gw-accent-contrast, var(--gw-default-on-accent)));
  --warn: var(--gw-warn, var(--gw-default-warn));
  --bad: var(--gw-danger, var(--gw-bad, var(--gw-default-danger)));
  --font-chrome: var(--gw-font-chrome, var(--gw-font, var(--gw-serif, var(--gw-default-font-chrome))));
  --font-prose: var(--gw-font-prose, var(--gw-prose, var(--gw-default-font-prose)));
  --ui: var(--font-chrome);
  /* The chrome face used to be two public names, and a customer on an older
     embed.css has both set — possibly to different stacks. So the serif alias
     reads --gw-serif ahead of --gw-font rather than taking --font-chrome, which
     prefers --gw-font and would discard the serif they chose. The current name
     still overrides both. */
  --serif: var(--gw-font-chrome, var(--gw-serif, var(--gw-font, var(--gw-default-font-chrome))));
  --mono: var(--gw-font-mono, var(--gw-mono, var(--gw-default-font-mono)));
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
                Powered by GaugeWright
            </a>
        </Show>
    );
}

const TURNSTILE_SCRIPT =
    "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";

interface TurnstileApi {
    render(
        container: HTMLElement,
        options: Record<string, unknown>,
    ): string | number;
    reset(widgetId: string | number): void;
    remove(widgetId: string | number): void;
}

declare global {
    interface Window {
        turnstile?: TurnstileApi;
    }
}

let turnstileScriptPromise: Promise<TurnstileApi> | undefined;

function loadTurnstile(): Promise<TurnstileApi> {
    if (window.turnstile) return Promise.resolve(window.turnstile);
    if (turnstileScriptPromise) return turnstileScriptPromise;
    const promise = new Promise<TurnstileApi>((resolve, reject) => {
        const existing = document.querySelector<HTMLScriptElement>(
            `script[src="${TURNSTILE_SCRIPT}"]`,
        );
        const script = existing ?? document.createElement("script");
        const loaded = () => {
            if (window.turnstile) resolve(window.turnstile);
            else {
                script.remove();
                reject(new Error("Turnstile did not initialize"));
            }
        };
        script.addEventListener("load", loaded, { once: true });
        script.addEventListener(
            "error",
            () => {
                script.remove();
                reject(new Error("Turnstile could not be loaded"));
            },
            { once: true },
        );
        if (!existing) {
            script.src = TURNSTILE_SCRIPT;
            script.async = true;
            script.defer = true;
            document.head.appendChild(script);
        }
    }).catch((error) => {
        turnstileScriptPromise = undefined;
        throw error;
    });
    turnstileScriptPromise = promise;
    return promise;
}

interface TurnstileRequired {
    code?: unknown;
    turnstile_site_key?: unknown;
    turnstile_action?: unknown;
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
    private _turnstileGate?: HTMLElement;
    private _turnstileWidget?: string | number;
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

    /** Render the provider-owned challenge in an isolated shadow tree so a
     * customer's global CSS cannot accidentally break the security boundary. */
    private async requestTurnstileToken(
        siteKey: string,
        action: string,
    ): Promise<string> {
        this.clearTurnstileGate();
        const gate = document.createElement("div");
        gate.setAttribute("data-gw-turnstile-gate", "");
        const root = gate.attachShadow({ mode: "closed" });
        root.innerHTML = `
            <style>
              ${brandTokensCss}
              :host { display: block !important; box-sizing: border-box !important; width: 100% !important; margin: 0 0 10px !important; }
              .gate { box-sizing: border-box; display: grid; place-items: center; gap: 8px; min-height: 82px; padding: 12px; border: 1px solid var(--gw-edge, var(--gw-default-edge)); border-radius: var(--gw-panel-radius, 12px); background: var(--gw-bg, var(--gw-default-bg)); color: var(--gw-ink, var(--gw-default-ink)); font: 12px/1.45 var(--gw-font-chrome, var(--gw-font, var(--gw-default-font-chrome))); text-align: center; color-scheme: var(--gw-color-scheme, dark); }
              .label { margin: 0; }
              .widget { width: min(100%, 300px); min-height: 65px; }
              .retry { padding: 7px 12px; border: 1px solid var(--gw-edge, var(--gw-default-edge)); border-radius: 7px; background: var(--gw-panel, var(--gw-default-panel)); color: inherit; font: inherit; cursor: pointer; }
              .retry:hover { border-color: var(--gw-accent, var(--gw-default-accent)); }
            </style>
            <div class="gate" role="status" aria-live="polite">
              <p class="label">One quick check before starting a new session.</p>
              <div class="widget"></div>
              <button class="retry" type="button" hidden>Try again</button>
            </div>`;
        const widget = root.querySelector<HTMLElement>(".widget");
        const label = root.querySelector<HTMLElement>(".label");
        const retry = root.querySelector<HTMLButtonElement>(".retry");
        if (!widget || !label || !retry) {
            throw new Error("Turnstile gate could not be created");
        }
        this.prepend(gate);
        this._turnstileGate = gate;
        const showFailure = (message: string) => {
            label.textContent = message;
            widget.hidden = true;
            retry.hidden = false;
            retry.onclick = () => {
                const base = this._base;
                this.clearTurnstileGate();
                if (base) void this.bootstrap(base);
            };
        };
        let api: TurnstileApi;
        try {
            api = await loadTurnstile();
        } catch (error) {
            showFailure(
                "Verification could not load. Check this site's Content Security Policy, then try again.",
            );
            throw error;
        }
        return new Promise<string>((resolve, reject) => {
            let settled = false;
            const fail = (message: string) => {
                if (settled) return;
                settled = true;
                showFailure(message);
                reject(new Error(message));
            };
            try {
                this._turnstileWidget = api.render(widget, {
                    sitekey: siteKey,
                    action,
                    theme: "auto",
                    size: "flexible",
                    appearance: "always",
                    retry: "auto",
                    callback: (token: string) => {
                        if (settled) return;
                        settled = true;
                        this.clearTurnstileGate();
                        resolve(token);
                    },
                    "error-callback": () =>
                        fail("Verification failed. Please try again."),
                    "expired-callback": () => {
                        if (this._turnstileWidget !== undefined) {
                            api.reset(this._turnstileWidget);
                        }
                    },
                    "timeout-callback": () => {
                        if (this._turnstileWidget !== undefined) {
                            api.reset(this._turnstileWidget);
                        }
                    },
                });
            } catch {
                fail("Verification could not start. Please try again.");
            }
        });
    }

    private clearTurnstileGate(): void {
        if (this._turnstileWidget !== undefined && window.turnstile) {
            window.turnstile.remove(this._turnstileWidget);
        }
        this._turnstileWidget = undefined;
        this._turnstileGate?.remove();
        this._turnstileGate = undefined;
    }

    private async satisfyTurnstile(
        response: Response,
        retry: (token: string) => Promise<Response>,
    ): Promise<Response> {
        if (response.status !== 428) return response;
        const required = (await response.json()) as TurnstileRequired;
        if (
            required.code !== "turnstile_required" ||
            typeof required.turnstile_site_key !== "string" ||
            typeof required.turnstile_action !== "string"
        ) {
            return response;
        }
        const token = await this.requestTurnstileToken(
            required.turnstile_site_key,
            required.turnstile_action,
        );
        return retry(token);
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
            const activate = (resume: string | null, turnstileToken?: string) =>
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
                            ...(turnstileToken
                                ? { turnstile_token: turnstileToken }
                                : {}),
                        },
                    ),
                });
            let res = await activate(resumeCapability);
            if (res.status === 410) {
                localStorage.removeItem(resumeStorageKey);
                resumeCapability = null;
                res = await activate(null);
            }
            res = await this.satisfyTurnstile(res, (token) =>
                activate(null, token),
            );
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
            {
                create: () => this.activateSession({ new_session: true }),
                ...(audienceAssertion
                    ? {
                          open: (chat: string) =>
                              this.activateSession({ requested_session_id: chat }),
                          erase: (chat: string) => this.eraseAudienceChat(chat),
                      }
                    : {}),
            },
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

    private async activateSession(
        selection: { requested_session_id: string } | { new_session: true },
    ): Promise<void> {
        const base = this._base;
        const audienceAssertion = this._audienceAssertion;
        if (!base) throw new Error("hosted session is unavailable");
        const traceId = `boot_${crypto.randomUUID().replaceAll("-", "")}`;
        this.observeLatency("bootstrap_start", { trace_id: traceId });
        const activate = (turnstileToken?: string) => fetch(`${base}/bootstrap`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            credentials: "omit",
            body: JSON.stringify({
                ...(audienceAssertion
                    ? { audience_assertion: audienceAssertion }
                    : {}),
                ...selection,
                trace_id: traceId,
                ...(turnstileToken
                    ? { turnstile_token: turnstileToken }
                    : {}),
            }),
        });
        const response = await this.satisfyTurnstile(
            await activate(),
            activate,
        );
        this.observeLatency("bootstrap_response", { trace_id: traceId });
        if (!response.ok) {
            throw new Error(`session activation: ${response.status}`);
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
        await this.activateSession(
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
        this.clearTurnstileGate();
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
        return (
            <ChatPanel
                session={session}
                audience
                openingMessage={this.getAttribute("opening-message") ?? undefined}
                agentName={this.getAttribute("agent-name") ?? undefined}
            />
        );
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
