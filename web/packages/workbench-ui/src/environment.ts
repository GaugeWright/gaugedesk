import {
    type ControlPlane,
    type Engagement,
    type EngagementId,
} from "@gaugewright/control-plane-client";
import { type Session } from "./session-context";

/** The product panels an Environment may mount (ADR 0076). A manifest selects
 * shared panels; it never names an environment-specific reimplementation. */
export const PANEL_IDS = ["chat", "viewer", "files", "chats"] as const;
export type PanelId = (typeof PANEL_IDS)[number];

export interface PanelManifest {
    readonly panels: readonly PanelId[];
}

export type EnvironmentIdentity =
    | { readonly kind: "local"; readonly subject: string }
    | { readonly kind: "authenticated"; readonly subject: string }
    | { readonly kind: "anonymous"; readonly subject: string };

export interface SessionBinding {
    readonly session: Session;
    readonly dispose: () => void;
}

export type EnvironmentSessionFactory = (
    controlPlane: ControlPlane,
    engagementId: EngagementId,
) => SessionBinding;

const panelIds = new Set<string>(PANEL_IDS);

/** Parse a declarative panel list. Unknown ids fail closed and duplicates fold
 * away without changing the caller's order. */
export function panelManifest(
    value: string | readonly PanelId[],
): PanelManifest {
    const candidates = typeof value === "string"
        ? value.split(",").map((part) => part.trim()).filter(Boolean)
        : [...value];
    const panels: PanelId[] = [];
    for (const candidate of candidates) {
        if (!panelIds.has(candidate)) {
            throw new Error(`unknown GaugeDesk panel: ${candidate}`);
        }
        const panel = candidate as PanelId;
        if (!panels.includes(panel)) panels.push(panel);
    }
    if (panels.length === 0) {
        throw new Error("an Environment requires at least one panel");
    }
    return Object.freeze({ panels: Object.freeze(panels) });
}

/** Identity + placement binding + panel composition. Cross-engagement commands
 * live here; a Session is only the per-engagement leaf this producer mints. */
export class Environment {
    readonly identity: EnvironmentIdentity;
    readonly controlPlane: ControlPlane;
    readonly manifest: PanelManifest;
    private readonly sessionFactory: EnvironmentSessionFactory;

    constructor(options: {
        readonly identity: EnvironmentIdentity;
        readonly controlPlane: ControlPlane;
        readonly manifest: PanelManifest;
        readonly sessionFactory: EnvironmentSessionFactory;
    }) {
        if (!options.identity.subject.trim()) {
            throw new Error("an Environment identity requires a subject");
        }
        if (options.manifest.panels.length === 0) {
            throw new Error("an Environment requires at least one panel");
        }
        this.identity = Object.freeze({ ...options.identity });
        this.controlPlane = options.controlPlane;
        this.manifest = panelManifest(options.manifest.panels);
        this.sessionFactory = options.sessionFactory;
    }

    includes(panel: PanelId): boolean {
        return this.manifest.panels.includes(panel);
    }

    listEngagements(): Promise<EngagementId[]> {
        return this.controlPlane.listEngagements();
    }

    createEngagement(id?: EngagementId): Promise<Engagement> {
        return this.controlPlane.createEngagement(id);
    }

    closeEngagement(id: EngagementId): Promise<void> {
        return this.controlPlane.deleteChat(id);
    }

    openSession(id: EngagementId): SessionBinding {
        return this.sessionFactory(this.controlPlane, id);
    }
}
