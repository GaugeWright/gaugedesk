import type {
    HomeId,
    ProjectId,
    Workspace,
} from "@gaugewright/control-plane-client";

export type MobileFreshness = "live" | "stale" | "offline";

export interface HomeScopedProjection<T> {
    readonly owner: string;
    readonly homeId: HomeId;
    readonly project: ProjectId;
    readonly key: string;
    readonly value: T;
    readonly freshness: MobileFreshness;
    readonly updatedAt: number;
}

/** Reduce a Home-wide workspace carriage to the exact project whose cache key
 * will own it. A partitioned key is not enough if its value still embeds sibling
 * projects. Offline fallback therefore retains only this project's project,
 * chats, workstreams, recent rows and work targets. */
export function projectScopedWorkspace(
    workspace: Workspace,
    projectId: ProjectId,
): Workspace | null {
    const project = workspace.projects.find((candidate) => candidate.id === projectId);
    if (!project) return null;
    const placements = new Set(
        project.placements.map((placement) => placement.placementId),
    );
    const chats = new Set(
        project.placements.flatMap((placement) =>
            placement.chats.map((chat) => chat.id),
        ),
    );
    const targets = new Set(project.targets.map((target) => target.id));
    return {
        archetypes: [],
        projects: [project],
        recent: workspace.recent.filter((chat) => chats.has(chat.id)),
        workstreams: workspace.workstreams
            .filter((workstream) => placements.has(workstream.placementId))
            .map((workstream) => ({
                ...workstream,
                members: workstream.members.filter((member) => chats.has(member)),
            })),
        workTargets: workspace.workTargets.filter((target) => targets.has(target.id)),
        personalPlacement:
            workspace.personalPlacement
            && placements.has(workspace.personalPlacement)
                ? workspace.personalPlacement
                : null,
    };
}

/**
 * Memory-only protected projection/draft cache. Every lookup names the Home,
 * project and record key; there is no fallback that could accidentally satisfy
 * a selection with another Home's value.
 */
export class MobileHomeCache<T> {
    private readonly entries = new Map<string, HomeScopedProjection<T>>();

    constructor(
        private readonly owner: string,
        private readonly storage: Pick<Storage, "getItem" | "setItem" | "removeItem"> | null = null,
        private readonly storageKey = "gw.mobile.projection-cache.v1",
    ) {
        this.restore();
    }

    put(entry: Omit<HomeScopedProjection<T>, "owner">): void {
        const owned = { ...entry, owner: this.owner };
        this.entries.set(this.cacheKey(entry.homeId, entry.project, entry.key), owned);
        this.persist();
    }

    get(
        homeId: HomeId,
        project: ProjectId,
        key: string,
    ): HomeScopedProjection<T> | null {
        return this.entries.get(this.cacheKey(homeId, project, key)) ?? null;
    }

    markHome(homeId: HomeId, freshness: Exclude<MobileFreshness, "live">): void {
        for (const [key, entry] of this.entries) {
            if (entry.homeId === homeId) {
                this.entries.set(key, { ...entry, freshness });
            }
        }
        this.persist();
    }

    clearHome(homeId: HomeId): void {
        for (const [key, entry] of this.entries) {
            if (entry.homeId === homeId) this.entries.delete(key);
        }
        this.persist();
    }

    clearAll(): void {
        this.entries.clear();
        this.persist();
    }

    snapshot(): HomeScopedProjection<T>[] {
        return [...this.entries.values()].sort((left, right) =>
            this.cacheKey(left.homeId, left.project, left.key)
                .localeCompare(this.cacheKey(right.homeId, right.project, right.key)),
        );
    }

    private cacheKey(homeId: HomeId, project: ProjectId, key: string): string {
        return `${this.owner}\u0000${homeId}\u0000${project}\u0000${key}`;
    }

    private restore(): void {
        if (!this.storage) return;
        try {
            const raw = this.storage.getItem(this.storageKey);
            if (!raw) return;
            const decoded = JSON.parse(raw) as { version?: unknown; entries?: unknown };
            if (decoded.version !== 1 || !Array.isArray(decoded.entries)) return;
            for (const candidate of decoded.entries) {
                const entry = candidate as HomeScopedProjection<T>;
                if (
                    entry.owner !== this.owner
                    || typeof entry.homeId !== "string"
                    || typeof entry.project !== "string"
                    || typeof entry.key !== "string"
                    || typeof entry.updatedAt !== "number"
                ) {
                    continue;
                }
                // A restarted client cannot assert that a persisted projection
                // remains live. It is stale until that exact Home refreshes it.
                const restored = { ...entry, freshness: "stale" as const };
                this.entries.set(
                    this.cacheKey(entry.homeId, entry.project, entry.key),
                    restored,
                );
            }
        } catch {
            // Corrupt or unavailable device storage is an empty cache, never truth.
        }
    }

    private persist(): void {
        if (!this.storage) return;
        try {
            const current = [...this.entries.values()]
                .sort((left, right) => left.updatedAt - right.updatedAt)
                .slice(-64);
            let otherOwners: HomeScopedProjection<T>[] = [];
            const prior = this.storage.getItem(this.storageKey);
            if (prior) {
                const decoded = JSON.parse(prior) as { version?: unknown; entries?: unknown };
                if (decoded.version === 1 && Array.isArray(decoded.entries)) {
                    otherOwners = (decoded.entries as HomeScopedProjection<T>[])
                        .filter((entry) => entry.owner !== this.owner);
                }
            }
            const entries = [...otherOwners, ...current].slice(-128);
            if (entries.length === 0) {
                this.storage.removeItem(this.storageKey);
                return;
            }
            this.storage.setItem(
                this.storageKey,
                JSON.stringify({ version: 1, entries }),
            );
        } catch {
            // Cache persistence is best-effort; authority remains at the Home.
        }
    }
}

export type MobileTargetKind = "project" | "chat" | "task" | "file";
export type MobileTargetPane = "nav" | "chat" | "files" | "content";

/** A notification/deep link contains references only. Protected labels,
 * messages, prompts and content are explicitly rejected. */
export interface MobileTargetReference {
    readonly version: 1;
    readonly project: ProjectId;
    readonly kind: MobileTargetKind;
    readonly id: string;
    readonly pane: MobileTargetPane;
    readonly engagement: string | null;
}

const kinds = new Set<MobileTargetKind>(["project", "chat", "task", "file"]);
const panes = new Set<MobileTargetPane>(["nav", "chat", "files", "content"]);
const protectedParameters = ["title", "name", "content", "message", "prompt", "body"];

export function parseMobileTargetReference(raw: string): MobileTargetReference | null {
    try {
        const url = new URL(raw);
        const opaqueRoute = url.pathname.replace(/^\/\//, "");
        const custom = url.protocol === "gaugewright:"
            && (
                (url.hostname === "open"
                    && (url.pathname === "" || url.pathname === "/"))
                || opaqueRoute === "open"
            );
        const universal = url.protocol === "https:"
            && url.hostname === "app.gaugewright.com"
            && url.pathname === "/link";
        if (!custom && !universal) return null;
        if (protectedParameters.some((parameter) => url.searchParams.has(parameter))) {
            return null;
        }
        const project = url.searchParams.get("project");
        const kind = url.searchParams.get("kind") as MobileTargetKind | null;
        const id = url.searchParams.get("id");
        const pane = url.searchParams.get("pane") as MobileTargetPane | null;
        const engagement = url.searchParams.get("chat");
        if (
            !project
            || !kind
            || !kinds.has(kind)
            || !id
            || !pane
            || !panes.has(pane)
            || (kind === "file" && !engagement)
        ) {
            return null;
        }
        return {
            version: 1,
            project: project as ProjectId,
            kind,
            id,
            pane,
            engagement,
        };
    } catch {
        return null;
    }
}
