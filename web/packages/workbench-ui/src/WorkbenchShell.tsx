import {
    createEffect,
    createSignal,
    onCleanup,
    Show,
    type Accessor,
    type JSX,
    type Setter,
} from "solid-js";
import { Carousel } from "./CarouselIsland";
import { applySelection } from "./CarouselIsland";
import { initial as initialCarousel, reduce as reduceCarousel } from "./carousel";
import { tapGesture } from "./carousel-view";
import type { CarouselState, PaneKind, Selection } from "./mobile-layout";
import { PanelCollapseIcon, type PanelCollapseDirection } from "./PanelCollapseIcon";

const RAIL = 30;
const RESIZER = 5;
const MOBILE_QUERY = "(max-width: 1024px)";

export interface WorkbenchShellState {
    isMobile: Accessor<boolean>;
    carousel: Accessor<CarouselState>;
    setCarousel: Setter<CarouselState>;
    collapsed: (pane: PaneKind) => boolean;
    setCollapsed: (pane: PaneKind, collapsed: boolean) => void;
    openPane: (pane: PaneKind, selection?: Selection) => void;
    columns: Accessor<string>;
    observeShell: (element: HTMLDivElement) => void;
    resize: (boundary: "nav" | "mid" | "files", clientX: number) => void;
}

export interface WorkbenchShellOptions {
    selection: Accessor<Selection>;
    storagePrefix?: string;
    /** Management environments navigate documents directly and can omit the
     * project-oriented Files pane entirely. */
    includeFiles?: boolean;
}

/**
 * The browser-local layout state for the shared four-pane workbench.
 *
 * Environments provide projections for the panes; they do not reimplement panel
 * sizing, folding, narrow-window navigation, or persistence. Keeping those
 * mechanics here makes the ordinary desktop and enterprise Admin Environment
 * genuinely the same shell rather than visually similar copies.
 */
export function createWorkbenchShellState(options: WorkbenchShellOptions): WorkbenchShellState {
    const prefix = options.storagePrefix ?? "ui";
    const includeFiles = options.includeFiles ?? true;
    const storage = typeof localStorage === "undefined" ? null : localStorage;
    const storedNumber = (key: string, fallback: number) => {
        const value = Number(storage?.getItem(`${prefix}.${key}`));
        return Number.isFinite(value) && value > 0 ? value : fallback;
    };
    const storedCollapsed = (key: string) => storage?.getItem(`${prefix}.${key}`) === "collapsed";

    // 206px keeps the three serif facet tabs on one row with slack across the
    // serif fallback stack's metric spread (STIX absent → wider Palatino/Noto).
    const [navWidth, setNavWidth] = createSignal(storedNumber("navW", 206));
    const [filesWidth, setFilesWidth] = createSignal(storedNumber("wsW", 230));
    const [chatFraction, setChatFraction] = createSignal(storedNumber("runFr", 0.5));
    const [navCollapsed, setNavCollapsed] = createSignal(storedCollapsed("navPanel"));
    const [chatCollapsed, setChatCollapsed] = createSignal(storedCollapsed("chatPanel"));
    const [contentCollapsed, setContentCollapsed] = createSignal(storedCollapsed("contentPanel"));
    const [filesCollapsed, setFilesCollapsed] = createSignal(storedCollapsed("filesPanel"));

    createEffect(() => storage?.setItem(`${prefix}.navW`, String(navWidth())));
    createEffect(() => storage?.setItem(`${prefix}.wsW`, String(filesWidth())));
    createEffect(() => storage?.setItem(`${prefix}.runFr`, String(chatFraction())));
    createEffect(() => storage?.setItem(`${prefix}.navPanel`, navCollapsed() ? "collapsed" : "open"));
    createEffect(() => storage?.setItem(`${prefix}.chatPanel`, chatCollapsed() ? "collapsed" : "open"));
    createEffect(() => storage?.setItem(`${prefix}.contentPanel`, contentCollapsed() ? "collapsed" : "open"));
    createEffect(() => storage?.setItem(`${prefix}.filesPanel`, filesCollapsed() ? "collapsed" : "open"));

    const collapsed = (pane: PaneKind) => {
        if (pane === "nav") return navCollapsed();
        if (pane === "chat") return chatCollapsed();
        if (pane === "content") return contentCollapsed();
        return filesCollapsed();
    };
    const setCollapsed = (pane: PaneKind, value: boolean) => {
        if (pane === "nav") setNavCollapsed(value);
        else if (pane === "chat") setChatCollapsed(value);
        else if (pane === "content") setContentCollapsed(value);
        else setFilesCollapsed(value);
    };

    const matchMobile = () =>
        typeof window !== "undefined" && typeof window.matchMedia === "function"
            ? window.matchMedia(MOBILE_QUERY).matches
            : false;
    const [isMobile, setIsMobile] = createSignal(matchMobile());
    createEffect(() => {
        if (typeof window === "undefined" || typeof window.matchMedia !== "function") return;
        const query = window.matchMedia(MOBILE_QUERY);
        const update = () => setIsMobile(query.matches);
        update();
        query.addEventListener("change", update);
        window.addEventListener("resize", update);
        onCleanup(() => {
            query.removeEventListener("change", update);
            window.removeEventListener("resize", update);
        });
    });

    const [carousel, setCarousel] = createSignal<CarouselState>(initialCarousel);
    createEffect(() => setCarousel((state) => applySelection(state, options.selection())));

    const openPane = (pane: PaneKind, selection = options.selection()) => {
        setCollapsed(pane, false);
        if (isMobile()) {
            setCarousel((state) =>
                reduceCarousel(applySelection(state, selection), tapGesture(pane)),
            );
        }
    };

    const clamp = (value: number, low: number, high: number) =>
        Math.max(low, Math.min(high, value));
    const effectiveNavWidth = () => (navCollapsed() ? RAIL : navWidth());
    const effectiveFilesWidth = () => (filesCollapsed() ? RAIL : filesWidth());
    let shellElement: HTMLDivElement | undefined;
    const observeShell = (element: HTMLDivElement) => {
        shellElement = element;
    };
    const resize = (boundary: "nav" | "mid" | "files", clientX: number) => {
        if (!shellElement) return;
        const bounds = shellElement.getBoundingClientRect();
        if (boundary === "nav") {
            setNavWidth(clamp(clientX - bounds.left, 120, bounds.width - effectiveFilesWidth() - 240));
        } else if (boundary === "files" && includeFiles) {
            setFilesWidth(clamp(bounds.right - clientX, 150, bounds.width - effectiveNavWidth() - 240));
        } else {
            const middleLeft = bounds.left + effectiveNavWidth() + RESIZER;
            const afterContent = !includeFiles ? 0 : filesCollapsed() ? RAIL : filesWidth() + RESIZER;
            const middleRight = bounds.right - afterContent;
            setChatFraction(clamp((clientX - middleLeft) / (middleRight - middleLeft), 0.15, 0.85));
        }
    };

    const columns = () => {
        const bothMiddleOpen = !chatCollapsed() && !contentCollapsed();
        const nav = navCollapsed()
            ? `${RAIL}px`
            : chatCollapsed() && contentCollapsed() && (!includeFiles || filesCollapsed())
                ? `minmax(${navWidth()}px,1fr)`
                : `${navWidth()}px`;
        const navResizer = navCollapsed() ? "0px" : `${RESIZER}px`;
        const chat = chatCollapsed()
            ? `${RAIL}px`
            : bothMiddleOpen
                ? `minmax(280px,${chatFraction()}fr)`
                : "minmax(280px,1fr)";
        const content = contentCollapsed()
            ? `${RAIL}px`
            : bothMiddleOpen
                ? `${RESIZER}px minmax(240px,${1 - chatFraction()}fr)`
                : `${RESIZER}px minmax(240px,1fr)`;
        const files = filesCollapsed()
            ? `${RAIL}px`
            : chatCollapsed() && contentCollapsed()
                ? `${RESIZER}px minmax(${filesWidth()}px,1fr)`
                : `${RESIZER}px ${filesWidth()}px`;
        return includeFiles
            ? `${nav} ${navResizer} ${chat} ${content} ${files}`
            : `${nav} ${navResizer} ${chat} ${content}`;
    };

    return {
        isMobile,
        carousel,
        setCarousel,
        collapsed,
        setCollapsed,
        openPane,
        columns,
        observeShell,
        resize,
    };
}

export interface WorkbenchShellProps {
    state: WorkbenchShellState;
    taskBar?: () => JSX.Element;
    nav: () => JSX.Element;
    navFooter?: () => JSX.Element;
    chat: () => JSX.Element;
    content: () => JSX.Element;
    files?: () => JSX.Element;
    overlays?: () => JSX.Element;
    onNewChat: () => void;
    titles?: Partial<Record<PaneKind, string>>;
    headings?: Partial<Record<PaneKind, boolean>>;
}

export function workbenchPaneTitle(
    pane: PaneKind,
    titles?: Partial<Record<PaneKind, string>>,
): string {
    return titles?.[pane] ?? ({ nav: "Navigate", chat: "Chat", content: "Content", files: "Files" } as const)[pane];
}

/** Render the canonical workbench chrome around environment-supplied panes. */
export function WorkbenchShell(props: WorkbenchShellProps) {
    const title = (pane: PaneKind) => workbenchPaneTitle(pane, props.titles);
    const showsHeading = (pane: PaneKind) => props.headings?.[pane] ?? true;
    const panes = (): Record<PaneKind, JSX.Element> => ({
        nav: props.nav(),
        chat: props.chat(),
        content: props.content(),
        files: props.files?.() ?? <></>,
    });

    const RightPanels = () => (
        <>
            <Show when={!props.state.collapsed("content")}>
                <Resizer onMove={(x) => props.state.resize("mid", x)} />
            </Show>
            <CollapsiblePanel
                cls="content"
                fold="right"
                controlEdge="left"
                title={title("content")}
                collapsed={props.state.collapsed("content")}
                onToggle={(value) => props.state.setCollapsed("content", value)}
            >
                {props.content()}
            </CollapsiblePanel>

            <Show when={props.files}>{
                <>
                    <Show when={!props.state.collapsed("files")}>
                        <Resizer onMove={(x) => props.state.resize("files", x)} />
                    </Show>
                    <CollapsiblePanel
                        cls="workspace"
                        fold="right"
                        controlEdge="left"
                        title={title("files")}
                        collapsed={props.state.collapsed("files")}
                        onToggle={(value) => props.state.setCollapsed("files", value)}
                    >
                        {props.files?.()}
                    </CollapsiblePanel>
                </>
            }</Show>
        </>
    );

    const Desktop = () => (
        <div
            class="workbench"
            classList={{ "without-taskbar": !props.taskBar }}
            ref={props.state.observeShell}
            style={{ "grid-template-columns": props.state.columns() }}
        >
            <Show when={props.taskBar}>{(taskBar) => <footer class="tasks">{taskBar()()}</footer>}</Show>
            <CollapsiblePanel
                cls="nav"
                fold="left"
                controlEdge="right"
                title={title("nav")}
                collapsed={props.state.collapsed("nav")}
                onToggle={(value) => props.state.setCollapsed("nav", value)}
            >
                <div class="nav-stack">
                    <div class="nav-scroll">
                        <h2 class="panel-heading">{title("nav")}</h2>
                        {props.nav()}
                    </div>
                    {props.navFooter?.()}
                </div>
            </CollapsiblePanel>
            <Resizer onMove={(x) => props.state.resize("nav", x)} />
            <Show
                when={!props.state.collapsed("chat")}
                fallback={
                    <div
                        class="panel run rail"
                        data-rail="run"
                        role="button"
                        tabindex="0"
                        title={`Show ${title("chat")}`}
                        onClick={() => props.state.setCollapsed("chat", false)}
                        onKeyDown={(event) =>
                            (event.key === "Enter" || event.key === " ") &&
                            props.state.setCollapsed("chat", false)
                        }
                    >
                        <span class="rail-chevron">›</span>
                        <span class="rail-label">{title("chat")}</span>
                    </div>
                }
            >
                <section class="panel run">
                    <Show when={showsHeading("chat")}><h2 class="panel-heading">{title("chat")}</h2></Show>
                    {props.chat()}
                </section>
            </Show>
            <RightPanels />
            {props.overlays?.()}
        </div>
    );

    const Mobile = () => (
        <div class="workbench mobile" data-mobile>
            <Carousel
                state={props.state.carousel()}
                onState={props.state.setCarousel}
                panes={panes()}
                paneOrder={props.files ? undefined : ["nav", "chat", "content"]}
                onNewChat={props.onNewChat}
            />
            {props.overlays?.()}
        </div>
    );

    return <Show when={props.state.isMobile()} fallback={<Desktop />}><Mobile /></Show>;
}

function CollapsiblePanel(props: {
    cls: string;
    fold: PanelCollapseDirection;
    controlEdge: "left" | "right";
    title: string;
    collapsed: boolean;
    onToggle: (value: boolean) => void;
    children: JSX.Element;
}) {
    const expandGlyph = () => (props.fold === "left" ? "›" : "‹");
    return (
        <Show
            when={!props.collapsed}
            fallback={
                <div
                    class={`panel ${props.cls} rail`}
                    data-rail={props.cls}
                    role="button"
                    tabindex="0"
                    title={`Show ${props.title}`}
                    onClick={() => props.onToggle(false)}
                    onKeyDown={(event) =>
                        (event.key === "Enter" || event.key === " ") && props.onToggle(false)
                    }
                >
                    <span class="rail-chevron">{expandGlyph()}</span>
                    <span class="rail-label">{props.title}</span>
                </div>
            }
        >
            <div class={`panel ${props.cls} collapsible`}>
                <button
                    class={`panel-collapse ${props.controlEdge}`}
                    data-collapse={props.cls}
                    title={`Hide ${props.title}`}
                    aria-label={`Hide ${props.title}`}
                    onClick={() => props.onToggle(true)}
                >
                    <PanelCollapseIcon direction={props.fold} />
                </button>
                <div class="panel-body">{props.children}</div>
            </div>
        </Show>
    );
}

function Resizer(props: { onMove: (clientX: number) => void }) {
    const [dragging, setDragging] = createSignal(false);
    const down = (event: PointerEvent) => {
        event.preventDefault();
        setDragging(true);
        document.body.style.cursor = "col-resize";
        document.body.style.userSelect = "none";
        const move = (next: PointerEvent) => props.onMove(next.clientX);
        const up = () => {
            setDragging(false);
            document.body.style.cursor = "";
            document.body.style.userSelect = "";
            window.removeEventListener("pointermove", move);
            window.removeEventListener("pointerup", up);
        };
        window.addEventListener("pointermove", move);
        window.addEventListener("pointerup", up);
    };
    return (
        <div
            class="resizer"
            classList={{ dragging: dragging() }}
            onPointerDown={down}
            role="separator"
            aria-orientation="vertical"
        />
    );
}
