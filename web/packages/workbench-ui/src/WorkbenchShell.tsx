import {
    batch,
    createEffect,
    createMemo,
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
import { dragWorkbenchDivider, dragWorkbenchRail, resolveWorkbenchLayout, workbenchRailResizePair, type PaneDivider } from "./workbench-layout";

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
    beginResize: (boundary: PaneDivider) => (deltaX: number) => void;
    canResizeRail: (pane: PaneKind) => boolean;
    beginRailResize: (pane: PaneKind) => ((deltaX: number) => void) | null;
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

    // 206px keeps the three facet tabs on one row with slack across the text
    // fallback stack's metric spread (Plex Serif absent → wider Palatino/Noto).
    const [navWidth, setNavWidth] = createSignal(storedNumber("navW", 206));
    const [filesWidth, setFilesWidth] = createSignal(storedNumber("wsW", 230));
    const [chatFraction, setChatFraction] = createSignal(storedNumber("runFr", 0.5));
    // An explicit width is set on the first drag. Until then, the saved fraction
    // gives the middle pair a useful initial split on any window size.
    const [chatWidth, setChatWidth] = createSignal<number | null>(null);
    const [shellWidth, setShellWidth] = createSignal(typeof window === "undefined" ? 1200 : window.innerWidth);
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

    let shellObserver: ResizeObserver | undefined;
    const observeShell = (element: HTMLDivElement) => {
        shellObserver?.disconnect();
        setShellWidth(element.getBoundingClientRect().width);
        if (typeof ResizeObserver !== "undefined") {
            shellObserver = new ResizeObserver(([entry]) => setShellWidth(entry.contentRect.width));
            shellObserver.observe(element);
        }
    };
    onCleanup(() => shellObserver?.disconnect());

    const layout = createMemo(() => resolveWorkbenchLayout({
        width: shellWidth(), includeFiles,
        collapsed: { nav: navCollapsed(), chat: chatCollapsed(), content: contentCollapsed(), files: filesCollapsed() },
        navWidth: navWidth(), filesWidth: filesWidth(), chatWidth: chatWidth(), chatFraction: chatFraction(),
    }));
    const collapsedPanes = () => ({
        nav: navCollapsed(), chat: chatCollapsed(), content: contentCollapsed(), files: filesCollapsed(),
    });
    const applyPair = (pair: readonly [PaneKind, PaneKind], next: ReturnType<typeof resolveWorkbenchLayout>) => {
        batch(() => {
            if (pair.includes("nav")) setNavWidth(next.nav);
            if (pair.includes("files")) setFilesWidth(next.files);
            if (pair.includes("chat")) {
                setChatWidth(next.chat);
                if (!contentCollapsed()) setChatFraction(next.chat / (next.chat + next.content));
            }
        });
    };
    const beginResize = (boundary: PaneDivider) => {
        const initial = layout();
        return (deltaX: number) => {
            const next = dragWorkbenchDivider(initial, boundary, deltaX);
            const pair = boundary === "nav" ? ["nav", "chat"] as const
                : boundary === "mid" ? ["chat", "content"] as const
                    : ["content", "files"] as const;
            applyPair(pair, next);
        };
    };
    const canResizeRail = (pane: PaneKind) => workbenchRailResizePair(layout(), collapsedPanes(), pane) !== null;
    const beginRailResize = (pane: PaneKind) => {
        const initial = layout();
        const initialCollapsed = collapsedPanes();
        const pair = workbenchRailResizePair(initial, initialCollapsed, pane);
        if (!pair) return null;
        return (deltaX: number) => applyPair(pair, dragWorkbenchRail(initial, initialCollapsed, pane, deltaX));
    };

    const columns = () => {
        const p = layout();
        return includeFiles
            ? `${p.nav}px ${p.navDivider}px ${p.chat}px ${p.midDivider}px ${p.content}px ${p.filesDivider}px ${p.files}px`
            : `${p.nav}px ${p.navDivider}px ${p.chat}px ${p.midDivider}px ${p.content}px`;
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
        beginResize,
        canResizeRail,
        beginRailResize,
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
            <Resizer enabled={!props.state.collapsed("chat") && !props.state.collapsed("content")}
                onStart={() => props.state.beginResize("mid")} />
            <CollapsiblePanel
                cls="content"
                fold="right"
                controlEdge="left"
                title={title("content")}
                collapsed={props.state.collapsed("content")}
                onToggle={(value) => props.state.setCollapsed("content", value)}
                canResize={props.state.canResizeRail("content")}
                onStartResize={() => props.state.beginRailResize("content")}
            >
                {props.content()}
            </CollapsiblePanel>

            <Show when={props.files}>{
                <>
                    <Resizer enabled={!props.state.collapsed("content") && !props.state.collapsed("files")}
                        onStart={() => props.state.beginResize("files")} />
                    <CollapsiblePanel
                        cls="workspace"
                        fold="right"
                        controlEdge="left"
                        title={title("files")}
                        collapsed={props.state.collapsed("files")}
                        onToggle={(value) => props.state.setCollapsed("files", value)}
                        canResize={props.state.canResizeRail("files")}
                        onStartResize={() => props.state.beginRailResize("files")}
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
            {/* The task bar stands in for the window's title bar where the desktop shell
                overlays it (macOS), so it is the drag handle; its controls still click. */}
            <Show when={props.taskBar}>{(taskBar) => <footer class="tasks" data-tauri-drag-region="deep">{taskBar()()}</footer>}</Show>
            <CollapsiblePanel
                cls="nav"
                fold="left"
                controlEdge="right"
                title={title("nav")}
                collapsed={props.state.collapsed("nav")}
                onToggle={(value) => props.state.setCollapsed("nav", value)}
                canResize={props.state.canResizeRail("nav")}
                onStartResize={() => props.state.beginRailResize("nav")}
            >
                <div class="nav-stack">
                    <div class="nav-scroll">
                        <Show when={showsHeading("nav")}><h2 class="panel-heading">{title("nav")}</h2></Show>
                        {props.nav()}
                    </div>
                    {props.navFooter?.()}
                </div>
            </CollapsiblePanel>
            <Resizer enabled={!props.state.collapsed("nav") && !props.state.collapsed("chat")}
                onStart={() => props.state.beginResize("nav")} />
            <Show
                when={!props.state.collapsed("chat")}
                fallback={
                    <CollapsedRail
                        cls="run" title={title("chat")} glyph="›"
                        onExpand={() => props.state.setCollapsed("chat", false)}
                        canResize={props.state.canResizeRail("chat")}
                        onStartResize={() => props.state.beginRailResize("chat")}
                    />
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
                paneLabels={{ files: title("files") }}
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
    canResize: boolean;
    onStartResize: () => ((deltaX: number) => void) | null;
    children: JSX.Element;
}) {
    const expandGlyph = () => (props.fold === "left" ? "›" : "‹");
    return (
        <Show
            when={!props.collapsed}
            fallback={
                <CollapsedRail
                    cls={props.cls} title={props.title} glyph={expandGlyph()}
                    onExpand={() => props.onToggle(false)}
                    canResize={props.canResize}
                    onStartResize={props.onStartResize}
                />
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

function CollapsedRail(props: {
    cls: string;
    title: string;
    glyph: string;
    onExpand: () => void;
    canResize: boolean;
    onStartResize: () => ((deltaX: number) => void) | null;
}) {
    const [dragging, setDragging] = createSignal(false);
    let gesture: { pointerId: number; startX: number; apply: ((deltaX: number) => void) | null; moved: boolean } | null = null;
    const end = () => {
        document.body.style.cursor = "";
        document.body.style.userSelect = "";
        setDragging(false);
        gesture = null;
    };
    return <div
        class={`panel ${props.cls} rail`}
        classList={{ "rail-resizable": props.canResize, dragging: dragging() }}
        data-rail={props.cls}
        role="button"
        tabindex="0"
        title={props.canResize ? `Drag to resize adjacent panels · Click to show ${props.title}` : `Show ${props.title}`}
        onPointerDown={(event) => {
            if (event.button !== 0) return;
            event.preventDefault();
            event.currentTarget.setPointerCapture(event.pointerId);
            gesture = { pointerId: event.pointerId, startX: event.clientX, apply: props.onStartResize(), moved: false };
        }}
        onPointerMove={(event) => {
            if (!gesture || event.pointerId !== gesture.pointerId || !gesture.apply) return;
            const deltaX = event.clientX - gesture.startX;
            if (!gesture.moved && Math.abs(deltaX) >= 4) {
                gesture.moved = true;
                setDragging(true);
                document.body.style.cursor = "col-resize";
                document.body.style.userSelect = "none";
            }
            if (gesture.moved) gesture.apply(deltaX);
        }}
        onPointerUp={(event) => {
            if (!gesture || event.pointerId !== gesture.pointerId) return;
            const moved = gesture.moved;
            end();
            if (!moved) props.onExpand();
        }}
        onPointerCancel={end}
        onKeyDown={(event) => {
            if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                props.onExpand();
            } else if (event.key === "ArrowLeft" || event.key === "ArrowRight") {
                const apply = props.onStartResize();
                if (apply) {
                    event.preventDefault();
                    apply(event.key === "ArrowLeft" ? -16 : 16);
                }
            }
        }}
    >
        <span class="rail-chevron">{props.glyph}</span>
        <span class="rail-label">{props.title}</span>
    </div>;
}

function Resizer(props: { enabled: boolean; onStart: () => (deltaX: number) => void }) {
    const [dragging, setDragging] = createSignal(false);
    const down = (event: PointerEvent) => {
        if (!props.enabled) return;
        event.preventDefault();
        (event.currentTarget as HTMLDivElement).setPointerCapture(event.pointerId);
        const startX = event.clientX;
        const apply = props.onStart();
        setDragging(true);
        document.body.style.cursor = "col-resize";
        document.body.style.userSelect = "none";
        const move = (next: PointerEvent) => apply(next.clientX - startX);
        const up = () => {
            setDragging(false);
            document.body.style.cursor = "";
            document.body.style.userSelect = "";
            window.removeEventListener("pointermove", move);
            window.removeEventListener("pointerup", up);
            window.removeEventListener("pointercancel", up);
        };
        window.addEventListener("pointermove", move);
        window.addEventListener("pointerup", up);
        window.addEventListener("pointercancel", up);
    };
    return (
        <div
            class="resizer"
            classList={{ dragging: dragging(), disabled: !props.enabled }}
            onPointerDown={down}
            role="separator"
            aria-orientation="vertical"
        />
    );
}
