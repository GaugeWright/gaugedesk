/**
 * The app's hover help. Every control that explains itself with a `title`
 * attribute gets a tooltip drawn in the workbench's own face and colours that
 * arrives a quarter-second after the pointer settles, instead of the
 * browser's, which waits about a second and draws in the system's small face.
 *
 * One delegated listener serves every `title` in its scope, so a component
 * keeps writing `title="…"` and nothing else changes. While a control is
 * pointed at, its title is borrowed — removed, so the browser's own tooltip
 * never appears beside this one — and it is put back when the pointer leaves,
 * so the DOM at rest is exactly what the component rendered. A title the
 * component changes while it is borrowed (a "Copy" that becomes "Copied") is
 * picked up and shown.
 *
 * Once one tooltip has shown, the next appears at once while the pointer moves
 * along a row of controls, as native toolbars do. A touch has no hover, so it
 * shows nothing; a keyboard focus shows the focused control's tooltip at once.
 * An empty `title=""` means "no tooltip here", as it does natively, and
 * `data-native-title` opts an element and its contents out.
 */

const SHOW_DELAY_MS = 250;
/** After a tooltip hides, the next shows without the delay for this long. */
const WARM_MS = 600;
const GAP = 6;
const EDGE = 6;

export interface Box {
    readonly left: number;
    readonly top: number;
    readonly width: number;
    readonly height: number;
}

/** Where a tooltip of `size` goes for an `anchor`: centred below it, above it
 *  when there is no room below, and always wholly inside the viewport. */
export function placeTooltip(
    anchor: Box,
    size: { readonly width: number; readonly height: number },
    viewport: { readonly width: number; readonly height: number },
): { left: number; top: number } {
    const below = anchor.top + anchor.height + GAP;
    const above = anchor.top - GAP - size.height;
    const top = below + size.height <= viewport.height - EDGE || above < EDGE ? below : above;
    const centred = anchor.left + anchor.width / 2 - size.width / 2;
    const left = Math.max(EDGE, Math.min(centred, viewport.width - size.width - EDGE));
    return { left: Math.round(left), top: Math.round(Math.max(EDGE, top)) };
}

/** Install the tooltip layer over `scope` and return what removes it. */
export function installTooltips(scope: Document | ShadowRoot = document): () => void {
    const ownerDocument = scope instanceof Document ? scope : scope.ownerDocument;
    const view = ownerDocument.defaultView ?? window;
    const tip = ownerDocument.createElement("div");
    tip.className = "app-tooltip";
    tip.setAttribute("role", "tooltip");
    tip.id = `app-tooltip-${Math.random().toString(36).slice(2, 10)}`;
    (scope instanceof Document ? scope.body : scope).appendChild(tip);

    /** The control whose title is borrowed, and the title it had. */
    let current: Element | null = null;
    let text = "";
    /** A label added so a title-only icon keeps its accessible name, and the
     *  description added while the tooltip shows; each is removed on release. */
    let lentLabel = false;
    let lentDescription = false;
    let pending: ReturnType<typeof setTimeout> | undefined;
    let warmUntil = 0;
    /** A control pressed while pointed at stays quiet until the pointer leaves. */
    let pressed: Element | null = null;

    const watcher = new MutationObserver(() => {
        if (!current) return;
        const next = current.getAttribute("title");
        if (next === null) return;
        current.removeAttribute("title");
        text = next;
        if (tip.classList.contains("visible")) {
            if (text) render();
            else hide();
        }
    });

    function titled(from: EventTarget | null): Element | null {
        let el = from instanceof Element ? from : null;
        for (; el; el = el.parentElement) {
            if (el.hasAttribute("data-native-title") || el instanceof HTMLIFrameElement) return null;
            if (el === current || el.hasAttribute("title")) return el;
        }
        return null;
    }

    function borrow(el: Element) {
        current = el;
        text = el.getAttribute("title") ?? "";
        el.removeAttribute("title");
        if (
            text &&
            !el.hasAttribute("aria-label") &&
            !el.hasAttribute("aria-labelledby") &&
            !el.textContent?.trim()
        ) {
            el.setAttribute("aria-label", text);
            lentLabel = true;
        }
        watcher.observe(el, { attributes: true, attributeFilter: ["title"] });
    }

    function release() {
        if (!current) return;
        watcher.disconnect();
        if (!current.hasAttribute("title")) current.setAttribute("title", text);
        if (lentLabel) current.removeAttribute("aria-label");
        if (lentDescription) current.removeAttribute("aria-describedby");
        current = null;
        text = "";
        lentLabel = false;
        lentDescription = false;
    }

    function render() {
        if (!current || !current.isConnected || !text) return hide();
        tip.textContent = text;
        // Measure at the origin, where the full width is available, so a
        // tooltip last shown near the right edge is not measured squeezed.
        tip.style.left = "0px";
        tip.style.top = "0px";
        tip.classList.add("visible");
        const anchor = current.getBoundingClientRect();
        const at = placeTooltip(
            anchor,
            { width: tip.offsetWidth, height: tip.offsetHeight },
            { width: view.innerWidth, height: view.innerHeight },
        );
        tip.style.left = `${at.left}px`;
        tip.style.top = `${at.top}px`;
        if (!lentLabel && !current.hasAttribute("aria-describedby")) {
            current.setAttribute("aria-describedby", tip.id);
            lentDescription = true;
        }
    }

    function hide() {
        clearTimeout(pending);
        pending = undefined;
        if (tip.classList.contains("visible")) warmUntil = Date.now() + WARM_MS;
        tip.classList.remove("visible");
    }

    function point(el: Element | null, immediate: boolean) {
        if (el === current) return;
        hide();
        release();
        if (!el) return;
        borrow(el);
        if (!text || el === pressed) return;
        if (immediate || Date.now() < warmUntil) render();
        else pending = setTimeout(render, SHOW_DELAY_MS);
    }

    const onOver = (event: Event) => {
        if ((event as PointerEvent).pointerType === "touch") return;
        const el = titled(event.target);
        if (pressed && el !== pressed) pressed = null;
        point(el, false);
    };
    const onOut = (event: Event) => {
        const to = (event as PointerEvent).relatedTarget;
        if (to instanceof Node && scope.contains(to)) return;
        pressed = null;
        point(null, false);
    };
    const onDown = () => {
        pressed = current;
        hide();
    };
    const onFocus = (event: Event) => {
        const target = event.target;
        if (!(target instanceof Element) || !target.matches(":focus-visible")) return;
        point(titled(target), true);
    };
    const onBlur = () => point(null, false);
    const onKey = (event: Event) => {
        if ((event as KeyboardEvent).key === "Escape") hide();
    };
    const onScroll = () => hide();

    const listeners: [EventTarget, string, EventListener, boolean][] = [
        [scope, "pointerover", onOver, false],
        [scope, "pointerout", onOut, false],
        [scope, "pointerdown", onDown, true],
        [scope, "focusin", onFocus, false],
        [scope, "focusout", onBlur, false],
        [scope, "keydown", onKey, true],
        [view, "scroll", onScroll, true],
        [view, "blur", onScroll, false],
    ];
    for (const [target, type, listener, capture] of listeners) {
        target.addEventListener(type, listener, capture);
    }
    return () => {
        for (const [target, type, listener, capture] of listeners) {
            target.removeEventListener(type, listener, capture);
        }
        hide();
        release();
        tip.remove();
    };
}
