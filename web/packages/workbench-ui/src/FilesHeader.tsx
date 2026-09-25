/** Compact Files pane header with its durable workspace uploads in one menu. */
import { createSignal, Show, type JSX } from "solid-js";
import { Icon } from "./icons";

export interface FilesHeaderProps {
    readonly canAdd: boolean;
    readonly canCreate: boolean;
    readonly onCreateFile: () => void;
    readonly onCreateFolder: () => void;
    readonly onAddFiles: () => void;
    readonly onAddFile: () => void;
}

export function FilesHeader(props: FilesHeaderProps): JSX.Element {
    const [open, setOpen] = createSignal(false);
    const [position, setPosition] = createSignal({ left: 0, top: 0 });
    let trigger: HTMLButtonElement | undefined;
    const close = () => setOpen(false);
    const show = () => {
        const rect = trigger?.getBoundingClientRect();
        if (rect) setPosition({
            left: Math.max(6, Math.min(rect.right - 200, window.innerWidth - 206)),
            top: rect.bottom + 4,
        });
        setOpen(true);
    };
    const choose = (action: () => void) => {
        close();
        action();
    };

    return <header class="files-header">
        <h2 class="files-header-title">Files</h2>
        <button
            ref={trigger}
            type="button"
            class="chat-options-trigger files-menu-trigger"
            classList={{ active: open() }}
            data-files-menu-trigger
            aria-label="Files menu"
            title={props.canAdd ? "Files menu" : "Open a chat to add files"}
            aria-haspopup="menu"
            aria-expanded={open()}
            disabled={!props.canAdd}
            onClick={() => open() ? close() : show()}
            onKeyDown={(event) => event.key === "Escape" && close()}
        >
            <Icon name="menu" />
        </button>
        <Show when={open()}>
            <div class="popover-catcher" onClick={close} />
            <div
                class="chat-options-popover files-menu-popover"
                data-files-menu
                role="menu"
                aria-label="Files actions"
                style={{ left: `${position().left}px`, top: `${position().top}px` }}
                onKeyDown={(event) => {
                    if (event.key === "Escape") {
                        event.stopPropagation();
                        close();
                        trigger?.focus();
                    }
                }}
            >
                <button type="button" role="menuitem" class="chat-options-item"
                    disabled={!props.canCreate} onClick={() => choose(props.onCreateFile)}>
                    New file
                </button>
                <button type="button" role="menuitem" class="chat-options-item"
                    disabled={!props.canCreate} onClick={() => choose(props.onCreateFolder)}>
                    New folder
                </button>
                <div class="files-menu-separator" role="separator" />
                <button type="button" role="menuitem" class="chat-options-item"
                    title="Add a folder of files for the agent to work with (copied into this chat's workspace)"
                    onClick={() => choose(props.onAddFiles)}>
                    Import folder…
                </button>
                <button type="button" role="menuitem" class="chat-options-item"
                    title="Add a single file for the agent to work with (copied into this chat's workspace)"
                    onClick={() => choose(props.onAddFile)}>
                    Import file…
                </button>
            </div>
        </Show>
    </header>;
}
