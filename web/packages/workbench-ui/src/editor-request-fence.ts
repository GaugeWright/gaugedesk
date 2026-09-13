/** Local callback ownership, not command identity or durable save evidence.
 * A context must be a fresh object each time the mounted chat/file changes,
 * including a return to a previously selected path. */
export function editorRequestFence(context: () => unknown) {
    let revision = 0;
    let disposed = false;
    let save: Token | null = null;
    let preview: Token | null = null;
    let read: Token | null = null;
    const capture = () => ({ context: context(), revision });
    type Token = ReturnType<typeof capture>;
    const belongs = (token: Token) => !disposed && token.context === context();
    const unchanged = (token: Token) => belongs(token) && token.revision === revision;
    const saving = () => save !== null && belongs(save);
    return {
        capture,
        beginRead: () => { read = capture(); return read; },
        currentRead: (token: Token) => read === token && belongs(token),
        invalidateReads: () => { read = null; },
        belongs,
        unchanged,
        change: () => { revision++; preview = null; },
        saving,
        beginSave: () => {
            if (disposed || saving()) return null;
            preview = null;
            save = capture();
            return save;
        },
        finishSave: (token: Token) => { if (save === token) save = null; },
        beginPreview: () => {
            if (disposed || saving()) return null;
            preview = capture();
            return preview;
        },
        currentPreview: (token: Token) => preview === token && unchanged(token) && !saving(),
        dispose: () => { disposed = true; save = null; preview = null; read = null; },
    };
}
