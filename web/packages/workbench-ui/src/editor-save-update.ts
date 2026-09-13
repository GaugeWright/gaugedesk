import type { SaveBase, SaveFileResult } from "@gaugewright/control-plane-client";

/** Apply an accepted submission to a possibly newer buffer. A newer buffer
 * keeps the basis it was actually derived from, even when the accepted save
 * merged additional changes. This does not infer native Saved evidence from
 * admission or from a working-copy read. */
export function editorSaveUpdate(submitted: string,
    result: Exclude<SaveFileResult, { kind: "conflict" }>,
    buffer: { draft: string | null; basis: SaveBase | null; unchanged: boolean }) {
    const accepted = result.kind === "merged" ? result.content : submitted;
    const clear = buffer.unchanged || buffer.draft === null || buffer.draft === accepted;
    return {
        accepted,
        cut: result.cut,
        draft: clear ? null : buffer.draft,
        basis: clear ? null : buffer.basis,
        message: !clear ? "previous edit saved — newer changes remain unsaved"
            : result.kind === "merged" ? "saved — merged with newer changes" : "saved",
    };
}
