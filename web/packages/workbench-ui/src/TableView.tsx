/**
 * The View tab for separated values.
 *
 * A `.csv` is text, and the pane used to render it as text: correct, and
 * useless past about four columns. This draws the grid the file describes,
 * which is what its author meant by writing one.
 *
 * Read-only, like every other renderer in the View tab. A table a person could
 * type into would be a second way to change a worktree file, around the
 * command path that Edit goes through — see the note in `OfficeView`.
 */

import { For, Show, createMemo } from "solid-js";
import { parseDelimited } from "./delimited";

export function TableView(props: { readonly text: string; readonly delimiter: string }) {
    const table = createMemo(() => parseDelimited(props.text, props.delimiter));
    // The first row is drawn as the header. Nothing in a separated-values file
    // says whether it has one, and every tool that reads these assumes it does
    // — so this follows the convention rather than inventing a guess from the
    // shape of the data, which would be wrong in a different direction.
    const header = () => table().rows[0] ?? [];
    const body = () => table().rows.slice(1);
    const note = () => {
        const { rows, totalRows, totalColumns } = table();
        const shown = Math.max(rows.length - 1, 0);
        const total = Math.max(totalRows - 1, 0);
        const columns = `${totalColumns} column${totalColumns === 1 ? "" : "s"}`;
        return table().truncated
            ? `showing the first ${shown.toLocaleString()} of ${total.toLocaleString()} rows · ${columns}`
            : `${total.toLocaleString()} row${total === 1 ? "" : "s"} · ${columns}`;
    };
    return (
        <div class="filetable" data-file-view data-file-table>
            <Show
                when={table().totalRows > 0}
                fallback={<div class="filetable-note">This file has no rows.</div>}
            >
                <div class="filetable-scroll">
                    <table>
                        <thead>
                            <tr>
                                {/* The row number column is unlabelled: its
                                    header cell is the corner of the grid. */}
                                <th class="filetable-gutter" />
                                <For each={header()}>{(cell) => <th>{cell}</th>}</For>
                            </tr>
                        </thead>
                        <tbody>
                            <For each={body()}>
                                {(row, index) => (
                                    <tr>
                                        <td class="filetable-gutter">{index() + 1}</td>
                                        {/* Every row is padded to the header's
                                            width so a short row does not pull
                                            the columns after it out of line. */}
                                        <For each={header()}>
                                            {(_, column) => <td>{row[column()] ?? ""}</td>}
                                        </For>
                                    </tr>
                                )}
                            </For>
                        </tbody>
                    </table>
                </div>
                <div class="filetable-note">{note()}</div>
            </Show>
        </div>
    );
}
