/**
 * Separated values, parsed the way a spreadsheet wrote them.
 *
 * `text.split(",")` is the obvious implementation and it is wrong for the
 * files people actually have: a quoted field may contain the delimiter, a
 * newline, or a doubled quote standing for one literal quote. Any export from
 * Excel, Sheets or a database dump carries all three within a few thousand
 * rows, and splitting on the delimiter silently tears those rows apart — the
 * table still renders, so nothing announces the damage.
 *
 * So this is a scanner over RFC 4180 shape, kept pure and separate from the
 * view that draws it. It reads a `\r\n` or a `\n` as a row end, and treats a
 * quote as opening a field only where a field begins, which is what
 * spreadsheets emit and what a hand-written file usually means.
 */

export interface DelimitedTable {
    /** Rows retained for display, at most the requested maximum. */
    readonly rows: readonly (readonly string[])[];
    /** Rows the file holds, counted whether or not they were retained. */
    readonly totalRows: number;
    /** Columns the widest row holds, counted before any column cap. */
    readonly totalColumns: number;
    /** True when `rows` stops short of `totalRows`. */
    readonly truncated: boolean;
}

export interface DelimitedLimits {
    /** Rows to retain. A worktree holds exports with millions of rows, and a
     *  DOM table of that size hangs the pane rather than informing anyone. */
    readonly maxRows: number;
    /** Columns to retain per row. */
    readonly maxColumns: number;
}

export const DEFAULT_DELIMITED_LIMITS: DelimitedLimits = { maxRows: 2000, maxColumns: 200 };

/**
 * Parse `text` into rows. Counting continues past `maxRows` so the view can
 * say how much it is not showing — that count is cheap, and a table that
 * quietly ends at its limit is the failure this whole module exists to avoid.
 */
export function parseDelimited(
    text: string,
    delimiter: string,
    limits: DelimitedLimits = DEFAULT_DELIMITED_LIMITS,
): DelimitedTable {
    const rows: string[][] = [];
    let totalRows = 0;
    let totalColumns = 0;
    let row: string[] = [];
    let field = "";
    let quoted = false;
    // True while nothing has been read for the current field, which is the
    // only position where a quote opens one.
    let atFieldStart = true;

    const endField = () => {
        if (row.length < limits.maxColumns) row.push(field);
        else row.length = limits.maxColumns;
        field = "";
        atFieldStart = true;
    };
    const endRow = () => {
        endField();
        totalColumns = Math.max(totalColumns, row.length);
        totalRows += 1;
        if (rows.length < limits.maxRows) rows.push(row);
        row = [];
    };

    for (let i = 0; i < text.length; i += 1) {
        const character = text[i];
        if (quoted) {
            if (character !== '"') {
                field += character;
            } else if (text[i + 1] === '"') {
                field += '"';
                i += 1;
            } else {
                quoted = false;
            }
            continue;
        }
        if (character === '"' && atFieldStart) {
            quoted = true;
            atFieldStart = false;
            continue;
        }
        if (character === delimiter) {
            endField();
            continue;
        }
        if (character === "\n") {
            endRow();
            continue;
        }
        if (character === "\r" && text[i + 1] === "\n") {
            continue;
        }
        field += character;
        atFieldStart = false;
    }

    // A file that does not end in a newline still ends in a row. One that does
    // must not gain an empty row from its own terminator.
    if (field !== "" || row.length > 0 || quoted) endRow();

    return {
        rows,
        totalRows,
        totalColumns,
        truncated: totalRows > rows.length,
    };
}
