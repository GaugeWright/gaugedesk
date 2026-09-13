/**
 * The cases that make a hand-rolled `split(",")` wrong. Each of these appears
 * in ordinary spreadsheet output, and each one tears a row apart silently.
 */

import { describe, expect, it } from "vitest";
import { DEFAULT_DELIMITED_LIMITS, parseDelimited } from "./delimited";

const parse = (text: string, delimiter = ",") => parseDelimited(text, delimiter);

describe("parseDelimited", () => {
    it("reads plain rows and fields", () => {
        expect(parse("a,b\n1,2").rows).toEqual([
            ["a", "b"],
            ["1", "2"],
        ]);
    });

    it("keeps a delimiter that sits inside quotes", () => {
        expect(parse('name,note\n"Scully, Jack",hello').rows).toEqual([
            ["name", "note"],
            ["Scully, Jack", "hello"],
        ]);
    });

    it("keeps a newline that sits inside quotes as one field", () => {
        const table = parse('a,b\n"line one\nline two",c');
        expect(table.rows).toEqual([
            ["a", "b"],
            ["line one\nline two", "c"],
        ]);
        expect(table.totalRows).toBe(2);
    });

    it("reads a doubled quote as one literal quote", () => {
        expect(parse('a\n"she said ""hi"""').rows).toEqual([["a"], ['she said "hi"']]);
    });

    it("does not treat a quote mid-field as opening a quoted field", () => {
        expect(parse('a\n12" pipe,b').rows[1]).toEqual(['12" pipe', "b"]);
    });

    it("ends a file with no trailing newline on its last row", () => {
        expect(parse("a,b\n1,2").totalRows).toBe(2);
    });

    it("does not invent a row from a trailing newline", () => {
        expect(parse("a,b\n1,2\n").totalRows).toBe(2);
        expect(parse("a,b\n1,2\r\n").totalRows).toBe(2);
    });

    it("reads CRLF rows without leaving carriage returns in the last field", () => {
        expect(parse("a,b\r\n1,2\r\n").rows).toEqual([
            ["a", "b"],
            ["1", "2"],
        ]);
    });

    it("keeps empty fields rather than dropping them", () => {
        expect(parse("a,,c").rows).toEqual([["a", "", "c"]]);
        expect(parse(",,").rows).toEqual([["", "", ""]]);
    });

    it("splits on tabs when asked to", () => {
        expect(parse("a\tb\n1\t2", "\t").rows).toEqual([
            ["a", "b"],
            ["1", "2"],
        ]);
        // A comma is ordinary text in a tab-separated file.
        expect(parse("a,b\tc", "\t").rows).toEqual([["a,b", "c"]]);
    });

    it("counts rows it did not retain, so the view can say what it is hiding", () => {
        const text = Array.from({ length: 50 }, (_, i) => `row${i}`).join("\n");
        const table = parseDelimited(text, ",", { maxRows: 10, maxColumns: 8 });
        expect(table.rows).toHaveLength(10);
        expect(table.totalRows).toBe(50);
        expect(table.truncated).toBe(true);
    });

    it("caps columns and still reports the widest row", () => {
        const table = parseDelimited("a,b,c,d,e", ",", { maxRows: 10, maxColumns: 3 });
        expect(table.rows[0]).toEqual(["a", "b", "c"]);
        expect(table.totalColumns).toBe(3);
    });

    it("is not truncated when it retained everything", () => {
        expect(parse("a,b\n1,2").truncated).toBe(false);
    });

    it("reads an unterminated quoted field to the end rather than losing it", () => {
        expect(parse('a\n"never closed').rows[1]).toEqual(["never closed"]);
    });

    it("treats an empty file as no rows at all", () => {
        const table = parse("");
        expect(table.rows).toEqual([]);
        expect(table.totalRows).toBe(0);
        expect(table.truncated).toBe(false);
    });

    it("ships limits a worktree-sized export cannot hang the pane with", () => {
        expect(DEFAULT_DELIMITED_LIMITS.maxRows).toBeLessThanOrEqual(5000);
    });
});
