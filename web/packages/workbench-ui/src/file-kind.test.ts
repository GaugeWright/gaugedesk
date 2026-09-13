/**
 * The View tab's open-this-file decision. The rule is deliberately about the
 * path rather than the bytes — these pin that, and pin the fallbacks that keep
 * an unrecognised file honest rather than mojibake.
 */

import { describe, expect, it } from "vitest";
import {
    describeSize,
    fileExtension,
    readAsTextFailed,
    syntaxLanguageFor,
    viewerFileFor,
} from "./file-kind";

describe("fileExtension", () => {
    it("reads the last extension, lowercased", () => {
        expect(fileExtension("report.PDF")).toBe("pdf");
        expect(fileExtension("shots/screen.final.png")).toBe("png");
    });

    it("gives a dotfile and an extensionless file no extension", () => {
        expect(fileExtension(".gitignore")).toBe("");
        expect(fileExtension("docs/.env")).toBe("");
        expect(fileExtension("Makefile")).toBe("");
        expect(fileExtension("bin/run")).toBe("");
    });

    it("is not fooled by a dot in a directory name", () => {
        expect(fileExtension("v1.2/notes")).toBe("");
    });
});

describe("viewerFileFor", () => {
    it("opens PDFs and pictures as themselves", () => {
        expect(viewerFileFor("invoice.pdf")).toEqual({ kind: "pdf", mediaType: "application/pdf" });
        expect(viewerFileFor("a/b/shot.PNG")).toEqual({ kind: "image", mediaType: "image/png" });
        expect(viewerFileFor("photo.jpeg")).toEqual({ kind: "image", mediaType: "image/jpeg" });
    });

    it("treats SVG as a picture — it renders through an <img>, which runs no script", () => {
        expect(viewerFileFor("logo.svg")).toEqual({ kind: "image", mediaType: "image/svg+xml" });
    });

    it("routes Word, Excel and PowerPoint to the OOXML engine, naming the format", () => {
        expect(viewerFileFor("report.docx")).toMatchObject({ kind: "office", format: "docx" });
        expect(viewerFileFor("deck.PPTX")).toMatchObject({ kind: "office", format: "pptx" });
        expect(viewerFileFor("a/b/book.xlsx")).toMatchObject({ kind: "office", format: "xlsx" });
    });

    it("leaves the legacy binary Office formats opaque — a different format family", () => {
        expect(viewerFileFor("memo.doc").kind).toBe("opaque");
        expect(viewerFileFor("sheet.xls").kind).toBe("opaque");
        expect(viewerFileFor("slides.ppt").kind).toBe("opaque");
    });

    it("names a format it cannot show rather than painting it", () => {
        expect(viewerFileFor("bundle.zip").kind).toBe("opaque");
        expect(viewerFileFor("app.wasm").kind).toBe("opaque");
        expect(viewerFileFor("lib.so").kind).toBe("opaque");
    });

    it("leaves everything else as text, exactly as before", () => {
        for (const path of ["main.rs", "notes.md", "Makefile", ".gitignore", "a.b.unknown"]) {
            expect(viewerFileFor(path).kind).toBe("text");
        }
    });
});

describe("readAsTextFailed", () => {
    it("passes ordinary text, including empty and non-ASCII", () => {
        expect(readAsTextFailed("")).toBe(false);
        expect(readAsTextFailed("fn main() {}\n")).toBe(false);
        expect(readAsTextFailed("naïve café — résumé\n")).toBe(false);
    });

    it("catches a body carrying NULs", () => {
        expect(readAsTextFailed("PK\u0003\u0004\u0000\u0000")).toBe(true);
    });

    it("catches a body thick with replacement characters", () => {
        expect(readAsTextFailed("\ufffd".repeat(20) + "x".repeat(80))).toBe(true);
    });

    it("tolerates the occasional replacement character in real text", () => {
        expect(readAsTextFailed("a".repeat(4000) + "\ufffd")).toBe(false);
    });
});

describe("describeSize", () => {
    it("reads in the units a person uses", () => {
        expect(describeSize(0)).toBe("0 bytes");
        expect(describeSize(512)).toBe("512 bytes");
        expect(describeSize(2048)).toBe("2.0 KiB");
        expect(describeSize(20 * 1024)).toBe("20 KiB");
        expect(describeSize(3 * 1024 * 1024 + 512 * 1024)).toBe("3.5 MiB");
    });
});

describe("viewerFileFor — recordings and tables", () => {
    it("sends a recording to the element that plays it", () => {
        expect(viewerFileFor("turn/clip.mp4")).toEqual({
            kind: "media",
            media: "video",
            mediaType: "video/mp4",
        });
        expect(viewerFileFor("notes/voice.mp3")).toEqual({
            kind: "media",
            media: "audio",
            mediaType: "audio/mpeg",
        });
    });

    it("no longer calls a playable recording opaque", () => {
        // These were named-but-unshowable before the platform played them.
        for (const path of ["a.wav", "a.ogg", "a.webm", "a.mov", "a.flac"]) {
            expect(viewerFileFor(path).kind).toBe("media");
        }
    });

    it("keeps the delimiter with the table so the parser need not guess", () => {
        expect(viewerFileFor("export.csv")).toEqual({
            kind: "table",
            delimiter: ",",
            mediaType: "text/csv",
        });
        expect(viewerFileFor("export.TSV")).toEqual({
            kind: "table",
            delimiter: "\t",
            mediaType: "text/tab-separated-values",
        });
    });

    it("leaves the formats we still cannot open alone", () => {
        expect(viewerFileFor("old.doc").kind).toBe("opaque");
        expect(viewerFileFor("bundle.zip").kind).toBe("opaque");
        expect(viewerFileFor("font.woff2").kind).toBe("opaque");
    });
});

describe("syntaxLanguageFor", () => {
    it("names a grammar for source it recognises", () => {
        expect(syntaxLanguageFor("crates/app/src/main.rs")).toBe("rust");
        expect(syntaxLanguageFor("web/src/App.tsx")).toBe("typescript");
        expect(syntaxLanguageFor("scripts/check.SH")).toBe("bash");
    });

    it("settles from the whole name when there is no extension", () => {
        expect(syntaxLanguageFor("build/Dockerfile")).toBe("dockerfile");
        expect(syntaxLanguageFor("Makefile")).toBe("makefile");
    });

    it("leaves anything it has no grammar for plain", () => {
        expect(syntaxLanguageFor("notes.txt")).toBeNull();
        expect(syntaxLanguageFor("README")).toBeNull();
        expect(syntaxLanguageFor("data.bin")).toBeNull();
    });

    it("does not claim a language for a file another view owns", () => {
        // Markdown, tables and pictures each have their own renderer; a
        // language here would race them for the same file.
        expect(syntaxLanguageFor("notes.md")).toBeNull();
        expect(syntaxLanguageFor("export.csv")).toBeNull();
        expect(syntaxLanguageFor("chart.png")).toBeNull();
    });
});
