import { describe, expect, it } from "vitest";
import { strToU8, zipSync } from "fflate";
import {
    type Attachment,
    buildOutgoing,
    classifyAttachment,
    documentFileType,
    extractDocumentAttachment,
    MAX_DOCUMENT_TEXT_CHARS,
} from "./attachments";

function pickedFile(name: string, type: string, bytes: BlobPart = "content"): Blob & { name: string; type: string } {
    return Object.assign(new Blob([bytes], { type }), { name });
}

function ooxml(entries: Record<string, string>): Uint8Array<ArrayBuffer> {
    return zipSync(Object.fromEntries(Object.entries(entries).map(([path, xml]) => [path, strToU8(xml)])));
}

describe("classifyAttachment", () => {
    it("treats the runtime-native image mimes as images", () => {
        for (const type of ["image/png", "image/jpeg", "image/webp", "image/gif"]) {
            expect(classifyAttachment({ type, name: `pic.${type.split("/")[1]}` })).toBe("image");
        }
    });

    it("treats text/* and known textual files as text", () => {
        expect(classifyAttachment({ type: "text/plain", name: "notes.txt" })).toBe("text");
        expect(classifyAttachment({ type: "application/json", name: "data.json" })).toBe("text");
        // No mime from the browser, but a known code extension.
        expect(classifyAttachment({ type: "", name: "main.rs" })).toBe("text");
        expect(classifyAttachment({ type: "", name: "README.md" })).toBe("text");
    });

    it("routes PDF and the three Office Open XML formats to local document extraction", () => {
        expect(classifyAttachment({ type: "application/pdf", name: "report.pdf" })).toBe("document");
        expect(
            classifyAttachment({
                type: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                name: "doc.docx",
            }),
        ).toBe("document");
        expect(
            classifyAttachment({
                type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                name: "sheet.xlsx",
            }),
        ).toBe("document");
        expect(
            classifyAttachment({
                type: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                name: "deck.pptx",
            }),
        ).toBe("document");
    });

    it("uses document extensions only for empty or generic MIME values", () => {
        expect(documentFileType({ type: "", name: "report.PDF" })).toBe("pdf");
        expect(documentFileType({ type: "application/octet-stream", name: "deck.pptx" })).toBe("pptx");
        expect(documentFileType({ type: "application/json", name: "report.pdf" })).toBeUndefined();
        expect(classifyAttachment({ type: "application/octet-stream", name: "blob.bin" })).toBe("unsupported");
    });
});

describe("extractDocumentAttachment", () => {
    it("passes bounded, no-OCR parser settings and returns normalized text", async () => {
        const seen: unknown[] = [];
        const attachment = await extractDocumentAttachment(
            pickedFile("report.pdf", "application/pdf"),
            async (_bytes, config) => {
                seen.push(config);
                return { toText: () => " first\r\nsecond\0 " };
            },
        );

        expect(attachment).toEqual({ kind: "text", name: "report.pdf", text: "first\nsecond" });
        expect(seen).toEqual([
            expect.objectContaining({
                fileType: "pdf",
                ocr: false,
                extractAttachments: false,
                includeRawContent: false,
                pdfWorkerSrc: expect.any(String),
                decompressionLimits: { maxUncompressedBytes: 64 * 1024 * 1024, maxZipEntries: 4_096 },
            }),
        ]);
    });

    it("marks extracted text truncation honestly", async () => {
        const attachment = await extractDocumentAttachment(
            pickedFile("large.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
            async () => ({ toText: () => "x".repeat(MAX_DOCUMENT_TEXT_CHARS + 5) }),
        );
        expect(attachment.text).toHaveLength(
            MAX_DOCUMENT_TEXT_CHARS +
                `\n\n[extracted text truncated at ${MAX_DOCUMENT_TEXT_CHARS} characters]`.length,
        );
        expect(attachment.text).toContain("[extracted text truncated at 1000000 characters]");
    });

    it("refuses documents with no extractable text", async () => {
        await expect(
            extractDocumentAttachment(pickedFile("empty.xlsx", "application/octet-stream"), async () => ({
                toText: () => " \n\0 ",
            })),
        ).rejects.toThrow("contains no extractable text");
    });

    it("extracts real docx, xlsx, and pptx packages through the lazy browser parser", async () => {
        const packages: Array<{
            name: string;
            mime: string;
            expected: string;
            entries: Record<string, string>;
        }> = [
            {
                name: "sample.docx",
                mime: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                expected: "hello from Word",
                entries: {
                    "[Content_Types].xml": '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
                    "word/document.xml": '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>hello from Word</w:t></w:r></w:p></w:body></w:document>',
                },
            },
            {
                name: "sample.xlsx",
                mime: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                expected: "hello from Excel",
                entries: {
                    "[Content_Types].xml": '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>',
                    "xl/workbook.xml": '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>',
                    "xl/_rels/workbook.xml.rels": '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>',
                    "xl/worksheets/sheet1.xml": '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>hello from Excel</t></is></c></row></sheetData></worksheet>',
                },
            },
            {
                name: "sample.pptx",
                mime: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                expected: "hello from PowerPoint",
                entries: {
                    "[Content_Types].xml": '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/><Override PartName="/ppt/slides/slide1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/></Types>',
                    "ppt/presentation.xml": '<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"/>',
                    "ppt/slides/slide1.xml": '<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><p:cSld><p:spTree><p:sp><p:nvSpPr><p:nvPr><p:ph type="title"/></p:nvPr></p:nvSpPr><p:txBody><a:p><a:r><a:t>hello from PowerPoint</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>',
                },
            },
        ];

        for (const sample of packages) {
            const attachment = await extractDocumentAttachment(
                pickedFile(sample.name, sample.mime, ooxml(sample.entries)),
            );
            expect(attachment.text).toBe(sample.expected);
        }
    });
});

describe("buildOutgoing", () => {
    const img: Attachment = { kind: "image", name: "shot.png", mimeType: "image/png", data: "QUJD" };
    const txt: Attachment = { kind: "text", name: "notes.txt", text: "hello" };

    it("inlines text files into the message and leaves images out of the text", () => {
        const { message, images } = buildOutgoing("look", [txt]);
        expect(message).toBe("look\n\n--- attached: notes.txt ---\nhello\n--- end notes.txt ---");
        expect(images).toEqual([]);
    });

    it("sends images in images[] and keeps base64 OUT of the message (INV-10)", () => {
        const { message, images } = buildOutgoing("describe this", [img]);
        expect(images).toEqual([{ name: "shot.png", mimeType: "image/png", data: "QUJD" }]);
        // Only a byte-free note in the durable text — never the base64 payload.
        expect(message).toBe("describe this\n\n[attached image: shot.png]");
        expect(message).not.toContain("QUJD");
    });

    it("combines a body, text files, and images", () => {
        const { message, images } = buildOutgoing("do it", [txt, img]);
        expect(message).toBe(
            "do it\n\n--- attached: notes.txt ---\nhello\n--- end notes.txt ---\n\n[attached image: shot.png]",
        );
        expect(images).toHaveLength(1);
    });

    it("an image-only message still carries a non-empty (byte-free) text note", () => {
        const { message, images } = buildOutgoing("", [img]);
        expect(message).toBe("[attached image: shot.png]");
        expect(message).not.toContain("QUJD");
        expect(images).toHaveLength(1);
    });
});
