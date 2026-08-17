// GENERATED FILE — do not edit.
//
// Owned by tools/palette/repo-check.mjs in the GaugeWright repository and
// rendered into each consuming repository by tools/palette.mjs. Edit it there
// and re-render; a local edit fails this repository's gate.
//
// This check is deliberately self-contained: it verifies the vendored brand
// tokens against a digest carried in the file itself, so a public repository
// can run it without access to the private company repository. Whether that
// digest is still the current one is checked from GaugeWright, which owns it.
//
// It also sweeps the source trees for a re-introduced copy of a brand value.
// The digest alone would not have caught the failure that prompted this: the
// vendored file was fine, and a *second* declaration elsewhere was what
// actually reached the screen. A colour that matches the palette and is not
// coming from the palette is the defect, wherever it is written.

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const EXPECTED_DIGEST = "181317932e20bf8414ea53e4a35e62c9fe9b8504e3b7ba26e7c3a039c84d4dff";
const TOKENS_PATH = "web/packages/workbench-ui/src/brand-tokens.css";
const SCAN_ROOTS = ["web/packages","web/apps","web/lab","ee/web"];
// "file" — TOKENS_PATH is wholly generated. "block" — the tokens are a rendered
// region inside a stylesheet this repository maintains, which is what a site
// serving raw CSS needs, since an @import there would be a render-blocking
// second request. The distinction matters twice below: where the declarations
// are read from, and how much of TOKENS_PATH the hex scan may skip.
const TOKENS_MODE = "file";
const BLOCK_BEGIN = "/* BEGIN GAUGEWRIGHT BRAND TOKENS";
const BLOCK_END = "/* END GAUGEWRIGHT BRAND TOKENS */";

// Build output, dependencies, and vendored fonts are not authored source; a
// value found there came from a build, not from someone typing it.
const SKIP_DIRECTORIES = new Set([
  "node_modules",
  "dist",
  "dist-embed",
  "dist-static-edge",
  "target",
  "assets",
  ".git",
]);
const SOURCE_EXTENSIONS = new Set([".css", ".ts", ".tsx", ".js", ".jsx", ".html", ".svelte"]);

// A file that declares itself a projection is exempt: flattening the tokens to
// literal values is the entire job of one (the published embed theme is a file
// customers copy and edit, so it cannot hand them a chain of var() references).
// The exemption is a marker in the file rather than a list here, so it cannot
// name a path that has since moved.
const PROJECTION_MARKER = "@gw-projection";

const root = path.resolve(process.argv[2] ?? process.cwd());
const failures = [];
const fail = (message) => failures.push(message);

// --- the vendored tokens ----------------------------------------------------

const tokensFile = path.join(root, TOKENS_PATH);
let canonicalValues = new Set();
// The span of TOKENS_PATH the tokens occupy, so the scan below can skip exactly
// that and no more. In block mode TOKENS_PATH is a stylesheet this repository
// writes; exempting the whole of it from the hex scan would excuse every rule in
// it, which is most of what the scan exists to read.
let tokensRegion = null;

if (!fs.existsSync(tokensFile)) {
  fail(
    `${TOKENS_PATH} is missing. This repository vendors the GaugeWright brand tokens; `
      + "render them from the GaugeWright repository with `node tools/palette.mjs --write`.",
  );
} else {
  const contents = fs.readFileSync(tokensFile, "utf8").replace(/\r\n/gu, "\n");
  let tokens = contents;

  if (TOKENS_MODE === "block") {
    const from = contents.indexOf(BLOCK_BEGIN);
    const to = contents.indexOf(BLOCK_END);
    if (from === -1 || to < from) {
      fail(
        `${TOKENS_PATH} does not carry a \`${BLOCK_BEGIN} … ${BLOCK_END}\` pair. `
          + "The brand tokens are rendered between those markers.",
      );
      tokens = "";
    } else {
      tokens = contents.slice(from, to + BLOCK_END.length);
      tokensRegion = [from, to + BLOCK_END.length];
    }
  }

  const start = tokens.indexOf(":root, :host {");
  const end = tokens.indexOf("\n}", start);

  if (tokens === "") {
    // Already reported above.
  } else if (start === -1 || end === -1) {
    fail(`${TOKENS_PATH} does not contain a well-formed \`:root, :host\` block.`);
  } else {
    const declarations = tokens.slice(tokens.indexOf("\n", start) + 1, end);
    const actual = crypto.createHash("sha256").update(declarations, "utf8").digest("hex");
    const declared = /sha256:([0-9a-f]{64})/u.exec(tokens)?.[1];

    if (actual !== EXPECTED_DIGEST) {
      fail(
        `${TOKENS_PATH} is stale or locally edited (sha256:${actual.slice(0, 12)}…, `
          + `expected sha256:${EXPECTED_DIGEST.slice(0, 12)}…). It is owned by the GaugeWright `
          + "repository; re-render it there rather than editing it here.",
      );
    } else if (declared !== actual) {
      fail(`${TOKENS_PATH} carries sha256:${declared?.slice(0, 12)}…, which does not match its own body.`);
    }

    for (const [, value] of declarations.matchAll(/^\s*--[\w-]+:\s*(#[0-9a-fA-F]{3,8})\s*;/gmu)) {
      canonicalValues.add(value.toLowerCase());
    }
  }
}

// --- no second copy ---------------------------------------------------------

function* sourceFiles(dir) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRECTORIES.has(entry.name)) yield* sourceFiles(path.join(dir, entry.name));
    } else if (SOURCE_EXTENSIONS.has(path.extname(entry.name))) {
      yield path.join(dir, entry.name);
    }
  }
}

if (canonicalValues.size > 0) {
  for (const scanRoot of SCAN_ROOTS) {
    for (const file of sourceFiles(path.join(root, scanRoot))) {
      const isTokensFile = path.relative(root, file) === TOKENS_PATH;
      // A wholly generated token file is skipped; a stylesheet that merely
      // *contains* the rendered block keeps every line outside it in scope.
      if (isTokensFile && tokensRegion === null) continue;
      let contents = fs.readFileSync(file, "utf8");
      if (contents.slice(0, 1000).includes(PROJECTION_MARKER)) continue;
      if (isTokensFile) {
        // Blank the region rather than cut it, so reported line numbers still
        // point at the line a person would open.
        const [from, to] = tokensRegion;
        contents = contents.slice(0, from)
          + contents.slice(from, to).replace(/[^\n]/gu, " ")
          + contents.slice(to);
      }
      const lines = contents.split("\n");
      for (const [index, line] of lines.entries()) {
        for (const [, hex] of line.matchAll(/(#[0-9a-fA-F]{3,8})\b/gu)) {
          if (!canonicalValues.has(hex.toLowerCase())) continue;
          fail(
            `${path.relative(root, file)}:${index + 1} writes ${hex}, which is a GaugeWright brand `
              + `value. Consume it through ${isTokensFile ? "the brand tokens above" : TOKENS_PATH} `
              + "instead — a value typed twice is a value that will disagree with itself.",
          );
        }
      }
    }
  }
}

// --- report -----------------------------------------------------------------

if (failures.length > 0) {
  console.error("brand token check FAILED:");
  for (const failure of failures) console.error(`  - ${failure}`);
  process.exit(1);
}

console.log(`brand token check passed at sha256:${EXPECTED_DIGEST.slice(0, 12)}…`);
