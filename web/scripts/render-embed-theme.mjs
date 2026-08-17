// Renders and verifies the published embed theme.
//
//   node web/scripts/render-embed-theme.mjs --check    verify (default)
//   node web/scripts/render-embed-theme.mjs --write    re-render
//
// `packages/gw-embed/public/embed.css` is what a customer downloads, copies into
// their site, and edits. It is a **projection**: every value in it is resolved
// from the shadow-root theme bridge in `packages/gw-embed/src/elements.tsx`,
// which in turn takes its defaults from `brand-tokens.css` — rendered from the
// company palette in the GaugeWright repository.
//
// It has to be flat. A customer cannot be handed
// `var(--gw-bg, var(--gw-default-bg))`; the file exists to show them the value
// they are about to change. So the chain is resolved here rather than in the
// file, and the file is generated rather than maintained. Nothing else in this
// repository may write a brand value by hand — see scripts/check-brand-tokens.mjs.
//
// The prose is authored, the values and the coverage are enforced. LAYOUT below
// carries the grouping and the comments a person wrote; a public token in the
// bridge that LAYOUT does not mention, or the reverse, fails. That is the part
// that actually rots: the previous check compared the file to the bridge with a
// regex, which is why the two agreed perfectly on a palette that had been
// superseded — they were consistent with each other and with nothing else.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const webRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const bridgeFile = path.join(webRoot, "packages/gw-embed/src/elements.tsx");
const tokensFile = path.join(webRoot, "packages/workbench-ui/src/brand-tokens.css");
const themeFile = path.join(webRoot, "packages/gw-embed/public/embed.css");

/// The published file's structure and prose. Order here is order in the file.
const LAYOUT = [
  {
    heading: "Main colors",
    tokens: [
      ["--gw-bg", "Panel background and composer input"],
      ["--gw-panel", "Raised controls and menus"],
      ["--gw-edge", "Borders and dividers"],
      ["--gw-ink", "Primary text"],
      ["--gw-muted", "Secondary text"],
      ["--gw-navy", "GaugeWright brand detail"],
    ],
  },
  {
    heading: "Actions and status",
    tokens: [
      ["--gw-accent"],
      ["--gw-accent-strong"],
      ["--gw-accent-hover"],
      ["--gw-on-accent", "Text and icons on an accent fill"],
      ["--gw-warn"],
      ["--gw-danger"],
    ],
  },
  {
    heading: "Panel frame",
    tokens: [
      ["--gw-panel-width"],
      ["--gw-panel-padding"],
      ["--gw-panel-border"],
      ["--gw-panel-radius"],
      ["--gw-panel-shadow"],
    ],
  },
  {
    heading: "Typography",
    note: `  /* Two faces (GaugeWright DR-0072), split on operate-vs-read.
     --gw-font-chrome is most of a panel — controls, labels, headings;
     --gw-font-prose is the face the transcript is set in. Both are the
     published customization surface, so a host that overrides only one still
     gets a coherent panel. */`,
    tokens: [
      ["--gw-font-chrome"],
      ["--gw-font-prose"],
      ["--gw-font-mono"],
      ["--gw-font-size-label"],
      ["--gw-font-size-small"],
      ["--gw-font-size-ui"],
      ["--gw-font-size-body"],
      ["--gw-font-size-title"],
      ["--gw-color-scheme"],
    ],
  },
];

/// The `--gw-default-*` values, read from the vendored token file.
function readDefaults() {
  const css = fs.readFileSync(tokensFile, "utf8");
  const defaults = new Map();
  for (const [, name, value] of css.matchAll(/^\s*(--gw-default-[\w-]+):\s*([^;]+);/gmu)) {
    defaults.set(name, value.trim());
  }
  if (defaults.size === 0) throw new Error(`${tokensFile} declares no --gw-default-* tokens`);
  return defaults;
}

/// Split a `var(…)` chain into the token names it tries, in order, and the
/// literal it falls back to. `var(--gw-danger, var(--gw-bad, var(--gw-default-danger)))`
/// gives names [--gw-danger, --gw-bad, --gw-default-danger] and no literal;
/// `var(--gw-panel-width, 100%)` gives [--gw-panel-width] and "100%".
///
/// This walks the parentheses rather than splitting on the last comma: a
/// fallback is routinely a whole value with commas of its own
/// (`0 14px 36px rgb(0 0 0 / 22%)`, a font stack), and a naive split takes the
/// wrong half of one.
export function parseChain(value) {
  const names = [];
  let rest = value.trim();

  for (;;) {
    if (!rest.startsWith("var(")) return { names, literal: names.length ? rest : null };

    let depth = 0;
    let comma = -1;
    let close = -1;
    for (let i = 3; i < rest.length; i += 1) {
      const char = rest[i];
      if (char === "(") depth += 1;
      else if (char === ")") {
        depth -= 1;
        if (depth === 0) {
          close = i;
          break;
        }
      } else if (char === "," && depth === 1 && comma === -1) comma = i;
    }
    if (close === -1) throw new Error(`unbalanced var() in ${value}`);

    names.push(rest.slice(4, comma === -1 ? close : comma).trim());
    if (comma === -1) return { names, literal: null };
    rest = rest.slice(comma + 1, close).trim();
  }
}

/// Every public token the bridge exposes, with the value a panel uses when the
/// host page sets nothing.
///
/// The whole theme template is scanned, not just `:host`: the frame tokens
/// (`--gw-panel-padding` and friends) are declared on the panel rule below it,
/// and a reader that stopped at the closing brace would publish a file missing
/// six of the knobs a customer is most likely to reach for.
export function readBridge(source, defaults) {
  const open = source.indexOf("const embedThemeCss");
  if (open === -1) throw new Error("no embedThemeCss template in the theme bridge");
  const template = source.slice(open, source.indexOf("\n`;", open));

  // A default may be written in terms of an internal alias — `--gw-panel-border`
  // falls back to `1px solid var(--edge)`. The published file has to name the
  // public token there, or it would tell a customer to set something that does
  // not exist outside the shadow root.
  const publicFor = new Map();
  for (const [, internal, exposed] of template.matchAll(
    /^\s*(--[\w-]+):\s*var\((--gw-[\w-]+)/gmu,
  )) {
    publicFor.set(internal, exposed);
  }

  const exposed = new Map();
  for (const [, value] of template.matchAll(
    /^\s*[\w-]+:\s*(var\(--gw-[^;]+?)(?:\s*!important)?;$/gmu,
  )) {
    // The height and min-height defaults are per element, not one value, so
    // they are rendered into the per-element blocks below instead.
    if (value.includes("${defaultMinHeight}") || value.includes("${defaultHeight}")) continue;

    const { names, literal } = parseChain(value);
    const publicName = names[0];
    const terminal = names.at(-1);
    const resolved = literal ?? defaults.get(terminal);
    if (resolved === undefined) {
      throw new Error(`${publicName} bottoms out in ${terminal}, which brand-tokens.css does not define`);
    }

    const spec = {
      value: resolved.replace(
        /var\((--[\w-]+)\)/gu,
        (whole, name) => (publicFor.has(name) ? `var(${publicFor.get(name)})` : whole),
      ),
      legacy: names.slice(1).filter((name) => !name.startsWith("--gw-default-")),
    };

    // One public token can be reached through more than one internal alias, and
    // the aliases need not try the legacy names in the same order — `--serif`
    // prefers `--gw-serif` where `--font-chrome` prefers `--gw-font`. What the
    // file publishes is the union in first-seen order; last-declaration-wins
    // would drop a name a customer still has set.
    const already = exposed.get(publicName);
    if (already !== undefined) {
      if (already.value !== spec.value) {
        throw new Error(
          `${publicName} resolves to ${already.value} through one alias and ${spec.value} `
            + "through another, so there is no single value to publish",
        );
      }
      for (const old of spec.legacy) {
        if (!already.legacy.includes(old)) already.legacy.push(old);
      }
      continue;
    }
    exposed.set(publicName, spec);
  }
  return exposed;
}

/// The per-element frame defaults (height and minimum height), read from the
/// element classes so the published file cannot claim a value the code does
/// not use. Every panel class declares both explicitly.
export function readFrames(source) {
  const tags = new Map(
    [...source.matchAll(/customElements\.define\("(gw-[\w-]+)",\s*(\w+)\)/gu)].map((m) => [m[2], m[1]]),
  );
  const read = (property) => {
    const values = new Map();
    const pattern = new RegExp(
      `export class (\\w+) extends GwPanelElement \\{[\\s\\S]*?${property}\\s*=\\s*"([^"]+)"`,
      "gu",
    );
    for (const [, className, value] of source.matchAll(pattern)) {
      const tag = tags.get(className);
      if (tag) values.set(tag, value);
    }
    return values;
  };
  const minHeights = read("defaultMinHeight");
  const heights = read("defaultHeight");
  if (minHeights.size === 0) throw new Error("no panel element min-heights found");
  for (const tag of minHeights.keys()) {
    if (!heights.has(tag)) {
      throw new Error(`${tag} declares no defaultHeight — every panel class must state both frame defaults`);
    }
  }
  const frames = new Map();
  for (const [tag, minHeight] of minHeights) {
    frames.set(tag, { height: heights.get(tag), minHeight });
  }
  return frames;
}

function render(exposed, frames) {
  const covered = new Set(LAYOUT.flatMap((group) => group.tokens.map(([name]) => name)));
  for (const name of exposed.keys()) {
    if (!covered.has(name)) {
      throw new Error(
        `the theme bridge exposes ${name}, which this renderer's LAYOUT does not publish. `
          + "Add it to a group — a public token missing from embed.css is a knob no customer can find.",
      );
    }
  }
  for (const name of covered) {
    if (!exposed.has(name)) {
      throw new Error(
        `LAYOUT publishes ${name}, which the theme bridge does not expose. `
          + "Remove it — embed.css must not advertise a token that does nothing.",
      );
    }
  }

  const width = 34;
  const groups = LAYOUT.map((group) => {
    const lines = [`  /* ${group.heading} */`];
    if (group.note) lines.push(group.note);
    for (const [name, comment] of group.tokens) {
      const declaration = `  ${name}: ${exposed.get(name).value};`;
      lines.push(comment ? `${declaration.padEnd(width)} /* ${comment} */` : declaration);
    }
    return lines.join("\n");
  }).join("\n\n");

  // Legacy names, grouped so the reason they exist is stated once.
  const renamed = [...exposed]
    .filter(([, spec]) => spec.legacy.length > 0)
    .flatMap(([name, spec]) => spec.legacy.map((old) => `${old} is now ${name}`));

  const frameBlocks = [...frames]
    .reduce((blocks, [tag, frame]) => {
      const existing = blocks.find(
        (block) => block.frame.height === frame.height && block.frame.minHeight === frame.minHeight,
      );
      if (existing) existing.tags.push(tag);
      else blocks.push({ frame, tags: [tag] });
      return blocks;
    }, [])
    .map(({ tags, frame }) =>
      `${tags.join(",\n")} {\n  --gw-panel-height: ${frame.height};\n  --gw-panel-min-height: ${frame.minHeight};\n}`)
    .join("\n\n");

  return `/**
 * GaugeDesk Embeddable Panels — optional editable theme
 *
 * The panels already include complete default styling. You do not need this
 * file to use them. Copy this file into your site only when you want to change
 * their appearance, then load your copy after the rest of your site CSS:
 *
 *   <link rel="stylesheet" href="/css/gaugedesk-embed.css">
 *
 * Change the values below; do not remove the \`--gw-\` prefixes. Variables set on
 * \`gw-session\` apply to every panel inside it. A value set directly on one panel
 * changes only that panel.
 *
 * Your copy is yours to edit. This original is generated (@gw-projection) from
 * the panel's own defaults, so it always states what a panel actually does when
 * you change nothing — re-download it to see the current values.
 *
 * Some tokens were renamed to match the GaugeWright palette. The former names
 * still work, so an older copy of this file keeps doing what it did:
${renamed.map((line) => ` *   ${line}`).join("\n")}
 */

gw-session {
${groups}
}

/* Each panel's frame out of the box. The chat has a definite height because its
   scroll behavior (send anchoring, jump-to-latest) lives in its own internal
   scroller; \`auto\` sizes a panel to its content. Edit these independently. */
${frameBlocks}

/**
 * Need one special exception?
 *
 * Every component exposes its outer frame as \`::part(panel)\`. More specific
 * names are also available: panel-chat, panel-viewer, panel-files, and
 * panel-chats. The GaugeDesk credit link is \`::part(attribution)\`.
 *
 * Uncomment and edit examples like these:
 *
 * gw-chat::part(panel) {
 *   box-shadow: none;
 * }
 *
 * gw-chat::part(attribution) {
 *   font-size: 12px;
 * }
 */
`;
}

/// The theme a current checkout should publish. Exported so the vitest suite can
/// assert on it without shelling out.
export function renderEmbedTheme() {
  const source = fs.readFileSync(bridgeFile, "utf8");
  return render(readBridge(source, readDefaults()), readFrames(source));
}

const invokedDirectly =
  process.argv[1] !== undefined
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (invokedDirectly) {
  const want = renderEmbedTheme();
  const have = fs.existsSync(themeFile) ? fs.readFileSync(themeFile, "utf8") : null;

  if (process.argv.includes("--write")) {
    if (have === want) {
      console.log("embed theme already current");
    } else {
      fs.writeFileSync(themeFile, want, "utf8");
      console.log(`embed theme rendered to ${path.relative(webRoot, themeFile)}`);
    }
  } else if (have !== want) {
    console.error(
      `embed theme check FAILED: ${path.relative(webRoot, themeFile)} is not what the panel `
        + "defaults render to. It is generated; run with --write rather than editing it.",
    );
    process.exit(1);
  } else {
    console.log("embed theme check passed");
  }
}
