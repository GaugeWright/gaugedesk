// Every class the stylesheet styles is a class something renders.
//
//   node scripts/check-css-renderers.mjs           check
//   node scripts/check-css-renderers.mjs --list    print the reference count per class
//
// A stylesheet with no renderer is invisible to every other check here. The
// brand-token scan reads it, the typecheck compiles around it, vite bundles it,
// and the minifier ships it to a customer — none of them ask whether anything
// draws it. That is how `MGMT-ENV-1 remove legacy management renderers` deleted
// a set of components and left 31 `.console-*` classes and `.status-badge`
// behind, in 82 rules that shipped in every embed bundle for months, and how a
// contrast audit came to measure ratios on surfaces nobody can see.
//
// The rule is deliberately weak: a class counts as rendered if its name appears
// as a whole word anywhere in the scanned source. That admits a mention in a
// comment or a test, which is the right trade — this exists to catch a class
// with *no* trace of a renderer, not to police how one is applied. Anything
// stricter would fail on `classList={{ … }}`, on a name composed from a
// variable, or on markup a dependency emits.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const STYLESHEET = "web/packages/workbench-ui/src/styles.css";

// Where a renderer could live. The embed and the enterprise composition draw the
// same stylesheet, so both are in scope.
const SOURCE_ROOTS = ["web/packages", "web/apps", "ee/web/apps", "ee/web/packages"];
// node_modules is skipped in the first pass and consulted in the second, below.
const SOURCE_EXTENSIONS = new Set([".ts", ".tsx", ".js", ".jsx", ".html", ".rs", ".md"]);
const SKIP_DIRECTORIES = new Set([
  "dist", "dist-embed", "dist-open", "dist-static-edge",
  "dist-enterprise-workbench", "target", "assets", ".git", "generated",
]);

/// Classes with no literal renderer, and why that is expected rather than rot.
///
/// Every entry needs a reason. "It is probably used somewhere" is not one — that
/// is the belief this check exists to replace. Prefer deleting the rule.
///
/// It is empty, and that is the point: every class this stylesheet styles has a
/// renderer today. A name composed at runtime still passes, because composition
/// here keeps a literal prefix — `class={`markdown-body${…}`}`, `class={`panel
/// ${props.cls}`}` — and the prefix is what the stylesheet selects on. An entry
/// becomes necessary only if that stops being true.
const EXPECTED_WITHOUT_RENDERER = new Map([]);

function* sourceFiles(dir) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const at = path.join(dir, entry.name);
    // `withFileTypes` describes the link, not what it points at. A worktree keeps its
    // own `node_modules` as a farm of links into the primary checkout (AGENTS.md), so
    // the package directory `highlight.js` arrives here as a non-directory entry whose
    // extension is `.js` — and reading it threw EISDIR, failing the whole gate on the
    // repository's own documented layout rather than on anything about the CSS.
    const isDirectory = entry.isDirectory()
      || (entry.isSymbolicLink() && statType(at) === "directory");
    if (isDirectory) {
      if (!SKIP_DIRECTORIES.has(entry.name)) yield* sourceFiles(at);
    } else if (SOURCE_EXTENSIONS.has(path.extname(entry.name)) && statType(at) === "file") {
      yield at;
    }
  }
}

/** What a path really is, following links. A dangling link is neither. */
function statType(at) {
  try {
    const stat = fs.statSync(at);
    return stat.isDirectory() ? "directory" : stat.isFile() ? "file" : "other";
  } catch {
    return "other";
  }
}

/// Class names the stylesheet styles.
///
/// Reads selectors only: a `.foo` inside a declaration value is not a selector,
/// and neither is one inside a comment.
export function stylesheetClasses(css) {
  const withoutComments = css.replace(/\/\*[\s\S]*?\*\//gu, "");
  const classes = new Set();
  // Walk rule heads: everything from the start of a rule to its `{`. The
  // selector is the *second* group — the first is the delimiter that ended the
  // previous rule. Binding the wrong one made this return nothing at all, and a
  // check that finds nothing passes just as quietly as one that finds nothing
  // wrong. The test below reintroduces a known-dead class for exactly that
  // reason.
  for (const [, , head] of withoutComments.matchAll(/(^|[};])\s*([^{};]*?)\s*\{/gmu)) {
    if (!head || head.trimStart().startsWith("@")) continue;
    for (const [, name] of head.matchAll(/\.(-?[A-Za-z_][\w-]*)/gu)) classes.add(name);
  }
  return classes;
}

const css = fs.readFileSync(path.join(root, STYLESHEET), "utf8");
const classes = [...stylesheetClasses(css)].sort();

// One pass over the sources, counting whole-word hits for every class at once —
// a grep per class over this tree is minutes, this is under a second.
const counts = new Map(classes.map((name) => [name, 0]));
const wordChar = /[\w-]/u;
for (const scanRoot of SOURCE_ROOTS) {
  for (const file of sourceFiles(path.join(root, scanRoot))) {
    if (path.relative(root, file) === STYLESHEET) continue;
    const text = fs.readFileSync(file, "utf8");
    for (const name of classes) {
      let from = 0;
      for (;;) {
        const at = text.indexOf(name, from);
        if (at === -1) break;
        const before = at === 0 ? "" : text[at - 1];
        const after = text[at + name.length] ?? "";
        if (!wordChar.test(before) && !wordChar.test(after)) {
          counts.set(name, counts.get(name) + 1);
          break;
        }
        from = at + 1;
      }
    }
  }
}

// A dependency that emits its own markup is a renderer too — the diff viewer
// ships `.diff-tailwindcss-wrapper` and this stylesheet dresses it. Only the
// classes still unaccounted for are looked up there, because sweeping every
// dependency for 583 names costs minutes and answers almost nothing.
const unmatched = classes.filter((name) => counts.get(name) === 0);
const missingModules = [];
if (unmatched.length > 0) {
  for (const modules of ["web/node_modules", "ee/web/node_modules"]) {
    const at = path.join(root, modules);
    if (!fs.existsSync(at)) {
      // Only the workbench tree is required: it holds the dependencies whose
      // markup this stylesheet dresses. ee/web is an app tree installed later in
      // scripts/check.sh than this runs, so demanding it here would fail every
      // CI run on ordering rather than on anything about the CSS.
      if (modules === "web/node_modules") missingModules.push(modules);
      continue;
    }
    for (const file of sourceFiles(at)) {
      const text = fs.readFileSync(file, "utf8");
      for (const name of unmatched) {
        if (counts.get(name) === 0 && text.includes(name)) counts.set(name, 1);
      }
    }
  }
}

// Without the dependencies there is no way to tell a dead class from one a
// dependency renders, and answering anyway would report `.diff-style-root` —
// which @git-diff-view/solid draws — as rot. Refuse instead. `scripts/check.sh`
// installs before it gets here; a direct run on a fresh checkout does not.
if (missingModules.length > 0 && unmatched.some((name) => counts.get(name) === 0)) {
  console.error(
    `CSS renderer check CANNOT ANSWER: ${missingModules.join(" and ")} is not `
      + "installed, so a class a dependency renders is indistinguishable from one "
      + "nothing renders. Run `npm --prefix web ci` (scripts/check.sh does this "
      + "for you).",
  );
  process.exit(1);
}

if (process.argv.includes("--list")) {
  for (const name of classes) console.log(`${String(counts.get(name)).padStart(4)}  ${name}`);
  process.exit(0);
}

const orphans = classes.filter((name) => counts.get(name) === 0);
const unexpected = orphans.filter((name) => !EXPECTED_WITHOUT_RENDERER.has(name));
const staleAllowances = [...EXPECTED_WITHOUT_RENDERER.keys()]
  .filter((name) => !orphans.includes(name));

const failures = [];
for (const name of unexpected) {
  failures.push(
    `.${name} is styled but nothing renders it. Delete the rule, or add it to `
      + "EXPECTED_WITHOUT_RENDERER with the reason its name never appears literally.",
  );
}
for (const name of staleAllowances) {
  failures.push(
    `.${name} is allowed to have no renderer, but one exists now. Remove the `
      + "allowance so the next class to lose its renderer is still caught.",
  );
}

if (failures.length > 0) {
  console.error("CSS renderer check FAILED:");
  for (const failure of failures) console.error(`  - ${failure}`);
  process.exit(1);
}

console.log(
  `CSS renderer check passed: ${classes.length} classes styled, all rendered`
    + `${EXPECTED_WITHOUT_RENDERER.size ? ` (${EXPECTED_WITHOUT_RENDERER.size} allowed without)` : ""}.`,
);
