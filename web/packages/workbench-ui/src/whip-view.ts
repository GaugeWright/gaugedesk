/**
 * The instance view model a `.whip` file's tabs render
 * (`whipplescript.instance_view.v0`).
 *
 * WhippleScript owns this projection and GaugeDesk renders it — ADR 0080 plane
 * 3: the runtime emits ordered labeled happenings, and this side holds pointers
 * rather than copies of the tool-effect record. So these types describe a
 * payload we receive; nothing here derives runtime state, and nothing here may
 * become a second store of it.
 *
 * The shape is `docs/json-reference.md` in the whipplescript repository, under
 * "Instance View". Two fields carry most of the meaning:
 *
 * - An effect entry with `absent: true` is a static effect the firing **never
 *   requested** — a `case` arm not taken, a `contended` branch on a lease that
 *   was held. It has no row in the runtime at all, which is why no event log can
 *   show it and why this view exists.
 * - `unattributedEffects` is the projection's self-check. Non-empty means it is
 *   keyed differently than the run was (a branched or restored instance), so the
 *   absences cannot be trusted — and the UI must say so rather than drawing
 *   confident ghosts.
 *
 * Payload bytes never cross this boundary: identifiers, statuses, reasons and
 * spans only. That is a property of the projection, not a setting here.
 */

export const INSTANCE_VIEW_SCHEMA = "whipplescript.instance_view.v0";

export interface WhipRun {
    readonly runId: string;
    readonly provider: string;
    readonly workerId: string;
    readonly status: string;
    readonly startedAt: string;
    readonly completedAt: string | null;
}

/** One static effect of a rule, in one firing. */
export interface WhipEffectSlot {
    /** The snapshot's node name (`turn`, `effect4`). Machinery: an effect id is
     *  a hash over it, and it is what a slot is joined on. Not a name a reader
     *  was ever shown — see {@link nodeTitle}. */
    readonly node: string;
    readonly kind: string;
    /** The source keyword the author wrote: `tell`, `exec`, `timer`, or a
     *  construct's own keyword. Not derivable from `kind` — see
     *  {@link nodeTitle}. */
    readonly verb: string;
    /** The author's own name for this effect, or `null` when they gave none. */
    readonly label: string | null;
    readonly binding: string | null;
    /** `"<binding>:<predicate>"` when the effect sits in an `after` arm. */
    readonly arm: string | null;
    readonly effectId?: string;
    readonly status?: string;
    readonly blockReason?: string | null;
    readonly runs?: readonly WhipRun[];
    /** No runtime row exists. Not a status — the absence IS the observation. */
    readonly absent?: boolean;
    readonly predictedEffectId?: string;
}

export interface WhipFiring {
    readonly rule: string;
    /** The firing's durable identity. One firing emits a commit per `after`
     *  continuation, all sharing this, so a view keyed on the event would show
     *  one work item as several. */
    readonly identity: string;
    readonly commits: number;
    readonly programVersionId: string;
    readonly structureAvailable: boolean;
    readonly effects: readonly WhipEffectSlot[];
}

/** One schema a rule records, and the construct that wrote the `record`. */
export interface WhipRecordSource {
    readonly schema: string;
    /** `table_row` for a row of a declared `table`. */
    readonly construct: string;
}

export interface WhipStructureRule {
    readonly name: string;
    readonly whens: readonly string[];
    readonly effects: readonly {
        readonly node: string;
        readonly kind: string;
        readonly verb: string;
        readonly label: string | null;
        /** The binding as the snapshot wrote it, synthetic prefix included. The
         *  graph resolves every edge through it, which is why it is not the
         *  `label`. */
        readonly binding: string | null;
        /** `"<binding>:<predicate>"`, the edge this effect hangs off. */
        readonly arm?: string | null;
    }[];
    /** What this rule records, and which construct wrote it. A `table`
     *  declaration lowers to a rule, and this is the only thing that says so. */
    readonly records: readonly WhipRecordSource[];
}

export interface WhipStructureEdge {
    readonly producer: string;
    readonly fact: string;
    readonly consumer: string;
}

export interface WhipStructure {
    readonly available: boolean;
    readonly workflow?: string;
    readonly reason?: string;
    readonly rules: readonly WhipStructureRule[];
    readonly ruleEdges: readonly WhipStructureEdge[];
}

export interface WhipInstanceView {
    readonly instanceId: string;
    readonly status: string;
    readonly programVersionId: string;
    readonly structure: WhipStructure;
    readonly firings: readonly WhipFiring[];
    readonly absentTotal: number;
    readonly unattributedEffects: readonly string[];
    readonly programVersionsSeen: readonly string[];
}

/** `whipplescript.instance_view.v0` as the runtime serialises it. Read
 *  defensively: every field the desk draws is checked, and anything else is
 *  carried as-is. A newer runtime can add a field without breaking a tab. */
type V0 = Record<string, unknown>;
const str = (v: unknown, fallback = ""): string => (typeof v === "string" ? v : fallback);
const num = (v: unknown, fallback = 0): number => (typeof v === "number" ? v : fallback);
const arr = (v: unknown): readonly V0[] => (Array.isArray(v) ? (v as V0[]) : []);
const strs = (v: unknown): readonly string[] =>
    Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];

/** The `structure` member of a v0 view — or the bare structure a program has
 *  before any instance, which the runtime serialises in the same shape. */
export function structureFromV0(value: unknown): WhipStructure {
    const v = (value ?? {}) as V0;
    if (v.available !== true) {
        return { available: false, reason: str(v.reason, "structure unavailable"), rules: [], ruleEdges: [] };
    }
    const rules = arr(v.rules).map((rule) => {
        // v0 carries arms as a dependency list; the renderer wants each effect
        // to name the edge it hangs off, which is the same fact read the other
        // way round.
        const arms = new Map<string, string>();
        for (const dep of arr(rule.dependencies)) {
            arms.set(str(dep.downstream), `${str(dep.upstream)}:${str(dep.predicate)}`);
        }
        return {
            name: str(rule.name),
            whens: strs(rule.whens),
            effects: arr(rule.effects).map((effect) => ({
                node: str(effect.node),
                kind: str(effect.kind),
                // The kind is the fallback and it is deliberately a visible one:
                // this desk pins the runtime that fills these in, so a node
                // reading `tracker.release` where a verb belongs says the pin is
                // behind, rather than quietly inventing a word.
                verb: str(effect.verb, str(effect.kind)),
                label: typeof effect.label === "string" ? effect.label : null,
                binding: typeof effect.binding === "string" ? effect.binding : null,
                arm: arms.get(str(effect.node)) ?? null,
            })),
            records: arr(rule.records).map((source) => ({
                schema: str(source.schema),
                construct: str(source.construct),
            })),
        };
    });
    const ruleEdges = arr(v.rule_edges).map((edge) => ({
        producer: str(edge.producer),
        fact: str(edge.fact),
        consumer: str(edge.consumer),
    }));
    return { available: true, workflow: str(v.workflow), rules, ruleEdges };
}

function slotFromV0(v: V0): WhipEffectSlot {
    const base = {
        node: str(v.node),
        kind: str(v.kind),
        verb: str(v.verb, str(v.kind)),
        label: typeof v.label === "string" ? v.label : null,
        binding: typeof v.binding === "string" ? v.binding : null,
        arm: typeof v.arm === "string" ? v.arm : null,
    };
    if (v.absent === true) {
        return { ...base, absent: true, predictedEffectId: str(v.predicted_effect_id) };
    }
    return {
        ...base,
        effectId: str(v.effect_id),
        status: str(v.status, "unknown"),
        blockReason: typeof v.block_reason === "string" ? v.block_reason : null,
        runs: arr(v.runs).map((run) => ({
            runId: str(run.run_id),
            provider: str(run.provider),
            workerId: str(run.worker_id),
            status: str(run.status),
            startedAt: str(run.started_at),
            completedAt: typeof run.completed_at === "string" ? run.completed_at : null,
        })),
    };
}

export function instanceViewFromV0(value: unknown): WhipInstanceView {
    const v = (value ?? {}) as V0;
    const instance = (v.instance ?? {}) as V0;
    return {
        instanceId: str(instance.instance_id),
        status: str(instance.status, "unknown"),
        programVersionId: str(instance.program_version_id),
        structure: structureFromV0(v.structure),
        firings: arr(v.firings).map((firing) => ({
            rule: str(firing.rule),
            identity: str(firing.identity),
            commits: arr(firing.commits).length,
            programVersionId: str(firing.program_version_id),
            structureAvailable: firing.structure_available === true,
            effects: arr(firing.effects).map(slotFromV0),
        })),
        absentTotal: num(v.absent_total),
        unattributedEffects: strs(v.unattributed_effects),
        programVersionsSeen: strs(v.program_versions_seen),
    };
}

/** One of a project's programs, as the desk draws it. */
export interface WhipProgram {
    /** Where the program lives in the project, when it is a file there. The
     *  inbound gate is; an agent package a chat runs is not. */
    readonly path: string | null;
    readonly program: string;
    readonly chat: string | null;
    readonly structure: WhipStructure | null;
    readonly instances: readonly WhipInstanceView[];
}

export function programsFromV1(value: {
    readonly whips: readonly {
        readonly path: string | null;
        readonly program: string;
        readonly chat: string | null;
        readonly structure: unknown | null;
        readonly instances: readonly unknown[];
    }[];
}): readonly WhipProgram[] {
    return value.whips.map((whip) => ({
        path: whip.path,
        program: whip.program,
        chat: whip.chat,
        structure: whip.structure == null ? null : structureFromV0(whip.structure),
        instances: whip.instances.map(instanceViewFromV0),
    }));
}

/** The program a file is, among the project's programs — by path, which is
 *  what the file nav selected. */
export function programForPath(programs: readonly WhipProgram[], path: string): WhipProgram | undefined {
    const normalised = path.replace(/^\/+/u, "");
    return programs.find((program) => program.path != null && program.path.replace(/^\/+/u, "") === normalised);
}

/** Whether a workspace path is a whip program, and therefore gets the extra
 *  tabs. Extension-based on purpose: the file nav lists paths, and a program is
 *  a program before any instance of it exists. */
export function isWhipProgram(path: string | null | undefined): boolean {
    return typeof path === "string" && path.toLowerCase().endsWith(".whip");
}

/** A firing's one-line summary: how far it got, and what it never asked for. */
export function firingSummary(firing: WhipFiring): string {
    const ran = firing.effects.filter((effect) => !effect.absent).length;
    const absent = firing.effects.length - ran;
    const commits = `${firing.commits} commit${firing.commits === 1 ? "" : "s"}`;
    if (!firing.structureAvailable) return `${commits} · structure unavailable`;
    return absent > 0 ? `${commits} · ${ran} ran · ${absent} never requested` : `${commits} · ${ran} ran`;
}

/** The status word a slot shows. Absence is deliberately NOT spelled as a
 *  status: there is no row, and calling it one would put it on the same footing
 *  as `queued`, which is exactly the confusion this view exists to remove. */
export function slotLabel(slot: WhipEffectSlot): string {
    if (slot.absent) return "not requested";
    return slot.status ?? "unknown";
}

/** The parts of an effect a figure names it by. Both a static node and a firing
 *  slot carry them, so one set of helpers labels both pictures. */
export interface NamedEffect {
    readonly node: string;
    readonly kind: string;
    readonly verb: string;
    readonly label: string | null;
}

/** The kind's family — `tracker` of `tracker.release`.
 *
 *  A verb on its own is sometimes ambiguous: `renew` is a tracker's and a
 *  lease's both. The family is what a node shows when its author gave it no name
 *  to show instead. */
export function kindFamily(kind: string): string {
    const dot = kind.indexOf(".");
    return dot > 0 ? kind.slice(0, dot) : kind;
}

/**
 * What a node is CALLED in a figure: the verb its author wrote.
 *
 * Never the node id. `effect4` is a lowering position and `__then_plan` is a
 * reserved handle an author is refused if they spell it themselves — a picture
 * showing either is showing its reader the compiler's bookkeeping and asking
 * them to find their own program inside it. The id is still on the node, in
 * `data-node` and in the tooltip, for anyone who wants the join.
 */
export function nodeTitle(effect: NamedEffect): string {
    return effect.verb || effect.node;
}

/** The line under it: the author's own name where they gave one, the kind's
 *  family where they did not. Two `release` nodes in one rule are then told
 *  apart by position, which is what a graph is for. */
export function nodeSubtitle(effect: NamedEffect): string {
    return effect.label ?? kindFamily(effect.kind);
}

/**
 * The shortest handle that still identifies an effect in TEXT: the author's own
 * name where they gave one, the node id where they did not.
 *
 * Distinct from {@link nodeTitle}, which a FIGURE uses. A figure has position to
 * tell two `release` nodes apart, so it can afford to show the verb; a line of
 * notes and a 26px column header have no position, and two lines both reading
 * `release` cost a reader more than `effect8` does.
 */
export function effectHandle(effect: {
    readonly node: string;
    readonly label: string | null;
}): string {
    return effect.label ?? effect.node;
}

/** The machinery a figure leaves out, for the tooltip that carries it. */
export function nodeProvenance(effect: NamedEffect): string {
    return `${effect.node} — ${effect.kind}`;
}

/** How many characters a rule box's header line carries before it is elided.
 *
 *  A box is sized by its longest line and a `where` guard is unbounded:
 *  `incident-router`'s is 170 characters, which on its own makes that rule's box
 *  about eleven hundred pixels wide and pushes the rest of the figure sideways
 *  off the page. The untruncated text stays in the line's tooltip. */
export const HEADER_LINE_MAX = 44;

export interface HeaderLine {
    /** `when` or `where`, drawn in the dimmed keyword ink. */
    readonly keyword: string;
    readonly text: string;
    /** The untruncated text, when `text` was elided. `null` when it was not. */
    readonly full: string | null;
}

function elide(text: string, max: number): string {
    return text.length > max ? `${text.slice(0, max - 1).trimEnd()}…` : text;
}

/**
 * A rule's `when` clauses as the lines its box draws.
 *
 * A guard becomes its own line. `when` answers what triggers the rule and
 * `where` answers "and only if"; run together on one line, the trigger — the
 * short structural half a reader scans for — is the part that falls off the end
 * of the box, because the guard in front of it can be arbitrarily long.
 */
export function headerLines(whens: readonly string[]): readonly HeaderLine[] {
    const lines: HeaderLine[] = [];
    for (const when of whens) {
        // The snapshot writes `when <pattern> where <guard>`, so the first
        // occurrence is the separator. A pattern is a schema, an agent or a
        // resource read; none of them contains the word.
        const split = when.indexOf(" where ");
        const pattern = split < 0 ? when : when.slice(0, split);
        const guard = split < 0 ? null : when.slice(split + " where ".length);
        const shortPattern = elide(pattern, HEADER_LINE_MAX);
        lines.push({
            keyword: "when",
            text: shortPattern,
            full: shortPattern === pattern ? null : pattern,
        });
        if (guard !== null) {
            const shortGuard = elide(guard, HEADER_LINE_MAX);
            lines.push({
                keyword: "where",
                text: shortGuard,
                full: shortGuard === guard ? null : guard,
            });
        }
    }
    return lines;
}

/**
 * Whether a rule is a `table` declaration rather than behaviour someone wrote.
 *
 * A table lowers to a rule — `table_tickets`, `when started`, one `record` per
 * row — so from the rules alone the two are indistinguishable, and the coupling
 * figure gave a table of data a box the same size and weight as the rules that
 * act. In `gastown-lite` that is two boxes of four. The record sources are the
 * evidence: every `record` came from a declared table's row, and the rule does
 * nothing else at all.
 */
export function isTableRule(rule: {
    readonly effects: readonly unknown[];
    readonly records: readonly WhipRecordSource[];
}): boolean {
    return (
        rule.effects.length === 0 &&
        rule.records.length > 0 &&
        rule.records.every((source) => source.construct === "table_row")
    );
}

function count(n: number, noun: string): string {
    return `${n} ${noun}${n === 1 ? "" : "s"}`;
}

/**
 * The line beside a program's name: how much of it there is.
 *
 * Tables are counted apart from rules rather than with them. They lower to rules
 * and the figure now draws them as the data they are, so counting them as rules
 * would have the number disagree with the picture directly under it.
 */
export function structureSummary(structure: {
    readonly rules: readonly WhipStructureRule[];
    readonly ruleEdges: readonly unknown[];
}): string {
    const tables = structure.rules.filter(isTableRule).length;
    const parts = [
        count(structure.rules.length - tables, "rule"),
        count(structure.ruleEdges.length, "coupling"),
    ];
    if (tables > 0) parts.push(count(tables, "table"));
    return parts.join(" · ");
}

/** A table's own name. The `table_` prefix belongs to the lowering, not to the
 *  author who wrote `table tickets as Ticket [ … ]`. */
export function tableName(rule: { readonly name: string }): string {
    return rule.name.startsWith("table_") ? rule.name.slice("table_".length) : rule.name;
}

/** Which of the five tabs a `.whip` file offers, in order. A non-whip file keeps
 *  the three it always had. */
export function tabsForPath(path: string | null | undefined): readonly string[] {
    return isWhipProgram(path)
        ? ["view", "structure", "instances", "edit", "diff"]
        : ["view", "edit", "diff"];
}

/** One running program in a project, for the Project Home rollup. */
export interface ProjectWhip {
    readonly path: string;
    readonly workflow: string;
    readonly instanceId: string;
    readonly status: string;
    /** Effects the runtime is holding back, by typed reason. */
    readonly blocked: number;
    /** Static effects no firing ever asked for. */
    readonly neverRequested: number;
}

/** Roll one instance view up into a project-level row. Derived rather than
 *  reported separately, so the list and the file's Instances tab can never
 *  disagree about the same instance. */
export function projectWhipFor(path: string, view: WhipInstanceView): ProjectWhip {
    const effects = view.firings.flatMap((firing) => firing.effects);
    return {
        path,
        workflow: view.structure.workflow ?? "unknown",
        instanceId: view.instanceId,
        status: view.status,
        blocked: effects.filter((effect) => (effect.status ?? "").startsWith("blocked")).length,
        neverRequested: effects.filter((effect) => effect.absent).length,
    };
}

/** A node placed for drawing: its column is how far down the `after` chain it
 *  sits, its row its order within that column. */
export interface DagNode {
    readonly node: string;
    readonly kind: string;
    readonly depth: number;
    readonly row: number;
    /** The node this one waits on, and on what outcome. */
    readonly upstream: string | null;
    readonly predicate: string | null;
}

/**
 * Lay effects out as the dependency graph they are.
 *
 * The `arm` carries `"<binding>:<predicate>"`, so an effect's upstream is the
 * effect BOUND to that binding — which is what makes this a real graph rather
 * than a list in graph clothing. Depth is the length of the `after` chain, so
 * the drawing reads left to right in the order the runtime can reach them.
 *
 * Cycles cannot occur (an `after` names an earlier binding), but a missing
 * upstream can — a snapshot from a newer compiler — and that node simply roots
 * at depth 0 rather than disappearing.
 */
export function layoutDag(
    effects: readonly { readonly node: string; readonly kind: string; readonly arm?: string | null; readonly binding?: string | null }[],
): readonly DagNode[] {
    const byBinding = new Map<string, string>();
    for (const effect of effects) {
        // A node's binding is usually its own name; `binding` wins when they differ.
        byBinding.set(effect.binding ?? effect.node, effect.node);
    }
    const parsed = effects.map((effect) => {
        const [binding, predicate] = (effect.arm ?? "").split(":");
        return {
            node: effect.node,
            kind: effect.kind,
            upstream: binding ? (byBinding.get(binding) ?? null) : null,
            predicate: predicate ?? null,
        };
    });
    const depthOf = new Map<string, number>();
    const resolve = (name: string, seen: Set<string>): number => {
        if (depthOf.has(name)) return depthOf.get(name)!;
        if (seen.has(name)) return 0;
        seen.add(name);
        const entry = parsed.find((candidate) => candidate.node === name);
        const depth = entry?.upstream ? resolve(entry.upstream, seen) + 1 : 0;
        depthOf.set(name, depth);
        return depth;
    };
    for (const entry of parsed) resolve(entry.node, new Set());

    const rows = new Map<number, number>();
    return parsed.map((entry) => {
        const depth = depthOf.get(entry.node) ?? 0;
        const row = rows.get(depth) ?? 0;
        rows.set(depth, row + 1);
        return { ...entry, depth, row };
    });
}
