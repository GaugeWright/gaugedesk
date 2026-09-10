/**
 * The programs the whip figure lab draws, as `whipplescript.instance_view.v0`
 * actually prints them.
 *
 * Not written by hand and not trimmed: each `structure` below is exactly what
 * `gaugedesk_whip_runtime::program_structure` returns for that example program
 * under the pinned WhippleScript, so the bench cannot flatter the figure by
 * feeding it a shape the runtime never sends. Regenerate by calling that
 * function on the example sources in the whipplescript repository.
 *
 * Each of the three carries one of the things this figure used to render badly.
 */
export interface LabProgram {
    readonly name: string;
    readonly structure: unknown;
}

export const LAB_PROGRAMS: readonly LabProgram[] = [
    /** Nine effects in one rule, four of them unbound — the case where
     *  `effect7`, `effect8` and `effect9` were the whole of what a reader got.
     *  Its three `case` arms all hang off one edge, and only the pattern on
     *  each tells them apart. Two `table` declarations too.
     */
    {
        name: "gastown-lite",
        structure: {
            available: true,
            ir_hash: "5cbb95f2611e242cc79cd3ff50a64d8f",
            program_version_id: "",
            rule_edges: [
                {
                    consumer: "implement_ready_ticket",
                    fact: "tracker:backlog",
                    producer: "file_ticket",
                },
                {
                    consumer: "implement_ready_ticket",
                    fact: "tracker:backlog",
                    producer: "implement_ready_ticket",
                },
                {
                    consumer: "implement_ready_ticket",
                    fact: "schema:WorkspaceReady",
                    producer: "table_workspaces",
                },
            ],
            rules: [
                {
                    dependencies: [],
                    effects: [],
                    name: "table_workspaces",
                    records: [
                        {
                            construct: "table_row",
                            schema: "WorkspaceReady",
                        },
                    ],
                    whens: [
                        "started",
                    ],
                },
                {
                    dependencies: [],
                    effects: [
                        {
                            binding: null,
                            case: null,
                            kind: "tracker.file",
                            label: null,
                            node: "effect1",
                            verb: "file",
                        },
                    ],
                    name: "file_ticket",
                    records: [],
                    whens: [
                        "started",
                    ],
                },
                {
                    dependencies: [
                        {
                            downstream: "slot",
                            predicate: "succeeds",
                            upstream: "claimed",
                        },
                        {
                            downstream: "turn",
                            predicate: "completes",
                            upstream: "slot",
                        },
                        {
                            downstream: "effect4",
                            predicate: "completes",
                            upstream: "slot",
                        },
                        {
                            downstream: "review",
                            predicate: "succeeds",
                            upstream: "turn",
                        },
                        {
                            downstream: "log_entry",
                            predicate: "succeeds",
                            upstream: "review",
                        },
                        {
                            downstream: "effect7",
                            predicate: "succeeds",
                            upstream: "log_entry",
                        },
                        {
                            downstream: "effect8",
                            predicate: "succeeds",
                            upstream: "log_entry",
                        },
                        {
                            downstream: "effect9",
                            predicate: "succeeds",
                            upstream: "log_entry",
                        },
                    ],
                    effects: [
                        {
                            binding: "claimed",
                            case: null,
                            kind: "tracker.claim",
                            label: "claimed",
                            node: "claimed",
                            verb: "claim",
                        },
                        {
                            binding: "slot",
                            case: null,
                            kind: "lease.acquire",
                            label: "slot",
                            node: "slot",
                            verb: "acquire",
                        },
                        {
                            binding: "turn",
                            case: null,
                            kind: "agent.tell",
                            label: "turn",
                            node: "turn",
                            verb: "tell",
                        },
                        {
                            binding: null,
                            case: null,
                            kind: "tracker.release",
                            label: null,
                            node: "effect4",
                            verb: "release",
                        },
                        {
                            binding: "review",
                            case: null,
                            kind: "schema.coerce",
                            label: "review",
                            node: "review",
                            verb: "coerce",
                        },
                        {
                            binding: "log_entry",
                            case: null,
                            kind: "ledger.append",
                            label: "log_entry",
                            node: "log_entry",
                            verb: "append",
                        },
                        {
                            binding: null,
                            case: {
                                pattern: "\"merge\"",
                                scrutinee: "decision.verdict",
                            },
                            kind: "tracker.finish",
                            label: null,
                            node: "effect7",
                            verb: "finish",
                        },
                        {
                            binding: null,
                            case: {
                                pattern: "\"revise\"",
                                scrutinee: "decision.verdict",
                            },
                            kind: "tracker.release",
                            label: null,
                            node: "effect8",
                            verb: "release",
                        },
                        {
                            binding: null,
                            case: {
                                pattern: "\"blocked\"",
                                scrutinee: "decision.verdict",
                            },
                            kind: "tracker.release",
                            label: null,
                            node: "effect9",
                            verb: "release",
                        },
                    ],
                    name: "implement_ready_ticket",
                    records: [],
                    whens: [
                        "backlog has ready issue as issue",
                        "WorkspaceReady as ready",
                        "frontend is available",
                    ],
                },
            ],
            workflow: "GastownLite",
        },
    },
    /** A `then` chain, whose handles are `__then_plan` and `__then_signoff`.
     *  Neither was written by anyone: the author wrote `plan` and `signoff`.
     */
    {
        name: "triage-chain",
        structure: {
            available: true,
            ir_hash: "dc7b7ea848c278b9791b99ba30c5c84e",
            program_version_id: "",
            rule_edges: [
                {
                    consumer: "triage_ticket",
                    fact: "schema:Ticket",
                    producer: "table_tickets",
                },
            ],
            rules: [
                {
                    dependencies: [],
                    effects: [],
                    name: "table_tickets",
                    records: [
                        {
                            construct: "table_row",
                            schema: "Ticket",
                        },
                    ],
                    whens: [
                        "started",
                    ],
                },
                {
                    dependencies: [
                        {
                            downstream: "__then_signoff",
                            predicate: "succeeds",
                            upstream: "__then_plan",
                        },
                    ],
                    effects: [
                        {
                            binding: "__then_plan",
                            case: null,
                            kind: "agent.tell",
                            label: "plan",
                            node: "__then_plan",
                            verb: "tell",
                        },
                        {
                            binding: "__then_signoff",
                            case: null,
                            kind: "schema.coerce",
                            label: "signoff",
                            node: "__then_signoff",
                            verb: "coerce",
                        },
                    ],
                    name: "triage_ticket",
                    records: [],
                    whens: [
                        "Ticket as ticket where ticket.status == \"open\"",
                        "triager is available",
                    ],
                },
            ],
            workflow: "TriageChain",
        },
    },
    /** A 170-character `where` guard, which on one line made this rule's box
     *  about eleven hundred pixels wide and pushed the figure off the page.
     */
    {
        name: "incident-router",
        structure: {
            available: true,
            ir_hash: "7eb2fa799566300d26fb53f22c7819d7",
            program_version_id: "",
            rule_edges: [
                {
                    consumer: "route_incident",
                    fact: "schema:Incident",
                    producer: "table_incidents",
                },
            ],
            rules: [
                {
                    dependencies: [],
                    effects: [],
                    name: "table_incidents",
                    records: [
                        {
                            construct: "table_row",
                            schema: "Incident",
                        },
                        {
                            construct: "table_row",
                            schema: "Incident",
                        },
                    ],
                    whens: [
                        "started",
                    ],
                },
                {
                    dependencies: [],
                    effects: [
                        {
                            binding: "turn",
                            case: null,
                            kind: "agent.tell",
                            label: "turn",
                            node: "turn",
                            verb: "tell",
                        },
                    ],
                    name: "route_incident",
                    records: [],
                    whens: [
                        "Incident as incident where (((incident.severity >= 2) && (\"route\" in incident.metadata)) && (incident.metadata[\"route\"] in [\"code\", \"review\", \"ops\"])) && ((incident.owner == null) || exists(incident.owner))",
                        "incident.assignee is available",
                    ],
                },
            ],
            workflow: "IncidentRouter",
        },
    },
];
