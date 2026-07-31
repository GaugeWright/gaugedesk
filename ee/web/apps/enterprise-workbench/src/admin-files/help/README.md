# Administration help

Administration is a capability-gated Environment inside GaugeDesk. Each dashboard is the manifest-linked **View** of a plain canonical JSON document; **Edit** shows its literal source and **Changes** is the ordinary review surface.

Use the **Help** action in any Administration View for the guide tied to that document. The manifest, Views, Help, and agent definition live under the reserved `.environment/` namespace, hidden from the ordinary Files list unless **show internal files** is selected.

## Safety model

- Server-derived capability controls which files and commands exist.
- A configured endpoint or deep link grants nothing.
- Home inventory contributes only from live, target-admitted projections.
- Agent changes are proposals requiring human review.
- One-time credentials never enter files or agent context.
- The Admin session has no attachment or upload command; the server-side broker must reject undeclared content-ingest operations.
