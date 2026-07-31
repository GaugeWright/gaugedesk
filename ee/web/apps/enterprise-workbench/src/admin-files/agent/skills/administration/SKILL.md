# Administration workflow

Use this workflow for every Admin request.

1. Identify the owning Administration JSON document through `.environment/manifest.json` and read its linked Markdown guide.
2. Read the current admitted file. Query Homes only when the answer depends on Home-owned inventory or freshness.
3. State unknown, stale, unauthorized, and unreachable inputs explicitly. Never turn missing evidence into a positive posture claim.
4. For an explanation, cite the file and projection that support it.
5. For a change, prepare the smallest typed patch with `environment.changes.propose` and summarize its effect.
6. Ask the human when intent, scope, or a consequential value is missing. The answer supplies intent, not new authority.
7. Stop at proposal. The human reviews and admits through the manual interface and the owning capability-gated command.

## Special cases

- SCIM tokens and other one-time credentials are issued only by the manual control and never returned to the agent.
- Billing state never grants data or run access.
- Reported client build metadata is compatibility evidence, not device attestation.
- Aggregate compliance scores are forbidden; show source, freshness, and caveats instead.
