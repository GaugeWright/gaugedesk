# Verify security claims

GaugeDesk uses specifications, tests, formal models, and production records as
evidence. This evidence is not an independent audit or certification.

## Product claims and evidence

| Claim | Main evidence |
| --- | --- |
| A run receives only approved access | Core permission tests and application tests |
| Missing permission grants nothing | Denial tests and formal model checks |
| A file identifier does not grant file access | Resource-access tests |
| A work chat cannot change its agent | Agent-version contracts and Linux/macOS sandbox tests |
| Audit history is append-only | Event-store tests and recovery checks |
| Release needs required approval | Release lifecycle tests and formal models |
| A website session stays on one release | Session and release tests |
| Website credentials cannot fall back to a shared key | Provider and credential-binding tests |
| Website collection cannot change during a run | Release, session, and collection tests |
| Erasure keeps minimum audit facts | Content-erasure tests |

## Run the repository checks

In the GaugeDesk source repository, run:

```bash
cargo test --workspace
cd web
npm run typecheck
npm run test
cd ..
for model in specs/models/*.qnt; do quint typecheck "$model"; done
python3 scripts/audit-gate.py
```

These checks test source behavior and specification alignment. They do not
prove the state of a specific customer installation.

## Verify a release

For the release that you plan to install:

1. Identify the source revision.
2. Check the artifact checksum.
3. Check the platform signature or notarization, when available.
4. Inspect the SPDX software bill of materials.
5. Verify the build-provenance attestation.
6. Compare the result with the release notes and known limits.

## Verify a hosted feature

Ask for evidence from the actual environment and time period:

- active release identity;
- deployment configuration;
- health and security-event records;
- backup and restore test;
- incident history;
- subprocessor list; and
- current product-status statement.

A CI test or old production record does not prove that a service is currently
available.

## Limits of this evidence

This evidence does not replace:

- an independent penetration test;
- a SOC 2 report;
- ISO 27001 certification;
- legal advice;
- review of your configuration; or
- an uptime SLA.
