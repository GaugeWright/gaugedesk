# Security overview

GaugeDesk limits agent access and records important actions. GaugeWright does
not claim independent certification that it does not have.

## Read this first

GaugeDesk does not provide local or confidential model inference. The selected
model provider receives prompts and allowed context in plaintext.

For a website agent, GaugeWright's hosted runtime also processes visitor data.

## Product controls

- A run receives only approved files, tools, and actions.
- Missing or invalid permission grants nothing.
- A file identifier does not grant access to file contents.
- A work chat cannot change its agent instructions.
- Agent output remains proposed until review.
- Protected content needs approval before release.
- Audit history is append-only.
- Website sessions use one fixed release.
- Website credentials are bound to one approved provider and credential type.
- Website collection is fixed at publication and cannot be widened by the
  running agent.

## Company-operated controls

GaugeWright operates source and release checks, security-event monitoring,
responder alerts, encrypted backups with restore tests, incident response, a
privacy request path, a DPA, and a subprocessor list. See
[Security operations](trust/security-operations.md).

## Current limits

- GaugeWright is founder-operated. Independent internal approval is not
  available.
- The hosted control plane has no uptime SLA.
- GaugeWright does not have a completed independent penetration test.
- GaugeWright does not have a SOC 2 report or ISO 27001 certification.
- Confidential model inference is not implemented.
- Windows does not have the Linux and macOS instruction-isolation sandbox.

Tests and formal models support product claims. They are not an independent
audit or certification.

## Report a security issue

Use the method on [Support](trust/support.md). Do not put a credential,
customer data, or exploit details in a public issue.

See [Verify security claims](reference/verifying-claims.md) and
[Current limits](reference/limitations.md).
