# Security operations

| Area | Current operation |
| --- | --- |
| Source | Protected default branches, required checks, secret and dependency scanning, static analysis |
| Releases | SPDX SBOMs and OIDC build provenance for GaugeDesk and WhippleScript workflows |
| Monitoring | External probes, audit-integrity and export checks, Azure Monitor, Log Analytics, and responder alerts |
| Retention | 30 days for metadata-only central production events |
| Recovery | Encrypted backups in a separate failure boundary; restore tested into an erased Home |
| Access | Least privilege, provider MFA where supported, and quarterly privileged-access review |
| Abuse controls | Cloudflare edge rate-limiting on the authentication routes and an origin request-body cap, with an IP-keyed in-process failed-attempt lockout as defense-in-depth; the edge is the primary control |
| Review | Annual risk, incident, restore, vendor, and end-to-end alert exercises; earlier after material changes |

The alert path from ingestion to responder was exercised on July 29, 2026.
Internal recovery targets are 24-hour RPO and 8-hour RTO; they are not an SLA.
The hosted control plane remains single-node.

GaugeWright is founder-operated, so independent internal approval and
separation of duties are unavailable.

See [Incident response](incident-response.md), [Support](support.md), and
[Verify security claims](../reference/verifying-claims.md).
