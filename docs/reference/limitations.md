# Known limitations

The [status page](status.md) is authoritative for availability.

| Area | Current limit |
| --- | --- |
| Model inference | Models run remotely. The selected provider receives prompts and admitted context in plaintext. Confidential and local inference are unavailable. |
| Network isolation | Some hosts can only allow all network access or deny it entirely. Denial prevents remote inference. |
| Windows | Windows lacks the Linux/macOS method-isolation sandbox. |
| Website agents | Theory A is a production proof, not general self-service or a general-availability commitment. |
| Federation | Self-federation is available in its stated scope. General managed cross-party service is not. |
| Enterprise | Identity, provisioning, roles, audit, and Administration are built but not generally available. |
| Attested compute | Verification and key-release components are built; no general service is available. The model provider still sees plaintext. |
| Availability | The hosted control plane is single-node, without automatic failover or an uptime SLA. Internal recovery targets are 24-hour RPO and 8-hour RTO. |
| Assurance | GaugeWright has no independent penetration test, SOC 2 report, or ISO 27001 certification. |
| Mobile | Clients are built, but app-store distribution, production push, and complete physical-device proof remain. |

GaugeDesk uses Apache-2.0 outside `ee/` and Business Source License 1.1 with the
GaugeWright Enterprise Use Grant inside `ee/`. Check the release for current
artifacts, signatures, SBOM, and provenance.
