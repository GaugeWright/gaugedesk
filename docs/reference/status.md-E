# Product status

This page is the source of truth for what you can use now.

## Status terms

- <span class="status available">Available</span> — A user can use the
  capability now in its stated scope.
- <span class="status built">Built</span> — The capability is implemented and
  tested. It is not available in a supported production path unless this page
  says that it is deployed.
- <span class="status planned">Planned</span> — The capability has an accepted
  design but is not built.
- <span class="status none">Not implemented</span> — The capability does not
  exist.

**Production proof** means GaugeWright has verified one named production use,
not general availability or self-service.

## Important data-flow fact

GaugeDesk does not run the model on your device. A run sends the prompt and the
admitted context to the configured model provider. The provider sees that data
in plaintext.

For a local run, you select and authorize the provider. For a public
deployment, the deployment uses the exact hosted credential that its owner
selected. GaugeWright does not provide confidential inference today.

Read [Where your data goes](../concepts/protection.md#where-your-data-goes)
before you use sensitive data.

## Capability table

| Capability | Status | Current scope |
| --- | --- | --- |
| Local desktop workbench: build, run, and review | <span class="status available">Available</span> | Runs on the user's computer. Model inference is remote. |
| Self-federation across devices | <span class="status available">Available</span> | Verified with the product protocol and test environments. |
| Cross-party federation | <span class="status built">Built</span> | The protocol and relay path are tested. General cross-party service availability is not established. |
| Append-only audit log and export | <span class="status available">Available</span> | The application event log is append-only. Audit export is implemented. |
| Central production security-event monitoring | <span class="status available">Available</span> | Azure Monitor and Log Analytics collect metadata-only production events. Alert delivery was exercised on 2026-07-29. |
| Linux and macOS method isolation | <span class="status available">Available</span> | Uses the supported operating-system sandbox. |
| Windows method isolation | <span class="status planned">Planned</span> | Windows does not have the same kernel isolation. |
| Local encryption at rest | <span class="status available">Available</span> | Uses AES-256-GCM envelope encryption. |
| KMS-backed encryption | <span class="status built">Built</span> | The Key Vault adapter and recovery path are tested. Availability depends on the managed deployment. |
| Package and release lifecycle | <span class="status built">Built</span> | The immutable package and release controls are implemented. |
| Output review and release | <span class="status built">Built</span> | Review and approved transfer are implemented and tested. |
| Enterprise OIDC, SAML, SCIM, and RBAC | <span class="status built">Built</span> | The code and vendor conformance paths are tested. Customer rollout is not generally available. |
| GaugeDesk Administration | <span class="status built">Built</span> | The shared, capability-gated management environment is implemented. |
| Public Embeddable Panels runtime | **Production proof** | The Theory A deployment runs on the production edge. General self-service availability is not established. |
| Publish, preview, update, and monitor controls | <span class="status built">Built</span> | Production infrastructure exists. The complete no-founder-intervention path is still being proved. |
| Public-session collection | <span class="status built">Built</span> and deployed | Release-declared collections can be sealed and deposited. The complete author-to-visitor-to-review journey is not yet accepted as self-service. |
| Attested confidential-VM compute | <span class="status built">Built</span> | The verifier and key-release seams are tested. No generally available attested service exists. |
| Confidential inference | <span class="status planned">Planned</span> | The model provider remains in the trust boundary. |
| Native iOS and Android clients | <span class="status built">Built</span> | Signed CI and hosted-device journeys pass. Store distribution, carrier push, and physical-device proof remain. |
| GaugeDesk Plus | <span class="status built">Built</span> | The USD 12 per-seat monthly plan is defined. General commercial availability is not stated here. |
| SBOM and build provenance | <span class="status available">Available</span> | Release workflows generate SPDX SBOMs and OIDC provenance attestations. |
| Dependency, secret, and static scanning | <span class="status available">Available</span> | Scheduled and change-triggered checks run in active repositories. |
| Privacy notice, DPA, and subprocessor list | <span class="status available">Available</span> | GaugeWright publishes these documents and operates a privacy request path. |
| Independent penetration test | <span class="status planned">Planned</span> | No independent penetration test is complete. |
| SOC 2 or ISO 27001 certification | <span class="status planned">Planned</span> | GaugeWright does not claim either certification. |
| Contractual uptime SLA | <span class="status none">Not implemented</span> | The hosted control plane is single-node. Tested recovery is not high availability. |

See [Known limitations](limitations.md) for the constraints behind these
statuses.
