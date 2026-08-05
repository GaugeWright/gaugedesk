# GaugeDesk

GaugeDesk is a free, event-sourced, projection-first desktop workbench for
governed, multi-party agentic work — a way to apply external expertise to
private operational context under review, release, and audit controls.

This repository is the open-source distribution of the GaugeDesk platform.

## What is here

- **Core crates** — `crates/core` (pure, property-tested reducers), `crates/store`
  (SQLite event log + admission), `crates/workspace` (git instance/worktrees),
  `crates/boundary` (the egress membrane), `crates/pi-bridge` (drives
  `pi --mode rpc`), and `crates/app` (engine orchestrator + axum control plane).
- **Desktop shell** — `src-tauri/` (its own Cargo workspace).
- **Web** — `web/` (workbench, mobile, `workbench-ui`, `control-plane-client`,
  `gw-embed`) and the enterprise web workspace under `ee/web/`.
- **Enterprise (`ee/`)** — org/SSO/OIDC/SAML, SCIM, RBAC, enterprise audit
  (`ee/app`), and the SAML verifier sidecar (`ee/sidecar/saml-verify`).
- **Federation protocol** and the open Pi membrane plugin (`plugin/`).
- **Docs** — `docs/`, rendered to the documentation site.

## Download

Prebuilt desktop bundles — Linux `.deb`/`.AppImage`, macOS `.dmg`, Windows `.msi`
— are on the [releases page](https://github.com/GaugeWright/gaugedesk/releases).
Installers are now unsigned.

## Licensing

The GaugeDesk platform, including `ee/`, is **AGPL-3.0-only** with recorded
additional permissions for independent extensions through documented public
interfaces and for embedding the unmodified GaugeDesk Embed Client. See
[`LICENSE`](LICENSE),
[`LICENSE-ADDITIONAL-PERMISSIONS`](LICENSE-ADDITIONAL-PERMISSIONS), and
[`NOTICE`](NOTICE).

The `control-plane-client` and `gw-embed` packages remain **Apache-2.0**.
GaugeWright LLC also offers commercial licenses for uses that do not comply
with the public license; contact `licensing@gaugewright.com`.

## Quick start

```sh
# Backend
cargo test --workspace

# Web client
cd web
npm ci
npm run dev                     # dev server
npm run typecheck && npm run test
```

## Verifying the security claims

GaugeDesk's protection model is structural, and much of it is machine-checked.
[Verifying the security claims](docs/reference/verifying-claims.md) maps each
guarantee to the executable tests in this repository that exercise it. The formal
Quint models those tests are derived from are maintained in a separate private
repository. The tests that check the same properties are public here.

## Related projects

| Project | What it is |
| --- | --- |
| GaugeWright | The company that builds GaugeDesk |
| WhippleScript | Orchestration language + runtime |
| `gaugewright-cloud` (private) | Hosted control plane, managed relay, embed host, attestation/KMS, settlement plane |
| `gaugewright-directory` | The blind account directory service |
