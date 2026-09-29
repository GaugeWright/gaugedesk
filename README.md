# GaugeDesk

GaugeDesk is a free, event-sourced, projection-first desktop workbench for
governed, multi-party agentic work — a way to apply external expertise to
private operational context under review, release, and audit controls.

This repository is the open-source distribution of the GaugeDesk platform.

## What is here

- **Core crates** — `crates/core` (pure, property-tested reducers), `crates/store`
  (SQLite event log + admission), `crates/workspace` (git instance/worktrees),
  `crates/boundary` (the egress membrane), and `crates/app` (engine orchestrator + axum control plane).
- **Desktop shell** — `src-tauri/` (its own Cargo workspace).
- **Web** — `web/` (workbench, mobile, `workbench-ui`, `control-plane-client`,
  `gw-embed`) and the enterprise web workspace under `ee/web/`.
- **Enterprise (`ee/`)** — org/SSO/OIDC/SAML, SCIM, RBAC, enterprise audit
  (`ee/app`), and the SAML verifier sidecar (`ee/sidecar/saml-verify`).
- **Federation protocol** for remote runtime observation and admission.
- **Docs** — `docs/`, rendered to the documentation site.

## Download

Prebuilt desktop bundles are on the
[releases page](https://github.com/GaugeWright/gaugedesk/releases).
What each release after 0.4.30 changed is in [CHANGELOG.md](CHANGELOG.md).

| Platform | Bundle | Platform signature |
| --- | --- | --- |
| macOS (Apple silicon) | `.dmg` | Signed with GaugeWright LLC's Developer ID and notarized by Apple. The notarization ticket is stapled to the disk image and to the app in it. |
| Windows (x64) | `.msi` | Authenticode-signed by GaugeWright LLC through Azure Artifact Signing, with an RFC 3161 timestamp. The `gaugedesk.exe` in the installer is signed the same way. |
| Linux (x86_64) | `.deb`, `.AppImage` | None. Neither file carries a package signature. Check them with `SHA256SUMS` and the signed provenance. |

Every release also carries:

- **Updater signatures** — a `.sig` file for each bundle the in-app updater
  installs (on macOS, `GaugeDesk.app.tar.gz`, which is signed and notarized like
  the `.dmg`), and `latest.json`, which lists them. An installed GaugeDesk installs
  an update only when its signature verifies against the minisign key built into
  it (`plugins.updater.pubkey` in `src-tauri/tauri.conf.json`).
- **`SHA256SUMS`** — the SHA-256 digest of each bundle and updater signature.
- **Build provenance** — `gaugedesk-X.Y.Z.intoto.json`, an SLSA provenance
  statement that gives the SHA-256 digest of each release file except itself
  and its `.minisig` signature. Verify it with the public key in this
  repository:

  ```sh
  minisign -Vm gaugedesk-X.Y.Z.intoto.json -p docs/release-provenance.pub
  ```

- **Software bill of materials** — `gaugedesk-X.Y.Z.spdx.json`, in SPDX format.

### Debian and Ubuntu

The `.deb` is also published to a signed APT repository, so `apt` installs
GaugeDesk and keeps it up to date. Its signing key's fingerprint is
`5177 69B9 5FF8 599E 401D 742C 4E06 0974 CD0D 0ACF`.

```sh
sudo curl -fsSL https://packages.gaugewright.com/gaugewright-archive-keyring.gpg \
  -o /usr/share/keyrings/gaugewright-archive-keyring.gpg
sudo tee /etc/apt/sources.list.d/gaugewright.sources >/dev/null <<'SOURCES'
Types: deb
URIs: https://packages.gaugewright.com
Suites: stable
Components: main
Signed-By: /usr/share/keyrings/gaugewright-archive-keyring.gpg
SOURCES
sudo apt update
sudo apt install gaugedesk
```

Upgrade with `sudo apt upgrade`. `apt-get upgrade` holds back any release that
adds a dependency, and 0.4.30 added one.

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
