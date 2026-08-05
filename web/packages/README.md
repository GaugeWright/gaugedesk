# Web Package Split Roots

These directories are transitional package roots for the future frontend split.
Packages now contain moved implementation files. Some package indexes still
expose transitional `src/` state where ownership is not settled, so package-shaped
imports can typecheck while lower-level moves are staged.

Each package root has a private `package.json` with `gaugewright` metadata for
the future repo target, source posture, CI lane, dependency policy, and runtime
dependencies. Dev/build dependencies still stay at the root, but each package
has package-root and source-derived subpath exports plus a local `typecheck`
script; `gw-embed` also has a local `build` script for the standalone public
embed bundle. Publish metadata remains pending.

Package code and legacy `web/src` compatibility shims should consume sibling
roots through declared workspace package names. Reaching into `../*/src` or
`../../*/src` is reserved for tsconfig/build entry sentinels during this
migration. `workbench-ui` now consumes `control-plane-client` through
`@gaugewright/control-plane-client`.

These integration-core packages remain independent of Administration (`ee/`)
and managed-cloud source. That dependency boundary preserves reuse and the two
Apache SDK exceptions; it is no longer a separate platform license band
(ADR 0121).
