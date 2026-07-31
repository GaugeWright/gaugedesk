# Deployments

Technical public-agent deployment state from the selected tenant's admitted
Machines. Commercial offers and client entitlement remain in Vend.

An admitted administrator can propose a deployment by naming an existing
placement, setting the exact allowed audience origin, choosing the panel
ceiling, and setting spend and per-visitor limits. The proposal creates no
runtime state until a human accepts it. The accepted deployment is owned by the
selected tenant's Machine and remains separate from any Vend offer.

Configuration, pause, resume, package redeploy, and revocation use the same
reviewed command path. Pause blocks public operation until resumed. Revocation
is terminal and blocks future public operation without deleting audience,
session, usage, or package history. Redeploy changes the package snapshot copied
by future sessions; sessions already admitted keep their original snapshot.
