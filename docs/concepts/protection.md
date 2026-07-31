# How GaugeDesk protects your work

GaugeDesk limits what an agent can read, do, keep, and send. These controls do
not make the model provider private.

## Where your data goes

### Work on your computer

Your computer processes project files and agent actions. The selected model
provider receives the prompt and allowed context in plaintext.

### Work between systems

A relay can move encrypted content between systems without reading it. The
receiving system decrypts the content and checks permission again. Its operator
and model provider can see the plaintext needed for the work.

### Website agents

GaugeWright's hosted runtime and the selected model provider process visitor
input. The agent author's computer is not part of this path.

## What GaugeDesk enforces

- **Only allowed access:** A run receives only the files, tools, and actions
  approved for it.
- **Deny by default:** Missing, invalid, expired, or withdrawn permission
  grants nothing.
- **Fixed agent versions:** A work chat cannot change its agent instructions.
- **Review before acceptance:** Agent changes remain proposed until a person
  keeps them.
- **Review before release:** Content cannot cross a protected boundary without
  the required approval.
- **Permanent history:** GaugeDesk appends audit events instead of rewriting
  past events.
- **Safe erasure:** Erasure removes future content access but keeps the minimum
  facts needed to explain past actions.

## Network access

A project can deny all network access. A fully isolated run cannot call a
remote model.

Some hosts can limit network access to an approved model provider. If a host
cannot enforce that limit, GaugeDesk must show the lower protection level. It
must not claim that the route is filtered.

## Credentials

Credentials must not appear in agent instructions, project files, chats, URLs,
logs, browser messages, or public releases.

For a website agent, the deployment selects one exact stored credential. The
host checks that it matches the provider and credential type allowed by the
release.

## Collected website results

A published release defines what a website agent may collect. The running agent
cannot change that definition.

The hosted runtime validates and encrypts the result. When the owner downloads
it, GaugeDesk validates it again and puts it in quarantine for review.

## Independent verification

An independently verified host can remove the host operator from the set of
people who can read plaintext. It does not remove the model provider.

This capability is built but is not generally available.

For current evidence and limits, see
[Verify security claims](../reference/verifying-claims.md) and
[Current limits](../reference/limitations.md).
