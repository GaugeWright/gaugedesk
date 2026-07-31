# Publish an agent on a website

Website agents have a production proof, but general self-service access is not
available. Contact GaugeWright before promising this feature.

You need a tested fixed version, approved provider and hosted credential, exact
allowed website origins, session/spend/retention limits, and a visitor privacy
notice.

## Configure and test

1. Select the fixed version and confirm its tools, provider, panel types,
   initial files, and output limits.
2. Configure origins, visitor identity, panel types, session and concurrency
   limits, spend, retention, and the exact model credential.
3. If the deployment collects a result, define its eligible content, schema,
   recipient, size limit, and whether collection is required.
4. Preview an allowed and blocked origin, a normal session, refresh/resume,
   limits, provider failure, and collection validation.

The credential must match the provider and type allowed by the release; there
is no shared-key fallback. Collection rules cannot change during a run.

## Publish and update

Publishing creates a signed, immutable release. Copy the generated integration
code to an allowed site. New sessions use the active release; sessions already
running remain pinned to their original release.

The hosted runtime serves visitors even when the author's computer is offline.
Monitor use, spend, errors, and collected results. Publish a new fixed version
to update the deployment. Downloaded visitor material enters quarantine for
review.

## Visitor notice

Before accepting visitor data, disclose the operator, purpose, model provider,
GaugeWright hosting, collection, retention, privacy contact, and support path.
Do not claim local inference, SOC 2, ISO 27001 certification, or an independent
penetration test.

See [Current limits](../../reference/limitations.md).
