# Audit

This guide explains the derived View for `audit.json`. The JSON document remains the inspectable source for this surface.

Audit is an append-only, actor-attributed timeline of governance actions. Ordering is local for readability and does not imply a global total order. Payloads never appear in the log.

## Using the agent

Ask the Admin agent to explain this file or prepare a reviewed patch. The agent cannot use a shell or the web, cannot reveal credentials, and cannot admit its own proposal.
