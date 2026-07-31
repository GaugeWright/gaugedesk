# Client software admission

This guide explains the derived View for `software-policy.json`. The JSON document remains the inspectable source for this surface.

Set minimum GaugeDesk version and protocol, allowed release channels, and an optional grace deadline. Outside an explicit grace window, nonconforming clients fail closed.

## Using the agent

Ask the Admin agent to explain this file or prepare a reviewed patch. The agent cannot use a shell or the web, cannot reveal credentials, and cannot admit its own proposal.
