# Build agents with GaugeDesk

An agent is a reusable set of instructions, tools, and limits for one type of
work.

Use this workflow:

1. Build a draft agent.
2. Test it on safe sample files.
3. Fix its instructions and limits.
4. Save a fixed version.
5. Add that version to a project.
6. Run it and review its work.
7. Package it for another team or publish it on a website.

Start with [Build your first agent](build-an-agent.md).

## Two types of chat

- Use an **edit chat** to change the agent.
- Use a **work chat** to run the agent on project files.

A work chat cannot change the agent's own instructions. This separation keeps a
project file or user prompt from silently changing how the agent works.

## What the model provider sees

GaugeDesk sends the prompt and allowed context to the selected model provider.
The provider receives this data in plaintext. Do not use a provider that is not
approved for the data.

## Ways to share an agent

- [Package it for another team](package-and-deploy.md).
- [Publish it on a website](../embed/index.md).

Check [Product status](../../reference/status.md) before you promise a hosted or
enterprise feature to a customer.
