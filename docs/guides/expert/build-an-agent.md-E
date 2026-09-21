# Build your first agent

You need GaugeDesk with a model provider, a small test project, and a task whose
result you can check.

## Create the agent

1. Open the agent library and select **New agent**.
2. Give it a task-based name.
3. In an edit chat, define:
   - the work and expected output;
   - required input;
   - tools;
   - stop and refusal conditions; and
   - how to verify the result.

Example:

> Correct spelling and grammar in Markdown files. Preserve meaning, headings,
> links, and code examples. Do not edit source code. List each changed file.

## Set access and limits

Allow only the tools, files, services, network routes, and output types the
task requires. Select the model provider and credential type; never put the
credential itself in the agent.

The provider receives prompts and allowed files in plaintext.

## Test it

Test a normal task, missing input, denied file and tool access, cancellation,
a provider failure, and an attempt to change the agent's own instructions.
Review file access, tool calls, denials, changes, and final status.

Fix the draft in an edit chat and repeat until its behavior is predictable.
Then save a fixed version. Packages and website releases cannot use drafts.

Next: [Save and update versions](versioning-and-forking.md) or
[run the agent](run-and-review.md).
