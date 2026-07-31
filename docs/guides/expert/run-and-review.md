# Run an agent

Before sending sensitive data, confirm the selected model provider is approved
to receive it.

1. Add a fixed agent version to the project. Check its provider, tools, limits,
   and work folder.
2. Allow only the files needed for this run.
3. In a work chat, state the result, allowed and forbidden changes, checks, and
   output format.
4. During the run, inspect file and tool use, denials, errors, and model usage.
5. In **Changes**, compare the result with the starting files and run the
   required checks.
6. Select **Keep** or **Discard**.

The provider receives the prompt and allowed input in plaintext. A denial means
the action fell outside the run's permission; it is not necessarily an error.

Keeping work changes the project but does not send it elsewhere. To send a
result, use release review and confirm the recipient, purpose, files, and
approvals. See [Review work from an agent](../client/review-and-release.md).
