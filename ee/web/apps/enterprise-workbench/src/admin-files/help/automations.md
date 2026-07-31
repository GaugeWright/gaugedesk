# Automations

Automations register a versioned WhippleScript source against one exact project
and one active placement in the Machine that owns that project. The
WhippleScript package owns trigger and task bodies; Administration stores only
their stable references, lifecycle status, and secret-free run evidence.

Creating, enabling, disabling, or deleting an automation is a reviewed tenant
command. A trigger does not grant run authority: an automation can fire only
while enabled and while its placement still belongs to the registered project.
Deletion is terminal. Past run evidence remains visible after deletion.

Do not paste prompts, credentials, or workflow bodies into this form. Use the
source, trigger, and task references produced by the project’s WhippleScript
package.
