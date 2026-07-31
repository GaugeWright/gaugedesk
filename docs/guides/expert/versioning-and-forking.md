# Save and update agent versions

A draft can change. A fixed version cannot and has a permanent identity based
on its contents. Packages and deployments use fixed versions.

## Update an agent

1. Create a draft from the current version.
2. Make and test the change.
3. Save a new fixed version.
4. Update each project or deployment that should use it.

Projects do not update automatically. Existing website sessions remain on the
version they started with.

Create a separate agent when ownership, purpose, trust boundary, or long-term
maintenance differs. Keep its source version in the history.

Withdrawing a version stops new use but does not erase past runs. Erasing its
stored content removes future access while retaining the minimum audit record.
