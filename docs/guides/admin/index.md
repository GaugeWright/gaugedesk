# Manage GaugeDesk

Authorized administrators can manage one personal or organization account in
GaugeDesk Administration. General customer rollout is not established.

| Area | Controls |
| --- | --- |
| People | Invitations, roles, and access |
| Identity | OIDC, SAML, SCIM, and group mapping |
| Policy | Account and project limits |
| Operations | Machines, backups, deployments, and software |
| Commercial | Subscriptions, usage, and invoices |
| Audit | Account activity and export |

To change a setting, select the account and area, edit the value, review
**Changes**, submit or approve it, then confirm the new value and audit event.
The service rechecks authority at submission.

Account roles do not automatically grant project or file access. Account policy
can reduce supported access but cannot create a protection the product or host
does not enforce. Conflicting policies deny the action.

Administration, identity, provisioning, and role controls are built but not
generally available. GaugeWright is founder-operated and the hosted control
plane has no uptime SLA.

Next: [Set up SSO and SCIM](identity-and-provisioning.md).
