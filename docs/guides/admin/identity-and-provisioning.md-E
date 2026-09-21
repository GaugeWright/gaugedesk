# Set up SSO and SCIM

OIDC, SAML, SCIM, and role controls are built; general rollout is not
established. Use a test group and a test person without production access.

## OIDC or SAML

1. In **Administration → Identity**, select OIDC or SAML.
2. Enter the issuer or metadata, audience, claims, and redirect information.
3. Save, then test a valid sign-in and invalid issuer, audience, signature, and
   expired assertion.

Do not enforce SSO for every administrator until recovery access is tested.
GaugeDesk can require an accepted identity-provider MFA result but does not
perform the second factor.

## SCIM

1. In **Provisioning**, create a connection and copy its endpoint and credential
   to the identity provider.
2. Map groups to GaugeDesk roles.
3. Test create, update, group change, and deactivation.

Deactivation stops future access but does not erase project history.

Keep client secrets, signing keys, SCIM credentials, and recovery codes out of
Git, agents, projects, chats, screenshots, and support requests.
