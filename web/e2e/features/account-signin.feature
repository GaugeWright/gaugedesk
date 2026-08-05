@transport
Feature: GaugeWright account sign-in on the desktop (ADR 0123, LOGIN-3/4/5)

  The desktop links the person's GaugeWright account through the native device
  handoff: the control plane mints and holds the verifier, the OS deep-links a
  single-use code back, and the sealed session — bound to a trusted-device
  record — refreshes proactively until the device is revoked or the person
  signs out. The Hub here is the hermetic stand-in (`test-account-hub`); the
  real Hub handlers carry their own unit tests in `auth_oidc`.

  Scenario: sign in through the native handoff, refresh, revoke, sign out
    Given the workbench is open
    When I open my account
    Then the GaugeWright account section offers sign-in
    When I begin GaugeWright sign-in
    And the OS delivers the sign-in return "gaugewright://auth/callback#code=e2e-handoff-code"
    Then the account section shows me signed in as "e2e-person@example.test"
    And the session refresh extends the session
    And my account reach lists home "e2e-home" and project "e2e-project"
    When the Hub revokes this device
    Then the session refresh no longer extends the session
    When I sign out of my GaugeWright account
    Then the GaugeWright account section offers sign-in
