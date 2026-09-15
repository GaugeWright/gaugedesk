@transport @enterprise-composition
Feature: GaugeWright account sign-in in Desk (ADR 0123, LOGIN-3/4/5)

  The desktop links the person's GaugeWright account through the native device
  handoff: the control plane mints and holds the verifier, the OS deep-links a
  single-use code back, and the sealed session — bound to a trusted-device
  record — refreshes proactively until the device is revoked or the person
  signs out. The hosted account authority here is hermetic
  (`test-account-hub`); it is a protocol stand-in, not a separate user-facing
  Hub. The real account handlers carry their own unit tests in `auth_oidc`.

  Scenario: sign in through the native handoff, refresh, revoke, sign out
    Given the workbench is open
    When I open my account
    Then the GaugeWright account section offers sign-in
    When I begin GaugeWright sign-in
    And the OS delivers the sign-in return "gaugewright://auth/callback#code=e2e-handoff-code"
    Then the account section shows me signed in as "e2e-person@example.test"
    And the native Account Settings page is available
    When I open native Provider Connections
    And I connect the native OpenAI credential
    Then the native provider connection is loaded from account authority
    When I open native Trusted Devices
    And I start native device linking
    Then the native device link is loaded from account authority
    When I send a message to the native Account conversation
    Then the native Account conversation returns after reload
    And the session renewal advances
    And my account reach lists home "e2e-home" and project "e2e-project"
    When the account authority revokes this device
    Then the session renewal no longer advances
    When I sign out of my GaugeWright account
    Then the GaugeWright account section offers sign-in
