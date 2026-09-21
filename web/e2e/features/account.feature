@transport
Feature: Your account (ACCT-1)

  The operator's own surface (ADR 0053), reached from the account menu ▸ Settings: which
  models agents may run and whose credentials pay for them, what can reach your work,
  and who you are. The linked token is sealed server-side (SEC-4) and never shown again.

  Scenario: link an AI provider account
    Given the workbench is open
    When I open my model access
    And I link the "openai" account with token "sk-test-secret"
    Then "openai" shows as a linked account

  Scenario: configure the local managed-inference plan through the shipped Account client
    Given the workbench is open
    When I open my model access
    And I configure managed inference plan "wiring-managed" as "active" with 250000 included tokens
    Then the managed inference plan "wiring-managed" is durably "active" with 250000 included tokens

  # The entrance the shipped desktop actually uses (LOGIN-3/4/5). Deliberately
  # carries no lane tag, so it runs in the enterprise composition too — which is
  # the one `src-tauri/tauri.conf.json` ships, via
  # `frontendDist: ../ee/web/dist-enterprise-workbench`.
  #
  # That distinction is the whole bug. `EnterpriseWorkbench.tsx` passes
  # `gaugeApps` unconditionally, and the account menu read that prop to decide
  # between the card and `beginAccountAdmission`. So on every desktop, pressing
  # "Sign in" opened the Hub, which 303s to Google: a provider nobody had
  # chosen, then a return to a passkey prompt with no context for it. The card
  # with its address field, its passkey, and its three provider marks was never
  # on screen for the distro that ships.
  #
  # An earlier version of this scenario existed and was tagged `@open-only`
  # after it went red in the enterprise lane. That made the gate agree with the
  # bug. Untagged is the point.
  Scenario: signing in from the account menu opens the card, on every distro
    Given the workbench is open
    When I open my account
    And I choose sign-in from the account menu
    Then the sign-in card is open over the workbench
    And it offers an address, a passkey, and the provider marks
