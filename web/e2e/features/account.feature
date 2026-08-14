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
