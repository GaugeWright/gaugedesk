# authenticated-production-bundle
@transport @account-entry
Feature: Provider-neutral account recovery

  A person can recover the same custodied GaugeDesk account from the signed-out
  Desk without relying on an external identity provider. Recovery establishes
  the ordinary HttpOnly account session and consumes one recovery code.

  @authenticated
  Scenario: recover a custodied account through the real Desk entry
    Given a recoverable GaugeDesk account exists
    When I recover it with the delivered email proof and recovery code
    Then Desk re-enters the same account through a persistent recovery session
    And the used recovery proof cannot mint another session

  @authenticated
  Scenario: create and reopen an account with a passkey
    Given a new visitor has a platform passkey authenticator
    When I create an account with delivered email verification and that passkey
    Then Desk enters the new account through a persistent passkey session
    When I sign out and use the same passkey again
    Then Desk re-enters the same passkey account
