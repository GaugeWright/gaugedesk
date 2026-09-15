@transport @enterprise-composition
Feature: Provider-neutral account recovery in Desk

  A person who cannot use their linked identity provider can recover the same
  GaugeDesk account with a short-lived email proof and one unused recovery
  code. The account authority, not the browser, owns both proofs and the
  resulting session.

  Scenario: recover the account once and refuse proof replay
    Given a recoverable GaugeDesk account exists
    When I recover it with the delivered email proof and recovery code
    Then Desk re-enters the same account through a persistent recovery session
    And the used recovery proof cannot mint another session
